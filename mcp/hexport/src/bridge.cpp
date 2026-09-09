#include "pch.h"
#include "bridge.hpp"
#include "raw_io.hpp"
#include "kstl/string.hpp"

//-------------------------------------------------------------------------
// One headless worker: a child `hexport --stdio` holding exactly one database, spoken to over its
// stdin/stdout with the same newline-delimited JSON-RPC the client uses. Keeping the wire format
// identical is what makes the bridge a router instead of a translator -- adding a tool to the
// worker needs no change here at all.
//-------------------------------------------------------------------------
struct Worker
{
  kstl::string db;                 // database this worker owns; empty means none yet
  kstl::string exe;
  HANDLE proc = nullptr;
  HANDLE to_child = nullptr;       // requests are written here
  HANDLE from_child = nullptr;     // replies are read from here
  kstl::string pending;            // bytes read but not yet split into a line

  bool alive() const
  {
    return proc != nullptr && WaitForSingleObject(proc, 0) == WAIT_TIMEOUT;
  }

  void shutdown()
  {
    if ( to_child != nullptr )
    {
      CloseHandle(to_child);       // closing stdin is how the worker is asked to exit
      to_child = nullptr;
    }
    if ( from_child != nullptr )
    {
      CloseHandle(from_child);
      from_child = nullptr;
    }
    if ( proc != nullptr )
    {
      if ( WaitForSingleObject(proc, 5000) == WAIT_TIMEOUT )
        TerminateProcess(proc, 1);
      CloseHandle(proc);
      proc = nullptr;
    }
    pending.clear();
  }

  // settle_ms: how long to wait before starting a replacement. A worker that was killed rather
  // than closed still holds the database's file handles for a moment, and a replacement that opens
  // during that window comes up degraded -- it reports ready with the right function count but the
  // wrong module name and cannot decompile. Serving that silently is worse than a visible failure,
  // so a restart pauses first. A first start needs no pause.
  bool spawn(unsigned settle_ms = 0)
  {
    shutdown();
    if ( settle_ms != 0 )
      Sleep(settle_ms);
    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE in_r = nullptr;
    HANDLE in_w = nullptr;
    HANDLE out_r = nullptr;
    HANDLE out_w = nullptr;
    if ( !CreatePipe(&in_r, &in_w, &sa, 0) )
      return false;
    if ( !CreatePipe(&out_r, &out_w, &sa, 0) )
    {
      CloseHandle(in_r);
      CloseHandle(in_w);
      return false;
    }
    // Our ends must NOT be inheritable, or the child holds a copy of the write end open and a
    // read here never sees EOF when it dies -- the classic pipe hang.
    SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);

    kstl::string cmd;
    cmd.push_back('"');
    cmd.append(exe.c_str());
    cmd.append("\" --stdio");
    if ( !db.empty() )
    {
      cmd.append(" \"");
      cmd.append(db.c_str());
      cmd.push_back('"');
    }

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_r;
    si.hStdOutput = out_w;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);   // worker status joins ours on fd 2
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessA(nullptr, const_cast<char *>(cmd.c_str()), nullptr, nullptr,
                             TRUE, 0, nullptr, nullptr, &si, &pi);
    CloseHandle(in_r);
    CloseHandle(out_w);
    if ( !ok )
    {
      CloseHandle(in_w);
      CloseHandle(out_r);
      return false;
    }
    CloseHandle(pi.hThread);
    proc = pi.hProcess;
    to_child = in_w;
    from_child = out_r;
    return true;
  }

  bool send(const char *line, unsigned n)
  {
    if ( to_child == nullptr )
      return false;
    DWORD wrote = 0;
    if ( !WriteFile(to_child, line, n, &wrote, nullptr) || wrote != n )
      return false;
    return WriteFile(to_child, "\n", 1, &wrote, nullptr) != FALSE;
  }

  // One reply line. False means the child closed or died mid-request.
  bool recv(kstl::string *out)
  {
    for ( ;; )
    {
      unsigned nl = pending.find('\n');
      if ( nl != kstl::string::npos )
      {
        // Drop a trailing CR. The worker's stdout is a pipe the CRT opened in TEXT mode, so
        // its newline already reached us as CR LF; keeping that CR and then writing our own
        // newline -- which our text-mode stdout expands too -- produced CR CR LF and a
        // phantom blank line that broke every client's line reader after the first reply.
        unsigned n = nl;
        if ( n > 0 && pending[n - 1] == '\r' )
          --n;
        *out = pending.substr(0, n);
        pending = pending.substr(nl + 1);
        return true;
      }
      char buf[16384];
      DWORD got = 0;
      if ( !ReadFile(from_child, buf, DWORD(sizeof(buf)), &got, nullptr) || got == 0 )
        return false;
      pending.append(buf, unsigned(got));
    }
  }
};

//-------------------------------------------------------------------------
static kstl::string self_path()
{
  char buf[MAX_PATH];
  DWORD n = GetModuleFileNameA(nullptr, buf, DWORD(sizeof(buf)));
  return kstl::string(buf, unsigned(n));
}

// A JSON-RPC error, echoing the request id so the client can match it. The id is copied as raw
// text rather than re-serialized: it may be a number or a string, and the bridge has no business
// changing either.
static void reply_error_line(const char *id_text, const char *message)
{
  qstring s;
  s.sprnt("{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":-32603,\"message\":\"%s\"}}\n",
          id_text != nullptr && id_text[0] != 0 ? id_text : "null", message);
  write_out(s);
}

// The id as it appeared on the wire. Scanning the text keeps the bridge out of the business of
// understanding JSON values -- it only has to hand the same bytes back.
static kstl::string raw_id(const kstl::string &line)
{
  unsigned k = line.find("\"id\"");
  if ( k == kstl::string::npos )
    return kstl::string();
  const char *p = line.c_str() + k + 4;
  while ( *p == ' ' || *p == ':' )
    ++p;
  const char *start = p;
  if ( *p == '"' )
  {
    ++p;
    while ( *p != 0 && *p != '"' )
      ++p;
    if ( *p == '"' )
      ++p;
  }
  else
  {
    while ( *p != 0 && *p != ',' && *p != '}' && *p != ' ' )
      ++p;
  }
  return kstl::string(start, unsigned(p - start));
}

// The string value of "key" in a flat JSON line, or empty. Text scanning, like raw_id, and for the
// same reason: this process never calls init_library(), so the SDK's jparse -- which is kernel-side
// -- is not available to it. Using it here crashed the bridge before it forwarded a single request.
// A router has no business parsing the payload anyway; it only needs to spot a database switch.
static kstl::string json_str_value(const kstl::string &line, const char *key)
{
  kstl::string pat("\"");
  pat.append(key);
  pat.append("\"");
  unsigned k = line.find(pat.c_str());
  if ( k == kstl::string::npos )
    return kstl::string();
  const char *p = line.c_str() + k + pat.size();
  while ( *p == ' ' || *p == ':' )
    ++p;
  if ( *p != '"' )
    return kstl::string();
  ++p;
  kstl::string out;
  while ( *p != 0 && *p != '"' )
  {
    if ( *p == '\\' && p[1] != 0 )      // keep escaped characters intact, notably \\ in paths
    {
      out.push_back(*p);
      ++p;
    }
    out.push_back(*p);
    ++p;
  }
  return out;
}

//-------------------------------------------------------------------------
int run_bridge(const char *worker_exe, const char *initial_db)
{
  Worker w;
  w.exe = worker_exe != nullptr ? kstl::string(worker_exe) : self_path();
  if ( initial_db != nullptr )
    w.db = initial_db;
  if ( !w.spawn() )
  {
    write_err(qstring("hexport-bridge: could not start a worker\n"));
    return 1;
  }
  {
    qstring m;
    m.sprnt("hexport-bridge: worker %s%s\n", w.exe.c_str(),
            w.db.empty() ? " (no database)" : "");
    write_err(m);
  }

  kstl::string line;
  while ( read_line(&line) )
  {
    if ( line.empty() )
      continue;

    // The bridge does not interpret tools. It needs only the id -- to answer if every worker
    // attempt fails -- and the database an open_database asks for, to decide which process should
    // own it. Everything else is forwarded byte for byte, so adding a tool to the worker needs no
    // change here at all.
    kstl::string id_text = raw_id(line);

    // A database is locked by whichever process opens it, so a different file means a different
    // process. That is IDA's rule, not a routing choice.
    if ( line.find("\"open_database\"") != kstl::string::npos )
    {
      kstl::string want = json_str_value(line, "file_path");
      if ( !want.empty() && !(w.db == want) )
      {
        w.db = want;
        w.spawn();
      }
    }

    bool answered = false;
    for ( int attempt = 0; attempt < 2 && !answered; ++attempt )
    {
      if ( !w.alive() && !w.spawn(750) )
        break;
      bool sent = w.send(line.c_str(), line.size());
      if ( sent )
      {
        kstl::string reply;
        bool got = w.recv(&reply);
        if ( got )
        {
          qstring s(reply.c_str(), reply.size());
          s.append('\n');
          write_out(s);
          answered = true;
          break;
        }
      }
      // Died mid-request: restart and retry once. This is the whole point of the split -- the
      // client's session survives a worker that a bad database or a decompiler crash took down.
      write_err(qstring("hexport-bridge: worker died, restarting\n"));
      w.spawn();
    }
    if ( !answered && !id_text.empty() )
      reply_error_line(id_text.c_str(), "worker unavailable");
  }

  w.shutdown();
  return 0;
}
