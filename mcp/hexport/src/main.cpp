// hexport - headless IDA (idalib) MCP server. Opens a database in-process and serves
// the tools our exporter needs over MCP (stdio via --stdio, or HTTP via --http). The
// database is optional at startup - it can be opened/closed at any time via the
// open_database / close_database tools, or with --open/--close on the command line.
#include "pch.h"
#include "mcp.hpp"
#include "bridge.hpp"
#include "raw_io.hpp"
#include "strhash.hpp"

//-------------------------------------------------------------------------
// Licensing. IDA searches $IDAUSR BEFORE $IDADIR, so a licence sitting in the roaming profile wins
// over the one in the installation -- and if that profile licence is IDA Free while the install is
// Professional, the kernel refuses to start at all ("Fatal error before kernel init"). That is a
// real machine here: %APPDATA%\Hex-Rays\IDA Pro\idafree_*.hexlic against
// C:\Program Files\IDA Professional 9.4\idapro.hexlic.
//
// So by default point IDAUSR at the installation directory, which is where the licence belonging to
// the idalib we actually loaded lives. --license overrides it, --keep-idausr opts out entirely for
// anyone who really does want their profile's plugins and configuration.
//
// This must happen BEFORE init_library(): the licence is read during kernel init.
static bool dir_has_license(const char *dir)
{
  qstring pat;
  pat.sprnt("%s\\*.hexlic", dir);
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(pat.c_str(), &fd);
  if ( h == INVALID_HANDLE_VALUE )
    return false;
  FindClose(h);
  return true;
}

// Directory of the idalib we are bound to -- the installation this build actually runs against,
// rather than whichever IDA happens to be first on PATH.
static qstring idalib_dir()
{
  HMODULE m = GetModuleHandleA("idalib.dll");
  if ( m == nullptr )
    m = GetModuleHandleA("idalib64.dll");
  if ( m == nullptr )
    return qstring();
  char buf[MAX_PATH];
  DWORD n = GetModuleFileNameA(m, buf, DWORD(sizeof(buf)));
  if ( n == 0 )
    return qstring();
  for ( DWORD i = n; i-- > 0; )
  {
    if ( buf[i] == '\\' || buf[i] == '/' )
    {
      buf[i] = 0;
      return qstring(buf);
    }
  }
  return qstring();
}

static void setup_license(const char *license, const char *idadir, bool keep_idausr)
{
  if ( idadir != nullptr )
    SetEnvironmentVariableA("IDADIR", idadir);

  if ( license != nullptr )
  {
    // A file or the directory holding it; IDAUSR wants a directory.
    qstring dir(license);
    if ( dir_has_license(dir.c_str()) )
    {
      SetEnvironmentVariableA("IDAUSR", dir.c_str());
    }
    else
    {
      for ( ssize_t i = ssize_t(dir.length()); i-- > 0; )
      {
        if ( dir[i] == '\\' || dir[i] == '/' )
        {
          dir.resize(size_t(i));
          break;
        }
      }
      SetEnvironmentVariableA("IDAUSR", dir.c_str());
    }
    qstring m;
    m.sprnt("hexport: IDAUSR -> %s (from --license)\n", dir.c_str());
    write_err(m);
    return;
  }

  if ( keep_idausr )
    return;

  qstring dir = idadir != nullptr ? qstring(idadir) : idalib_dir();
  if ( dir.empty() || !dir_has_license(dir.c_str()) )
    return;                       // nothing better to offer; leave the environment alone

  SetEnvironmentVariableA("IDAUSR", dir.c_str());
  qstring m;
  m.sprnt("hexport: IDAUSR -> %s (installation licence; --keep-idausr to opt out)\n", dir.c_str());
  write_err(m);
}

static void usage(const char *a0)
{
  qstring m;
  m.sprnt("usage: %s [--stdio | --http [--port N]] [--open <db.i64|binary>] "
          "[--run-auto] [--close] [db.i64|binary]\n"
          "  --http   serve MCP over HTTP POST /mcp, auto-scanning up from --port (default 13337)\n", a0);
  write_err(m);
}

int main(int argc, char *argv[])
{
  const char *dbpath = nullptr;
  bool use_stdio = false;
  bool use_http = false;
  bool use_bridge = false;
  const char *worker_exe = nullptr;
  const char *license = nullptr;
  const char *idadir = nullptr;
  bool keep_idausr = false;
  bool run_auto = false;
  bool want_close = false;
  int http_port = 13337;   // ida-pro-mcp convention; instances auto-bump to 13338, 13339, ...

  for ( int i = 1; i < argc; ++i )
  {
    switch ( str_hash(argv[i]) )
    {
      case "--stdio"_h:    use_stdio = true;   break;
      case "--http"_h:     use_http = true;    break;
      case "--bridge"_h:   use_bridge = true;  break;
      case "--worker"_h:   if ( i + 1 < argc ) worker_exe = argv[++i]; break;
      case "--license"_h:  if ( i + 1 < argc ) license = argv[++i]; break;
      case "--idadir"_h:   if ( i + 1 < argc ) idadir = argv[++i]; break;
      case "--keep-idausr"_h: keep_idausr = true; break;
      case "--port"_h:     if ( i + 1 < argc ) http_port = atoi(argv[++i]); break;
      case "--run-auto"_h: run_auto = true;    break;
      case "--close"_h:    want_close = true;  break;
      case "--open"_h:     if ( i + 1 < argc ) dbpath = argv[++i]; break;
      case "--help"_h:
      case "-h"_h:         usage(argv[0]); return 0;
      default:             if ( argv[i][0] != '-' ) dbpath = argv[i]; break;
    }
  }

  // The bridge is a router with no database of its own: it must not initialise idalib,
  // both because that cost is pointless here and because a process that never opens a
  // database can never be the one holding a lock on it.
  if ( use_bridge )
    return run_bridge(worker_exe, dbpath);

  setup_license(license, idadir, keep_idausr);   // before init_library: read at kernel init

  mute_stdout();
  int rc = init_library();
  unmute_stdout();
  if ( rc != 0 )
  {
    qstring m;
    m.sprnt("hexport: init_library failed (%d)\n", rc);
    write_err(m);
    return rc;
  }

  Mcp server;
  if ( dbpath != nullptr && !want_close )
  {
    qstring m;
    if ( server.startup_open(dbpath, run_auto) )
      m.sprnt("hexport: opened %s\n", dbpath);
    else
      m.sprnt("hexport: could not open '%s' (open it later via open_database)\n", dbpath);
    write_err(m);
  }

  int result = 0;
  if ( use_http )
    result = server.run_http(http_port);
  else if ( use_stdio )
    result = server.run_stdio();
  else
    write_err(qstring("hexport: ready. Pass --stdio or --http to serve MCP.\n"));

  server.startup_close();
  return result;
}
