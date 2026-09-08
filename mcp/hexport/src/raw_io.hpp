// The IDA SDK poisons the C stdio symbols (fprintf/stdout/stderr/fflush/...) to keep
// plugins off the console. hexport IS a console MCP server, so we talk to the OS file
// descriptors directly: fd 1 (stdout) carries the JSON-RPC protocol, fd 2 (stderr)
// carries the live status. _write/_dup* are not poisoned.
#pragma once
#include "pch.h"
#include <io.h>
#include "kstl/string.hpp"

inline void write_out(const qstring &s) { _write(1, s.c_str(), unsigned(s.length())); }
inline void write_err(const qstring &s) { _write(2, s.c_str(), unsigned(s.length())); }

// Redirect stdout -> stderr around noisy idalib calls so the protocol on fd 1 is never
// corrupted; restore afterward.
inline int g_saved_fd1 = -1;
inline void mute_stdout()
{
  if ( g_saved_fd1 != -1 )
    return;
  g_saved_fd1 = _dup(1);
  _dup2(2, 1);
}
inline void unmute_stdout()
{
  if ( g_saved_fd1 == -1 )
    return;
  _dup2(g_saved_fd1, 1);
  _close(g_saved_fd1);
  g_saved_fd1 = -1;
}

// Read one line from fd 0, stripped of its newline. Returns false only at EOF with nothing buffered,
// so a final line without a trailing newline is still delivered. This replaced std::getline(std::cin)
// -- the protocol loop was the only reason <iostream> was included at all.
//
// Buffered on purpose: a _read per character would be a syscall per character. The buffer is static
// because the caller is a single-threaded protocol loop that must not lose bytes between calls.
inline bool read_line(kstl::string *out)
{
  static char rbuf[65536];
  static unsigned rlen = 0;
  static unsigned rpos = 0;
  out->clear();
  for ( ;; )
  {
    if ( rpos == rlen )
    {
      int r = _read(0, rbuf, unsigned(sizeof(rbuf)));
      if ( r <= 0 )
        return !out->empty();
      rlen = unsigned(r);
      rpos = 0;
    }
    unsigned start = rpos;
    while ( rpos < rlen && rbuf[rpos] != '\n' )
      ++rpos;
    out->append(rbuf + start, rpos - start);
    if ( rpos == rlen )
      continue;                       // buffer ran out mid-line; refill and keep going
    ++rpos;                           // consume the '\n'
    if ( !out->empty() && (*out)[out->size() - 1] == '\r' )
      out->pop_back();                // tolerate CRLF
    return true;
  }
}
