// The IDA SDK poisons the C stdio symbols (fprintf/stdout/stderr/fflush/...) to keep
// plugins off the console. hexport IS a console MCP server, so we talk to the OS file
// descriptors directly: fd 1 (stdout) carries the JSON-RPC protocol, fd 2 (stderr)
// carries the live status. _write/_dup* are not poisoned.
#pragma once
#include "pch.h"
#include <io.h>

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
