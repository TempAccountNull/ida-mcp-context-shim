// hexport - headless IDA (idalib) MCP server. Opens a database in-process and serves
// the tools our exporter needs over MCP (stdio for now; HTTP in M4).
#include "pch.h"
#include "mcp.hpp"

#include <cstring>
#include <io.h>
#include <fcntl.h>

static void usage(const char *a0)
{
  std::fprintf(stderr, "usage: %s --stdio <database.i64 | binary>\n", a0);
}

int main(int argc, char *argv[])
{
  const char *dbpath = nullptr;
  bool stdio = false;
  for ( int i = 1; i < argc; ++i )
  {
    if ( std::strcmp(argv[i], "--stdio") == 0 )
      stdio = true;
    else if ( argv[i][0] != '-' )
      dbpath = argv[i];
  }
  if ( dbpath == nullptr )
  {
    usage(argv[0]);
    return 2;
  }

  // idalib and any GUI-only plugins that fail headless print to stdout; that would
  // corrupt the JSON-RPC stream. Redirect stdout -> stderr for the whole startup, then
  // restore a clean stdout for the protocol.
  int saved = _dup(1);
  _dup2(_fileno(stderr), 1);

  int rc = init_library();   // no argv: our --stdio/db args are not IDA switches
  if ( rc == 0 )
  {
    enable_console_messages(false);
    rc = open_database(dbpath, /*run_auto=*/true);
    if ( rc == 0 )
      auto_wait();
  }
  fflush(stdout);
  _dup2(saved, 1);
  _close(saved);

  if ( rc != 0 )
  {
    std::fprintf(stderr, "hexport: idalib failed to open '%s' (%d)\n", dbpath, rc);
    return rc;
  }

  int result = 0;
  Mcp server;
  if ( stdio )
    result = server.run_stdio();
  else
    std::fprintf(stderr, "hexport: idalib opened OK. No transport selected (pass --stdio).\n");

  close_database(/*save=*/false);
  return result;
}
