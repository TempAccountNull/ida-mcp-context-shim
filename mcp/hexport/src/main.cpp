// hexport - headless IDA (idalib) MCP server. Opens a database in-process and serves
// the tools our exporter needs over MCP (stdio for now; HTTP in M4). The database is
// optional at startup - it can be opened/closed at any time via the open_database /
// close_database tools, or with --open/--close on the command line.
#include "pch.h"
#include "mcp.hpp"
#include "raw_io.hpp"
#include "strhash.hpp"

static void usage(const char *a0)
{
  qstring m;
  m.sprnt("usage: %s [--stdio] [--open <db.i64|binary>] [--run-auto] [--close] [db.i64|binary]\n", a0);
  write_err(m);
}

int main(int argc, char *argv[])
{
  const char *dbpath = nullptr;
  bool use_stdio = false;
  bool run_auto = false;
  bool want_close = false;

  for ( int i = 1; i < argc; ++i )
  {
    switch ( str_hash(argv[i]) )
    {
      case "--stdio"_h:    use_stdio = true;   break;
      case "--run-auto"_h: run_auto = true;    break;
      case "--close"_h:    want_close = true;  break;
      case "--open"_h:     if ( i + 1 < argc ) dbpath = argv[++i]; break;
      case "--help"_h:
      case "-h"_h:         usage(argv[0]); return 0;
      default:             if ( argv[i][0] != '-' ) dbpath = argv[i]; break;
    }
  }

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
  if ( use_stdio )
    result = server.run_stdio();
  else
    write_err(qstring("hexport: ready. Pass --stdio to serve MCP over stdio.\n"));

  server.startup_close();
  return result;
}
