// Mcp - the MCP/JSON-RPC server: protocol core + transports (stdio and HTTP POST /mcp).
#pragma once
#include "pch.h"
#include "mcp_commands.hpp"

class Mcp
{
public:
  // Open a database at startup (for --open / positional path). Tools can also open/close
  // at any time via the open_database/close_database MCP tools.
  bool startup_open(const char *path, bool run_auto) { return cmds.open(path, run_auto); }
  void startup_close() { cmds.close(); }
  int run_stdio();          // read newline-delimited JSON-RPC from stdin, reply on stdout
  int run_http(int port);   // serve JSON-RPC over HTTP POST /mcp; auto-scans up from port

private:
  McpCommands cmds;
  // When set, write_response appends the serialized reply here instead of stdout, so the
  // HTTP transport can capture a request's reply. null => stdio (write to fd 1).
  qstring *capture = nullptr;

  qstring dispatch_line(const char *json);   // run one request, return its captured reply
  void handle_http_client(SOCKET c);

  void handle_request(const jobj_t &req);
  void call_tool(const jobj_t &params, jvalue_t *result_out, bool *is_error, qstring *errmsg);
  void tools_list(jvalue_t *out);
  void write_response(jobj_t &resp);
  void reply_result(const jvalue_t *id, jvalue_t &result);
  void reply_error(const jvalue_t *id, int code, const char *message);
};
