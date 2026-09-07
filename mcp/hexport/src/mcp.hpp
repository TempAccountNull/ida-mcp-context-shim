// Mcp - the MCP/JSON-RPC server. M2: stdio transport + protocol core. HTTP lands in M4.
#pragma once
#include "pch.h"
#include "mcp_commands.hpp"

class Mcp
{
public:
  int run_stdio();   // read newline-delimited JSON-RPC from stdin, reply on stdout

private:
  McpCommands cmds;

  void handle_request(const jobj_t &req);
  void call_tool(const jobj_t &params, jvalue_t *result_out, bool *is_error, qstring *errmsg);
  void tools_list(jvalue_t *out);
  void write_response(jobj_t &resp);
  void reply_result(const jvalue_t *id, jvalue_t &result);
  void reply_error(const jvalue_t *id, int code, const char *message);
};
