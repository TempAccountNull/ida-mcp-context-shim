#include "pch.h"
#include "mcp.hpp"
#include "json_util.hpp"
#include <iostream>

//-------------------------------------------------------------------------
static void set_id(jobj_t &resp, const jvalue_t *id)
{
  if ( id != nullptr )
  {
    jvalue_t copy = *id;
    resp.get_value_or_new("id")->swap(copy);
  }
  else
  {
    resp.get_value_or_new("id")->set_null();
  }
}

void Mcp::write_response(jobj_t &resp)
{
  resp.put("jsonrpc", "2.0");
  qstring line = jdump(resp);
  fwrite(line.c_str(), 1, line.length(), stdout);
  fputc('\n', stdout);
  fflush(stdout);
}

void Mcp::reply_result(const jvalue_t *id, jvalue_t &result)
{
  jobj_t resp;
  set_id(resp, id);
  resp.get_value_or_new("result")->swap(result);
  write_response(resp);
}

void Mcp::reply_error(const jvalue_t *id, int code, const char *message)
{
  jobj_t resp;
  set_id(resp, id);
  jobj_t *err = new jobj_t;
  err->put("code", int64(code));
  err->put("message", message);
  resp.put("error", err);
  write_response(resp);
}

//-------------------------------------------------------------------------
void Mcp::tools_list(jvalue_t *out)
{
  static const char *const names[] = { "server_health", "list_funcs" };
  jarr_t *tools = new jarr_t;
  for ( const char *n : names )
  {
    jobj_t *t = new jobj_t;
    t->put("name", n);
    t->put("description", n);
    jobj_t *schema = new jobj_t;
    schema->put("type", "object");
    t->put("inputSchema", schema);
    tools->values.push_back().set_obj(t);
  }
  jobj_t *o = new jobj_t;
  o->put("tools", tools);
  out->set_obj(o);
}

void Mcp::call_tool(const jobj_t &params, jvalue_t *result_out, bool *is_error, qstring *errmsg)
{
  *is_error = false;
  qstring name = jstr(params, "name");
  const jobj_t *args = jsub(params, "arguments");

  if ( name == "server_health" )
  {
    cmds.server_health(result_out);
  }
  else if ( name == "list_funcs" )
  {
    const jvalue_t *queries = args != nullptr ? args->get_value("queries") : nullptr;
    cmds.list_funcs(queries, result_out);
  }
  else
  {
    *is_error = true;
    errmsg->sprnt("unknown tool: %s", name.c_str());
  }
}

//-------------------------------------------------------------------------
void Mcp::handle_request(const jobj_t &req)
{
  qstring method = jstr(req, "method");
  const jvalue_t *id = req.get_value("id");
  const jobj_t *params = jsub(req, "params");

  if ( method == "initialize" )
  {
    jobj_t *r = new jobj_t;
    r->put("protocolVersion", "2024-11-05");
    jobj_t *caps = new jobj_t;
    caps->put("tools", new jobj_t);
    r->put("capabilities", caps);
    jobj_t *info = new jobj_t;
    info->put("name", "hexport");
    info->put("version", "0.1.0");
    r->put("serverInfo", info);
    jvalue_t rv;
    rv.set_obj(r);
    reply_result(id, rv);
  }
  else if ( method == "notifications/initialized" || method == "initialized" )
  {
    // notification: no response
  }
  else if ( method == "tools/list" )
  {
    jvalue_t rv;
    tools_list(&rv);
    reply_result(id, rv);
  }
  else if ( method == "tools/call" )
  {
    jvalue_t toolres;
    bool is_error = false;
    qstring emsg;
    if ( params != nullptr )
    {
      call_tool(*params, &toolres, &is_error, &emsg);
    }
    else
    {
      is_error = true;
      emsg = "missing params";
    }

    jobj_t *result = new jobj_t;
    jarr_t *content = new jarr_t;
    result->put("content", content);
    if ( is_error )
    {
      result->put("isError", true);
      jobj_t *txt = new jobj_t;
      txt->put("type", "text");
      txt->put("text", emsg);
      content->values.push_back().set_obj(txt);
    }
    else
    {
      jobj_t *sc = new jobj_t;
      sc->get_value_or_new("result")->swap(toolres);
      result->put("structuredContent", sc);
    }
    jvalue_t rv;
    rv.set_obj(result);
    reply_result(id, rv);
  }
  else if ( method == "resources/read" )
  {
    // ida://cursor is meaningless headless; return empty contents.
    jobj_t *r = new jobj_t;
    r->put("contents", new jarr_t);
    jvalue_t rv;
    rv.set_obj(r);
    reply_result(id, rv);
  }
  else if ( id != nullptr )
  {
    reply_error(id, -32601, "method not found");
  }
}

int Mcp::run_stdio()
{
  std::string line;
  while ( std::getline(std::cin, line) )
  {
    if ( line.empty() )
      continue;
    jvalue_t req;
    if ( !jparse(line.c_str(), &req) || req.type() != JT_OBJ )
      continue;
    handle_request(req.obj());
  }
  return 0;
}
