#include "pch.h"
#include "mcp.hpp"
#include "json_util.hpp"
#include "raw_io.hpp"
#include "strhash.hpp"
#include <iostream>

// The one canonical tool list. tools/list is generated from it; the dispatch switch
// below routes each name to its command (per-tool argument shapes differ, so the bodies
// stay explicit). Add a tool in exactly these two spots.
#define HEXPORT_TOOLS(X) \
  X(open_database) X(close_database) X(list_databases) X(server_health) \
  X(entity_query) X(list_funcs) X(disasm) X(decompile) X(analyze_batch) \
  X(lookup_funcs) X(force_recompile)

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
  line.append("\n");
  write_out(line);   // fd 1 (JSON-RPC protocol); _write is unbuffered, no flush needed
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
static void add_tool(jarr_t *tools, const char *name)
{
  jobj_t *t = new jobj_t;
  t->put("name", name);
  t->put("description", name);
  jobj_t *schema = new jobj_t;
  schema->put("type", "object");
  t->put("inputSchema", schema);
  tools->values.push_back().set_obj(t);
}

void Mcp::tools_list(jvalue_t *out)
{
  jarr_t *tools = new jarr_t;
#define X(n) add_tool(tools, #n);
  HEXPORT_TOOLS(X)
#undef X
  jobj_t *o = new jobj_t;
  o->put("tools", tools);
  out->set_obj(o);
}

void Mcp::call_tool(const jobj_t &params, jvalue_t *result_out, bool *is_error, qstring *errmsg)
{
  *is_error = false;
  qstring name = jstr(params, "name");
  const jobj_t *args = jsub(params, "arguments");
  const jvalue_t *queries = args != nullptr ? args->get_value("queries") : nullptr;

  switch ( str_hash(name.c_str()) )
  {
    case "open_database"_h:   cmds.open_database(args, result_out);    break;
    case "close_database"_h:  cmds.close_database(result_out);         break;
    case "list_databases"_h:  cmds.list_databases(result_out);         break;
    case "server_health"_h:   cmds.server_health(result_out);          break;
    case "entity_query"_h:    cmds.entity_query(queries, result_out);  break;
    case "list_funcs"_h:      cmds.list_funcs(queries, result_out);    break;
    case "disasm"_h:          cmds.disasm(args, result_out);           break;
    case "decompile"_h:       cmds.decompile(args, result_out);        break;
    case "analyze_batch"_h:   cmds.analyze_batch(queries, result_out); break;
    case "lookup_funcs"_h:    cmds.lookup_funcs(queries, result_out);  break;
    case "force_recompile"_h: cmds.force_recompile(args, result_out);  break;
    default:
      *is_error = true;
      errmsg->sprnt("unknown tool: %s", name.c_str());
      break;
  }
}

//-------------------------------------------------------------------------
void Mcp::handle_request(const jobj_t &req)
{
  qstring method = jstr(req, "method");
  const jvalue_t *id = req.get_value("id");
  const jobj_t *params = jsub(req, "params");

  switch ( str_hash(method.c_str()) )
  {
    case "initialize"_h:
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
      break;
    }

    case "notifications/initialized"_h:
    case "initialized"_h:
      break;   // notification: no response

    case "tools/list"_h:
    {
      jvalue_t rv;
      tools_list(&rv);
      reply_result(id, rv);
      break;
    }

    case "tools/call"_h:
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
      break;
    }

    case "resources/read"_h:
    {
      // ida://cursor is meaningless headless; return empty contents.
      jobj_t *r = new jobj_t;
      r->put("contents", new jarr_t);
      jvalue_t rv;
      rv.set_obj(r);
      reply_result(id, rv);
      break;
    }

    default:
      if ( id != nullptr )
        reply_error(id, -32601, "method not found");
      break;
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
