#include "pch.h"
#include "mcp.hpp"
#include "json_util.hpp"
#include "raw_io.hpp"
#include "strhash.hpp"

#pragma comment(lib, "ws2_32.lib")   // M4 HTTP transport (Winsock)

// The one canonical tool list. tools/list is generated from it; the dispatch switch
// below routes each name to its command (per-tool argument shapes differ, so the bodies
// stay explicit). Add a tool in exactly these two spots.
#define HEXPORT_TOOLS(X) \
  X(open_database) X(close_database) X(list_databases) X(server_health) \
  X(entity_query) X(list_funcs) X(disasm) X(decompile) X(analyze_batch) \
  X(lookup_funcs) X(force_recompile) X(set_type) X(redefine_func) X(infer_types) \
  X(get_bytes) X(patch_bytes) X(undefine) X(define_func) \
  X(rename) X(set_comments) X(get_string) X(xrefs_to) X(callees) \
  X(define_code) X(make_data) X(list_globals) \
  X(find_bytes) X(basic_blocks) X(stack_frame) X(set_op_type) X(imports) \
  X(type_apply_batch) X(repair_badcall)

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
  if ( capture != nullptr )
    capture->append(line);            // HTTP transport: buffer the reply for one request
  else
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
    case "close_database"_h:  cmds.close_database(args, result_out);   break;
    case "list_databases"_h:  cmds.list_databases(result_out);         break;
    case "server_health"_h:   cmds.server_health(result_out);          break;
    case "entity_query"_h:    cmds.entity_query(queries, result_out);  break;
    case "list_funcs"_h:      cmds.list_funcs(queries, result_out);    break;
    case "disasm"_h:          cmds.disasm(args, result_out);           break;
    case "decompile"_h:       cmds.decompile(args, result_out);        break;
    case "analyze_batch"_h:   cmds.analyze_batch(queries, result_out); break;
    case "lookup_funcs"_h:    cmds.lookup_funcs(queries, result_out);  break;
    case "force_recompile"_h: cmds.force_recompile(args, result_out);  break;
    case "set_type"_h:        cmds.set_type(args, result_out);         break;
    case "redefine_func"_h:   cmds.redefine_func(args, result_out);    break;
    case "infer_types"_h:     cmds.infer_types(args, result_out);      break;
    case "get_bytes"_h:       cmds.get_bytes(args, result_out);        break;
    case "patch_bytes"_h:     cmds.patch_bytes(args, result_out);      break;
    case "undefine"_h:        cmds.undefine(args, result_out);         break;
    case "define_func"_h:     cmds.define_func(args, result_out);      break;
    case "rename"_h:          cmds.rename(args, result_out);           break;
    case "set_comments"_h:    cmds.set_comments(args, result_out);     break;
    case "get_string"_h:      cmds.get_string(args, result_out);       break;
    case "xrefs_to"_h:        cmds.xrefs_to(args, result_out);         break;
    case "callees"_h:         cmds.callees(args, result_out);          break;
    case "define_code"_h:     cmds.define_code(args, result_out);      break;
    case "make_data"_h:       cmds.make_data(args, result_out);        break;
    case "list_globals"_h:    cmds.list_globals(args, result_out);     break;
    case "find_bytes"_h:      cmds.find_bytes(args, result_out);       break;
    case "basic_blocks"_h:    cmds.basic_blocks(args, result_out);     break;
    case "stack_frame"_h:     cmds.stack_frame(args, result_out);      break;
    case "set_op_type"_h:     cmds.set_op_type(args, result_out);      break;
    case "imports"_h:         cmds.imports(args, result_out);          break;
    case "type_apply_batch"_h: cmds.type_apply_batch(args, result_out); break;
    case "repair_badcall"_h:  cmds.repair_badcall(args, result_out);   break;
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
  kstl::string line;
  while ( read_line(&line) )
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

//-------------------------------------------------------------------------
// HTTP transport (M4). One request per connection, JSON-RPC in the body, JSON reply out.
// Single-threaded by necessity: idalib requires every call on the thread that inited it.
//-------------------------------------------------------------------------
qstring Mcp::dispatch_line(const char *json)
{
  qstring captured;
  capture = &captured;
  jvalue_t req;
  if ( jparse(json, &req) && req.type() == JT_OBJ )
    handle_request(req.obj());
  capture = nullptr;
  return captured;   // empty for a notification (no id) or unparseable input
}

static void send_all(SOCKET c, const char *p, size_t n)
{
  while ( n > 0 )
  {
    int w = send(c, p, int(n > 0x40000 ? 0x40000 : n), 0);
    if ( w <= 0 )
      return;
    p += w;
    n -= size_t(w);
  }
}

void Mcp::handle_http_client(SOCKET c)
{
  kstl::string buf;
  char tmp[8192];
  unsigned hdr_end;
  while ( (hdr_end = buf.find("\r\n\r\n")) == kstl::string::npos )
  {
    int r = recv(c, tmp, sizeof(tmp), 0);
    if ( r <= 0 )
      return;
    buf.append(tmp, unsigned(r));
    if ( buf.size() > (16u << 20) )   // 16 MB header guard
      return;
  }
  kstl::string head = buf.substr(0, hdr_end);

  unsigned clen = 0;   // case-insensitive Content-Length
  for ( unsigned i = 0; i + 15 <= head.size(); ++i )
  {
    if ( (head[i] | 0x20) == 'c' && _strnicmp(head.c_str() + i, "content-length:", 15) == 0 )
    {
      clen = unsigned(strtoull(head.c_str() + i + 15, nullptr, 10));
      break;
    }
  }
  unsigned body_start = hdr_end + 4;
  while ( buf.size() - body_start < clen )
  {
    int r = recv(c, tmp, sizeof(tmp), 0);
    if ( r <= 0 )
      break;
    buf.append(tmp, unsigned(r));
  }

  bool is_post = head.starts_with("POST ");
  qstring reply = is_post ? dispatch_line(buf.substr(body_start, clen).c_str()) : qstring();

  qstring hdr;
  if ( is_post && !reply.empty() )
    hdr.sprnt("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
              "Content-Length: %u\r\nConnection: close\r\n\r\n", unsigned(reply.length()));
  else if ( is_post )
    hdr = "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  else
    hdr = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  send_all(c, hdr.c_str(), hdr.length());
  if ( is_post && !reply.empty() )
    send_all(c, reply.c_str(), reply.length());
}

int Mcp::run_http(int port)
{
  WSADATA wsa;
  if ( WSAStartup(MAKEWORD(2, 2), &wsa) != 0 )
  {
    write_err(qstring("hexport: WSAStartup failed\n"));
    return 1;
  }
  SOCKET listener = INVALID_SOCKET;
  int bound = 0;
  for ( int p = port; p < port + 64; ++p )   // auto-scan up from the requested port
  {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( s == INVALID_SOCKET )
      continue;
    BOOL excl = TRUE;   // borrowed from re-mcp: EXCLUSIVEADDRUSE makes the scan race-free
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char *>(&excl), sizeof(excl));
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // 127.0.0.1 only
    addr.sin_port = htons(u_short(p));
    if ( bind(s, (sockaddr *)&addr, sizeof(addr)) == 0 && listen(s, SOMAXCONN) == 0 )
    {
      listener = s;
      bound = p;
      break;
    }
    closesocket(s);
  }
  if ( listener == INVALID_SOCKET )
  {
    qstring m;
    m.sprnt("hexport: no free port in [%d, %d)\n", port, port + 64);
    write_err(m);
    WSACleanup();
    return 1;
  }
  qstring m;
  m.sprnt("hexport: HTTP MCP listening on http://127.0.0.1:%d/mcp\n", bound);
  write_err(m);

  for ( ;; )   // headless server: runs until the process is killed (Ctrl+C)
  {
    SOCKET c = accept(listener, nullptr, nullptr);
    if ( c == INVALID_SOCKET )
      continue;
    handle_http_client(c);
    closesocket(c);
  }
}
