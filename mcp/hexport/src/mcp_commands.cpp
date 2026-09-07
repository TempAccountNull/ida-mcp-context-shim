#include "pch.h"
#include "mcp_commands.hpp"
#include "json_util.hpp"
#include "raw_io.hpp"
#include "kuser.hpp"

//-------------------------------------------------------------------------
static ea_t resolve_ea(const char *s)
{
  if ( s == nullptr || *s == '\0' )
    return BADADDR;
  char *endp = nullptr;
  unsigned long long v = strtoull(s, &endp, 0);
  if ( endp != nullptr && *endp == '\0' )
    return ea_t(v);
  return get_name_ea(BADADDR, s);
}

//-------------------------------------------------------------------------
void McpCommands::status(const char *op, ea_t ea, const char *name)
{
  // Elapsed straight from the KUSER shared page (InterruptTime), no QPC/chrono call.
  double elapsed = double(KUser::get_instance().clock.interrupt_time_100ns() - t_start_100ns) * 1e-7;
  double rate = elapsed > 0.001 ? double(processed) / elapsed : 0.0;
  qstring s;
  s.sprnt("\r[hexport] %" FMT_64 "u/%" FMT_64 "u  %-11s %-40s @ 0x%" FMT_64 "x  %6.1fs  %5.1f fn/s   ",
          uint64(processed), uint64(get_func_qty()),
          op, (name != nullptr && *name != '\0') ? name : "?", uint64(ea),
          elapsed, rate);
  write_err(s);
}

//-------------------------------------------------------------------------
qstring McpCommands::module_name() const
{
  char buf[QMAXPATH];
  if ( get_root_filename(buf, sizeof(buf)) <= 0 )
    return qstring("target");

  std::string s(buf);
  size_t slash = s.find_last_of("\\/");
  if ( slash != std::string::npos )
    s = s.substr(slash + 1);

  std::string stem = s, ext;
  size_t dot = s.find_last_of('.');
  if ( dot != std::string::npos && dot != 0 )
  {
    stem = s.substr(0, dot);
    ext = s.substr(dot);
  }

  stem = std::regex_replace(stem, std::regex(R"(\s*-\s*copy(\s*\(\d+\))?\s*$)", std::regex::icase), "");
  stem = std::regex_replace(stem, std::regex(R"(\s*\(\d+\)\s*$)"), "");
  while ( !stem.empty() && stem.back() == ' ' )
    stem.pop_back();
  if ( stem.empty() )
    stem = "target";

  std::string res = stem + ext;
  return qstring(res.c_str());
}

//-------------------------------------------------------------------------
bool McpCommands::open(const char *file_path, bool run_auto)
{
  if ( is_open )
    close();
  mute_stdout();
  int rc = ::open_database(file_path, run_auto);
  if ( rc == 0 )
    auto_wait();
  unmute_stdout();
  if ( rc != 0 )
    return false;
  is_open = true;
  processed = 0;
  t_start_100ns = KUser::get_instance().clock.interrupt_time_100ns();   // start the KUSER elapsed timer
  hexrays_ok = init_hexrays_plugin();
  return true;
}

void McpCommands::close()
{
  if ( !is_open )
    return;
  mute_stdout();
  ::close_database(false);
  unmute_stdout();
  is_open = false;
  hexrays_ok = false;
}

//-------------------------------------------------------------------------
void McpCommands::open_database(const jobj_t *args, jvalue_t *out)
{
  qstring path = args != nullptr ? jstr(*args, "file_path") : qstring();
  bool run_auto = args != nullptr ? jbool(*args, "run_auto_analysis", false) : false;
  jobj_t *result = new jobj_t;
  if ( path.empty() )
  {
    result->put("error", "file_path is required");
  }
  else if ( !open(path.c_str(), run_auto) )
  {
    result->put("error", "failed to open database");
  }
  else
  {
    result->put("status", "ok");
    result->put("module", module_name());
    result->put("functions", int64(get_func_qty()));
    result->put("hexrays", hexrays_ok);
  }
  out->set_obj(result);
}

void McpCommands::close_database(jvalue_t *out)
{
  close();
  jobj_t *result = new jobj_t;
  result->put("status", "closed");
  out->set_obj(result);
}

void McpCommands::list_databases(jvalue_t *out)
{
  jarr_t *arr = new jarr_t;
  if ( is_open )
  {
    jobj_t *e = new jobj_t;
    e->put("module", module_name());
    e->put("functions", int64(get_func_qty()));
    arr->values.push_back().set_obj(e);
  }
  out->set_arr(arr);
}

//-------------------------------------------------------------------------
void McpCommands::server_health(jvalue_t *out)
{
  jobj_t *o = new jobj_t;
  o->put("status", is_open ? "ok" : "no_database");
  o->put("module", is_open ? module_name() : qstring(""));
  o->put("ready", is_open);
  o->put("hexrays", hexrays_ok);
  o->put("functions", int64(is_open ? get_func_qty() : 0));
  out->set_obj(o);
}

void McpCommands::entity_query(const jvalue_t *, jvalue_t *out)
{
  jarr_t *arr = new jarr_t;
  jobj_t *page = new jobj_t;
  page->put("kind", "functions");
  page->put("data", new jarr_t);
  page->get_value_or_new("next_offset")->set_null();
  page->put("total", int64(is_open ? get_func_qty() : 0));
  arr->values.push_back().set_obj(page);
  out->set_arr(arr);
}

//-------------------------------------------------------------------------
struct fnrow_t
{
  ea_t ea;
  qstring name;
  asize_t size;
};

static void collect_functions(qvector<fnrow_t> &rows)
{
  for ( ea_t ea = get_next_func_ea(0); ea != BADADDR; ea = get_next_func_ea(ea) )
  {
    fnrow_t &r = rows.push_back();
    r.ea = ea;
    get_func_name(&r.name, ea);
    func_t *f = get_func(ea);
    r.size = f != nullptr ? asize_t(f->end_ea - f->start_ea) : 0;
  }
}

static jobj_t *make_entry(const fnrow_t &r)
{
  jobj_t *e = new jobj_t;
  qstring tmp;
  tmp.sprnt("0x%" FMT_64 "x", uint64(r.ea));
  e->put("addr", tmp);
  e->put("name", r.name);
  tmp.sprnt("0x%" FMT_64 "x", uint64(r.size));
  e->put("size", tmp);
  return e;
}

static void one_page(const qvector<fnrow_t> &rows, int64 offset, int64 count, jarr_t *pages)
{
  int64 total = int64(rows.size());
  if ( offset < 0 )
    offset = 0;
  int64 start = offset > total ? total : offset;
  int64 eff = count <= 0 ? (total - start) : count;
  int64 end = start + eff;
  if ( end > total )
    end = total;

  jarr_t *data = new jarr_t;
  for ( int64 i = start; i < end; ++i )
    data->values.push_back().set_obj(make_entry(rows[size_t(i)]));

  jobj_t *page = new jobj_t;
  page->put("data", data);
  int64 next = offset + eff;
  if ( next < total )
    page->put("next_offset", next);
  else
    page->get_value_or_new("next_offset")->set_null();

  pages->values.push_back().set_obj(page);
}

void McpCommands::list_funcs(const jvalue_t *queries, jvalue_t *out)
{
  qvector<fnrow_t> rows;
  collect_functions(rows);

  jarr_t *pages = new jarr_t;
  switch ( queries != nullptr ? queries->type() : JT_UNKNOWN )
  {
    case JT_ARR:
    {
      const jarr_t &qa = queries->arr();
      for ( size_t i = 0; i < qa.values.size(); ++i )
        if ( qa.values[i].type() == JT_OBJ )
          one_page(rows, jint(qa.values[i].obj(), "offset", 0), jint(qa.values[i].obj(), "count", 100), pages);
      break;
    }
    case JT_OBJ:
      one_page(rows, jint(queries->obj(), "offset", 0), jint(queries->obj(), "count", 100), pages);
      break;
    default:
      one_page(rows, 0, 0, pages);
      break;
  }
  out->set_arr(pages);
}

//-------------------------------------------------------------------------
int64 McpCommands::build_disasm(ea_t addr, int64 max_instructions, int64 offset, jarr_t *lines, bool *more, bool as_text)
{
  *more = false;
  func_t *pfn = get_func(addr);
  ea_t start = pfn != nullptr ? pfn->start_ea : addr;
  ea_t end = pfn != nullptr ? pfn->end_ea : (addr + 0x1000);
  int64 idx = 0, emitted = 0;
  for ( ea_t ea = start; ea != BADADDR && ea < end; ea = next_head(ea, end) )
  {
    if ( !is_code(get_flags_ex(ea, 0)) )
      continue;
    if ( idx < offset )
    {
      idx++;
      continue;
    }
    if ( emitted >= max_instructions )
    {
      *more = true;
      break;
    }
    qstring dl;
    generate_disasm_line(&dl, ea, GENDSM_REMOVE_TAGS);
    if ( as_text )
    {
      // "<hexaddr>  <disasm>" -- ida-pro-mcp's analyze_batch shape; the exporter
      // joins these with "\n". generate_disasm_line already appends IDA's comments.
      qstring s;
      s.sprnt("%" FMT_64 "x  %s", uint64(ea), dl.c_str());
      lines->values.push_back().set_str(s.c_str());
    }
    else
    {
      jobj_t *e = new jobj_t;
      qstring tmp;
      tmp.sprnt("%" FMT_64 "x", uint64(ea));
      e->put("addr", tmp);
      e->put("instruction", dl);
      qstring nm;
      if ( get_ea_name(&nm, ea, 0) > 0 && !nm.empty() )
        e->put("label", nm);
      qstring c;
      jarr_t *cs = nullptr;
      if ( get_cmt(&c, ea, false) > 0 && !c.empty() )
      {
        cs = new jarr_t;
        cs->values.push_back().set_str(c.c_str());
      }
      if ( get_cmt(&c, ea, true) > 0 && !c.empty() )
      {
        if ( cs == nullptr )
          cs = new jarr_t;
        cs->values.push_back().set_str(c.c_str());
      }
      if ( cs != nullptr )
        e->put("comments", cs);
      lines->values.push_back().set_obj(e);
    }
    emitted++;
    idx++;
  }
  return emitted;
}

void McpCommands::disasm(const jobj_t *args, jvalue_t *out)
{
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  int64 max_ins = args != nullptr ? jint(*args, "max_instructions", 5000) : 5000;
  if ( max_ins <= 0 || max_ins > 50000 )
    max_ins = 50000;
  int64 offset = args != nullptr ? jint(*args, "offset", 0) : 0;

  jobj_t *result = new jobj_t;
  func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
  if ( pfn == nullptr )
  {
    result->put("error", "no function at address");
    jobj_t *cur = new jobj_t;
    cur->put("done", true);
    result->put("cursor", cur);
    out->set_obj(result);
    return;
  }
  qstring name;
  get_func_name(&name, pfn->start_ea);
  ++processed;
  status("disasm", pfn->start_ea, name.c_str());

  jarr_t *lines = new jarr_t;
  bool more = false;
  int64 n = build_disasm(pfn->start_ea, max_ins, offset, lines, &more, /*as_text=*/false);

  jobj_t *asmo = new jobj_t;
  asmo->put("lines", lines);
  result->put("asm", asmo);
  jobj_t *cur = new jobj_t;
  cur->put("done", !more);
  if ( more )
    cur->put("next", offset + n);
  result->put("cursor", cur);
  out->set_obj(result);
}

//-------------------------------------------------------------------------
qstring McpCommands::pseudocode(ea_t func_ea, qstring *err)
{
  err->clear();
  if ( !hexrays_ok )
  {
    *err = "decompiler unavailable";
    return qstring();
  }
  hexrays_failure_t hf;
  cfuncptr_t cf = decompile_function(func_ea, &hf, DECOMP_NO_WAIT);
  if ( cf == nullptr )
  {
    err->sprnt("decompilation failed: %s", hf.str.c_str());
    return qstring();
  }
  const strvec_t &sv = cf->get_pseudocode();
  qstring text;
  for ( size_t i = 0; i < sv.size(); ++i )
  {
    qstring plain;
    tag_remove(&plain, sv[i].line.c_str());
    text.append(plain);
    text.append("\n");
  }
  return text;
}

void McpCommands::decompile(const jobj_t *args, jvalue_t *out)
{
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
  jobj_t *result = new jobj_t;
  if ( pfn == nullptr )
  {
    result->put("error", "no function at address");
    out->set_obj(result);
    return;
  }
  ea_t fea = pfn->start_ea;
  qstring name;
  get_func_name(&name, fea);
  ++processed;
  status("decompile", fea, name.c_str());

  qstring err;
  qstring code = pseudocode(fea, &err);
  if ( !err.empty() )
    result->put("error", err);
  else
    result->put("code", code);
  out->set_obj(result);
}

//-------------------------------------------------------------------------
void McpCommands::analyze_batch(const jvalue_t *queries, jvalue_t *out)
{
  jarr_t *results = new jarr_t;
  auto handle = [&](const jobj_t &q)
  {
    qstring target = jstr(q, "addr");
    ea_t ea = resolve_ea(target.c_str());
    func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
    jobj_t *item = new jobj_t;
    item->put("target", target);
    if ( pfn == nullptr )
    {
      item->get_value_or_new("addr")->set_null();
      item->get_value_or_new("analysis")->set_null();
      item->put("error", "function not found");
      results->values.push_back().set_obj(item);
      return;
    }
    qstring name;
    get_func_name(&name, pfn->start_ea);
    qstring a;
    a.sprnt("0x%" FMT_64 "x", uint64(pfn->start_ea));
    item->put("addr", a);
    item->put("name", name);
    ++processed;

    jobj_t *analysis = new jobj_t;
    bool want_dis = jbool(q, "include_disasm", false);
    bool want_dec = jbool(q, "include_decompile", true);
    if ( want_dis )
    {
      status("disasm", pfn->start_ea, name.c_str());
      int64 max_ins = jint(q, "max_disasm_insns", 50000);
      if ( max_ins <= 0 || max_ins > 50000 )
        max_ins = 50000;
      jarr_t *lines = new jarr_t;
      bool more = false;
      int64 n = build_disasm(pfn->start_ea, max_ins, 0, lines, &more, /*as_text=*/true);
      jobj_t *d = new jobj_t;
      d->put("lines", lines);
      d->put("instruction_count", n);
      d->put("truncated", more);
      analysis->put("disasm", d);
    }
    if ( want_dec )
    {
      status("decompile", pfn->start_ea, name.c_str());
      qstring err;
      qstring code = pseudocode(pfn->start_ea, &err);
      if ( !err.empty() )
      {
        analysis->get_value_or_new("decompile")->set_null();
        analysis->put("decompile_error", err);
      }
      else
      {
        analysis->put("decompile", code);
      }
    }
    item->put("analysis", analysis);
    results->values.push_back().set_obj(item);
  };

  switch ( queries != nullptr ? queries->type() : JT_UNKNOWN )
  {
    case JT_ARR:
    {
      const jarr_t &qa = queries->arr();
      for ( size_t i = 0; i < qa.values.size(); ++i )
        if ( qa.values[i].type() == JT_OBJ )
          handle(qa.values[i].obj());
      break;
    }
    case JT_OBJ:
      handle(queries->obj());
      break;
    default:
      break;
  }
  out->set_arr(results);
}

//-------------------------------------------------------------------------
void McpCommands::lookup_funcs(const jvalue_t *queries, jvalue_t *out)
{
  jarr_t *arr = new jarr_t;
  auto one = [&](const char *q)
  {
    ea_t ea = resolve_ea(q);
    func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
    jobj_t *entry = new jobj_t;
    if ( pfn != nullptr )
    {
      qstring name;
      get_func_name(&name, pfn->start_ea);
      jobj_t *fn = new jobj_t;
      qstring a;
      a.sprnt("0x%" FMT_64 "x", uint64(pfn->start_ea));
      fn->put("addr", a);
      fn->put("name", name);
      entry->put("fn", fn);
    }
    else
    {
      entry->get_value_or_new("fn")->set_null();
    }
    arr->values.push_back().set_obj(entry);
  };

  switch ( queries != nullptr ? queries->type() : JT_UNKNOWN )
  {
    case JT_STR:
      one(queries->qstr().c_str());
      break;
    case JT_ARR:
    {
      const jarr_t &qa = queries->arr();
      for ( size_t i = 0; i < qa.values.size(); ++i )
        if ( qa.values[i].type() == JT_STR )
          one(qa.values[i].qstr().c_str());
      break;
    }
    default:
      break;
  }
  out->set_arr(arr);
}

//-------------------------------------------------------------------------
void McpCommands::force_recompile(const jobj_t *args, jvalue_t *out)
{
  int64 total = 0, ok = 0;
  bool all = true;
  const jvalue_t *items = args != nullptr ? args->get_value("items") : nullptr;
  switch ( items != nullptr ? items->type() : JT_UNKNOWN )
  {
    case JT_ARR:
    {
      all = false;
      const jarr_t &ia = items->arr();
      for ( size_t i = 0; i < ia.values.size(); ++i )
      {
        if ( ia.values[i].type() != JT_OBJ )
          continue;
        total++;
        ea_t ea = resolve_ea(jstr(ia.values[i].obj(), "addr").c_str());
        if ( ea != BADADDR )
        {
          mark_cfunc_dirty(ea, false);
          ok++;
        }
      }
      break;
    }
    default:   // no items -> invalidate every function
      for ( ea_t ea = get_next_func_ea(0); ea != BADADDR; ea = get_next_func_ea(ea) )
      {
        mark_cfunc_dirty(ea, false);
        total++;
        ok++;
      }
      break;
  }
  jobj_t *summary = new jobj_t;
  summary->put("total", total);
  summary->put("ok", ok);
  summary->put("failed", total - ok);
  summary->put("all", all);
  jobj_t *result = new jobj_t;
  result->put("summary", summary);
  out->set_obj(result);
}
