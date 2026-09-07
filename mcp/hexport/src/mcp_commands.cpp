#include "pch.h"
#include "mcp_commands.hpp"
#include "json_util.hpp"

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

  // strip a trailing " - Copy", " - Copy (N)", or " (N)" decoration.
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
void McpCommands::server_health(jvalue_t *out) const
{
  jobj_t *o = new jobj_t;
  o->put("status", "ok");
  o->put("module", module_name());
  o->put("ready", true);
  o->put("functions", int64(get_func_qty()));
  out->set_obj(o);
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

void McpCommands::list_funcs(const jvalue_t *queries, jvalue_t *out) const
{
  qvector<fnrow_t> rows;
  collect_functions(rows);

  jarr_t *pages = new jarr_t;
  if ( queries != nullptr && queries->type() == JT_ARR )
  {
    const jarr_t &qa = queries->arr();
    for ( size_t i = 0; i < qa.values.size(); ++i )
    {
      const jvalue_t &q = qa.values[i];
      if ( q.type() == JT_OBJ )
        one_page(rows, jint(q.obj(), "offset", 0), jint(q.obj(), "count", 100), pages);
    }
  }
  else if ( queries != nullptr && queries->type() == JT_OBJ )
  {
    one_page(rows, jint(queries->obj(), "offset", 0), jint(queries->obj(), "count", 100), pages);
  }
  else
  {
    one_page(rows, 0, 0, pages);
  }
  out->set_arr(pages);
}
