#include "pch.h"
#include "name_clean.hpp"
#include "mcp_commands.hpp"
#include "json_util.hpp"
#include "raw_io.hpp"
#include "kuser.hpp"

//-------------------------------------------------------------------------
// Every address that leaves this server goes out as "0x...". It was written out by hand in three
// dozen places and, in one of them, with a different format specifier -- so the same address could
// come back looking different depending on which tool answered.
static qstring hexstr(ea_t ea)
{
  qstring a;
  a.sprnt("0x%" FMT_64 "x", uint64(ea));
  return a;
}

static void put_hex(jobj_t *o, const char *key, ea_t ea)
{
  o->put(key, hexstr(ea));
}

// What this function calls. Code references that leave the function body are calls; ones that stay
// inside are branches. Written out four times before this -- in callees, callgraph, func_profile and
// the badcall search -- and every copy had to remember the same distinction.
static void collect_callees(const func_t *pfn, qvector<ea_t> *targets)
{
  if ( pfn == nullptr )
    return;
  for ( ea_t p = pfn->start_ea; p < pfn->end_ea && p != BADADDR; p = next_head(p, pfn->end_ea) )
  {
    for ( ea_t t = get_first_cref_from(p); t != BADADDR; t = get_next_cref_from(p, t) )
    {
      if ( t >= pfn->start_ea && t < pfn->end_ea )
        continue;                            // stays inside: a branch, not a call
      if ( get_func(t) != nullptr && !targets->has(t) )
        targets->push_back(t);
    }
  }
}

// One named type out of the local library, or a failure the caller can read.
static bool named_type(tinfo_t *out, const qstring &name)
{
  return !name.empty() && out->get_named_type(get_idati(), name.c_str());
}

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
// Which binary this database is of.
//
// get_root_filename() reads the input file name out of the root netnode, and on a 374 MB database it
// came back empty in 3 of 250 opens -- while ready, hexrays and a function count of 10,109 all said
// the database was fine and stderr was byte-identical to a good open. module_name() then returned
// its "target" fallback, which reads like a real name, so an export could be filed under the wrong
// binary with nothing anywhere saying so.
//
// Measured further: it is STICKY, not a transient read. Four health calls in one affected session
// all returned "target", and list_databases agreed. So retrying inside the session cannot help --
// that whole session simply has no readable root filename.
//
// But the database PATH is never in doubt: hexport passed it to open_database itself, and
// get_path(PATH_TYPE_IDB) hands it straight back. "hexx64 - Copy.dll.i64" minus the database
// suffix is "hexx64 - Copy.dll", which is exactly what the root netnode would have said. So fall
// back to that before falling back to a name that means nothing.
//
// Cached on success: the answer cannot change while a database is open, and re-reading a netnode on
// every server_health call was work for nothing.
qstring McpCommands::module_name() const
{
  if ( !cached_module.empty() )
    return cached_module;

  char buf[QMAXPATH];
  buf[0] = 0;
  ssize_t n = get_root_filename(buf, sizeof(buf));
  if ( n > 0 && buf[0] != 0 )
  {
    cached_module = qstring(hexport::clean_module_name(buf).c_str());
    return cached_module;
  }

  // Second source: the database path we opened. Strip the database suffix, then let
  // clean_module_name do the rest (it splits the path and trims a " - Copy" tail).
  const char *idb = get_path(PATH_TYPE_IDB);
  if ( idb != nullptr && idb[0] != 0 )
  {
    qstring p(idb);
    static const char *const DB_SUFFIX[] = { ".i64", ".idb" };
    for ( size_t i = 0; i < qnumber(DB_SUFFIX); ++i )
    {
      size_t sl = qstrlen(DB_SUFFIX[i]);
      if ( p.length() > sl && qstrcmp(p.c_str() + p.length() - sl, DB_SUFFIX[i]) == 0 )
      {
        p.resize(p.length() - sl);
        break;
      }
    }
    if ( !p.empty() )
    {
      qstring m;
      m.sprnt("hexport: root filename unreadable (get_root_filename returned %d); "
              "naming the module from the database path instead" "\n", int(n));
      write_err(m);
      cached_module = qstring(hexport::clean_module_name(p.c_str()).c_str());
      return cached_module;
    }
  }

  // Neither source worked. Do not cache this: it is a failure, not an answer.
  write_err(qstring("hexport: WARNING neither the root filename nor the database path is "
                    "readable; module reported as \"target\"" "\n"));
  return qstring("target");
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
  module_name();                  // resolve it once, now, while the database is settled
  hexrays_ok = init_hexrays_plugin();
  if ( !hexrays_ok )
  {
    // Worth one line on stderr. Without it a decompiler that never loaded is indistinguishable from
    // a function that cannot be decompiled: server_health still reports ready (the database IS
    // open) and every decompile returns "decompiler unavailable" as if it were a per-function fact.
    write_err(qstring("hexport: WARNING Hex-Rays did not initialise; decompile is unavailable "
                      "for this session (server_health reports hexrays=false)\n"));
  }
  return true;
}

// Closing is where a database gets destroyed, so it is worth doing exactly the way re-mcp does.
//
// close_database() blocks until the auto-analyser has drained, and the analyser can always find
// more to do -- a decompile queues type propagation, which queues reanalysis, and so on. A close
// that never returns looks like a hang, and a hang invites SIGKILL, and killing a process holding a
// PACKED .i64 leaves it unpacked and inconsistent on disk. That is not hypothetical: it is how this
// project's 374 MB database ended up giving IDA "Fatal error before kernel init".
//
// So: turn the analyser off, empty every queue, and only then close. `save` defaults to false
// everywhere -- reading a database must never rewrite it.
void McpCommands::close(bool save)
{
  if ( !is_open )
    return;
  mute_stdout();

  enable_auto(false);
  static const atype_t QUEUES[] = {
    AU_UNK, AU_CODE, AU_WEAK, AU_PROC, AU_TAIL, AU_FCHUNK, AU_USED,
    AU_USD2, AU_TYPE, AU_LIBF, AU_LBF2, AU_LBF3, AU_CHLB, AU_FINAL,
  };
  for ( size_t i = 0; i < qnumber(QUEUES); ++i )
    auto_unmark(0, BADADDR, QUEUES[i]);

  ::close_database(save);
  unmute_stdout();
  is_open = false;
  hexrays_ok = false;
  cached_module.clear();          // belongs to the database that just closed
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

// Saves by default. Auto-analysis and Hex-Rays both write to the database, so closing without
// saving throws that work away and the next open pays for it again.
void McpCommands::close_database(const jobj_t *args, jvalue_t *out)
{
  // Default FALSE, deliberately. This server exists to READ a database; writing 374 MB back
  // because a caller omitted an argument is not a default anyone wants, and an export that
  // silently saved through a newer idalib than the user's IDA is exactly how a database ends
  // up refusing to open. Saving is opt-in.
  const bool save = args != nullptr ? jbool(*args, "save", false) : false;
  close(save);
  jobj_t *result = new jobj_t;
  result->put("status", "closed");
  result->put("saved", save);
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
  int major = 0, minor = 0, build = 0;
  if ( get_library_version(major, minor, build) )
  {
    qstring v;
    v.sprnt("%d.%d.%d", major, minor, build);
    o->put("ida_version", v);
  }
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
  e->put("addr", hexstr(r.ea));
  e->put("name", r.name);
  e->put("size", hexstr(r.size));
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
qstring McpCommands::pseudocode(ea_t func_ea, qstring *err, int *code, ea_t *errea)
{
  err->clear();
  if ( code != nullptr )
    *code = 0;
  if ( errea != nullptr )
    *errea = BADADDR;
  if ( !hexrays_ok )
  {
    *err = "decompiler unavailable";
    return qstring();
  }
  hexrays_failure_t hf;
  cfuncptr_t cf = decompile_function(func_ea, &hf, DECOMP_NO_WAIT);
  if ( cf == nullptr )
  {
    // hf.str is very often EMPTY -- Hex-Rays puts the real reason in hf.code (a MERR_ enum) and
    // hf.errea (where it gave up), and desc() is what formats all three into something readable.
    // Reporting only hf.str produced "decompilation failed: " with nothing after the colon for
    // every one of the 38 failures on hexx64.dll, which is unactionable: you cannot tell a function
    // that is merely too big from one whose stack analysis failed.
    qstring d = hf.desc();
    if ( d.empty() )
      d.sprnt("merror %d", int(hf.code));
    err->sprnt("decompilation failed: %s", d.c_str());
    if ( code != nullptr )
      *code = int(hf.code);
    if ( errea != nullptr )
      *errea = hf.errea;
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

// The ONLY write this server performs. Everything else is a query, deliberately -- a bulk exporter
// has no business editing a database. This exists for one repair.
//
// 38 of hexx64.dll's 10,109 functions fail with MERR_BADCALL ("could not determine call arguments")
// and no retry recovers them: the failure is not transient. Hex-Rays cannot work out the argument
// list of a variadic call, so it abandons the whole function. Telling it the prototype is the fix,
// and a prototype is a write.
//
// Two steps, the same ones the reference IDA MCP servers use: parse_decl() turns the text into a
// tinfo_t, apply_tinfo() attaches it with TINFO_DEFINITE -- a definite type rather than a guess, so
// later auto-analysis will not quietly drop it again.
void McpCommands::set_type(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring addr = args != nullptr ? jstr(*args, "addr") : qstring();
  qstring decl = args != nullptr ? jstr(*args, "decl") : qstring();
  if ( addr.empty() || decl.empty() )
  {
    result->put("error", "addr and decl are both required");
    out->set_obj(result);
    return;
  }
  ea_t ea = resolve_ea(addr.c_str());
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }

  qstring text = decl;               // parse_decl wants a terminated declaration
  text.trim2();
  if ( !text.empty() && text[text.length() - 1] != ';' )
    text.append(';');

  tinfo_t tif;
  qstring parsed_name;
  if ( !parse_decl(&tif, &parsed_name, nullptr, text.c_str(), PT_SIL | PT_TYP) )
  {
    result->put("error", "could not parse declaration");
    out->set_obj(result);
    return;
  }

  qstring before;
  tinfo_t old_tif;
  if ( get_tinfo(&old_tif, ea) )
    old_tif.print(&before);

  if ( !apply_tinfo(ea, tif, TINFO_DEFINITE) )
  {
    result->put("error", "failed to apply type");
    out->set_obj(result);
    return;
  }

  qstring after;
  tif.print(&after);
  result->put("status", "ok");
  result->put("addr", addr);
  result->put("old_type", before);
  result->put("new_type", after);
  out->set_obj(result);
}

// The "u then p" cycle a human performs in IDA: undefine the function and its bytes, then let the
// analyser re-create the instructions and the function from scratch. Worth having as one tool
// because the two halves are useless apart -- undefining and stopping leaves a hole in the database.
//
// Why it can fix a decompilation: MERR_BADCALL means Hex-Rays could not work out a call's
// arguments, and that often rests on stale analysis -- a wrong function end, a call IDA never
// created a cross-reference for, an instruction decoded as data. Re-running analysis over the range
// rebuilds all of that. It is the fallback for the cases a prototype cannot fix, because there is
// no single global to blame.
void McpCommands::redefine_func(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring addr = args != nullptr ? jstr(*args, "addr") : qstring();
  ea_t ea = resolve_ea(addr.c_str());
  func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
  if ( pfn == nullptr )
  {
    result->put("error", "no function at address");
    out->set_obj(result);
    return;
  }

  ea_t start = pfn->start_ea;
  ea_t end = pfn->end_ea;
  qstring name;
  get_func_name(&name, start);
  result->put("addr", addr);
  result->put("name", name);
  result->put("old_end", int64(end));

  mute_stdout();                       // analysis chatters on stdout; fd 1 carries the protocol
  del_func(start);                     // 'u' -- drop the function
  del_items(start, DELIT_EXPAND, asize_t(end - start));   // ...and the instructions under it
  plan_and_wait(start, end);           // let auto-analysis re-decode the range
  create_insn(start);                  // 'p' -- an instruction at the entry, then a function on it
  bool made = add_func(start, end);
  if ( !made )
    made = add_func(start);            // let IDA find the end itself if the old one was wrong
  plan_and_wait(start, end);
  unmute_stdout();

  func_t *now = get_func(start);
  result->put("redefined", made && now != nullptr);
  if ( now != nullptr )
    result->put("new_end", int64(now->end_ea));
  out->set_obj(result);
}

// Ask IDA to work out the type at an address from the disassembly, and apply what it finds.
// Ported from ida-pro-mcp's infer_types, which is guess_tinfo() plus apply_tinfo().
//
// This is the honest form of the repair that set_type does by hand. A guessed prototype written by
// a human -- "__int64 __fastcall f(__int64)" -- fixes the caller's decompilation while quietly
// asserting an argument count nobody verified, and a wrong prototype produces confidently wrong
// pseudocode, which is worse than a function that visibly failed. guess_tinfo derives the signature
// from the code instead, so prefer it and fall back to a hand-written type only when it declines.
void McpCommands::infer_types(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring addr = args != nullptr ? jstr(*args, "addr") : qstring();
  ea_t ea = resolve_ea(addr.c_str());
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  result->put("addr", addr);

  qstring before;
  tinfo_t old_tif;
  if ( get_tinfo(&old_tif, ea) )
    old_tif.print(&before);
  result->put("old_type", before);

  tinfo_t tif;
  if ( guess_tinfo(&tif, ea) == GUESS_FUNC_FAILED )
  {
    result->put("inferred", false);
    result->put("error", "could not infer a type here");
    out->set_obj(result);
    return;
  }

  qstring guessed;
  tif.print(&guessed);
  result->put("inferred_type", guessed);
  bool applied = jbool(*args, "apply", true) && apply_tinfo(ea, tif, TINFO_DEFINITE);
  result->put("inferred", true);
  result->put("applied", applied);
  out->set_obj(result);
}

// ---- bytes: the repair primitive -------------------------------------------------------------
//
// Patching bytes then undefining and redefining (IDA's "u" then "p") is how a human fixes code that
// the analyser got wrong -- a bad prologue, a jump table decoded as data, an instruction split in
// the middle. These make that reachable from a client.
//
// Everything here happens in the LOADED database only. Nothing writes the .i64 unless someone
// explicitly calls close_database with save=true, so a repair can be tried, measured, and thrown
// away without touching the file on disk.

// Hex text to bytes. Accepts "48 89 5C 24 08", "4889...", or "0x48,0x89,...".
static bool parse_hex_bytes(const char *s, qvector<uchar> *out)
{
  int hi = -1;
  for ( const char *p = s; *p != 0; ++p )
  {
    char c = *p;
    if ( c == ' ' || c == ',' || c == '\t' || c == '_' )
      continue;
    if ( c == '0' && (p[1] == 'x' || p[1] == 'X') )   // skip a 0x prefix
    {
      ++p;
      continue;
    }
    int v;
    if ( c >= '0' && c <= '9' )      v = c - '0';
    else if ( c >= 'a' && c <= 'f' ) v = 10 + (c - 'a');
    else if ( c >= 'A' && c <= 'F' ) v = 10 + (c - 'A');
    else                             return false;
    if ( hi < 0 )
      hi = v;
    else
    {
      out->push_back(uchar((hi << 4) | v));
      hi = -1;
    }
  }
  return hi < 0 && !out->empty();    // an odd number of nibbles is a typo, not a patch
}

void McpCommands::get_bytes(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  int64 n = args != nullptr ? jint(*args, "size", 16) : 16;
  if ( ea == BADADDR || n <= 0 || n > 4096 )
  {
    result->put("error", "addr required, size 1..4096");
    out->set_obj(result);
    return;
  }
  qvector<uchar> buf;
  buf.resize(size_t(n));
  ssize_t got = ::get_bytes(buf.begin(), size_t(n), ea);
  if ( got <= 0 )
  {
    result->put("error", "unreadable at that address");
    out->set_obj(result);
    return;
  }
  qstring hex;
  for ( ssize_t i = 0; i < got; ++i )
  {
    qstring b;
    b.sprnt(i == 0 ? "%02X" : " %02X", buf[size_t(i)]);
    hex.append(b);
  }
  result->put("addr", jstr(*args, "addr"));
  result->put("size", int64(got));
  result->put("bytes", hex);
  out->set_obj(result);
}

void McpCommands::patch_bytes(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring addr = args != nullptr ? jstr(*args, "addr") : qstring();
  qstring hex = args != nullptr ? jstr(*args, "bytes") : qstring();
  ea_t ea = resolve_ea(addr.c_str());
  if ( ea == BADADDR || hex.empty() )
  {
    result->put("error", "addr and bytes are both required");
    out->set_obj(result);
    return;
  }
  qvector<uchar> bytes;
  if ( !parse_hex_bytes(hex.c_str(), &bytes) )
  {
    result->put("error", "bytes must be hex, an even number of nibbles");
    out->set_obj(result);
    return;
  }

  // Hand back what was there first. A caller that cannot undo its own patch has no business
  // making one, and this is what makes a repair attempt reversible without saving anything.
  qvector<uchar> prev;
  prev.resize(bytes.size());
  qstring before;
  if ( ::get_bytes(prev.begin(), bytes.size(), ea) == ssize_t(bytes.size()) )
  {
    for ( size_t i = 0; i < prev.size(); ++i )
    {
      qstring b;
      b.sprnt(i == 0 ? "%02X" : " %02X", prev[i]);
      before.append(b);
    }
  }

  ::patch_bytes(ea, bytes.begin(), bytes.size());
  result->put("status", "ok");
  result->put("addr", addr);
  result->put("size", int64(bytes.size()));
  result->put("old_bytes", before);
  out->set_obj(result);
}

// "u" on its own: drop whatever is defined over a range, back to raw bytes.
void McpCommands::undefine(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  int64 n = args != nullptr ? jint(*args, "size", 1) : 1;
  func_t *pfn = get_func(ea);
  if ( pfn != nullptr && ea == pfn->start_ea )
  {
    if ( n <= 1 )
      n = int64(pfn->end_ea - pfn->start_ea);   // a whole function by default
    del_func(pfn->start_ea);
  }
  mute_stdout();
  bool ok = del_items(ea, DELIT_EXPAND, asize_t(n));
  unmute_stdout();
  result->put("status", ok ? "ok" : "failed");
  result->put("addr", jstr(*args, "addr"));
  result->put("size", n);
  out->set_obj(result);
}

// "p" on its own: make code here, and a function starting here.
void McpCommands::define_func(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  qstring end_s = args != nullptr ? jstr(*args, "end") : qstring();
  ea_t end = end_s.empty() ? BADADDR : resolve_ea(end_s.c_str());

  mute_stdout();
  create_insn(ea);
  bool made = add_func(ea, end);
  if ( !made )
    made = add_func(ea);                 // let IDA find the end itself
  plan_and_wait(ea, end != BADADDR ? end : ea + 1);
  unmute_stdout();

  func_t *now = get_func(ea);
  // add_func returns false when a function already covers the address, which auto-analysis often
  // creates for us. What matters is whether one exists now, not which call produced it.
  result->put("status", now != nullptr ? "ok" : "failed");
  result->put("created_by_call", made);
  if ( now != nullptr )
  {
    result->put("end", hexstr(now->end_ea));
    qstring nm;
    get_func_name(&nm, now->start_ea);
    result->put("name", nm);
  }
  out->set_obj(result);
}

// ---- analysis and annotation, ported from ida-pro-mcp -----------------------------------------
//
// These exist so a failure can be UNDERSTOOD, not just repaired. When a function will not decompile
// the useful questions are what calls it, what it calls, what its blocks look like and what strings
// it touches -- and after a repair, being able to name and annotate what you found.
//
// Everything here is in-session. Nothing writes the .i64 unless close_database is asked to save.

void McpCommands::rename(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  qstring name = args != nullptr ? jstr(*args, "name") : qstring();
  if ( ea == BADADDR || name.empty() )
  {
    result->put("error", "addr and name are both required");
    out->set_obj(result);
    return;
  }
  qstring before;
  get_name(&before, ea);
  // SN_FORCE appends a suffix rather than failing when the name is taken, which is what a bulk
  // renamer wants: one collision should not abort the pass.
  bool ok = set_name(ea, name.c_str(), SN_CHECK | SN_FORCE);
  qstring after;
  get_name(&after, ea);
  result->put("status", ok ? "ok" : "failed");
  result->put("old_name", before);
  result->put("new_name", after);
  out->set_obj(result);
}

void McpCommands::set_comments(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  qstring text = args != nullptr ? jstr(*args, "comment") : qstring();
  bool rpt = args != nullptr ? jbool(*args, "repeatable", false) : false;
  bool func = args != nullptr ? jbool(*args, "function", false) : false;
  bool ok = func ? set_func_cmt_ea(ea, text.c_str(), rpt)
                 : set_cmt(ea, text.c_str(), rpt);
  result->put("status", ok ? "ok" : "failed");
  result->put("addr", jstr(*args, "addr"));
  out->set_obj(result);
}

void McpCommands::get_string(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  // Ask whether a string is actually DEFINED here first. Without this check get_strlit_contents
  // happily decodes whatever bytes it finds -- pointed at code it returned "H" for the 0x48 of a
  // push instruction, which is a confidently wrong answer rather than a useful one.
  if ( !is_strlit(get_flags(ea)) )
  {
    result->put("error", "no string literal defined here");
    result->put("addr", jstr(*args, "addr"));
    out->set_obj(result);
    return;
  }
  qstring s;
  ssize_t n = get_strlit_contents(&s, ea, size_t(-1), int32(-1));
  if ( n < 0 )
    result->put("error", "could not read the string");
  else
    result->put("text", s);
  result->put("addr", jstr(*args, "addr"));
  out->set_obj(result);
}

void McpCommands::xrefs_to(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  int64 limit = args != nullptr ? jint(*args, "limit", 200) : 200;
  jarr_t *arr = new jarr_t;
  xrefblk_t xb;
  int64 n = 0;
  for ( bool ok = xb.first_to(ea, XREF_ALL); ok && n < limit; ok = xb.next_to(), ++n )
  {
    jobj_t *e = new jobj_t;
    e->put("from", hexstr(xb.from));
    e->put("code", xb.iscode != 0);
    e->put("type", int64(xb.type));
    qstring fn;
    func_t *pfn = get_func(xb.from);
    if ( pfn != nullptr && get_func_name(&fn, pfn->start_ea) > 0 )
      e->put("in_function", fn);
    arr->values.push_back().set_obj(e);
  }
  result->put("addr", jstr(*args, "addr"));
  result->get_value_or_new("xrefs")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::callees(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
  if ( pfn == nullptr )
  {
    result->put("error", "no function at address");
    out->set_obj(result);
    return;
  }
  // Cheaper and more precise than scanning all xrefs, and it keeps tail chunks out of the answer.
  qvector<ea_t> targets;
  collect_callees(pfn, &targets);
  jarr_t *arr = new jarr_t;
  for ( size_t i = 0; i < targets.size(); ++i )
  {
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(targets[i]));
    qstring nm;
    if ( get_func_name(&nm, targets[i]) > 0 )
      e->put("name", nm);
    arr->values.push_back().set_obj(e);
  }
  qstring fn;
  get_func_name(&fn, pfn->start_ea);
  result->put("name", fn);
  result->get_value_or_new("callees")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::define_code(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  int64 count = args != nullptr ? jint(*args, "count", 1) : 1;
  mute_stdout();
  int64 made = 0;
  ea_t p = ea;
  for ( int64 i = 0; i < count && p != BADADDR; ++i )
  {
    int len = create_insn(p);
    if ( len <= 0 )
      break;
    ++made;
    p += len;
  }
  unmute_stdout();
  result->put("status", made > 0 ? "ok" : "failed");
  result->put("instructions", made);
  out->set_obj(result);
}

void McpCommands::make_data(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  qstring kind = args != nullptr ? jstr(*args, "kind", "dword") : qstring("dword");
  int64 count = args != nullptr ? jint(*args, "count", 1) : 1;
  if ( count < 1 )
    count = 1;

  mute_stdout();
  bool ok = false;
  if ( kind == "string" )
  {
    ok = create_strlit(ea, 0, int32(-1));       // length 0 => let IDA find the terminator
  }
  else
  {
    flags64_t f = dword_flag();
    asize_t elem = 4;
    if ( kind == "byte" )       { f = byte_flag();  elem = 1; }
    else if ( kind == "word" )  { f = word_flag();  elem = 2; }
    else if ( kind == "qword" ) { f = qword_flag(); elem = 8; }
    del_items(ea, DELIT_SIMPLE, asize_t(count) * elem);
    ok = create_data(ea, f, asize_t(count) * elem, BADNODE);
  }
  unmute_stdout();
  result->put("status", ok ? "ok" : "failed");
  result->put("kind", kind);
  out->set_obj(result);
}

void McpCommands::list_globals(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  int64 limit = args != nullptr ? jint(*args, "limit", 200) : 200;
  int64 offset = args != nullptr ? jint(*args, "offset", 0) : 0;
  qstring filter = args != nullptr ? jstr(*args, "filter") : qstring();

  jarr_t *arr = new jarr_t;
  size_t total = get_nlist_size();
  int64 seen = 0;
  int64 emitted = 0;
  for ( size_t i = 0; i < total && emitted < limit; ++i )
  {
    ea_t ea = get_nlist_ea(i);
    if ( get_func(ea) != nullptr )
      continue;                                 // functions have their own tool
    const char *nm = get_nlist_name(i);
    if ( nm == nullptr )
      continue;
    if ( !filter.empty() && strstr(nm, filter.c_str()) == nullptr )
      continue;
    if ( seen++ < offset )
      continue;
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(ea));
    e->put("name", nm);
    arr->values.push_back().set_obj(e);
    ++emitted;
  }
  result->put("total_names", int64(total));
  result->get_value_or_new("globals")->set_arr(arr);
  out->set_obj(result);
}

// ---- structure, search and operands ----------------------------------------------------------

// Hex byte pattern with '?' wildcards, e.g. "48 8B ? ? 48 89". Wildcards matter: the whole point of
// searching for a prologue or a call idiom is that the displacement differs at every site.
void McpCommands::find_bytes(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring pat = args != nullptr ? jstr(*args, "pattern") : qstring();
  if ( pat.empty() )
  {
    result->put("error", "pattern is required");
    out->set_obj(result);
    return;
  }
  qvector<uchar> bytes;
  qvector<uchar> mask;
  int hi = -1;
  for ( const char *p = pat.c_str(); *p != 0; ++p )
  {
    char c = *p;
    if ( c == ' ' || c == ',' )
      continue;
    // A lone '?' means a whole wildcard byte -- that is how everyone writes a pattern
    // ("48 89 5C 24 ?"), and requiring "??" rejected the obvious form.
    if ( c == '?' )
    {
      bytes.push_back(0);
      mask.push_back(0x00);
      if ( p[1] == '?' )
        ++p;
      continue;
    }
    int v;
    if ( c >= '0' && c <= '9' ) v = c - '0';
    else if ( c >= 'a' && c <= 'f' ) v = 10 + (c - 'a');
    else if ( c >= 'A' && c <= 'F' ) v = 10 + (c - 'A');
    else
    {
      result->put("error", "pattern must be hex bytes, '?' allowed");
      out->set_obj(result);
      return;
    }
    if ( hi < 0 )
    {
      hi = v;
    }
    else
    {
      bytes.push_back(uchar((hi << 4) | v));
      mask.push_back(0xFF);
      hi = -1;
    }
  }
  if ( bytes.empty() || hi >= 0 )
  {
    result->put("error", "pattern must be whole bytes");
    out->set_obj(result);
    return;
  }

  int64 limit = args != nullptr ? jint(*args, "limit", 32) : 32;
  jarr_t *arr = new jarr_t;
  ea_t p = inf_get_min_ea();
  ea_t end = inf_get_max_ea();
  int64 n = 0;
  while ( n < limit )
  {
    ea_t hit = bin_search(p, end, bytes.begin(), mask.begin(), bytes.size(), BIN_SEARCH_FORWARD);
    if ( hit == BADADDR )
      break;
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(hit));
    qstring fn;
    func_t *pfn = get_func(hit);
    if ( pfn != nullptr && get_func_name(&fn, pfn->start_ea) > 0 )
      e->put("in_function", fn);
    arr->values.push_back().set_obj(e);
    ++n;
    p = hit + 1;
  }
  result->put("matches", n);
  result->get_value_or_new("hits")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::basic_blocks(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
  if ( pfn == nullptr )
  {
    result->put("error", "no function at address");
    out->set_obj(result);
    return;
  }
  // FC_PREDS no longer exists (the SDK marks its value FC_RESERVED); predecessors and
  // successors are computed for a normal flow chart, so no flag is needed.
  qflow_chart_t fc("hexport", pfn, pfn->start_ea, pfn->end_ea, 0);
  jarr_t *arr = new jarr_t;
  for ( int i = 0; i < fc.size(); ++i )
  {
    const qbasic_block_t &b = fc.blocks[i];
    jobj_t *e = new jobj_t;
    e->put("start", hexstr(b.start_ea));
    e->put("end", hexstr(b.end_ea));
    jarr_t *succ = new jarr_t;
    for ( int k = 0; k < fc.nsucc(i); ++k )
    {
      int s = fc.succ(i, k);
      succ->values.push_back().set_str(hexstr(fc.blocks[s].start_ea).c_str());
    }
    e->get_value_or_new("succs")->set_arr(succ);
    arr->values.push_back().set_obj(e);
  }
  qstring fn;
  get_func_name(&fn, pfn->start_ea);
  result->put("name", fn);
  result->put("blocks", int64(fc.size()));
  result->get_value_or_new("basic_blocks")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::stack_frame(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
  if ( pfn == nullptr )
  {
    result->put("error", "no function at address");
    out->set_obj(result);
    return;
  }
  result->put("frame_size", int64(get_frame_size_ea(pfn->start_ea)));
  result->put("ret_size", int64(get_frame_retsize_ea(pfn->start_ea)));

  // The frame is a UDT: walking its members is how you see the locals and arguments Hex-Rays will
  // work from, which is the first place to look when a decompilation comes out wrong.
  tinfo_t frame;
  jarr_t *arr = new jarr_t;
  if ( get_func_frame_ea(&frame, pfn->start_ea) )
  {
    udt_type_data_t udt;
    if ( frame.get_udt_details(&udt) )
    {
      for ( size_t i = 0; i < udt.size(); ++i )
      {
        const udm_t &m = udt[i];
        jobj_t *e = new jobj_t;
        e->put("name", m.name);
        e->put("offset", int64(m.offset / 8));      // bit offset in the SDK
        e->put("size", int64(m.size / 8));
        qstring ts;
        m.type.print(&ts);
        e->put("type", ts);
        arr->values.push_back().set_obj(e);
      }
    }
  }
  result->get_value_or_new("members")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::set_op_type(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( ea == BADADDR )
  {
    result->put("error", "bad address");
    out->set_obj(result);
    return;
  }
  int n = int(args != nullptr ? jint(*args, "operand", 0) : 0);
  qstring kind = args != nullptr ? jstr(*args, "kind", "hex") : qstring("hex");
  bool ok = false;
  if ( kind == "hex" )       ok = op_hex(ea, n);
  else if ( kind == "dec" )  ok = op_dec(ea, n);
  else if ( kind == "oct" )  ok = op_oct(ea, n);
  else if ( kind == "bin" )  ok = op_bin(ea, n);
  else if ( kind == "char" ) ok = op_chr(ea, n);
  else
  {
    result->put("error", "kind must be hex, dec, oct, bin or char");
    out->set_obj(result);
    return;
  }
  result->put("status", ok ? "ok" : "failed");
  result->put("kind", kind);
  result->put("operand", int64(n));
  out->set_obj(result);
}

void McpCommands::imports(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring filter = args != nullptr ? jstr(*args, "filter") : qstring();
  int64 limit = args != nullptr ? jint(*args, "limit", 500) : 500;

  struct ctx_t
  {
    jarr_t *arr;
    const char *module;
    const char *filter;
    int64 left;
  };
  ctx_t ctx = { new jarr_t, nullptr, filter.empty() ? nullptr : filter.c_str(), limit };

  uint nmods = get_import_module_qty();
  for ( uint m = 0; m < nmods && ctx.left > 0; ++m )
  {
    qstring mod;
    get_import_module_name(&mod, int(m));
    ctx.module = mod.c_str();
    enum_import_names(int(m),
      [](ea_t ea, const char *name, uval_t ord, void *param) -> int
      {
        ctx_t *c = static_cast<ctx_t *>(param);
        if ( c->left <= 0 )
          return 0;
        if ( name != nullptr && (c->filter == nullptr || strstr(name, c->filter) != nullptr) )
        {
          jobj_t *e = new jobj_t;
          e->put("addr", hexstr(ea));
          e->put("name", name != nullptr ? name : "");
          e->put("module", c->module != nullptr ? c->module : "");
          e->put("ordinal", int64(ord));
          c->arr->values.push_back().set_obj(e);
          --c->left;
        }
        return 1;
      }, &ctx);
  }
  result->put("modules", int64(nmods));
  result->get_value_or_new("imports")->set_arr(ctx.arr);
  out->set_obj(result);
}

// Several set_type calls under one round trip. A repair pass usually has a handful of prototypes to
// apply, and each one costing its own request is the sort of thing that turns a second into a
// minute over thousands of functions.
void McpCommands::type_apply_batch(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  const jarr_t *items = args != nullptr ? jsubarr(*args, "items") : nullptr;
  if ( items == nullptr )
  {
    result->put("error", "items must be an array of {addr, decl}");
    out->set_obj(result);
    return;
  }
  jarr_t *arr = new jarr_t;
  int64 ok_n = 0;
  for ( size_t i = 0; i < items->values.size(); ++i )
  {
    const jvalue_t &v = items->values[i];
    jobj_t *e = new jobj_t;
    if ( v.type() != JT_OBJ )
    {
      e->put("error", "not an object");
      arr->values.push_back().set_obj(e);
      continue;
    }
    jvalue_t one;
    set_type(&v.obj(), &one);
    if ( one.type() == JT_OBJ )
    {
      const jvalue_t *st = one.obj().get_value("status", JT_STR);
      if ( st != nullptr && st->qstr() == "ok" )
        ++ok_n;
      arr->values.push_back().swap(one);
      continue;
    }
    e->put("error", "unexpected result");
    arr->values.push_back().set_obj(e);
  }
  result->put("applied", ok_n);
  result->put("total", int64(items->values.size()));
  result->get_value_or_new("results")->set_arr(arr);
  out->set_obj(result);
}

// ---- repair_badcall ---------------------------------------------------------------------------
//
// MERR_BADCALL means Hex-Rays could not work out the arguments of a call inside a function, so it
// abandoned the whole function. It is not transient: on hexx64.dll a plain retry and force_recompile
// each recovered 0 of 38. What does recover them is telling Hex-Rays the prototype of whatever it
// choked on -- and that is a database edit, which is why this lives in the server rather than in a
// script that copies .i64 files around and saves them.
//
// The repair runs entirely in the loaded database. Nothing reaches disk unless close_database is
// explicitly asked to save, so a caller can repair, export, and discard.
//
// Two kinds of culprit, and the indirect one is easy to miss:
//   * a DIRECT call to a function with no usable prototype;
//   * an INDIRECT call through a global function pointer -- `mov rax, cs:callui; call rax`. IDA
//     guesses a fixed concrete signature for such a global, and if the real one is variadic that
//     guess cannot be reconciled with the call sites. One global broke 34 of hexx64's 38.
//
// Every trial is reverted unless it actually makes the caller decompile. A prototype that has not
// earned its place is a lie about the argument count, and confidently wrong pseudocode is worse
// than a function that visibly failed.

static const char *BADCALL_PROTOS[] = {
  "__int64 __fastcall f(__int64)",
  "__int64 __fastcall f(__int64, __int64)",
  "__int64 __fastcall f(__int64, __int64, __int64)",
};

// Tried first on a global reached by an indirect call: the variadic dispatcher case.
static const char *BADCALL_PTR_PROTOS[] = {
  "__int64 (__fastcall *f)(int, ...)",
  "__int64 (__fastcall *f)(__int64, ...)",
};

bool McpCommands::badcall_at(ea_t fea, ea_t *errea)
{
  qstring err;
  int merr = 0;
  ea_t at = BADADDR;
  pseudocode(fea, &err, &merr, &at);
  if ( errea != nullptr )
    *errea = at;
  return !err.empty() && merr == -12;      // MERR_BADCALL
}

bool McpCommands::decompiles_now(ea_t fea)
{
  qstring err;
  mark_cfunc_dirty(fea);                   // drop the cached failure before re-asking
  pseudocode(fea, &err);
  return err.empty();
}

// One instruction's worth of "what could this be calling": code references that leave the function
// are direct calls, data references to non-functions are the globals a call might go through.
static void harvest_refs(ea_t p, ea_t lo, ea_t hi, qvector<ea_t> *direct, qvector<ea_t> *indirect)
{
  for ( ea_t t = get_first_cref_from(p); t != BADADDR; t = get_next_cref_from(p, t) )
  {
    if ( t >= lo && t < hi )
      continue;                            // stays inside: a branch, not a call
    if ( get_func(t) != nullptr && !direct->has(t) )
      direct->push_back(t);
  }
  for ( ea_t t = get_first_dref_from(p); t != BADADDR; t = get_next_dref_from(p, t) )
  {
    if ( get_func(t) != nullptr )
      continue;                            // a function, not a pointer to one
    if ( !indirect->has(t) )
      indirect->push_back(t);
  }
}

// How far back from the failing call to look for the load that set up an indirect target. The load
// is nearly always within a handful of instructions; when it is not, the whole-function fallback
// below still finds it, just slower.
static const int BADCALL_BACKWALK = 24;

// What the call Hex-Rays choked on might be reaching.
//
// hexrays_failure_t carries errea -- the exact address where the decompiler gave up. The first
// version of this tool ignored it and searched every callee and every global in the whole function,
// which on a large function is hundreds of candidates and a full re-decompilation per trial. Start
// where Hex-Rays pointed instead.
//
// `call rax` holds no reference to the global that produced rax: that data reference sits on the
// earlier `mov rax, cs:callui`. So take the call site's own references, then walk backwards a
// bounded distance to pick up the load.
void McpCommands::badcall_candidates(
        ea_t fea,
        ea_t errea,
        qvector<ea_t> *direct,
        qvector<ea_t> *indirect)
{
  func_t *pfn = get_func(fea);
  if ( pfn == nullptr )
    return;
  const ea_t lo = pfn->start_ea;
  const ea_t hi = pfn->end_ea;

  if ( errea >= lo && errea < hi )
  {
    ea_t p = errea;
    for ( int i = 0; i <= BADCALL_BACKWALK && p != BADADDR && p >= lo; ++i, p = prev_head(p, lo) )
      harvest_refs(p, lo, hi, direct, indirect);
    if ( !direct->empty() || !indirect->empty() )
      return;                              // the named spot named a target: no need to sweep
  }

  // No usable errea, or the call site referenced nothing we can type. Sweep the function.
  for ( ea_t p = lo; p < hi && p != BADADDR; p = next_head(p, hi) )
    harvest_refs(p, lo, hi, direct, indirect);
}

// The rename half. A global we have just PROVED is a called function pointer -- typing it as one
// turned a failing decompilation into a working one -- should not keep an anonymous `off_...`
// name. Only dummy names are touched: a global that already reads `callui` is better named than
// anything invented here.
static bool name_as_fptr(ea_t ea, qstring *newname)
{
  if ( !has_dummy_name(get_flags(ea)) )
    return false;
  qstring old;
  if ( get_name(&old, ea) <= 0 )
    return false;
  const char *us = strchr(old.c_str(), '_');
  if ( us == nullptr )
    return false;
  qstring nn("pfn");
  nn.append(us);
  if ( !set_name(ea, nn.c_str(), SN_CHECK | SN_FORCE | SN_NOWARN) )
    return false;
  get_name(newname, ea);
  return true;
}

void McpCommands::repair_badcall(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  const bool apply = args != nullptr ? jbool(*args, "apply", true) : true;
  const bool do_rename = args != nullptr ? jbool(*args, "rename", true) : true;

  // ---- which functions are failing this way ----------------------------------------------
  // A caller that already knows which functions failed (an export just told it) can pass them in
  // and skip the sweep entirely -- the sweep decompiles all 10,109 functions to find 38.
  qvector<ea_t> scan;
  const jarr_t *only = args != nullptr ? jsubarr(*args, "addrs") : nullptr;
  if ( only != nullptr )
  {
    const jarr_t &a = *only;
    for ( size_t i = 0; i < a.values.size(); ++i )
    {
      ea_t ea = resolve_ea(a.values[i].type() == JT_STR ? a.values[i].qstr().c_str() : "");
      func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
      if ( pfn != nullptr )
        scan.push_back(pfn->start_ea);
    }
  }
  else
  {
    size_t nfuncs = get_func_qty();
    for ( size_t i = 0; i < nfuncs; ++i )
    {
      func_t *pfn = getn_func(i);
      if ( pfn != nullptr )
        scan.push_back(pfn->start_ea);
    }
  }

  qvector<ea_t> failing;
  qvector<ea_t> failing_at;                // where Hex-Rays gave up, one per failing function
  for ( size_t i = 0; i < scan.size(); ++i )
  {
    status("repair-scan", scan[i], "");
    ea_t at = BADADDR;
    if ( badcall_at(scan[i], &at) )
    {
      failing.push_back(scan[i]);
      failing_at.push_back(at);
    }
  }
  result->put("badcall_found", int64(failing.size()));
  if ( failing.empty() || !apply )
  {
    jarr_t *fs = new jarr_t;
    for ( size_t i = 0; i < failing.size(); ++i )
    {
      fs->values.push_back().set_str(hexstr(failing[i]).c_str());
    }
    result->get_value_or_new("functions")->set_arr(fs);
    out->set_obj(result);
    return;
  }

  // ---- repair ------------------------------------------------------------------------------
  jarr_t *fixes = new jarr_t;
  qvector<ea_t> todo = failing;
  for ( size_t i = 0; i < todo.size(); ++i )
  {
    ea_t fea = todo[i];
    if ( decompiles_now(fea) )
      continue;                            // an earlier fix already covered this one

    qvector<ea_t> direct;
    qvector<ea_t> indirect;
    badcall_candidates(fea, failing_at[i], &direct, &indirect);

    bool done = false;
    // Indirect first: one shared function pointer is usually the cause of many failures at once,
    // so fixing it early spares every later function a search.
    for ( int phase = 0; phase < 2 && !done; ++phase )
    {
      const qvector<ea_t> &cands = phase == 0 ? indirect : direct;
      const char **protos = phase == 0 ? BADCALL_PTR_PROTOS : BADCALL_PROTOS;
      size_t nprotos = phase == 0 ? qnumber(BADCALL_PTR_PROTOS) : qnumber(BADCALL_PROTOS);
      for ( size_t c = 0; c < cands.size() && !done; ++c )
      {
        tinfo_t old_tif;
        bool had_old = get_tinfo(&old_tif, cands[c]);
        for ( size_t k = 0; k < nprotos && !done; ++k )
        {
          tinfo_t tif;
          qstring nm;
          qstring decl(protos[k]);
          decl.append(';');
          if ( !parse_decl(&tif, &nm, nullptr, decl.c_str(), PT_SIL | PT_TYP) )
            continue;
          if ( !apply_tinfo(cands[c], tif, TINFO_DEFINITE) )
            continue;
          if ( decompiles_now(fea) )
          {
            jobj_t *e = new jobj_t;
            e->put("function", hexstr(fea));
            qstring fn;
            get_func_name(&fn, fea);
            e->put("name", fn);
            e->put("culprit", hexstr(cands[c]));
            qstring cn;
            get_name(&cn, cands[c]);
            e->put("culprit_name", cn);
            e->put("kind", phase == 0 ? "indirect call through a global" : "direct call");
            e->put("applied", protos[k]);
            e->put("failed_at", hexstr(failing_at[i]));   // the call Hex-Rays named, not a guess
            qstring renamed;
            if ( do_rename && phase == 0 && name_as_fptr(cands[c], &renamed) )
              e->put("renamed", renamed);
            fixes->values.push_back().set_obj(e);
            done = true;
            break;
          }
          // Did not help: put the old type back rather than leave a guess behind.
          if ( had_old )
            apply_tinfo(cands[c], old_tif, TINFO_DEFINITE);
          else
            del_tinfo(cands[c]);
        }
      }
    }
  }

  int64 still = 0;
  jarr_t *unfixed = new jarr_t;
  for ( size_t i = 0; i < failing.size(); ++i )
  {
    if ( decompiles_now(failing[i]) )
      continue;
    ++still;
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(failing[i]));
    qstring fn;
    get_func_name(&fn, failing[i]);
    e->put("name", fn);
    unfixed->values.push_back().set_obj(e);
  }

  result->put("recovered", int64(failing.size()) - still);
  result->put("still_failing", still);
  result->get_value_or_new("fixes")->set_arr(fixes);
  result->get_value_or_new("unfixed")->set_arr(unfixed);
  // Say it plainly: the caller has to opt into persistence, and by default nothing reaches disk.
  result->put("saved", false);
  result->put("note", "in-session only; close_database with save=true to persist");
  out->set_obj(result);
}

// ---- microcode --------------------------------------------------------------------------------
//
// The decompiler runs the function through a pipeline of maturity levels, and a failure kills the
// whole thing. MERR_BADCALL happens at MMAT_CALLS, the level whose job is working out call
// arguments -- so asking for microcode at the level BEFORE that succeeds on exactly the functions
// that will not decompile. That is the point of this tool: to see what the decompiler saw at the
// moment it gave up, instead of inferring it from pseudocode that does not exist.
//
// Pair it with repair_badcall's failed_at: dump the microcode around that address and the offending
// call is right there, with the registers live across it.

struct mba_text_t : public vd_printer_t
{
  qstring text;
  AS_PRINTF(3, 4) int print(int indent, const char *format, ...) override
  {
    qstring line;
    if ( indent > 0 )
      line.sprnt("%*s", indent, "");
    va_list va;
    va_start(va, format);
    line.cat_vsprnt(format, va);
    va_end(va);
    qstring plain;
    tag_remove(&plain, line.c_str());       // microcode text is colour-tagged like everything else
    text.append(plain);
    return int(plain.length());
  }
};

static mba_maturity_t maturity_by_name(const qstring &s)
{
  if ( s == "generated" )    return MMAT_GENERATED;
  if ( s == "preoptimized" ) return MMAT_PREOPTIMIZED;
  if ( s == "locopt" )       return MMAT_LOCOPT;
  if ( s == "calls" )        return MMAT_CALLS;
  if ( s == "glbopt1" )      return MMAT_GLBOPT1;
  if ( s == "glbopt2" )      return MMAT_GLBOPT2;
  if ( s == "glbopt3" )      return MMAT_GLBOPT3;
  if ( s == "lvars" )        return MMAT_LVARS;
  return MMAT_ZERO;
}

void McpCommands::microcode(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
  if ( !is_open || !hexrays_ok || pfn == nullptr )
  {
    result->put("error", !is_open      ? "no database is open"
                       : !hexrays_ok   ? "decompiler unavailable"
                                       : "no function at address");
    out->set_obj(result);
    return;
  }

  // Default to the level just before call analysis, because that is the one that still works when
  // call analysis is what failed.
  qstring want = args != nullptr ? jstr(*args, "maturity", "preoptimized") : qstring("preoptimized");
  mba_maturity_t mat = maturity_by_name(want);
  if ( mat == MMAT_ZERO )
  {
    result->put("error", "maturity must be one of: generated preoptimized locopt calls "
                         "glbopt1 glbopt2 glbopt3 lvars");
    out->set_obj(result);
    return;
  }

  mute_stdout();
  hexrays_failure_t hf;
  decomp_ranges_t dcr(pfn->start_ea);
  mba_t *mba = gen_microcode(dcr, &hf, nullptr, DECOMP_NO_WAIT, mat);
  unmute_stdout();
  if ( mba == nullptr )
  {
    qstring d = hf.desc();
    if ( d.empty() )
      d.sprnt("merror %d", int(hf.code));
    result->put("error", d);
    result->put("merror_code", int64(hf.code));
    if ( hf.errea != BADADDR )
    {
      result->put("error_addr", hexstr(hf.errea));
    }
    out->set_obj(result);
    return;
  }

  mba_text_t p;
  mba->print(p);
  delete mba;                                // ~mba_t calls term(); this is not garbage collected

  // Whole listings run to thousands of lines. `around` keeps the window near the interesting
  // address, which for a repair is whatever failed_at reported.
  ea_t around = resolve_ea(args != nullptr ? jstr(*args, "around").c_str() : "");
  int64 ctx = args != nullptr ? jint(*args, "context", 40) : 40;
  qstring text = p.text;
  if ( around != BADADDR && ctx > 0 )
  {
    qstring needle;
    needle.sprnt("%a", around);
    qvector<qstring> lines;
    size_t start = 0;
    for ( size_t i = 0; i <= text.length(); ++i )
    {
      if ( i == text.length() || text[i] == '\n' )
      {
        lines.push_back(qstring(text.c_str() + start, i - start));
        start = i + 1;
      }
    }
    ssize_t hit = -1;
    for ( size_t i = 0; i < lines.size() && hit < 0; ++i )
      if ( strstr(lines[i].c_str(), needle.c_str()) != nullptr )
        hit = ssize_t(i);
    if ( hit >= 0 )
    {
      size_t lo = size_t(hit) > size_t(ctx) ? size_t(hit) - size_t(ctx) : 0;
      size_t hi = qmin(lines.size(), size_t(hit) + size_t(ctx) + 1);
      qstring win;
      for ( size_t i = lo; i < hi; ++i )
      {
        win.append(lines[i]);
        win.append('\n');
      }
      text = win;
      result->put("window", needle);
    }
  }

  qstring fn;
  get_func_name(&fn, pfn->start_ea);
  result->put("name", fn);
  result->put("maturity", want);
  result->put("microcode", text);
  out->set_obj(result);
}

// ---- idalib session ---------------------------------------------------------------------------
//
// idalib's own surface is small: init_library, open_database, close_database, make_signatures,
// enable_console_messages, set_screen_ea, get_library_version. Everything else hexport does comes
// from the SDK proper. Of the four we were not using, make_signatures is the only one that does
// real work; get_library_version belongs in server_health so a caller can tell which IDA produced
// an export. enable_console_messages is redundant here (hexport mutes at the file-descriptor
// level, which also catches output from the kernel's own C runtime) and set_screen_ea has no
// meaning without a screen.
void McpCommands::make_sigs(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  const bool only_pat = args != nullptr ? jbool(*args, "only_pat", false) : false;
  mute_stdout();
  bool ok = make_signatures(only_pat);
  unmute_stdout();
  result->put("status", ok ? "ok" : "failed");
  result->put("only_pat", only_pat);
  // Written beside the input file, named after it. This is the one hexport operation that produces
  // a file on disk without being asked to save a database.
  result->put("note", only_pat ? "wrote .pat beside the input file"
                               : "wrote .pat and .sig beside the input file");
  out->set_obj(result);
}

// ---- save_as ----------------------------------------------------------------------------------
//
// The session-level call that matters most here, and it is not in idalib.hpp at all -- it is
// loader.hpp's save_database(outfile, ...). It writes the CURRENT in-memory database to a
// DIFFERENT path.
//
// Until now a repair had exactly two endings: discard it on close, or save over the original. The
// first wastes eight minutes of work every time; the second is the thing that must never happen to
// a database somebody cares about. save_as gives the third ending -- keep the repair, write it
// somewhere new, leave the input file byte-identical.
//
// DBFL_BAK is deliberately not offered: a backup of a file we are not writing to is meaningless,
// and the flag is about the current path, not the output path.
void McpCommands::save_as(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring path = args != nullptr ? jstr(*args, "path") : qstring();
  if ( !is_open || path.empty() )
  {
    result->put("error", !is_open ? "no database is open" : "path is required");
    out->set_obj(result);
    return;
  }
  // Refuse to write over the database we opened. That is what close_database(save=true) is for,
  // and confusing the two is exactly the mistake this tool exists to prevent.
  const char *cur = get_path(PATH_TYPE_IDB);
  if ( cur != nullptr && qstrcmp(cur, path.c_str()) == 0 )
  {
    result->put("error", "path is the current database; use close_database with save=true "
                         "if overwriting it is really what you want");
    out->set_obj(result);
    return;
  }

  const bool compress = args != nullptr ? jbool(*args, "compress", false) : false;
  mute_stdout();
  // Analysis queued by the repairs has to settle before the snapshot, or it is written half-done.
  auto_wait();
  bool ok = save_database(path.c_str(), compress ? DBFL_COMP : 0);
  unmute_stdout();

  result->put("status", ok ? "ok" : "failed");
  result->put("path", path);
  result->put("compressed", compress);
  result->put("source_untouched", true);
  out->set_obj(result);
}

// ---- revert_decisions -------------------------------------------------------------------------
//
// "Undefine, then let IDA redefine it" as one operation. revert_ida_decisions throws away only what
// the auto-analyser concluded about a range -- guessed code, guessed data, guessed types -- and
// leaves anything a human (or an earlier repair) set explicitly. Re-planning the range then makes
// IDA work it out again from scratch.
//
// This is the safe form of the undefine/redefine cycle: undefine() plus define_func() destroys user
// annotations along with the bad guess.
void McpCommands::revert_decisions(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t start = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( !is_open || start == BADADDR )
  {
    result->put("error", !is_open ? "no database is open" : "bad address");
    out->set_obj(result);
    return;
  }
  qstring end_s = args != nullptr ? jstr(*args, "end") : qstring();
  ea_t end = BADADDR;
  if ( !end_s.empty() )
  {
    end = resolve_ea(end_s.c_str());
  }
  else
  {
    func_t *pfn = get_func(start);           // no end given: the enclosing function, else one item
    end = pfn != nullptr ? pfn->end_ea : next_head(start, BADADDR);
  }
  if ( end == BADADDR || end <= start )
  {
    result->put("error", "could not work out a range to revert");
    out->set_obj(result);
    return;
  }

  const bool wait = args != nullptr ? jbool(*args, "wait", true) : true;
  mute_stdout();
  revert_ida_decisions(start, end);
  plan_range(start, end);
  if ( wait )
    auto_wait_range(start, end);
  unmute_stdout();

  result->put("start", hexstr(start));
  result->put("end", hexstr(end));
  result->put("status", "ok");
  func_t *pfn = get_func(start);
  result->put("function_after", pfn != nullptr);
  out->set_obj(result);
}

// ---- local types, structures, enums, stack frames ---------------------------------------------
//
// Ported from ida-pro-mcp. These are the tools that let a caller BUILD understanding rather than
// just read it out: name a stack slot, declare the struct a pointer really points at, extend an
// enum as constants are worked out. All of it is in-session; nothing reaches disk unless save_as or
// close_database(save=true) is asked for it.
//
// IDA 9 has no separate struct/enum API any more -- both are tinfo_t in the local type library, so
// everything here goes through get_idati().

static const char *tinfo_kind(const tinfo_t &t)
{
  if ( t.is_enum() )      return "enum";
  if ( t.is_union() )     return "union";
  if ( t.is_struct() )    return "struct";
  if ( t.is_typedef() )   return "typedef";
  if ( t.is_func() )      return "func";
  if ( t.is_ptr() )       return "ptr";
  if ( t.is_array() )     return "array";
  return "scalar";
}

// Members of a struct/union, or constants of an enum. Both are worth reporting the same way: a name,
// where it sits, and how big it is.
static void emit_members(jobj_t *o, const tinfo_t &tif, int64 max_members)
{
  if ( tif.is_enum() )
  {
    enum_type_data_t ed;
    if ( !tif.get_enum_details(&ed) )
      return;
    jarr_t *arr = new jarr_t;
    for ( size_t i = 0; i < ed.size() && int64(i) < max_members; ++i )
    {
      jobj_t *e = new jobj_t;
      e->put("name", ed[i].name);
      qstring v;
      v.sprnt("0x%" FMT_64 "x", ed[i].value);
      e->put("value", v);
      if ( !ed[i].cmt.empty() )
        e->put("comment", ed[i].cmt);
      arr->values.push_back().set_obj(e);
    }
    o->put("member_count", int64(ed.size()));
    o->get_value_or_new("members")->set_arr(arr);
    return;
  }

  udt_type_data_t udt;
  if ( !tif.get_udt_details(&udt) )
    return;
  jarr_t *arr = new jarr_t;
  for ( size_t i = 0; i < udt.size() && int64(i) < max_members; ++i )
  {
    const udm_t &m = udt[i];
    jobj_t *e = new jobj_t;
    e->put("name", m.name);
    e->put("offset", int64(m.offset / 8));      // udm_t offsets are in BITS
    e->put("size", int64(m.size / 8));
    qstring ts;
    m.type.print(&ts);
    e->put("type", ts);
    if ( !m.cmt.empty() )
      e->put("comment", m.cmt);
    arr->values.push_back().set_obj(e);
  }
  o->put("member_count", int64(udt.size()));
  o->get_value_or_new("members")->set_arr(arr);
}

void McpCommands::declare_type(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  // Accept one declaration or many, the way ida-pro-mcp does: a header pasted in one go is the
  // common case, and splitting it up would break declarations that reference each other.
  qvector<qstring> decls;
  const jvalue_t *v = args != nullptr ? args->get_value("decls", JT_ARR) : nullptr;
  if ( v != nullptr )
  {
    const jarr_t &a = v->arr();
    for ( size_t i = 0; i < a.values.size(); ++i )
      if ( a.values[i].type() == JT_STR )
        decls.push_back(a.values[i].qstr());
  }
  else
  {
    qstring one = args != nullptr ? jstr(*args, "decls") : qstring();
    if ( !one.empty() )
      decls.push_back(one);
  }
  if ( decls.empty() )
  {
    result->put("error", "decls is required (a C declaration, or an array of them)");
    out->set_obj(result);
    return;
  }

  jarr_t *arr = new jarr_t;
  int64 errors = 0;
  for ( size_t i = 0; i < decls.size(); ++i )
  {
    mute_stdout();
    int n = parse_decls(get_idati(), decls[i].c_str(), nullptr, HTI_DCL);
    unmute_stdout();
    jobj_t *e = new jobj_t;
    e->put("decl", decls[i]);
    e->put("errors", int64(n));               // parse_decls returns the NUMBER OF ERRORS, not a count of types
    e->put("status", n == 0 ? "ok" : "failed");
    if ( n != 0 )
      ++errors;
    arr->values.push_back().set_obj(e);
  }
  result->put("failed", errors);
  result->get_value_or_new("results")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::type_inspect(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  const jarr_t *qs = args != nullptr ? jsubarr(*args, "queries") : nullptr;
  qvector<const jobj_t *> items;
  if ( qs != nullptr )
  {
    for ( size_t i = 0; i < qs->values.size(); ++i )
      if ( qs->values[i].type() == JT_OBJ )
        items.push_back(&qs->values[i].obj());
  }
  else
  {
    const jobj_t *one = args != nullptr ? jsub(*args, "queries") : nullptr;
    if ( one != nullptr )
      items.push_back(one);
  }

  for ( size_t i = 0; i < items.size(); ++i )
  {
    const jobj_t &q = *items[i];
    jobj_t *e = new jobj_t;
    qstring name = jstr(q, "name");
    e->put("name", name);
    tinfo_t tif;
    if ( !is_open || !named_type(&tif, name) )
    {
      e->put("error", !is_open ? "no database is open" : "no such type");
      outer->values.push_back().set_obj(e);
      continue;
    }
    e->put("kind", tinfo_kind(tif));
    e->put("size", int64(tif.get_size()));
    qstring decl;
    tif.print(&decl, name.c_str(), PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI);
    e->put("declaration", decl);
    if ( jbool(q, "include_members", true) )
      emit_members(e, tif, jint(q, "max_members", 256));
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

void McpCommands::type_query(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  const jobj_t *q = args != nullptr ? jsub(*args, "queries") : nullptr;
  qstring filter = q != nullptr ? jstr(*q, "filter") : qstring();
  qstring kind = q != nullptr ? jstr(*q, "kind", "any") : qstring("any");
  int64 offset = q != nullptr ? jint(*q, "offset", 0) : 0;
  int64 count = q != nullptr ? jint(*q, "count", 100) : 100;
  bool want_decl = q != nullptr ? jbool(*q, "include_decl", false) : false;
  bool want_members = q != nullptr ? jbool(*q, "include_members", false) : false;

  jarr_t *arr = new jarr_t;
  const til_t *til = get_idati();
  uint32 limit = get_ordinal_limit(til);
  int64 seen = 0;
  int64 emitted = 0;
  int64 total = 0;
  for ( uint32 ord = 1; ord < limit; ++ord )
  {
    const char *nm = get_numbered_type_name(til, ord);
    if ( nm == nullptr )
      continue;
    if ( !filter.empty() && strstr(nm, filter.c_str()) == nullptr )
      continue;
    tinfo_t tif;
    if ( !tif.get_numbered_type(til, ord) )
      continue;
    if ( kind != "any" && kind != tinfo_kind(tif) )
      continue;
    ++total;
    if ( seen++ < offset || (count > 0 && emitted >= count) )
      continue;
    jobj_t *e = new jobj_t;
    e->put("ordinal", int64(ord));
    e->put("name", nm);
    e->put("kind", tinfo_kind(tif));
    e->put("size", int64(tif.get_size()));
    if ( want_decl )
    {
      qstring decl;
      tif.print(&decl, nm, PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_SEMI);
      e->put("declaration", decl);
    }
    if ( want_members )
      emit_members(e, tif, q != nullptr ? jint(*q, "max_members", 64) : 64);
    arr->values.push_back().set_obj(e);
    ++emitted;
  }
  result->put("total_matching", total);
  result->put("ordinal_limit", int64(limit));
  result->get_value_or_new("types")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::enum_upsert(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  const jobj_t *q = args != nullptr ? jsub(*args, "queries") : nullptr;
  qstring name = q != nullptr ? jstr(*q, "name") : qstring();
  if ( !is_open || name.empty() )
  {
    result->put("error", !is_open ? "no database is open" : "queries.name is required");
    out->set_obj(result);
    return;
  }

  // Upsert, not replace. An enum being built up over a session gets members added a few at a time,
  // and a create-or-overwrite would silently drop everything worked out so far.
  tinfo_t tif;
  enum_type_data_t ed;
  bool existed = named_type(&tif, name) && tif.get_enum_details(&ed);
  const bool want_bitfield = q != nullptr && jbool(*q, "bitfield", false);

  int64 added = 0;
  int64 updated = 0;
  const jarr_t *ms = q != nullptr ? jsubarr(*q, "members") : nullptr;
  if ( ms != nullptr )
  {
    for ( size_t i = 0; i < ms->values.size(); ++i )
    {
      if ( ms->values[i].type() != JT_OBJ )
        continue;
      const jobj_t &m = ms->values[i].obj();
      qstring mn = jstr(m, "name");
      if ( mn.empty() )
        continue;
      // Values arrive as a number or as a "0x..." string; both are normal in a JSON client.
      uint64 val = 0;
      const jvalue_t *vv = m.get_value("value", JT_NUM);
      if ( vv != nullptr )
        val = uint64(vv->num());
      else
        val = uint64(strtoull(jstr(m, "value", "0").c_str(), nullptr, 0));

      bool found = false;
      for ( size_t k = 0; k < ed.size(); ++k )
      {
        if ( ed[k].name == mn )
        {
          if ( ed[k].value != val )
          {
            ed[k].value = val;
            ++updated;
          }
          found = true;
          break;
        }
      }
      if ( !found )
      {
        edm_t &e = ed.push_back();
        e.name = mn;
        e.value = val;
        ++added;
      }
    }
  }

  // create_enum() takes a non-const reference and consumes what it is given, so ed.size() reads 0
  // afterwards. Count before handing it over -- reporting member_count 0 on a successful upsert made
  // the tool look like it had silently dropped everything.
  const int64 member_count = int64(ed.size());
  mute_stdout();
  tinfo_t nt;
  bool ok = nt.create_enum(ed) && nt.set_named_type(get_idati(), name.c_str(), NTF_REPLACE) == TERR_OK;
  // 'bitmask' is a property of the stored type, not a field of enum_type_data_t, so it can only be
  // set once the type has a name to hang off.
  bool bitfield_ok = !want_bitfield;
  if ( ok && want_bitfield )
  {
    tinfo_t stored;
    if ( named_type(&stored, name) )
      bitfield_ok = stored.set_enum_is_bitmask(tinfo_t::ENUMBM_ON) == TERR_OK;
  }
  unmute_stdout();

  result->put("status", ok ? "ok" : "failed");
  result->put("name", name);
  if ( want_bitfield )
    result->put("bitfield", bitfield_ok);
  result->put("existed", existed);
  result->put("added", added);
  result->put("updated", updated);
  result->put("member_count", member_count);
  out->set_obj(result);
}

void McpCommands::read_struct(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  const jarr_t *qs = args != nullptr ? jsubarr(*args, "queries") : nullptr;
  qvector<const jobj_t *> items;
  if ( qs != nullptr )
  {
    for ( size_t i = 0; i < qs->values.size(); ++i )
      if ( qs->values[i].type() == JT_OBJ )
        items.push_back(&qs->values[i].obj());
  }
  else
  {
    const jobj_t *one = args != nullptr ? jsub(*args, "queries") : nullptr;
    if ( one != nullptr )
      items.push_back(one);
  }

  for ( size_t i = 0; i < items.size(); ++i )
  {
    const jobj_t &q = *items[i];
    jobj_t *e = new jobj_t;
    ea_t ea = resolve_ea(jstr(q, "addr").c_str());
    put_hex(e, "addr", ea);
    qstring sname = jstr(q, "struct");
    tinfo_t tif;
    // With no struct named, use whatever type is already applied at the address. That is the
    // common case after infer_types or a set_type, and guessing anything else would be a fiction.
    bool have = !sname.empty() ? named_type(&tif, sname) : get_tinfo(&tif, ea);
    if ( !is_open || ea == BADADDR || !have || !tif.is_udt() )
    {
      e->put("error", !is_open ? "no database is open"
                    : ea == BADADDR ? "bad address"
                    : !have ? (sname.empty()
                                 ? "no type applied here; pass struct, or run infer_types first"
                                 : "no such type in the local type library")
                            : "the type here is not a structure or union");
      outer->values.push_back().set_obj(e);
      continue;
    }
    qstring tn;
    tif.print(&tn);
    e->put("struct", tn);

    udt_type_data_t udt;
    if ( !tif.get_udt_details(&udt) )
    {
      e->put("error", "could not read the structure layout");
      outer->values.push_back().set_obj(e);
      continue;
    }
    jarr_t *arr = new jarr_t;
    for ( size_t k = 0; k < udt.size(); ++k )
    {
      const udm_t &m = udt[k];
      jobj_t *f = new jobj_t;
      f->put("name", m.name);
      asize_t off = asize_t(m.offset / 8);
      asize_t sz = asize_t(m.size / 8);
      f->put("offset", int64(off));
      qstring ts;
      m.type.print(&ts);
      f->put("type", ts);
      // Only whole small scalars get a value; anything else is reported by shape, not invented.
      if ( sz >= 1 && sz <= 8 && (m.size % 8) == 0 )
      {
        uint64 raw = 0;
        if ( ::get_bytes(&raw, size_t(sz), ea + off) == ssize_t(sz) )
        {
          qstring hv;
          hv.sprnt("0x%" FMT_64 "x", raw);
          f->put("value", hv);
          f->put("value_dec", int64(raw));
        }
        else
        {
          f->put("error", "unreadable");
        }
      }
      else
      {
        f->put("size", int64(sz));
      }
      arr->values.push_back().set_obj(f);
    }
    e->get_value_or_new("fields")->set_arr(arr);
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

// Collect {addr,...} items that may arrive as one object or an array of them. Every ported tool
// below takes that shape, because ida-pro-mcp's batch tools all do.
static void collect_items(const jobj_t *args, const char *key, qvector<const jobj_t *> *items)
{
  const jarr_t *a = args != nullptr ? jsubarr(*args, key) : nullptr;
  if ( a != nullptr )
  {
    for ( size_t i = 0; i < a->values.size(); ++i )
      if ( a->values[i].type() == JT_OBJ )
        items->push_back(&a->values[i].obj());
    return;
  }
  const jobj_t *one = args != nullptr ? jsub(*args, key) : nullptr;
  if ( one != nullptr )
    items->push_back(one);
}

void McpCommands::declare_stack(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  qvector<const jobj_t *> items;
  collect_items(args, "items", &items);
  for ( size_t i = 0; i < items.size(); ++i )
  {
    const jobj_t &q = *items[i];
    jobj_t *e = new jobj_t;
    ea_t fea = resolve_ea(jstr(q, "addr").c_str());
    func_t *pfn = fea != BADADDR ? get_func(fea) : nullptr;
    qstring name = jstr(q, "name");
    qstring ty = jstr(q, "ty");
    e->put("addr", jstr(q, "addr"));
    e->put("name", name);
    if ( !is_open || pfn == nullptr || name.empty() || ty.empty() )
    {
      e->put("error", !is_open ? "no database is open"
                    : pfn == nullptr ? "no function at address"
                                     : "name and ty are both required");
      outer->values.push_back().set_obj(e);
      continue;
    }
    // Offsets are strings here because they are routinely negative (locals sit below the frame
    // pointer) and clients disagree about how to encode a negative in JSON.
    sval_t off = sval_t(strtoll(jstr(q, "offset", "0").c_str(), nullptr, 0));

    tinfo_t tif;
    qstring nm;
    qstring decl(ty);
    decl.append(" x;");
    if ( !parse_decl(&tif, &nm, get_idati(), decl.c_str(), PT_SIL) )
    {
      e->put("error", "could not parse the type");
      outer->values.push_back().set_obj(e);
      continue;
    }
    mute_stdout();
    bool ok = add_frame_member_ea(pfn->start_ea, name.c_str(), uval_t(off), tif);
    if ( !ok )                                 // already there: retype it rather than fail
      ok = set_frame_member_type_ea(pfn->start_ea, uval_t(off), tif);
    unmute_stdout();
    e->put("status", ok ? "ok" : "failed");
    e->put("offset", jstr(q, "offset", "0"));
    e->put("type", ty);
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

void McpCommands::delete_stack(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  qvector<const jobj_t *> items;
  collect_items(args, "items", &items);
  for ( size_t i = 0; i < items.size(); ++i )
  {
    const jobj_t &q = *items[i];
    jobj_t *e = new jobj_t;
    ea_t fea = resolve_ea(jstr(q, "addr").c_str());
    func_t *pfn = fea != BADADDR ? get_func(fea) : nullptr;
    qstring name = jstr(q, "name");
    e->put("addr", jstr(q, "addr"));
    e->put("name", name);
    tinfo_t frame;
    if ( !is_open || pfn == nullptr || name.empty() || !get_func_frame_ea(&frame, pfn->start_ea) )
    {
      e->put("error", !is_open ? "no database is open"
                    : pfn == nullptr ? "no function at address"
                    : name.empty() ? "name is required"
                                   : "this function has no frame");
      outer->values.push_back().set_obj(e);
      continue;
    }
    // Delete by NAME, which is what a caller has, by looking the offset up in the frame first.
    udt_type_data_t udt;
    bool found = false;
    uint64 lo = 0, hi = 0;
    if ( frame.get_udt_details(&udt) )
    {
      for ( size_t k = 0; k < udt.size(); ++k )
      {
        if ( udt[k].name == name )
        {
          lo = udt[k].offset / 8;
          hi = lo + (udt[k].size / 8);
          found = true;
          break;
        }
      }
    }
    if ( !found )
    {
      e->put("error", "no stack variable with that name");
      outer->values.push_back().set_obj(e);
      continue;
    }
    mute_stdout();
    bool ok = delete_frame_members_ea(pfn->start_ea, uval_t(lo), uval_t(hi > lo ? hi : lo + 1));
    unmute_stdout();
    e->put("status", ok ? "ok" : "failed");
    e->put("offset", int64(lo));
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

// ---- call graph, profiling, search, strings, integers, annotations ----------------------------
//
// The second half of the ida-pro-mcp port. Everything here is read-mostly except add_bookmark and
// append_comments, and all of it stays in the session.

// qstring has no case-folding of its own, and qstrlwr works on a char buffer in place.
static void lower_in_place(qstring *s)
{
  if ( !s->empty() )
    qstrlwr(s->begin());
}

void McpCommands::callgraph(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  // Roots may be one name/address or a list. A call graph with no root is the whole binary, which
  // is never what anyone means.
  qvector<ea_t> roots;
  const jarr_t *ra = args != nullptr ? jsubarr(*args, "roots") : nullptr;
  if ( ra != nullptr )
  {
    for ( size_t i = 0; i < ra->values.size(); ++i )
      if ( ra->values[i].type() == JT_STR )
      {
        ea_t ea = resolve_ea(ra->values[i].qstr().c_str());
        func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
        if ( pfn != nullptr && !roots.has(pfn->start_ea) )
          roots.push_back(pfn->start_ea);
      }
  }
  else
  {
    ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "roots").c_str() : "");
    func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
    if ( pfn != nullptr )
      roots.push_back(pfn->start_ea);
  }
  if ( roots.empty() )
  {
    result->put("error", "roots is required (a function address or name, or a list of them)");
    out->set_obj(result);
    return;
  }

  const int64 max_depth = args != nullptr ? jint(*args, "max_depth", 5) : 5;
  const int64 max_nodes = args != nullptr ? jint(*args, "max_nodes", 1000) : 1000;
  const int64 max_edges = args != nullptr ? jint(*args, "max_edges", 5000) : 5000;
  const int64 max_per   = args != nullptr ? jint(*args, "max_edges_per_func", 200) : 200;

  // Breadth-first, so max_depth means what it says and the truncation is even across the frontier
  // rather than dropping whole subtrees the way a depth-first walk would.
  qvector<ea_t> seen = roots;
  qvector<ea_t> frontier = roots;
  jarr_t *edges = new jarr_t;
  int64 nedges = 0;
  bool truncated = false;
  for ( int64 depth = 0; depth < max_depth && !frontier.empty() && !truncated; ++depth )
  {
    qvector<ea_t> next;
    for ( size_t i = 0; i < frontier.size() && !truncated; ++i )
    {
      func_t *pfn = get_func(frontier[i]);
      if ( pfn == nullptr )
        continue;
      qvector<ea_t> targets;
      collect_callees(pfn, &targets);
      for ( size_t k = 0; k < targets.size() && int64(k) < max_per && !truncated; ++k )
      {
        const ea_t to = targets[k];
        jobj_t *e = new jobj_t;
        e->put("from", hexstr(pfn->start_ea));
        e->put("to", hexstr(to));
        qstring nm;
        if ( get_func_name(&nm, to) > 0 )
          e->put("to_name", nm);
        edges->values.push_back().set_obj(e);
        if ( ++nedges >= max_edges )
        {
          truncated = true;
          break;
        }
        if ( seen.has(to) )
          continue;
        if ( int64(seen.size()) >= max_nodes )
        {
          truncated = true;
          break;
        }
        seen.push_back(to);
        next.push_back(to);
      }
    }
    frontier = next;
  }

  jarr_t *nodes = new jarr_t;
  for ( size_t i = 0; i < seen.size(); ++i )
  {
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(seen[i]));
    qstring nm;
    if ( get_func_name(&nm, seen[i]) > 0 )
      e->put("name", nm);
    nodes->values.push_back().set_obj(e);
  }
  result->put("node_count", int64(seen.size()));
  result->put("edge_count", nedges);
  result->put("truncated", truncated);        // say so rather than let a partial graph read as whole
  result->get_value_or_new("nodes")->set_arr(nodes);
  result->get_value_or_new("edges")->set_arr(edges);
  out->set_obj(result);
}

void McpCommands::func_profile(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  const jobj_t *q = args != nullptr ? jsub(*args, "queries") : nullptr;
  qstring want = q != nullptr ? jstr(*q, "addr") : qstring();
  qstring filter = q != nullptr ? jstr(*q, "filter") : qstring();
  int64 offset = q != nullptr ? jint(*q, "offset", 0) : 0;
  int64 count = q != nullptr ? jint(*q, "count", 100) : 100;
  bool want_proto = q != nullptr ? jbool(*q, "include_prototype", true) : true;
  bool want_lists = q != nullptr ? jbool(*q, "include_lists", false) : false;
  int64 max_items = q != nullptr ? jint(*q, "max_items", 32) : 32;

  qvector<ea_t> targets;
  if ( !want.empty() && want != "*" )
  {
    ea_t ea = resolve_ea(want.c_str());
    func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
    if ( pfn != nullptr )
      targets.push_back(pfn->start_ea);
  }
  else
  {
    size_t n = get_func_qty();
    for ( size_t i = 0; i < n; ++i )
    {
      func_t *pfn = getn_func(i);
      if ( pfn == nullptr )
        continue;
      if ( !filter.empty() )
      {
        qstring nm;
        if ( get_func_name(&nm, pfn->start_ea) <= 0 || strstr(nm.c_str(), filter.c_str()) == nullptr )
          continue;
      }
      targets.push_back(pfn->start_ea);
    }
  }

  jarr_t *arr = new jarr_t;
  int64 emitted = 0;
  for ( size_t i = size_t(offset < 0 ? 0 : offset);
        i < targets.size() && (count <= 0 || emitted < count); ++i )
  {
    func_t *pfn = get_func(targets[i]);
    if ( pfn == nullptr )
      continue;
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(pfn->start_ea));
    qstring nm;
    get_func_name(&nm, pfn->start_ea);
    e->put("name", nm);
    e->put("size", int64(pfn->end_ea - pfn->start_ea));

    qflow_chart_t fc;
    fc.create("profile", pfn, pfn->start_ea, pfn->end_ea, FC_NOEXT);
    e->put("blocks", int64(fc.size()));

    qvector<ea_t> callee_list;
    collect_callees(pfn, &callee_list);
    int64 ncallees = int64(callee_list.size());
    int64 ncallers = 0;
    qvector<ea_t> caller_list;
    xrefblk_t xb;
    for ( bool ok = xb.first_to(pfn->start_ea, XREF_ALL); ok; ok = xb.next_to() )
    {
      func_t *cf = get_func(xb.from);
      if ( cf == nullptr || caller_list.has(cf->start_ea) )
        continue;
      caller_list.push_back(cf->start_ea);
      ++ncallers;
    }
    e->put("callees", ncallees);
    e->put("callers", ncallers);
    if ( want_proto )
    {
      tinfo_t tif;
      qstring proto;
      if ( get_tinfo(&tif, pfn->start_ea) && tif.print(&proto, nm.c_str()) )
        e->put("prototype", proto);
    }
    if ( want_lists )
    {
      jarr_t *cl = new jarr_t;
      for ( size_t k = 0; k < callee_list.size() && int64(k) < max_items; ++k )
      {
        qstring cn;
        get_func_name(&cn, callee_list[k]);
        cl->values.push_back().set_str(cn.c_str());
      }
      e->get_value_or_new("callee_names")->set_arr(cl);
      jarr_t *pl = new jarr_t;
      for ( size_t k = 0; k < caller_list.size() && int64(k) < max_items; ++k )
      {
        qstring cn;
        get_func_name(&cn, caller_list[k]);
        pl->values.push_back().set_str(cn.c_str());
      }
      e->get_value_or_new("caller_names")->set_arr(pl);
    }
    arr->values.push_back().set_obj(e);
    ++emitted;
  }
  result->put("total_matching", int64(targets.size()));
  result->get_value_or_new("functions")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::export_funcs(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  qvector<ea_t> addrs;
  const jarr_t *aa = args != nullptr ? jsubarr(*args, "addrs") : nullptr;
  if ( aa != nullptr )
  {
    for ( size_t i = 0; i < aa->values.size(); ++i )
      if ( aa->values[i].type() == JT_STR )
      {
        ea_t ea = resolve_ea(aa->values[i].qstr().c_str());
        func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
        if ( pfn != nullptr )
          addrs.push_back(pfn->start_ea);
      }
  }
  else
  {
    ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addrs").c_str() : "");
    func_t *pfn = ea != BADADDR ? get_func(ea) : nullptr;
    if ( pfn != nullptr )
      addrs.push_back(pfn->start_ea);
  }
  if ( addrs.empty() )
  {
    result->put("error", "addrs is required (a function address or name, or a list of them)");
    out->set_obj(result);
    return;
  }
  qstring format = args != nullptr ? jstr(*args, "format", "json") : qstring("json");

  // c_header and prototypes are both text a caller can paste straight into a build; json keeps the
  // fields separate for anything that wants to process them.
  if ( format == "c_header" || format == "prototypes" )
  {
    qstring text;
    if ( format == "c_header" )
      text.append("/* generated by hexport export_funcs */\n\n");
    for ( size_t i = 0; i < addrs.size(); ++i )
    {
      qstring nm;
      get_func_name(&nm, addrs[i]);
      tinfo_t tif;
      qstring proto;
      if ( get_tinfo(&tif, addrs[i]) && tif.print(&proto, nm.c_str()) )
        text.append(proto);
      else
        text.append(qstring("void ") + nm + "()");
      text.append(";\n");
    }
    result->put("format", format);
    result->put("text", text);
    result->put("count", int64(addrs.size()));
    out->set_obj(result);
    return;
  }

  jarr_t *arr = new jarr_t;
  for ( size_t i = 0; i < addrs.size(); ++i )
  {
    func_t *pfn = get_func(addrs[i]);
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(addrs[i]));
    qstring nm;
    get_func_name(&nm, addrs[i]);
    e->put("name", nm);
    if ( pfn != nullptr )
      e->put("size", int64(pfn->end_ea - pfn->start_ea));
    tinfo_t tif;
    qstring proto;
    if ( get_tinfo(&tif, addrs[i]) && tif.print(&proto, nm.c_str()) )
      e->put("prototype", proto);
    arr->values.push_back().set_obj(e);
  }
  result->put("format", "json");
  result->get_value_or_new("functions")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::search_text(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring pattern = args != nullptr ? jstr(*args, "pattern") : qstring();
  if ( !is_open || pattern.empty() )
  {
    result->put("error", !is_open ? "no database is open" : "pattern is required");
    out->set_obj(result);
    return;
  }
  const bool cs = args != nullptr ? jbool(*args, "case_sensitive", false) : false;
  const bool code_only = args != nullptr ? jbool(*args, "code_only", true) : true;
  int64 limit = args != nullptr ? jint(*args, "limit", 30) : 30;
  if ( limit > 500 )
    limit = 500;
  qstring s_start = args != nullptr ? jstr(*args, "start") : qstring();
  qstring s_end = args != nullptr ? jstr(*args, "end") : qstring();
  ea_t lo = s_start.empty() ? inf_get_min_ea() : resolve_ea(s_start.c_str());
  ea_t hi = s_end.empty() ? inf_get_max_ea() : resolve_ea(s_end.c_str());
  if ( lo == BADADDR )
    lo = inf_get_min_ea();
  if ( hi == BADADDR )
    hi = inf_get_max_ea();

  qstring needle = pattern;
  if ( !cs )
    lower_in_place(&needle);

  jarr_t *arr = new jarr_t;
  int64 hits = 0;
  int64 scanned = 0;
  for ( ea_t p = lo; p < hi && p != BADADDR && hits < limit; p = next_head(p, hi) )
  {
    if ( code_only && !is_code(get_flags(p)) )
      continue;
    ++scanned;
    qstring line;
    if ( !generate_disasm_line(&line, p, GENDSM_REMOVE_TAGS) )
      continue;
    qstring hay = line;
    if ( !cs )
      lower_in_place(&hay);
    if ( strstr(hay.c_str(), needle.c_str()) == nullptr )
      continue;
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(p));
    e->put("line", line);
    qstring fn;
    func_t *pfn = get_func(p);
    if ( pfn != nullptr && get_func_name(&fn, pfn->start_ea) > 0 )
      e->put("function", fn);
    arr->values.push_back().set_obj(e);
    ++hits;
  }
  result->put("pattern", pattern);
  result->put("hits", hits);
  result->put("items_scanned", scanned);
  result->put("truncated", hits >= limit);
  result->get_value_or_new("results")->set_arr(arr);
  out->set_obj(result);
}

// hexport had no way to enumerate strings at all -- get_string reads one address. The string list is
// built on demand because build_strlist() walks the whole image.
void McpCommands::list_strings(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  qstring filter = args != nullptr ? jstr(*args, "filter") : qstring();
  const bool cs = args != nullptr ? jbool(*args, "case_sensitive", false) : false;
  int64 offset = args != nullptr ? jint(*args, "offset", 0) : 0;
  int64 limit = args != nullptr ? jint(*args, "limit", 100) : 100;
  int64 min_len = args != nullptr ? jint(*args, "min_length", 0) : 0;

  mute_stdout();
  build_strlist();
  unmute_stdout();

  if ( !cs )
    lower_in_place(&filter);

  jarr_t *arr = new jarr_t;
  size_t total = get_strlist_qty();
  int64 matched = 0;
  int64 emitted = 0;
  for ( size_t i = 0; i < total && (limit <= 0 || emitted < limit); ++i )
  {
    string_info_t si;
    if ( !get_strlist_item(&si, i) )
      continue;
    if ( si.length < min_len )
      continue;
    qstring text;
    if ( get_strlit_contents(&text, si.ea, size_t(-1), int32(-1)) < 0 )
      continue;
    if ( !filter.empty() )
    {
      qstring hay = text;
      if ( !cs )
        lower_in_place(&hay);
      if ( strstr(hay.c_str(), filter.c_str()) == nullptr )
        continue;
    }
    if ( matched++ < offset )
      continue;
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(si.ea));
    e->put("length", int64(si.length));
    e->put("text", text);
    arr->values.push_back().set_obj(e);
    ++emitted;
  }
  result->put("total_strings", int64(total));
  result->put("matched", matched);
  result->get_value_or_new("strings")->set_arr(arr);
  out->set_obj(result);
}

// ---- integers ---------------------------------------------------------------------------------
//
// "i32", "u8", "i16be" and so on. Endianness matters here: a big-endian field inside a little-endian
// image is common in network and file-format code, and reading it the wrong way round produces a
// number that looks plausible and is wrong.
static bool parse_int_class(const qstring &ty, int *size, bool *is_signed, bool *big_endian)
{
  if ( ty.length() < 2 )
    return false;
  const char *s = ty.c_str();
  if ( *s != 'i' && *s != 'u' )
    return false;
  *is_signed = (*s == 'i');
  ++s;
  int bits = 0;
  while ( *s >= '0' && *s <= '9' )
    bits = bits * 10 + (*s++ - '0');
  if ( bits != 8 && bits != 16 && bits != 32 && bits != 64 )
    return false;
  *size = bits / 8;
  *big_endian = qstrcmp(s, "be") == 0;
  if ( *s != 0 && qstrcmp(s, "be") != 0 && qstrcmp(s, "le") != 0 )
    return false;
  return true;
}

static uint64 swap_bytes(uint64 v, int size)
{
  uint64 r = 0;
  for ( int i = 0; i < size; ++i )
    r = (r << 8) | ((v >> (8 * i)) & 0xFF);
  return r;
}

static int64 sign_extend(uint64 v, int size)
{
  const int shift = 64 - 8 * size;
  return int64(v << shift) >> shift;
}

void McpCommands::get_int(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  qvector<const jobj_t *> items;
  collect_items(args, "queries", &items);
  for ( size_t i = 0; i < items.size(); ++i )
  {
    const jobj_t &q = *items[i];
    jobj_t *e = new jobj_t;
    ea_t ea = resolve_ea(jstr(q, "addr").c_str());
    qstring ty = jstr(q, "ty", "u32");
    e->put("addr", jstr(q, "addr"));
    e->put("ty", ty);
    int size = 0;
    bool sgn = false, be = false;
    if ( !is_open || ea == BADADDR || !parse_int_class(ty, &size, &sgn, &be) )
    {
      e->put("error", !is_open ? "no database is open"
                    : ea == BADADDR ? "bad address"
                                    : "ty must look like i8/u16/i32be/u64le");
      outer->values.push_back().set_obj(e);
      continue;
    }
    uint64 raw = 0;
    if ( ::get_bytes(&raw, size_t(size), ea) != ssize_t(size) )
    {
      e->put("error", "unreadable at this address");
      outer->values.push_back().set_obj(e);
      continue;
    }
    if ( be )
      raw = swap_bytes(raw, size);
    qstring hv;
    hv.sprnt("0x%" FMT_64 "x", raw);
    e->put("hex", hv);
    e->put("value", sgn ? sign_extend(raw, size) : int64(raw));
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

void McpCommands::put_int(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  qvector<const jobj_t *> items;
  collect_items(args, "items", &items);
  for ( size_t i = 0; i < items.size(); ++i )
  {
    const jobj_t &q = *items[i];
    jobj_t *e = new jobj_t;
    ea_t ea = resolve_ea(jstr(q, "addr").c_str());
    qstring ty = jstr(q, "ty", "u32");
    e->put("addr", jstr(q, "addr"));
    e->put("ty", ty);
    int size = 0;
    bool sgn = false, be = false;
    if ( !is_open || ea == BADADDR || !parse_int_class(ty, &size, &sgn, &be) )
    {
      e->put("error", !is_open ? "no database is open"
                    : ea == BADADDR ? "bad address"
                                    : "ty must look like i8/u16/i32be/u64le");
      outer->values.push_back().set_obj(e);
      continue;
    }
    // Values arrive as strings so a negative or a 0x form survives whatever JSON the client speaks.
    qstring vs = jstr(q, "value", "0");
    uint64 v = vs.length() > 0 && vs[0] == '-'
             ? uint64(strtoll(vs.c_str(), nullptr, 0))
             : strtoull(vs.c_str(), nullptr, 0);
    if ( be )
      v = swap_bytes(v, size);
    mute_stdout();
    put_bytes(ea, &v, size_t(size));         // returns void; failure shows up as unchanged bytes
    uint64 back = 0;
    bool ok = ::get_bytes(&back, size_t(size), ea) == ssize_t(size) && back == v;
    unmute_stdout();
    e->put("status", ok ? "ok" : "failed");
    e->put("wrote_bytes", int64(size));
    // The database is edited in memory only. Nothing here reaches the .i64 without save_as or an
    // explicit close_database(save=true).
    e->put("saved", false);
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

void McpCommands::int_convert(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  qvector<const jobj_t *> items;
  collect_items(args, "inputs", &items);
  for ( size_t i = 0; i < items.size(); ++i )
  {
    const jobj_t &q = *items[i];
    jobj_t *e = new jobj_t;
    qstring text = jstr(q, "text");
    int64 size = jint(q, "size", 0);
    e->put("input", text);
    if ( text.empty() )
    {
      e->put("error", "text is required");
      outer->values.push_back().set_obj(e);
      continue;
    }
    bool neg = text[0] == '-';
    uint64 v = neg ? uint64(strtoll(text.c_str(), nullptr, 0))
                   : strtoull(text.c_str(), nullptr, 0);
    if ( size <= 0 )
      size = v > 0xFFFFFFFFull ? 8 : v > 0xFFFF ? 4 : v > 0xFF ? 2 : 1;
    if ( size > 8 )
      size = 8;
    uint64 masked = size >= 8 ? v : (v & ((1ull << (8 * size)) - 1));

    qstring hex;
    hex.sprnt("0x%" FMT_64 "x", masked);
    e->put("hex", hex);
    e->put("decimal", int64(masked));
    e->put("signed", sign_extend(masked, int(size)));
    e->put("size", size);

    qstring bin;
    for ( int b = int(8 * size) - 1; b >= 0; --b )
    {
      bin.append(((masked >> b) & 1) ? '1' : '0');
      if ( b != 0 && (b % 8) == 0 )
        bin.append('_');
    }
    e->put("binary", bin);

    // Bytes as they would sit in memory, plus the printable form: the usual reason for converting a
    // constant is finding out it is four ASCII characters.
    qstring ascii;
    for ( int k = 0; k < int(size); ++k )
    {
      char c = char((masked >> (8 * k)) & 0xFF);
      ascii.append(c >= 0x20 && c < 0x7F ? c : '.');
    }
    e->put("ascii_le", ascii);
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

void McpCommands::get_global_value(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  qvector<qstring> names;
  const jarr_t *qa = args != nullptr ? jsubarr(*args, "queries") : nullptr;
  if ( qa != nullptr )
  {
    for ( size_t i = 0; i < qa->values.size(); ++i )
      if ( qa->values[i].type() == JT_STR )
        names.push_back(qa->values[i].qstr());
  }
  else
  {
    qstring one = args != nullptr ? jstr(*args, "queries") : qstring();
    if ( !one.empty() )
      names.push_back(one);
  }

  for ( size_t i = 0; i < names.size(); ++i )
  {
    jobj_t *e = new jobj_t;
    e->put("query", names[i]);
    ea_t ea = resolve_ea(names[i].c_str());
    if ( !is_open || ea == BADADDR )
    {
      e->put("error", !is_open ? "no database is open" : "no such address or name");
      outer->values.push_back().set_obj(e);
      continue;
    }
    e->put("addr", hexstr(ea));
    qstring nm;
    if ( get_name(&nm, ea) > 0 )
      e->put("name", nm);

    // Size comes from the applied type when there is one; otherwise from how the item is defined.
    // Reading eight bytes off a defined dword would report neighbouring data as part of the value.
    tinfo_t tif;
    asize_t sz = 0;
    if ( get_tinfo(&tif, ea) )
    {
      qstring ts;
      tif.print(&ts);
      e->put("type", ts);
      sz = asize_t(tif.get_size());
    }
    if ( sz == 0 || sz == asize_t(BADSIZE) )
      sz = get_item_size(ea);
    e->put("size", int64(sz));

    if ( is_strlit(get_flags(ea)) )
    {
      qstring s;
      if ( get_strlit_contents(&s, ea, size_t(-1), int32(-1)) >= 0 )
        e->put("string", s);
    }
    else if ( sz >= 1 && sz <= 8 )
    {
      uint64 raw = 0;
      if ( ::get_bytes(&raw, size_t(sz), ea) == ssize_t(sz) )
      {
        qstring hv;
        hv.sprnt("0x%" FMT_64 "x", raw);
        e->put("hex", hv);
        e->put("value", int64(raw));
      }
      else
      {
        e->put("error", "unreadable");
      }
    }
    else
    {
      e->put("note", "too large to read inline; use get_bytes");
    }
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

void McpCommands::add_bookmark(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  qstring name = args != nullptr ? jstr(*args, "name") : qstring();
  if ( !is_open || ea == BADADDR || name.empty() )
  {
    result->put("error", !is_open ? "no database is open"
                       : ea == BADADDR ? "bad address" : "name is required");
    out->set_obj(result);
    return;
  }
  qstring prefix = args != nullptr ? jstr(*args, "prefix", "hexport: ") : qstring("hexport: ");
  qstring title = prefix + name;

  lochist_entry_t le;
  le.set_place(idaplace_t(ea, 0));
  le.renderer_info().pos.cx = 0;
  le.renderer_info().pos.cy = 0;
  mute_stdout();
  uint32 slot = bookmarks_t::mark(le, uint32(-1), title.c_str(), nullptr, nullptr);
  unmute_stdout();

  result->put("status", slot != uint32(-1) ? "ok" : "failed");
  result->put("slot", int64(int32(slot)));
  result->put("title", title);
  put_hex(result, "addr", ea);
  out->set_obj(result);
}

void McpCommands::append_comments(const jobj_t *args, jvalue_t *out)
{
  jarr_t *outer = new jarr_t;
  qvector<const jobj_t *> items;
  collect_items(args, "items", &items);
  for ( size_t i = 0; i < items.size(); ++i )
  {
    const jobj_t &q = *items[i];
    jobj_t *e = new jobj_t;
    ea_t ea = resolve_ea(jstr(q, "addr").c_str());
    qstring text = jstr(q, "comment");
    e->put("addr", jstr(q, "addr"));
    if ( !is_open || ea == BADADDR || text.empty() )
    {
      e->put("error", !is_open ? "no database is open"
                    : ea == BADADDR ? "bad address" : "comment is required");
      outer->values.push_back().set_obj(e);
      continue;
    }
    // "auto" means a function comment when the address starts one, a line comment otherwise, which
    // is what a caller annotating a function actually wants.
    qstring scope = jstr(q, "scope", "auto");
    func_t *pfn = get_func(ea);
    bool as_func = scope == "func" || (scope == "auto" && pfn != nullptr && pfn->start_ea == ea);

    qstring existing;
    if ( as_func )
      get_func_cmt_ea(&existing, ea, false);
    else
      get_cmt(&existing, ea, false);
    if ( jbool(q, "dedupe", true) && !existing.empty()
      && strstr(existing.c_str(), text.c_str()) != nullptr )
    {
      e->put("status", "skipped");
      e->put("reason", "identical text is already there");
      outer->values.push_back().set_obj(e);
      continue;
    }
    qstring merged = existing;
    if ( !merged.empty() )
      merged.append('\n');
    merged.append(text);

    mute_stdout();
    bool ok = as_func ? set_func_cmt_ea(ea, merged.c_str(), false)
                      : set_cmt(ea, merged.c_str(), false);
    unmute_stdout();
    e->put("status", ok ? "ok" : "failed");
    e->put("scope", as_func ? "func" : "line");
    outer->values.push_back().set_obj(e);
  }
  out->set_arr(outer);
}

// ---- the gaps ---------------------------------------------------------------------------------
//
// Third porting pass, and deliberately not more wrappers. Each of these answers a question hexport
// previously could not answer at all:
//
//   segments      what is in this image, and where
//   exports       what it offers outward (imports existed; its mirror did not)
//   xrefs_from    what an address reaches (xrefs_to existed; its mirror did not)
//   insn_query    where a given instruction occurs across the image
//   search_structs which type has a member by this name
//   stack_xrefs   what touches a stack slot
//
// The composite tools in ida-pro-mcp's set (survey_binary, analyze_component, trace_data_flow) stay
// unported: they are these primitives glued together, and a caller gluing them chooses its own
// limits instead of inheriting someone else's.

void McpCommands::segments(const jobj_t *, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  jarr_t *arr = new jarr_t;
  int n = get_segm_qty();
  for ( int i = 0; i < n; ++i )
  {
    segment_t *s = getnseg(i);
    if ( s == nullptr )
      continue;
    jobj_t *e = new jobj_t;
    qstring nm;
    get_segm_name(&nm, s);
    e->put("name", nm);
    qstring cls;
    get_segm_class(&cls, s);
    e->put("class", cls);
    e->put("start", hexstr(s->start_ea));
    e->put("end", hexstr(s->end_ea));
    e->put("size", int64(s->end_ea - s->start_ea));
    // Permissions as letters rather than a number: "rwx" is read at a glance, 7 is not.
    qstring perm;
    perm.append((s->perm & SEGPERM_READ) != 0 ? 'r' : '-');
    perm.append((s->perm & SEGPERM_WRITE) != 0 ? 'w' : '-');
    perm.append((s->perm & SEGPERM_EXEC) != 0 ? 'x' : '-');
    e->put("perm", perm);
    e->put("bitness", int64(s->abits()));
    arr->values.push_back().set_obj(e);
  }
  result->put("count", int64(n));
  result->get_value_or_new("segments")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::exports(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  if ( !is_open )
  {
    result->put("error", "no database is open");
    out->set_obj(result);
    return;
  }
  qstring filter = args != nullptr ? jstr(*args, "filter") : qstring();
  int64 limit = args != nullptr ? jint(*args, "limit", 500) : 500;
  int64 offset = args != nullptr ? jint(*args, "offset", 0) : 0;

  jarr_t *arr = new jarr_t;
  size_t total = get_entry_qty();
  int64 matched = 0;
  int64 emitted = 0;
  for ( size_t i = 0; i < total && (limit <= 0 || emitted < limit); ++i )
  {
    uval_t ord = get_entry_ordinal(i);
    ea_t ea = get_entry(ord);
    if ( ea == BADADDR )
      continue;
    qstring nm;
    get_entry_name(&nm, ord);
    if ( !filter.empty() && strstr(nm.c_str(), filter.c_str()) == nullptr )
      continue;
    if ( matched++ < offset )
      continue;
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(ea));
    e->put("name", nm);
    // The ordinal is only meaningful when it is not just the address again, which is how IDA
    // records an entry point that has no ordinal of its own.
    if ( uint64(ord) != uint64(ea) )
      e->put("ordinal", int64(ord));
    e->put("is_function", get_func(ea) != nullptr);
    arr->values.push_back().set_obj(e);
    ++emitted;
  }
  result->put("total", int64(total));
  result->put("matched", matched);
  result->get_value_or_new("exports")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::xrefs_from(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t ea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  if ( !is_open || ea == BADADDR )
  {
    result->put("error", !is_open ? "no database is open" : "bad address");
    out->set_obj(result);
    return;
  }
  int64 limit = args != nullptr ? jint(*args, "limit", 200) : 200;
  jarr_t *arr = new jarr_t;
  xrefblk_t xb;
  int64 n = 0;
  for ( bool ok = xb.first_from(ea, XREF_ALL); ok && n < limit; ok = xb.next_from(), ++n )
  {
    jobj_t *e = new jobj_t;
    e->put("to", hexstr(xb.to));
    e->put("code", xb.iscode != 0);
    e->put("type", int64(xb.type));
    qstring nm;
    if ( get_name(&nm, xb.to) > 0 )
      e->put("name", nm);
    func_t *pfn = get_func(xb.to);
    if ( pfn != nullptr && pfn->start_ea == xb.to )
      e->put("is_function", true);
    arr->values.push_back().set_obj(e);
  }
  result->put("addr", hexstr(ea));
  result->put("count", n);
  result->get_value_or_new("xrefs")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::insn_query(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring mnem = args != nullptr ? jstr(*args, "mnem") : qstring();
  if ( !is_open || mnem.empty() )
  {
    result->put("error", !is_open ? "no database is open" : "mnem is required (e.g. \"wrmsr\")");
    out->set_obj(result);
    return;
  }
  // Mnemonics are matched case-insensitively and exactly. A substring match would make "mov" also
  // report "movzx" and "movsd", which is never what someone hunting a specific instruction wants.
  lower_in_place(&mnem);
  qstring operand = args != nullptr ? jstr(*args, "operand") : qstring();
  lower_in_place(&operand);
  int64 limit = args != nullptr ? jint(*args, "limit", 200) : 200;
  qstring s_start = args != nullptr ? jstr(*args, "start") : qstring();
  qstring s_end = args != nullptr ? jstr(*args, "end") : qstring();
  ea_t lo = s_start.empty() ? inf_get_min_ea() : resolve_ea(s_start.c_str());
  ea_t hi = s_end.empty() ? inf_get_max_ea() : resolve_ea(s_end.c_str());
  if ( lo == BADADDR )
    lo = inf_get_min_ea();
  if ( hi == BADADDR )
    hi = inf_get_max_ea();

  jarr_t *arr = new jarr_t;
  int64 hits = 0;
  int64 scanned = 0;
  for ( ea_t p = lo; p < hi && p != BADADDR && hits < limit; p = next_head(p, hi) )
  {
    if ( !is_code(get_flags(p)) )
      continue;
    ++scanned;
    qstring m;
    if ( !print_insn_mnem(&m, p) )
      continue;
    lower_in_place(&m);
    if ( m != mnem )
      continue;
    qstring line;
    generate_disasm_line(&line, p, GENDSM_REMOVE_TAGS);
    if ( !operand.empty() )
    {
      qstring hay = line;
      lower_in_place(&hay);
      if ( strstr(hay.c_str(), operand.c_str()) == nullptr )
        continue;
    }
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(p));
    e->put("line", line);
    func_t *pfn = get_func(p);
    if ( pfn != nullptr )
    {
      qstring fn;
      if ( get_func_name(&fn, pfn->start_ea) > 0 )
        e->put("function", fn);
    }
    arr->values.push_back().set_obj(e);
    ++hits;
  }
  result->put("mnem", mnem);
  result->put("hits", hits);
  result->put("instructions_scanned", scanned);
  result->put("truncated", hits >= limit);
  result->get_value_or_new("results")->set_arr(arr);
  out->set_obj(result);
}

void McpCommands::search_structs(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  qstring member = args != nullptr ? jstr(*args, "member") : qstring();
  if ( !is_open || member.empty() )
  {
    result->put("error", !is_open ? "no database is open"
                                  : "member is required (the field name to look for)");
    out->set_obj(result);
    return;
  }
  // type_query filters on the TYPE's name. This filters on member names, which is the question you
  // have when a field turns up in pseudocode and you do not know which struct it belongs to.
  int64 limit = args != nullptr ? jint(*args, "limit", 100) : 100;
  const bool exact = args != nullptr ? jbool(*args, "exact", false) : false;

  jarr_t *arr = new jarr_t;
  const til_t *til = get_idati();
  uint32 ord_limit = get_ordinal_limit(til);
  int64 hits = 0;
  int64 types_scanned = 0;
  for ( uint32 ord = 1; ord < ord_limit && hits < limit; ++ord )
  {
    const char *tn = get_numbered_type_name(til, ord);
    if ( tn == nullptr )
      continue;
    tinfo_t tif;
    if ( !tif.get_numbered_type(til, ord) || !tif.is_udt() )
      continue;
    ++types_scanned;
    udt_type_data_t udt;
    if ( !tif.get_udt_details(&udt) )
      continue;
    for ( size_t k = 0; k < udt.size() && hits < limit; ++k )
    {
      const udm_t &m = udt[k];
      bool match = exact ? (m.name == member)
                         : strstr(m.name.c_str(), member.c_str()) != nullptr;
      if ( !match )
        continue;
      jobj_t *e = new jobj_t;
      e->put("type", tn);
      e->put("member", m.name);
      e->put("offset", int64(m.offset / 8));
      e->put("size", int64(m.size / 8));
      qstring ts;
      m.type.print(&ts);
      e->put("member_type", ts);
      arr->values.push_back().set_obj(e);
      ++hits;
    }
  }
  result->put("member", member);
  result->put("hits", hits);
  result->put("types_scanned", types_scanned);
  result->put("truncated", hits >= limit);
  result->get_value_or_new("results")->set_arr(arr);
  out->set_obj(result);
}

// ida-pro-mcp's xrefs_to_field covers struct fields generally. IDA 9 moved structures into tinfo_t
// and there is no exported equivalent for a global struct member, so that stays unported -- but the
// STACK frame case does have one, build_stkvar_xrefs_ea, and it is the case that actually comes up:
// "what touches this local?". Named for what it really does rather than borrowing a name for a
// wider promise it cannot keep.
void McpCommands::stack_xrefs(const jobj_t *args, jvalue_t *out)
{
  jobj_t *result = new jobj_t;
  ea_t fea = resolve_ea(args != nullptr ? jstr(*args, "addr").c_str() : "");
  func_t *pfn = fea != BADADDR ? get_func(fea) : nullptr;
  qstring name = args != nullptr ? jstr(*args, "name") : qstring();
  tinfo_t frame;
  if ( !is_open || pfn == nullptr || name.empty() || !get_func_frame_ea(&frame, pfn->start_ea) )
  {
    result->put("error", !is_open ? "no database is open"
                       : pfn == nullptr ? "no function at address"
                       : name.empty() ? "name is required (the stack variable)"
                                      : "this function has no frame");
    out->set_obj(result);
    return;
  }
  udt_type_data_t udt;
  uint64 lo = 0, hi = 0;
  bool found = false;
  if ( frame.get_udt_details(&udt) )
  {
    for ( size_t k = 0; k < udt.size(); ++k )
    {
      if ( udt[k].name == name )
      {
        lo = udt[k].offset / 8;
        hi = lo + (udt[k].size / 8);
        found = true;
        break;
      }
    }
  }
  if ( !found )
  {
    result->put("error", "no stack variable with that name");
    out->set_obj(result);
    return;
  }

  xreflist_t xl;
  build_stkvar_xrefs_ea(&xl, pfn->start_ea, uval_t(lo), uval_t(hi > lo ? hi : lo + 1));

  jarr_t *arr = new jarr_t;
  for ( size_t i = 0; i < xl.size(); ++i )
  {
    jobj_t *e = new jobj_t;
    e->put("addr", hexstr(xl[i].ea));
    e->put("operand", int64(xl[i].opnum));
    e->put("type", int64(xl[i].type));
    qstring line;
    if ( generate_disasm_line(&line, xl[i].ea, GENDSM_REMOVE_TAGS) )
      e->put("line", line);
    arr->values.push_back().set_obj(e);
  }
  result->put("name", name);
  result->put("offset", int64(lo));
  result->put("count", int64(xl.size()));
  result->get_value_or_new("xrefs")->set_arr(arr);
  out->set_obj(result);
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
  int merr = 0;
  ea_t errea = BADADDR;
  qstring code = pseudocode(fea, &err, &merr, &errea);
  if ( !err.empty() )
  {
    // The message alone is not enough to act on. merror_code says WHAT failed and error_addr says
    // WHERE, which is what makes an automated repair pass possible: "call analysis failed" plus the
    // address of the call it choked on points straight at the callee whose prototype is missing.
    result->put("error", err);
    result->put("merror_code", int64(merr));
    if ( errea != BADADDR )
    {
      result->put("error_addr", hexstr(errea));
    }
  }
  else
  {
    result->put("code", code);
  }
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
    item->put("addr", hexstr(pfn->start_ea));
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
      int merr = 0;
      ea_t errea = BADADDR;
      qstring code = pseudocode(pfn->start_ea, &err, &merr, &errea);
      if ( !err.empty() )
      {
        // Same structured reason the single decompile tool reports. A bulk export needs it more,
        // not less: it is the difference between "38 functions failed" and "38 functions hit
        // MERR_BADCALL at these call sites", which is the only form a caller can act on.
        analysis->get_value_or_new("decompile")->set_null();
        analysis->put("decompile_error", err);
        analysis->put("decompile_merror", int64(merr));
        if ( errea != BADADDR )
        {
          analysis->put("decompile_error_addr", hexstr(errea));
        }
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
      fn->put("addr", hexstr(pfn->start_ea));
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
