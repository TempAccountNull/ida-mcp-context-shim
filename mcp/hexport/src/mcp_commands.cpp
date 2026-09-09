#include "pch.h"
#include "name_clean.hpp"
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

  return qstring(hexport::clean_module_name(buf).c_str());
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
    qstring s;
    s.sprnt("0x%" FMT_64 "x", uint64(now->end_ea));
    result->put("end", s);
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
    qstring a;
    a.sprnt("0x%" FMT_64 "x", uint64(xb.from));
    e->put("from", a);
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
  // Walk the function's own instructions and take every code reference that leaves it. Cheaper and
  // more precise than scanning all xrefs, and it keeps tail chunks out of the answer.
  jarr_t *arr = new jarr_t;
  for ( ea_t p = pfn->start_ea; p < pfn->end_ea; p = next_head(p, pfn->end_ea) )
  {
    if ( p == BADADDR )
      break;
    for ( ea_t t = get_first_cref_from(p); t != BADADDR; t = get_next_cref_from(p, t) )
    {
      if ( t >= pfn->start_ea && t < pfn->end_ea )
        continue;                              // stays inside: a branch, not a call
      jobj_t *e = new jobj_t;
      qstring a;
      a.sprnt("0x%" FMT_64 "x", uint64(t));
      e->put("addr", a);
      qstring nm;
      if ( get_func_name(&nm, t) > 0 )
        e->put("name", nm);
      arr->values.push_back().set_obj(e);
    }
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
    qstring a;
    a.sprnt("0x%" FMT_64 "x", uint64(ea));
    e->put("addr", a);
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
    qstring a;
    a.sprnt("0x%" FMT_64 "x", uint64(hit));
    e->put("addr", a);
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
    qstring a;
    a.sprnt("0x%" FMT_64 "x", uint64(b.start_ea));
    e->put("start", a);
    a.sprnt("0x%" FMT_64 "x", uint64(b.end_ea));
    e->put("end", a);
    jarr_t *succ = new jarr_t;
    for ( int k = 0; k < fc.nsucc(i); ++k )
    {
      int s = fc.succ(i, k);
      qstring sa;
      sa.sprnt("0x%" FMT_64 "x", uint64(fc.blocks[s].start_ea));
      succ->values.push_back().set_str(sa.c_str());
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
          qstring a;
          a.sprnt("0x%" FMT_64 "x", uint64(ea));
          e->put("addr", a);
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

bool McpCommands::badcall_at(ea_t fea)
{
  qstring err;
  int merr = 0;
  ea_t errea = BADADDR;
  pseudocode(fea, &err, &merr, &errea);
  return !err.empty() && merr == -12;      // MERR_BADCALL
}

bool McpCommands::decompiles_now(ea_t fea)
{
  qstring err;
  mark_cfunc_dirty(fea);                   // drop the cached failure before re-asking
  pseudocode(fea, &err);
  return err.empty();
}

// Everything this function might be blaming: functions it calls, and globals it references (a
// function pointer is reached by a data reference, not a code one).
void McpCommands::badcall_candidates(ea_t fea, qvector<ea_t> *direct, qvector<ea_t> *indirect)
{
  func_t *pfn = get_func(fea);
  if ( pfn == nullptr )
    return;
  for ( ea_t p = pfn->start_ea; p < pfn->end_ea && p != BADADDR; p = next_head(p, pfn->end_ea) )
  {
    for ( ea_t t = get_first_cref_from(p); t != BADADDR; t = get_next_cref_from(p, t) )
    {
      if ( t >= pfn->start_ea && t < pfn->end_ea )
        continue;                          // stays inside: a branch, not a call
      if ( get_func(t) != nullptr && !direct->has(t) )
        direct->push_back(t);
    }
    for ( ea_t t = get_first_dref_from(p); t != BADADDR; t = get_next_dref_from(p, t) )
    {
      if ( get_func(t) != nullptr )
        continue;                          // a function, not a pointer to one
      if ( !indirect->has(t) )
        indirect->push_back(t);
    }
  }
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

  // ---- which functions are failing this way ----------------------------------------------
  qvector<ea_t> failing;
  size_t nfuncs = get_func_qty();
  for ( size_t i = 0; i < nfuncs; ++i )
  {
    func_t *pfn = getn_func(i);
    if ( pfn == nullptr )
      continue;
    status("repair-scan", pfn->start_ea, "");
    if ( badcall_at(pfn->start_ea) )
      failing.push_back(pfn->start_ea);
  }
  result->put("badcall_found", int64(failing.size()));
  if ( failing.empty() || !apply )
  {
    jarr_t *fs = new jarr_t;
    for ( size_t i = 0; i < failing.size(); ++i )
    {
      qstring a;
      a.sprnt("0x%" FMT_64 "x", uint64(failing[i]));
      fs->values.push_back().set_str(a.c_str());
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
    badcall_candidates(fea, &direct, &indirect);

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
            qstring a;
            a.sprnt("0x%" FMT_64 "x", uint64(fea));
            e->put("function", a);
            qstring fn;
            get_func_name(&fn, fea);
            e->put("name", fn);
            a.sprnt("0x%" FMT_64 "x", uint64(cands[c]));
            e->put("culprit", a);
            qstring cn;
            get_name(&cn, cands[c]);
            e->put("culprit_name", cn);
            e->put("kind", phase == 0 ? "indirect call through a global" : "direct call");
            e->put("applied", protos[k]);
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
    qstring a;
    a.sprnt("0x%" FMT_64 "x", uint64(failing[i]));
    e->put("addr", a);
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
      qstring hex;
      hex.sprnt("0x%a", errea);
      result->put("error_addr", hex);
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
          qstring eh;
          eh.sprnt("0x%" FMT_64 "x", uint64(errea));
          analysis->put("decompile_error_addr", eh);
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
