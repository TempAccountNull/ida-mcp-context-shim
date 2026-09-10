// McpCommands - the IDA-side tools + database lifecycle. Every method assumes it runs
// on the idalib thread (idalib is single-threaded; the transport guarantees this).
#pragma once
#include "pch.h"

class McpCommands
{
public:
  // --- database lifecycle (also exposed as MCP tools) ---
  bool open(const char *file_path, bool run_auto);   // used by --open and open_database
  void close(bool save = false);
  bool opened() const { return is_open; }

  qstring module_name() const;     // normalized "name.ext" (strips " - Copy" etc.)

  // --- tools: build structured result into `out` (Mcp wraps as {"result": out}) ---
  void open_database(const jobj_t *args, jvalue_t *out);
  void close_database(const jobj_t *args, jvalue_t *out);
  void list_databases(jvalue_t *out);
  void server_health(jvalue_t *out);
  void entity_query(const jvalue_t *queries, jvalue_t *out);
  void list_funcs(const jvalue_t *queries, jvalue_t *out);
  void disasm(const jobj_t *args, jvalue_t *out);
  void decompile(const jobj_t *args, jvalue_t *out);
  void analyze_batch(const jvalue_t *queries, jvalue_t *out);
  void lookup_funcs(const jvalue_t *queries, jvalue_t *out);
  void force_recompile(const jobj_t *args, jvalue_t *out);
  void set_type(const jobj_t *args, jvalue_t *out);
  void redefine_func(const jobj_t *args, jvalue_t *out);
  void infer_types(const jobj_t *args, jvalue_t *out);
  void get_bytes(const jobj_t *args, jvalue_t *out);
  void patch_bytes(const jobj_t *args, jvalue_t *out);
  void undefine(const jobj_t *args, jvalue_t *out);
  void define_func(const jobj_t *args, jvalue_t *out);
  void rename(const jobj_t *args, jvalue_t *out);
  void set_comments(const jobj_t *args, jvalue_t *out);
  void get_string(const jobj_t *args, jvalue_t *out);
  void xrefs_to(const jobj_t *args, jvalue_t *out);
  void callees(const jobj_t *args, jvalue_t *out);
  void define_code(const jobj_t *args, jvalue_t *out);
  void make_data(const jobj_t *args, jvalue_t *out);
  void list_globals(const jobj_t *args, jvalue_t *out);
  void find_bytes(const jobj_t *args, jvalue_t *out);
  void basic_blocks(const jobj_t *args, jvalue_t *out);
  void stack_frame(const jobj_t *args, jvalue_t *out);
  void set_op_type(const jobj_t *args, jvalue_t *out);
  void imports(const jobj_t *args, jvalue_t *out);
  void type_apply_batch(const jobj_t *args, jvalue_t *out);
  void repair_badcall(const jobj_t *args, jvalue_t *out);
  void microcode(const jobj_t *args, jvalue_t *out);
  void make_sigs(const jobj_t *args, jvalue_t *out);
  void save_as(const jobj_t *args, jvalue_t *out);
  void revert_decisions(const jobj_t *args, jvalue_t *out);
  void declare_type(const jobj_t *args, jvalue_t *out);
  void type_inspect(const jobj_t *args, jvalue_t *out);
  void type_query(const jobj_t *args, jvalue_t *out);
  void enum_upsert(const jobj_t *args, jvalue_t *out);
  void read_struct(const jobj_t *args, jvalue_t *out);
  void declare_stack(const jobj_t *args, jvalue_t *out);
  void delete_stack(const jobj_t *args, jvalue_t *out);
  void callgraph(const jobj_t *args, jvalue_t *out);
  void func_profile(const jobj_t *args, jvalue_t *out);
  void export_funcs(const jobj_t *args, jvalue_t *out);
  void search_text(const jobj_t *args, jvalue_t *out);
  void list_strings(const jobj_t *args, jvalue_t *out);
  void get_int(const jobj_t *args, jvalue_t *out);
  void put_int(const jobj_t *args, jvalue_t *out);
  void int_convert(const jobj_t *args, jvalue_t *out);
  void get_global_value(const jobj_t *args, jvalue_t *out);
  void add_bookmark(const jobj_t *args, jvalue_t *out);
  void append_comments(const jobj_t *args, jvalue_t *out);

private:
  bool badcall_at(ea_t fea, ea_t *errea);
  bool decompiles_now(ea_t fea);
  void badcall_candidates(ea_t fea, ea_t errea, qvector<ea_t> *direct,
                          qvector<ea_t> *indirect);
public:

private:
  bool is_open = false;
  bool hexrays_ok = false;
  mutable qstring cached_module;   // see module_name(); resolved once, cleared on close
  uint64 processed = 0;            // functions handled so far (for the live status line)
  uint64 t_start_100ns = 0;        // KUSER InterruptTime at open, for the live elapsed/rate readout

  void status(const char *op, ea_t ea, const char *name);
  // as_text=false -> structured {addr,instruction,label,comments} lines (disasm tool);
  // as_text=true  -> flat "<hexaddr>  <disasm>" strings, matching ida-pro-mcp's
  // analyze_batch (the exporter joins these with "\n" directly).
  int64 build_disasm(ea_t addr, int64 max_instructions, int64 offset, jarr_t *lines, bool *more, bool as_text);
  qstring pseudocode(ea_t func_ea, qstring *err, int *code = nullptr, ea_t *errea = nullptr);
};
