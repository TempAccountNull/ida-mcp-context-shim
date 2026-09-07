// McpCommands - the IDA-side tools + database lifecycle. Every method assumes it runs
// on the idalib thread (idalib is single-threaded; the transport guarantees this).
#pragma once
#include "pch.h"

class McpCommands
{
public:
  // --- database lifecycle (also exposed as MCP tools) ---
  bool open(const char *file_path, bool run_auto);   // used by --open and open_database
  void close();
  bool opened() const { return is_open; }

  qstring module_name() const;     // normalized "name.ext" (strips " - Copy" etc.)

  // --- tools: build structured result into `out` (Mcp wraps as {"result": out}) ---
  void open_database(const jobj_t *args, jvalue_t *out);
  void close_database(jvalue_t *out);
  void list_databases(jvalue_t *out);
  void server_health(jvalue_t *out);
  void entity_query(const jvalue_t *queries, jvalue_t *out);
  void list_funcs(const jvalue_t *queries, jvalue_t *out);
  void disasm(const jobj_t *args, jvalue_t *out);
  void decompile(const jobj_t *args, jvalue_t *out);
  void analyze_batch(const jvalue_t *queries, jvalue_t *out);
  void lookup_funcs(const jvalue_t *queries, jvalue_t *out);
  void force_recompile(const jobj_t *args, jvalue_t *out);

private:
  bool is_open = false;
  bool hexrays_ok = false;
  uint64 processed = 0;            // functions handled so far (for the live status line)

  void status(const char *op, ea_t ea, const char *name);
  int64 build_disasm(ea_t addr, int64 max_instructions, int64 offset, jarr_t *lines, bool *more);
  qstring pseudocode(ea_t func_ea, qstring *err);
};
