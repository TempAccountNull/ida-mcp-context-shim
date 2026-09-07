// McpCommands - the IDA-side tools. Every method assumes it runs on the idalib thread
// (idalib is single-threaded; the transport guarantees this).
#pragma once
#include "pch.h"

class McpCommands
{
public:
  // Normalized input file name for output naming: basename with " - Copy"/" (N)"
  // decorations stripped -> "name.ext" (e.g. "hexx64 - Copy.dll" -> "hexx64.dll").
  qstring module_name() const;

  // Tool bodies build their structured result into `out` (Mcp wraps it as
  // {"result": out} in structuredContent, matching what the exporter parses).
  void server_health(jvalue_t *out) const;
  void list_funcs(const jvalue_t *queries, jvalue_t *out) const;
};
