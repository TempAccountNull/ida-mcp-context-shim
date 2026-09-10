# Porting the rest of the ida-pro-mcp tools

hexport went from 37 tools to 55. This records what was ported, what was deliberately not, and why
— because "we skipped it" and "we forgot it" look identical six months later.

Schemas came from the live ida-pro-mcp servers rather than from guesswork, so argument names and
shapes match. The implementation is hexport's own: C++ against the IDA SDK, no Python, no new
dependencies.

## Ported (19)

| tool | notes |
|---|---|
| `declare_type` | `parse_decls` into the local type library. Takes one declaration or a list, because a pasted header has to go in as one unit for cross-references to resolve. |
| `type_inspect` | size, kind, declaration, member layout. Member offsets are reported in **bytes**; `udm_t` stores them in bits. |
| `type_query` | walks ordinals with filter, kind, pagination. |
| `enum_upsert` | creates or extends. Existing members are updated in place, never replaced wholesale — an enum built up over a session would otherwise lose everything worked out so far. |
| `read_struct` | reads memory through a struct layout. With no `struct` given it uses the type already applied at the address. |
| `declare_stack` | `add_frame_member_ea`, falling back to `set_frame_member_type_ea` when the slot already exists. Offsets are strings: locals are routinely negative and clients disagree about negative numbers in JSON. |
| `delete_stack` | deletes by **name**, which is what a caller has, by looking the offset up in the frame first. |
| `callgraph` | breadth-first from the roots, so `max_depth` means what it says and truncation is even across the frontier instead of dropping whole subtrees. Reports `truncated` rather than letting a partial graph read as complete. |
| `func_profile` | size, basic blocks, caller and callee counts, optional prototype and name lists. |
| `export_funcs` | `json`, `c_header`, `prototypes`. |
| `search_text` | scans the rendered listing between bounds. |
| `list_strings` | **not in ida-pro-mcp's set under that name, and a real gap**: hexport could read one string by address and had no way to enumerate them. |
| `get_int` / `put_int` | `i8`…`u64` with explicit `le`/`be`. Endianness matters: a big-endian field in a little-endian image read the wrong way round gives a plausible wrong number. `put_int` reads back what it wrote, because `put_bytes` returns void. |
| `int_convert` | hex, decimal, signed, binary, and the little-endian ASCII — the usual reason to convert a constant is discovering it is four characters. |
| `get_global_value` | size comes from the applied type, falling back to the item size. Reading eight bytes off a defined dword would report neighbouring data as part of the value. |
| `add_bookmark` | `bookmarks_t::mark`. |
| `append_comments` | appends rather than overwrites, deduping exact text. `auto` scope means a function comment at a function start and a line comment elsewhere. |

## Not ported, and why

| tool | reason |
|---|---|
| `patch_asm` | **The SDK exports no assembler.** ida-pro-mcp reaches `ida_idp.assemble` through IDAPython; there is no C++ equivalent to link against, and bringing in an assembler would be a new dependency for one tool. `patch_bytes` covers the byte-level need. |
| `py_eval`, `py_exec_file` | hexport has no Python interpreter, by design. Adding one would import the whole failure mode hexport exists to avoid. |
| `open_file`, `list_instances`, `select_instance` | different process model. hexport is one process per database; `open_database`, `list_databases` and `close_database` already cover it. |
| `idb_save` | saves the database **in place**. That is the hazard this project exists around. `save_as` writes to a new path instead. |
| `survey_binary`, `analyze_component`, `analyze_function`, `trace_data_flow`, `diff_before_after`, `find_xref_signatures` | orchestration over primitives hexport now has. A caller composes them, and gets to choose the limits rather than inherit someone else's. |
| `make_signature`, `make_signature_for_function`, `make_signature_for_range` | `make_sigs` (idalib's `make_signatures`) covers FLIRT generation for the database. Per-function variants need the pattern generator, which is not exported either. |
| `func_query`, `insn_query`, `xref_query`, `imports_query`, `search_structs`, `find`, `find_regex` | query-language wrappers over data already exposed by `list_funcs`, `disasm`, `xrefs_to`, `imports`, `type_query` and `list_strings`. `find_regex` additionally wants a regex engine, and hexport removed its last `std::regex` use on purpose. |
| `xrefs_to_field` | IDA 9 moved structures into `tinfo_t`, and the struct-member xref path that ida-pro-mcp uses does not have a clean equivalent here. Left out rather than shipped half-working. |

## Two bugs the tests caught

**`enum_upsert` reported `member_count: 0` on success.** `create_enum()` takes a non-const reference
and consumes it, so `ed.size()` read zero afterwards. The count is now taken before the call. The
enum was always correct; only the report was wrong, which is the kind of thing that gets believed.

The test now reads the enum back out of the type library rather than trusting the tool's own count:

```
enum_upsert creates an enum                       PASS
enum_upsert is idempotent (updates, not replaces) PASS   added=1 updated=1 member_count=3
the enum really holds the merged members          PASS   {HX_A: 0x1, HX_B: 0x20, HX_C: 0x3}
```

**`read_struct` gave the wrong reason for a missing type.** Naming a type that does not exist
reported "no type applied here", which points at the wrong fix. It now distinguishes the two.

## Measured

`tools/test_ported.py`, on a copy of the 60-function fixture. Every tool is checked for something
specific rather than for the absence of an error — a tool that returns `{}` for every input passes
an error check and is useless.

30 checks, all passing. Source database untouched, working copy unchanged on disk, closed with
`save=false`.

`test_hexport.ps1`: 40 passed, 0 failed.
