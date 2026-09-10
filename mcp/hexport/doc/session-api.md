# Session-level API: what idalib actually offers

Written after the question "there's gotta be more commands from the idalib we can use to interact
with the session of IDA -- look at the lib". Answer: idalib's own surface is seven functions, and
the useful session control is not in idalib at all. It is in `loader.hpp` and `auto.hpp`.

## idalib.hpp, in full

`src/dep/ida-sdk/src/include/idalib.hpp` declares exactly this:

| function | status |
|---|---|
| `init_library(argc, argv)` | used, `main.cpp` |
| `open_database(path, run_auto, args)` | used, `open_database` tool |
| `close_database(save)` | used, `close_database` tool, defaults to `save=false` |
| `make_signatures(only_pat)` | **added** as the `make_sigs` tool |
| `get_library_version(major, minor, build)` | **added** to `server_health` as `ida_version` |
| `enable_console_messages(enable)` | deliberately not used |
| `set_screen_ea(ea)` | deliberately not used |

`enable_console_messages` is redundant: hexport mutes at the file-descriptor level, which also
catches writes from the kernel's own C runtime that this flag does not reach. Anything weaker would
corrupt the stdio JSON-RPC stream, which is the one thing that must stay clean.

`set_screen_ea` exists so `get_screen_ea` returns something in a process that has no screen. No
hexport code path consults the screen ea, so setting it would only make a later reader think a
cursor position meant something.

That is the whole library. The interesting session control is elsewhere.

## What was worth taking from the rest of the SDK

### `save_database(outfile, flags)` -- `loader.hpp:1004`

The most valuable one, and the reason to go looking past idalib.

`close_database(save)` writes back to the path that was opened, or discards. So a repair had two
endings: throw away eight minutes of work, or overwrite a database somebody cares about.
`save_database` takes an **output path**, so the repaired in-memory database can be written
somewhere new with the input file left byte-identical.

Exposed as `save_as { path, compress }`. It refuses when `path` equals `get_path(PATH_TYPE_IDB)` --
overwriting the current database is what `close_database(save=true)` is for, and silently accepting
that argument here would defeat the point of the tool. It calls `auto_wait()` first, because
analysis queued by a repair is still draining and a snapshot taken mid-drain is written half-done.

`DBFL_COMP` (compress) is offered. `DBFL_BAK` is not: it backs up the *current* path, which is
precisely the file this tool exists to avoid touching.

### `revert_ida_decisions(ea1, ea2)` -- `auto.hpp:210`

The safe form of the undefine/redefine cycle. It discards only what the auto-analyser concluded
about a range and leaves anything set explicitly, where `undefine` + `define_func` destroys user
annotations along with the bad guess.

Exposed as `revert_decisions { addr, end?, wait? }`, paired with `plan_range` and
`auto_wait_range`. With no `end` it takes the enclosing function.

### `gen_microcode(dcr, hf, retlist, flags, reqmat)` -- `hexrays.hpp:8245`

Not session control, but the answer to "why did this fail" rather than "did this fail".

The decompiler runs a function through maturity levels and a failure kills the whole pipeline.
`MERR_BADCALL` happens at `MMAT_CALLS`, whose job is working out call arguments -- so asking for
microcode at the level *before* that succeeds on exactly the functions that will not decompile.

Measured on `hr_ask_form` (`0x1300278b0`), one of the 38, with no repair applied:

| request | result |
|---|---|
| `decompile` | fails, merror -12 at `0x1300278DF` |
| `microcode` at `preoptimized` | **29 lines** |
| `microcode` at `calls` | fails, merror -12 |
| `microcode` at `glbopt3` | fails, merror -12 |

So `preoptimized` is the last level that survives, and the failure is at `calls` exactly as the
error code says. Windowing four instructions either side of the address Hex-Rays named shows the
whole bug:

```
1.14 ldx    ds.2, rax.8, r9.8   ; 1300278DC   load the function pointer out of a global
1.15 icall  cs.2, r9.8          ; 1300278DF   indirect call through it -- clobbers ALLMEM
```

`icall` is an indirect call with no argument list, and the clobber set is ALLMEM because the
decompiler has no idea what it reaches. That is the diagnosis `repair_badcall` produces by trial,
readable directly.

Note the distance: the load is **one instruction** before the call. `BADCALL_BACKWALK` of 24 is
generous for this shape.

Exposed as `microcode { addr, maturity?, around?, context? }`, defaulting to `preoptimized` for
that reason. `around` windows the listing, which otherwise runs to thousands of lines.

## Considered and rejected

| API | why not |
|---|---|
| `set_database_flag(DBFL_KILL)` | deletes the unpacked database on close. One wrong call destroys the session's work with no confirmation step. `save_as` covers the real need. |
| `DBFL_TEMP` | must be set before load; hexport's caller already chooses whether to keep anything. |
| `flush_buffers()` | writes the current database to its own path. Same hazard as saving, none of the benefit. |
| `auto_wait()` as a tool | already implicit where it matters (`open_database`, `save_as`, `revert_decisions`). A standalone version invites blocking a session for minutes with no progress. |
| snapshot args to `save_database` | IDA's snapshot tree is a UI feature; a headless caller wanting versions is better served by separate `save_as` paths. |

## Tool count

33 → 37: `microcode`, `make_sigs`, `save_as`, `revert_decisions`.
`test_hexport.ps1` asserts the count; update it alongside.

## Measured

`tools/test_session.py`, against the 60-function fixture. The claim under test is the safety one,
checked by SHA-256 rather than by trust:

```
save_as refuses the current database path      PASS
save_as reports ok / wrote the new file        PASS   215,850 bytes
source hash unchanged                          PASS   be0d08b819ef2f59
source size unchanged                          PASS
source mtime unchanged                         PASS
revert_decisions ok, function survives replan  PASS
decompiles after revert                        PASS
microcode preoptimized returns text            PASS   34 lines
microcode rejects a bad maturity               PASS
microcode around/context windows the listing   PASS   5 lines
make_sigs runs                                 PASS
source after close                             IDENTICAL
```

`test_hexport.ps1`: 38 passed, 0 failed.

## repair_badcall, after using errea

`hexrays_failure_t::errea` is the address where the decompiler gave up. The first version of the
tool ignored it and swept every callee and global in the function, trying prototypes and
re-decompiling after each. Starting at the address Hex-Rays names instead, and walking back at most
24 instructions to catch the load feeding an indirect call:

| phase | before | after |
|---|---|---|
| sweep, decompiling 10,109 functions to find the 38 | ~292s | 291.7s |
| repair | ~188s | **1.0s** |
| total | 479.5s | 292.8s |

Recovery is unchanged at 38 of 38. The sweep now dominates completely, and the `addrs` argument
exists to skip it: a caller that already knows which functions failed passes them in and pays the
1 second.

The four culprits on hexx64.dll, with the call site Hex-Rays named:

| culprit | prototype applied | kind | failed at |
|---|---|---|---|
| `callui` | `__int64 (__fastcall *f)(int, ...)` | indirect through a global | `0x1300278df` |
| `hr_unregister_debug_provider` | `__int64 __fastcall f(__int64)` | direct | `0x1300fa9dc` |
| `hr_apply_pattern` | `__int64 __fastcall f(__int64)` | direct | `0x1302105ef` |
| `hr_copy_pseudocode_to_listing` | `__int64 __fastcall f(__int64)` | direct | `0x1302b56a8` |

The rename half (`off_...` on a proven function pointer becomes `pfn_...`) did not fire on this
binary: all four culprits already had real names, and inventing a name for something already called
`callui` would be a loss. It is built but unexercised here.
