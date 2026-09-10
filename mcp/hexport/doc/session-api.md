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

## HTTP mode had no clean exit

Found while chasing an intermittent `http decompile returns full pseudocode` failure in
`test_hexport.ps1` (seen once in three runs). The flake itself did not reproduce -- 12 isolated
Phase-4 runs and 12 full-suite runs, all clean -- but the investigation turned up something worse
and fully deterministic.

`run_http` was `for ( ;; )` with no exit. So `startup_close()` in `main()` was unreachable in HTTP
mode: the only way to stop an `--http` server was to kill it. Killing a process that holds an open
database leaves a packed `.i64` unpacked and inconsistent on disk, which is exactly how this
project's 374 MB database came to give IDA "Fatal error before kernel init".

The shipped test did this on every run. After a loop of the suite, four orphaned files sat beside
the fixture:

```
db.i64  db.id0  db.id1  db.nam  db.til
```

The `.i64` itself was byte-identical, but the next open sees that working set rather than the packed
file. A clean close repacks and removes them -- confirmed in both directions, since a later
clean-closing session tidied up residue an earlier killed run had left.

### The fix, and the wrong first version of it

A console control handler now breaks the accept loop so the normal shutdown path runs.

The first attempt set a stop flag and returned `TRUE` immediately. That was wrong, and the test
caught it: for `CTRL_CLOSE_EVENT` Windows terminates the process as soon as the handler returns --
returning `TRUE` means "handled", not "spare me". The process died mid-close with exit code
`0xC000013A` (`STATUS_CONTROL_C_EXIT`) and still left all four files.

The handler now blocks on an event that the shutdown path signals once the database is really
closed, bounded at 30 seconds so a hung close cannot wedge a logoff. `run_http` calls
`startup_close()` itself and then signals; `close()` returns early when nothing is open, so
`main()` calling it again is a no-op.

| | before | after |
|---|---|---|
| exit code | `0xC000013A` | `0` |
| unpacked files left | 4 | 0 |
| database bytes | unchanged | unchanged |

`tools/test_http_shutdown.ps1` asserts all four of those. It never force-kills anything and runs on
a copy.

### Test changes

- **Close before stopping.** Phase 4's `finally` now calls `close_database` on each instance and
  then stops the process, so the kill lands on a process holding nothing. It also asserts that no
  unpacked files remain, rather than trusting it.
- **Assert `hexrays`.** The health check tested `ready` and `functions` only. `ready` means the
  database is open; decompiling additionally needs the decompiler, so a session where Hex-Rays
  failed to load passed that assertion and then failed at the decompile with no explanation.
- **Say what came back.** The decompile assertion now reports which of the possible causes actually
  happened -- empty HTTP reply, missing `structuredContent`, a server-side error string, or code
  present without the expected symbol. Previously all of them read as "no pseudocode".
- **One stderr file per instance.** Both `http_inst` calls passed the same base port, so both
  redirected stderr to the same path; the second `Start-Process` truncated the file the first was
  still writing to, and the port was then parsed out of whatever survived. Stale files from a
  previous run are removed too, since the port scan could otherwise read a dead run's line.

### Server diagnostic

`open()` set `hexrays_ok = init_hexrays_plugin()` and carried on silently when it failed. It now
warns once on stderr. Without that line a decompiler that never loaded is indistinguishable from a
function that cannot be decompiled: `server_health` still reports `ready` (the database really is
open) and every `decompile` returns "decompiler unavailable" as though it were a per-function fact.

`ready` deliberately still means "database open". A database can legitimately be open with no
decompiler -- an unsupported processor, or no decompiler licence -- so folding `hexrays` into
`ready` would report a working session as broken.

### Not reproduced

The original intermittent failure did not recur in 24 attempts. What is established: if
`hexrays_ok` is false, `decompile` returns `{"error": "decompiler unavailable"}` with no `code`
field, which matches the observed symptom exactly, and the old assertions could not tell that apart
from anything else. A stress test that killed instances at randomised delays to damage the working
set deliberately was written but not run -- force-killing database-holding processes is precisely
what this repo forbids. If the flake returns, the new assertions name the cause on the spot.

### A second flake, found while verifying

Run 3 of a six-run loop failed a different assertion:

```
[FAIL] module 'hexx64 - Copy.dll' -> 'hexx64.dll' (got 'target')
```

`"target"` is `module_name()`'s fallback for `get_root_filename()` returning <= 0, and
`server_health` only calls `module_name()` when `is_open` is true. So the database was open and the
filename lookup failed, which is not the same as a failed open. The cause could not be recovered
after the fact, because Phase 3 was passing `$null` as its stderr file and throwing the server's
own account of the open away.

Phase 3 now keeps stderr and, on failure, reports `ready`, `hexrays`, `functions` and the relevant
stderr lines alongside the module name.

Six direct probes of that same open (`tools/../probe`, Python, stderr kept) came back
`module='hexx64.dll' ready=True hexrays=True funcs=10109` every time, so it is rare rather than
systematic. Cause not established.

Worth noting for whoever picks this up: `module_name()` returning `"target"` when the lookup fails
is a plausible-looking value standing in for an error, which is the same shape as `server_health`
reporting `ready` while the decompiler is missing. Both make an initialisation failure read as
success. It was left alone here because the export path uses `module` for output naming and changing
it is a behaviour change that wants its own measurement.

### Tally

| | attempts | recurrences |
|---|---|---|
| Phase 4 `http decompile`, isolated repro | 12 | 0 |
| Phase 4, via the full suite | 34 | 0 |
| Phase 3 `module`, via the full suite | 34 | 1 |
| Phase 3, direct probe | 6 | 0 |

34 full-suite runs: 12 before the fix, 22 after (20 against copies, 2 against the real fixtures).
The single Phase 3 failure landed in the third of those, before Phase 3 kept its stderr.

The suite is 40 passed / 0 failed against the real fixtures, and the two databases it opens are left
with no orphaned working files.

Unrelated but visible from here: `D:\source\repos\test_research\hexrays\` holds 10 orphaned files
from earlier sessions -- `hexx64.dll.id0/.id1/.id2/.nam/.til` and the same set for `ida.dll`, the
latter 834 MB beside a 1.06 GB `ida.dll.i64`. They predate this fix (Sep 3 and Sep 6) and belong to
databases the test does not open. Left in place; deleting someone's unpacked database is not a
cleanup to do unasked.
