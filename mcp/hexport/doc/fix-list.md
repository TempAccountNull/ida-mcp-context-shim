# Fix list

What is wrong, what it costs, and what it would take. Ordered by value. Every number here was
measured on `ref/hexx64 - Copy.dll.i64` (374 MB, 10,109 functions) unless stated.

---

## Settled: do NOT rewrite the exporter in C++

Measured before deciding, because the rewrite is expensive and irreversible:

| | time |
|---|---|
| Bare driver -- no discovery, no retries, no file writing, no progress UI | **278.8s** |
| Full Python exporter, same 10,109 functions | **277s** |

The Python pipeline adds **no measurable overhead**. All of the time is Hex-Rays decompiling inside
hexport, at 36.6 functions/sec. A C++ exporter would call the same decompiler and finish at the same
time. Spend the effort on items 1-3 instead.

(An earlier estimate of 110 fn/s was wrong: it extrapolated from the first 40 functions returned by
`list_funcs`, which sit at the start of the binary and are small. Do not size a run from a head
sample.)

---

## Done

### F1. Hex-Rays failures were unactionable -- FIXED
`pseudocode()` reported `hf.str`, which Hex-Rays leaves empty. Every one of the 38 failures came out
as `decompilation failed: ` with nothing after the colon: no way to tell a function that is too big
from one whose stack analysis failed.

Now uses `hf.desc()` and also returns `merror_code` and `error_addr` as structured fields, on both
`decompile` and `analyze_batch`. The 38 failures turn out to be **100% `MERR_BADCALL (-12), could
not determine call arguments`**, at variadic call sites -- `hr_ask_form`, and wrappers around IDA's
variadic `callui`.

### F2. Retries burned on failures that cannot recover -- FIXED
Verified there is nothing to recover: a plain retry fixed **0 of 38**, and `force_recompile` fixed
**0 of 38**. The manifest now records `merror`, `merror_name`, `error_addr` and `permanent`, and
`--retry-skipped` skips permanent codes. A retry pass over hexx64 now exits immediately instead of
paying 38 full decompile attempts to reach the identical failure.

`PERMANENT_MERRORS` deliberately excludes `MERR_MEM` and `MERR_CANCELED` -- those genuinely can
clear on a retry.

---

## Open, in priority order

### F3. Repairing a failed function -- DONE, 34 of 38 recovered
hexport was read-only: eleven tools, all queries. It could name a failure precisely and do nothing
about it. It now has exactly one write, `set_type`, which applies a C declaration at an address --
`parse_decl()` then `apply_tinfo(..., TINFO_DEFINITE)`, the same two steps the reference IDA MCP
servers use. Nothing else about the server changed; a bulk exporter still has no business doing
general database editing.

**What the 38 actually were.** Not what the prologues suggested. Every one of them opens with the
x64 variadic spill (`mov [rsp+arg_0], rcx` ... `arg_18, r9`) and they are named `hr_ask_form`,
`hr_msg`, `hr_warning`, `hr_show_wait_box` -- so the obvious theory was a missing variadic prototype
on the function itself. That theory was **wrong**: applying one recovered 0 of 38, and `set_type`
reported `old_type` was *already* `__int64(const char *, ...)`. The functions were fine.

The real cause is one level down. They all reach IDA's UI through an indirect call on the global
`callui`, which is variadic, and IDA had guessed a fixed concrete signature for it that Hex-Rays
could not reconcile with the actual call sites. Typing that single global:

```
set_type callui  ->  __int64 (__fastcall *callui)(int, ...)
```

**recovered 34 of the 38.** One type on one global, and 34 functions came back.

Packaged as `tools/repair_types.py`: it scans for MERR_BADCALL, applies each recipe, verifies the
recipe actually recovered something before keeping it, works on a copy unless given `--in-place`,
and saves only if it helped.

Applied to `ref/hexx64 - Copy.dll.i64` (backed up first). Full export before and after:

| | before | after |
|---|---|---|
| Fully successful | 10,071 | **10,105** |
| Failed | 38 | **4** |
| Wall clock | 277s | 278s (unchanged -- this was a correctness fix, not a speed one) |

### F3b. The last 4 (open)
`hr_plugin_term`, `hr_interr_50057`, `hr_action_3229B8_activate`, `hr_action_EditCmt_activate`.
Still MERR_BADCALL, but each fails at a *different* indirect call -- vtable slots and other globals,
not `callui`. Each needs its own prototype identified, so each is its own small investigation rather
than one shared recipe. 0.04% of the binary.

### F4. `chunk = 150` is hardcoded (speed, only with `--db-copies`)
`export_batch` splits work into fixed 150-function chunks. With one session that is fine. With N
workers it is the thing that decides whether they get work at all: a target with fewer than
`150 x N` functions leaves workers idle. hexx64 has 68 chunks over 4 workers, so it happened not to
bite here. Should be `max(1, total // (workers * 4))` with a floor, and exposed as a flag.

### F5. Parallel export changes inferred types (correctness caveat, documented not fixed)
`--db-copies 4` produced pseudocode differing from serial on 3,162 of 819,252 lines (0.39%). Same
2,725 function bodies, same 38 failures, same addresses -- the differences are Hex-Rays type
inference: `unsigned int a2` vs `int a2`, `__int64 v8` vs `unsigned __int8 *v8`, `0x11u` vs `17`.

Cause: Hex-Rays propagates inferred types between functions as it decompiles. One session sees all
10,109; four workers each see a quarter and infer from a narrower context. **Serial output has
better-inferred prototypes.** This is inherent to Hex-Rays, not the transport. Serial stays the
default; `--db-copies` is opt-in and buys ~2.9x wall clock for slightly weaker types.

### F6. A second process on one database fails confusingly (guarded, not fixed)
An IDA database is locked by whoever opens it. A second hexport comes up `ready=false` and answers
every request `no function at address` -- which surfaces as hundreds of per-function failures rather
than one clear error. `database_busy_warning()` now predicts it up front. The underlying limit
cannot be fixed; a plugin does not help either, since every SDK database call goes through
`execute_sync` with `MFF_READ`/`MFF_WRITE` and runs on IDA's single idle main thread.

---

## Measured baseline

| | serial | `--db-copies 4` |
|---|---|---|
| Wall clock | 277s | **97s (2.9x)** |
| Successful | 10,071 | 10,071 |
| Failed | 38 (identical set) | 38 (identical set) |
| Output | 26.07 MB | 26.07 MB |
| Copies left behind | -- | 0 |

Transport: hexport over stdio. The previous path spawned a `curl.exe`, made a temp directory and
wrote three files **per JSON-RPC request**; it is now one process, one pipe, a write and a readline.
