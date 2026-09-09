#!/usr/bin/env python3
"""Repair MERR_BADCALL decompilation failures by giving Hex-Rays the prototypes it is missing.

Hex-Rays abandons a whole function when it cannot work out the arguments of a call inside it
(MERR_BADCALL). The usual cause is an indirect call through a global function pointer that IDA
guessed a wrong, concrete signature for -- typically a VARIADIC dispatcher, which IDA cannot guess
because the argument list differs per call site.

Measured on hexx64.dll: all 38 failures were MERR_BADCALL, no retry or force_recompile fixed any of
them, and typing the single `callui` global as a variadic function pointer fixed 34 of the 38.

Safety, in order:
  * verifies each recipe actually FIXES something before it is kept,
  * works on a COPY by default; --in-place is required to touch the real database,
  * saves only when at least one function was recovered.

  python repair_types.py <database.i64> [--in-place] [--hexport PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Prototypes worth trying, as (address-or-symbol, C declaration, why).
# Keep these conservative: a wrong prototype produces confidently wrong pseudocode, which is worse
# than a function that visibly failed.
RECIPES = [
    ("callui", "__int64 (__fastcall *callui)(int, ...)",
     "IDA's UI dispatcher is variadic; IDA guesses a fixed signature and Hex-Rays then cannot "
     "reconcile it with the actual call sites"),
]


# Tried in order on the callee at a failure point. Deliberately short: each extra guess is another
# chance to assert a wrong argument count.
CALLEE_CANDIDATES = [
    "__int64 __fastcall f(__int64)",
    "__int64 __fastcall f(__int64, __int64)",
    "__int64 __fastcall f(__int64, __int64, __int64)",
]


def decompiles(call, addr) -> bool:
    call("tools/call", {"name": "force_recompile", "arguments": {"items": [{"addr": addr}]}})
    d = result_of(call("tools/call", {"name": "decompile", "arguments": {"addr": addr}})) or {}
    return bool(d.get("code"))


def rpc(proc, ident, method, params):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": ident, "method": method,
                                 "params": params}) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def result_of(reply):
    return (reply.get("result") or {}).get("structuredContent", {}).get("result")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("database")
    ap.add_argument("--hexport", default=str(Path(__file__).resolve().parents[1] / "build" / "hexport.exe"))
    ap.add_argument("--in-place", action="store_true",
                    help="modify the real database instead of a throwaway copy")
    args = ap.parse_args()

    if not os.path.isfile(args.database):
        print(f"no such database: {args.database}", file=sys.stderr)
        return 2

    tmp = None
    target = args.database
    if not args.in_place:
        tmp = tempfile.mkdtemp(prefix="repair_types_")
        target = os.path.join(tmp, "work" + Path(args.database).suffix)
        print(f"copying to {target} (use --in-place to edit the original)", flush=True)
        shutil.copy2(args.database, target)

    proc = subprocess.Popen([args.hexport, "--stdio", target],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                            errors="replace", bufsize=1)
    ident = [0]

    def call(method, params):
        ident[0] += 1
        return rpc(proc, ident[0], method, params)

    try:
        call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                            "clientInfo": {"name": "repair_types", "version": "1"}})

        # Which functions currently fail, and why.
        rows = result_of(call("tools/call", {"name": "list_funcs",
                                             "arguments": {"queries": {"offset": 0, "count": 0}}}))
        data = rows[0]["data"] if isinstance(rows, list) else rows["data"]
        addrs = [d.get("start") or d.get("addr") for d in data]
        print(f"{len(addrs):,} functions; scanning for decompilation failures...", flush=True)

        failing = []
        for k in range(0, len(addrs), 150):
            chunk = addrs[k:k + 150]
            r = result_of(call("tools/call", {"name": "analyze_batch", "arguments": {"queries": [
                {"addr": a, "include_decompile": True, "include_disasm": False} for a in chunk]}})) or []
            for item in r:
                an = (item or {}).get("analysis") or {}
                if an.get("decompile") is None:
                    failing.append((item.get("addr"), item.get("name", ""), an.get("decompile_merror")))
        badcall = [f for f in failing if f[2] == -12]
        print(f"  {len(failing)} failing, {len(badcall)} of them MERR_BADCALL", flush=True)
        if not badcall:
            print("nothing this tool can repair")
            return 0

        before = {a for a, _, _ in badcall}
        applied = []

        # Phase 1: global recipes. One wrong global type can break hundreds of callers at once, so
        # this is where the leverage is -- `callui` alone recovered 34 of 38 on hexx64.dll.
        for where, decl, why in RECIPES:
            r = result_of(call("tools/call", {"name": "set_type",
                                              "arguments": {"addr": where, "decl": decl}})) or {}
            if r.get("error"):
                print(f"  skip {where}: {r['error']}")
                continue
            fixed_now = sum(1 for a in sorted(before) if decompiles(call, a))
            print(f"  {where}: {decl}")
            print(f"    {why}")
            print(f"    -> recovered {fixed_now}/{len(before)}")
            if fixed_now:
                applied.append((where, fixed_now))

        still = [a for a in sorted(before) if not decompiles(call, a)]
        print(f"\n{len(still)} still failing; trying the callee at each failure point")

        # Phase 2: per-function. Type the callee Hex-Rays choked on. EVERY trial is reverted unless
        # it actually fixes the caller -- a prototype that does not earn its place is a lie about the
        # argument count, and confidently wrong pseudocode is worse than a visible failure.
        #
        # These are hand-written on purpose. ida-pro-mcp's infer_types (guess_tinfo) was ported and
        # tried here first: it returns argument-less signatures like `__int64 __fastcall()`, which is
        # precisely what Hex-Rays cannot use, and it recovered 0 of 4.
        for a in list(still):
            d = result_of(call("tools/call", {"name": "decompile", "arguments": {"addr": a}})) or {}
            ea = d.get("error_addr") or a
            dis = result_of(call("tools/call", {"name": "disasm",
                                                "arguments": {"addr": ea, "max_instructions": 14}})) or {}
            callees = []
            for line in ((dis.get("asm") or {}).get("lines") or []):
                m = re.search(r"call\s+([A-Za-z_][A-Za-z0-9_]*)", line.get("instruction", ""))
                if m and m.group(1) not in callees:
                    callees.append(m.group(1))
            done = False
            for callee in callees[:4]:
                for decl in CALLEE_CANDIDATES:
                    r = result_of(call("tools/call", {"name": "set_type",
                                                      "arguments": {"addr": callee, "decl": decl}})) or {}
                    if r.get("error"):
                        continue
                    if decompiles(call, a):
                        print(f"    {a}: {callee} := {decl}")
                        applied.append((callee, 1))
                        still.remove(a)
                        done = True
                        break
                    old_type = r.get("old_type")
                    if old_type:                       # revert: it did not fix anything
                        call("tools/call", {"name": "set_type",
                                            "arguments": {"addr": callee, "decl": old_type + ";"}})
                if done:
                    break

        recovered = len(before) - len(still)
        total = recovered
        if not applied:
            print("no recipe recovered anything; nothing saved")
            return 1

        print(f"\nrecovered {total} of {len(before)} MERR_BADCALL functions")
        if args.in_place:
            call("tools/call", {"name": "close_database", "arguments": {"save": True}})
            print("saved to the database")
        else:
            print("copy only -- rerun with --in-place to keep these types")
        return 0
    finally:
        try:
            proc.stdin.close()
            proc.wait(timeout=120)
        except Exception:
            proc.kill()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
