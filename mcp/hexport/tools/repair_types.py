#!/usr/bin/env python3
"""Repair MERR_BADCALL decompilation failures by giving Hex-Rays the prototypes it is missing.

Hex-Rays abandons a whole function when it cannot work out the arguments of a call inside it
(MERR_BADCALL). The usual cause is an indirect call through a global function pointer that IDA
guessed a wrong CONCRETE signature for -- typically a variadic dispatcher, which IDA cannot guess
because the argument list differs at every call site.

Measured on hexx64.dll: all 38 failures were MERR_BADCALL. Neither a plain retry nor
force_recompile fixed a single one. Typing the single `callui` global recovered 34; typing one
callee recovered 2 more.

This script no longer writes anything, ever. It works on a copy, closes with save=false, and
reports what it found. There is no flag to make it persist: hexport's `repair_badcall` tool does the
same repair inside the session and `save_as` writes the result to a NEW path, which is a better
answer than teaching a throwaway script to overwrite a database.

Safety, in order:
  * works on a COPY, so the real .i64 is never opened, let alone written;
  * closes with save=false regardless;
  * reverts every trial prototype that does not actually fix the caller. A prototype that has not
    earned its place is a lie about the argument count, and confidently wrong pseudocode is worse
    than a function that visibly failed.

  python repair_types.py <database.i64> [--hexport PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Global fixes. One wrong global type breaks every caller at once, so this is where the leverage is.
RECIPES = [
    ("callui", "__int64 (__fastcall *callui)(int, ...)",
     "IDA's UI dispatcher is variadic; IDA guesses a fixed signature and Hex-Rays then cannot "
     "reconcile it with the actual call sites"),
]

# Tried in order on the callee Hex-Rays choked on. Deliberately short: each extra guess is another
# chance to assert a wrong argument count.
CALLEE_CANDIDATES = [
    "__int64 __fastcall f(__int64)",
    "__int64 __fastcall f(__int64, __int64)",
    "__int64 __fastcall f(__int64, __int64, __int64)",
]


class Hexport:
    """One headless hexport session over stdio."""

    def __init__(self, exe: str, database: str):
        self.proc = subprocess.Popen(
            [exe, "--stdio", database],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        self._id = 0
        self.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                "clientInfo": {"name": "repair_types", "version": "2"}})

    def rpc(self, method, params):
        self._id += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self._id,
                                          "method": method, "params": params}) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    def tool(self, name, args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        return (r.get("result") or {}).get("structuredContent", {}).get("result")

    def decompiles(self, addr) -> bool:
        self.tool("force_recompile", {"items": [{"addr": addr}]})
        d = self.tool("decompile", {"addr": addr}) or {}
        return bool(d.get("code"))

    def close(self, save: bool):
        try:
            self.tool("close_database", {"save": save})
            self.proc.stdin.close()
            self.proc.wait(timeout=300)
        except Exception:
            self.proc.kill()


def scan_failures(h: Hexport):
    """Every function that will not decompile, with the Hex-Rays reason."""
    rows = h.tool("list_funcs", {"queries": {"offset": 0, "count": 0}})
    data = rows[0]["data"] if isinstance(rows, list) else rows["data"]
    addrs = [d.get("start") or d.get("addr") for d in data]
    print(f"{len(addrs):,} functions; scanning...", flush=True)
    failing = []
    for k in range(0, len(addrs), 150):
        r = h.tool("analyze_batch", {"queries": [
            {"addr": a, "include_decompile": True, "include_disasm": False}
            for a in addrs[k:k + 150]]}) or []
        for item in r:
            an = (item or {}).get("analysis") or {}
            if an.get("decompile") is None:
                failing.append((item.get("addr"), item.get("name", ""),
                                an.get("decompile_merror")))
    return len(addrs), failing


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("database")
    ap.add_argument("--hexport",
                    default=str(Path(__file__).resolve().parents[1] / "build" / "hexport.exe"))
    args = ap.parse_args()

    if not os.path.isfile(args.database):
        print(f"no such database: {args.database}", file=sys.stderr)
        return 2

    tmp = tempfile.mkdtemp(prefix="repair_types_")
    target = os.path.join(tmp, "work" + Path(args.database).suffix)
    print("working on a copy; the real database is never opened", flush=True)
    shutil.copy2(args.database, target)

    h = Hexport(args.hexport, target)
    try:
        _total, failing = scan_failures(h)
        badcall = [f for f in failing if f[2] == -12]
        print(f"  {len(failing)} failing, {len(badcall)} of them MERR_BADCALL", flush=True)
        if not badcall:
            print("nothing this tool can repair")
            return 0

        before = [a for a, _, _ in badcall]
        names = {a: n for a, n, _ in badcall}

        # ---- phase 1: global recipes -------------------------------------------------------
        for where, decl, why in RECIPES:
            r = h.tool("set_type", {"addr": where, "decl": decl}) or {}
            if r.get("error"):
                print(f"  skip {where}: {r['error']}")
                continue
            fixed = sum(1 for a in before if h.decompiles(a))
            print(f"  {where}: {decl}")
            print(f"    {why}")
            print(f"    -> recovered {fixed}/{len(before)}", flush=True)

        still = [a for a in before if not h.decompiles(a)]
        print(f"\n  {len(still)} still failing; asking each one what it calls", flush=True)

        # ---- phase 2: per-function ---------------------------------------------------------
        # `callees` reports the call targets directly, with names. Before that tool existed the
        # only way to find them was to disassemble around the failure address and regex the text.
        for a in list(still):
            c = h.tool("callees", {"addr": a}) or {}
            targets = [x.get("name") for x in (c.get("callees") or []) if x.get("name")]
            if not targets:
                print(f"    {a} {names.get(a, '')}: no resolvable call at the failure point")
                continue
            done = False
            for callee in targets[:4]:
                for decl in CALLEE_CANDIDATES:
                    r = h.tool("set_type", {"addr": callee, "decl": decl}) or {}
                    if r.get("error"):
                        continue
                    if h.decompiles(a):
                        print(f"    {a} {names.get(a, '')}: {callee} := {decl}")
                        still.remove(a)
                        done = True
                        break
                    old = r.get("old_type")
                    if old:                       # revert: it did not earn its place
                        h.tool("set_type", {"addr": callee, "decl": old + ";"})
                if done:
                    break

        recovered = len(before) - len(still)
        print(f"\nrecovered {recovered} of {len(before)} MERR_BADCALL functions")
        for a in still:
            print(f"  still failing: {a} {names.get(a, '')}")

        print("database unchanged")
        return 0
    finally:
        try:
            if h.proc.poll() is None:
                h.close(save=False)
        except Exception:
            pass
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
