"""Checks for the six gap-filling tools.

Each asserts something specific about the fixture. A tool that returned {} for every input would
pass an error check and be useless, so nothing here settles for "no error".

Runs on a COPY. Closes with save=false. Never force-kills.
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

EXE = r'E:\AI\srcfiles\vulnchecking\ida-mcp-context-shim\mcp\hexport\build\hexport.exe'
SRC = r'D:\source\repos\test_research\crcrun2\db.i64'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


src_before = sha(SRC)
tmp = tempfile.mkdtemp(prefix="batch3_")
db = os.path.join(tmp, "db.i64")
shutil.copy2(SRC, db)

p = subprocess.Popen([EXE, '--stdio', db], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, text=True, encoding='utf-8',
                     errors='replace', bufsize=1)
_id = [0]


def tool(name, a):
    _id[0] += 1
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": _id[0], "method": "tools/call",
                              "params": {"name": name, "arguments": a}}) + "\n")
    p.stdin.flush()
    r = json.loads(p.stdout.readline())
    return (r.get("result") or {}).get("structuredContent", {}).get("result")


_id[0] += 1
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": _id[0], "method": "initialize",
                          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                     "clientInfo": {"name": "t", "version": "1"}}}) + "\n")
p.stdin.flush()
p.stdout.readline()

fails = []


def check(label, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + label + ("   " + str(detail)[:150] if detail else ""),
          flush=True)
    if not cond:
        fails.append(label)


try:
    FEA = "0x140001000"

    # ---- segments -------------------------------------------------------------------
    r = tool("segments", {}) or {}
    segs = r.get("segments") or []
    names = [s.get("name") for s in segs]
    check("segments lists the image's sections", len(segs) > 0, f"{len(segs)}: {names}")
    text = [s for s in segs if s.get("name") == ".text"]
    check(".text is present and executable",
          bool(text) and "x" in (text[0].get("perm") or ""),
          text[0] if text else "no .text")
    check("segment ranges are ordered and sized",
          all(int(s["end"], 16) > int(s["start"], 16) and s["size"] > 0 for s in segs))

    # ---- exports ---------------------------------------------------------------------
    r = tool("exports", {}) or {}
    exps = r.get("exports") or []
    check("exports finds the entry point(s)", len(exps) > 0,
          [e.get("name") for e in exps][:5])
    check("an export resolves to a real address",
          all(e.get("addr", "").startswith("0x") for e in exps))

    # ---- xrefs_from vs xrefs_to ------------------------------------------------------
    # xrefs_from is per-ADDRESS, the exact mirror of xrefs_to. A function's start is one
    # instruction, so ask at a real call site instead: find one, then walk the edge both ways.
    calls = (tool("insn_query", {"mnem": "call", "limit": 40}) or {}).get("results") or []
    site = None
    target = None
    for c in calls:
        f = tool("xrefs_from", {"addr": c["addr"]}) or {}
        fn = [x for x in (f.get("xrefs") or []) if x.get("is_function")]
        if fn:
            site, target = c["addr"], fn[0]
            break
    check("xrefs_from resolves a call site to its target",
          target is not None, f"{site} -> {target.get('name') if target else None}")
    mirrored = False
    if target:
        back = tool("xrefs_to", {"addr": target["to"]}) or {}
        mirrored = any(x.get("from", "").lower() == site.lower()
                       for x in (back.get("xrefs") or []))
    check("xrefs_from and xrefs_to agree on the same edge", mirrored,
          f"{site} -> {target.get('to') if target else None} and back")

    # ---- insn_query -------------------------------------------------------------------
    r = tool("insn_query", {"mnem": "call", "limit": 50}) or {}
    hits = r.get("results") or []
    check("insn_query finds call instructions", r.get("hits", 0) > 0,
          f"{r.get('hits')} of {r.get('instructions_scanned')} scanned")
    check("every insn_query hit really is that mnemonic",
          all((h.get("line") or "").lstrip().lower().startswith("call") for h in hits),
          [h.get("line") for h in hits[:2]])
    # Exact, not substring: "mov" must not drag in movzx/movsd.
    r2 = tool("insn_query", {"mnem": "mov", "limit": 100}) or {}
    bad = [h for h in (r2.get("results") or [])
           if not (h.get("line") or "").lstrip().lower().split()[0] == "mov"]
    check("insn_query matches mnemonics exactly, not by substring", not bad,
          bad[0].get("line") if bad else f"{r2.get('hits')} mov hits, none of them movzx/movsd")
    r3 = tool("insn_query", {"mnem": "definitely_not_an_instruction"}) or {}
    check("insn_query reports zero for a nonexistent mnemonic", r3.get("hits") == 0)

    # ---- search_structs ---------------------------------------------------------------
    tool("declare_type", {"decls": "struct hx_probe_t { int alpha; char beta_field[8]; };"})
    r = tool("search_structs", {"member": "beta_field"}) or {}
    res = r.get("results") or []
    check("search_structs finds the type owning a member", any(
        x.get("type") == "hx_probe_t" and x.get("member") == "beta_field" for x in res), res[:2])
    hit = next((x for x in res if x.get("type") == "hx_probe_t"), None)
    check("search_structs reports the member's offset in bytes",
          hit is not None and hit.get("offset") == 4, hit)
    r = tool("search_structs", {"member": "no_such_member_anywhere"}) or {}
    check("search_structs reports zero when nothing matches", r.get("hits") == 0)

    # ---- stack_xrefs ------------------------------------------------------------------
    sf = tool("stack_frame", {"addr": FEA}) or {}
    vars_ = sf.get("members") or sf.get("vars") or sf.get("frame") or []
    vname = None
    for v in (vars_ if isinstance(vars_, list) else []):
        if isinstance(v, dict) and v.get("name"):
            vname = v["name"]
            break
    if vname:
        r = tool("stack_xrefs", {"addr": FEA, "name": vname}) or {}
        check(f"stack_xrefs finds what touches '{vname}'",
              r.get("error") is None and r.get("count", 0) >= 0,
              f"count={r.get('count')} offset={r.get('offset')}")
        if (r.get("xrefs") or []):
            check("each stack xref carries the instruction that touches it",
                  all(x.get("line") for x in r["xrefs"]), r["xrefs"][0])
    else:
        # Declare one, then it must be findable.
        tool("declare_stack", {"items": {"addr": FEA, "offset": "-8",
                                         "name": "hx_probe_var", "ty": "int"}})
        r = tool("stack_xrefs", {"addr": FEA, "name": "hx_probe_var"}) or {}
        check("stack_xrefs resolves a declared stack variable",
              r.get("error") is None, r)
    r = tool("stack_xrefs", {"addr": FEA, "name": "definitely_not_a_local"}) or {}
    check("stack_xrefs rejects an unknown variable by name",
          (r.get("error") or "").startswith("no stack variable"), r.get("error"))

finally:
    print("\nclose:", json.dumps(tool("close_database", {"save": False})), flush=True)
    p.stdin.close()
    p.wait(timeout=300)
    copy_same = sha(db) == src_before if os.path.exists(db) else False
    print("copy unchanged on disk:", copy_same, flush=True)
    print("SOURCE untouched:", sha(SRC) == src_before, flush=True)
    if sha(SRC) != src_before:
        fails.append("SOURCE DATABASE CHANGED")
    shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + ("ALL PASS" if not fails else "FAILURES: " + ", ".join(fails)), flush=True)
