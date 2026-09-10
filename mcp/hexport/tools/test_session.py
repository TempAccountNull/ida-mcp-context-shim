"""save_as / revert_decisions / make_sigs / microcode against the small test database.

The claim under test is the safety one: save_as writes a NEW file and leaves the opened database
byte-identical. Everything is checked by hash, not by trust.
"""
import hashlib
import json
import os
import subprocess
import tempfile

EXE = r'E:\AI\srcfiles\vulnchecking\ida-mcp-context-shim\mcp\hexport\build\hexport.exe'
DB = r'D:\source\repos\test_research\crcrun2\db.i64'


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


before = (sha(DB), os.path.getsize(DB), os.path.getmtime(DB))
print("source before:", before[0][:16], before[1], "bytes", flush=True)

p = subprocess.Popen([EXE, '--stdio', DB], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, text=True, encoding='utf-8',
                     errors='replace', bufsize=1)
_id = [0]


def tool(name, args):
    _id[0] += 1
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": _id[0], "method": "tools/call",
                              "params": {"name": name, "arguments": args}}) + "\n")
    p.stdin.flush()
    r = json.loads(p.stdout.readline())
    return (r.get("result") or {}).get("structuredContent", {}).get("result")


_id[0] += 1
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": _id[0], "method": "initialize",
                          "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                     "clientInfo": {"name": "t", "version": "1"}}}) + "\n")
p.stdin.flush()
p.stdout.readline()

tmp = tempfile.mkdtemp(prefix="save_as_")
outp = os.path.join(tmp, "repaired.i64")
fails = []


def check(label, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + label + ("  " + detail if detail else ""), flush=True)
    if not cond:
        fails.append(label)


try:
    h = tool("server_health", {}) or {}
    print("health:", json.dumps(h), flush=True)
    funcs = tool("list_funcs", {"queries": {"offset": 0, "count": 3}})
    rows = funcs[0]["data"] if isinstance(funcs, list) else funcs["data"]
    fea = rows[0].get("start") or rows[0].get("addr")
    print(f"\nusing function {fea} ({rows[0].get('name')})\n", flush=True)

    # ---- save_as refuses to overwrite the open database -----------------------------
    r = tool("save_as", {"path": DB}) or {}
    check("save_as refuses the current database path", bool(r.get("error")), str(r.get("error"))[:60])

    # ---- make an in-memory change, then save it elsewhere ---------------------------
    tool("set_comments", {"addr": fea, "comment": "save_as probe", "function": True})
    r = tool("save_as", {"path": outp}) or {}
    check("save_as reports ok", r.get("status") == "ok", json.dumps(r))
    check("save_as wrote the new file", os.path.isfile(outp),
          f"{os.path.getsize(outp) if os.path.isfile(outp) else 0} bytes")

    after = (sha(DB), os.path.getsize(DB), os.path.getmtime(DB))
    check("source hash unchanged", after[0] == before[0], after[0][:16])
    check("source size unchanged", after[1] == before[1], str(after[1]))
    check("source mtime unchanged", after[2] == before[2])

    # ---- revert_decisions ------------------------------------------------------------
    r = tool("revert_decisions", {"addr": fea}) or {}
    check("revert_decisions ok", r.get("status") == "ok", json.dumps(r))
    check("function still present after revert+replan", r.get("function_after") is True)
    d = tool("decompile", {"addr": fea}) or {}
    check("decompiles after revert", bool(d.get("code")), (d.get("error") or "")[:50])

    # ---- microcode ---------------------------------------------------------------------
    mc = tool("microcode", {"addr": fea, "maturity": "preoptimized"}) or {}
    check("microcode preoptimized returns text", bool(mc.get("microcode")),
          f"{len(str(mc.get('microcode') or '').splitlines())} lines")
    mc2 = tool("microcode", {"addr": fea, "maturity": "nonsense"}) or {}
    check("microcode rejects a bad maturity", bool(mc2.get("error")))
    mc3 = tool("microcode", {"addr": fea, "maturity": "glbopt3", "around": fea, "context": 3}) or {}
    n3 = len(str(mc3.get("microcode") or "").splitlines())
    check("microcode around/context windows the listing", 0 < n3 <= 8, f"{n3} lines")

    # ---- make_sigs ---------------------------------------------------------------------
    r = tool("make_sigs", {"only_pat": True}) or {}
    check("make_sigs runs", r.get("status") in ("ok", "failed"), json.dumps(r))
finally:
    print("\nclose:", json.dumps(tool("close_database", {"save": False})), flush=True)
    p.stdin.close()
    p.wait(timeout=300)
    final = (sha(DB), os.path.getsize(DB), os.path.getmtime(DB))
    print("source after close:", final[0][:16],
          "IDENTICAL" if final == before else "*** CHANGED ***", flush=True)
    if final != before:
        fails.append("source changed across the whole session")
    print(f"\n{'ALL PASS' if not fails else 'FAILURES: ' + ', '.join(fails)}", flush=True)
