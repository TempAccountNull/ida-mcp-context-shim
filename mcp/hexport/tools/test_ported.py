"""Exercise the 19 tools ported from ida-pro-mcp, against a COPY of a real database.

Every tool is called and its answer checked for something specific, not merely for the absence of an
error -- a tool that returns {} for every input passes an error check and is useless.

Closes with save=false and works on a copy, so nothing can reach a real .i64.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

EXE = r'E:\AI\srcfiles\vulnchecking\ida-mcp-context-shim\mcp\hexport\build\hexport.exe'
SRC = sys.argv[1] if len(sys.argv) > 1 else r'D:\source\repos\test_research\crcrun2\db.i64'

tmp = tempfile.mkdtemp(prefix="ported_")
DB = os.path.join(tmp, "db.i64")
shutil.copy2(SRC, DB)


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


before = sha(DB)
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
p.stdin.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
p.stdin.flush()
p.stdout.readline()

fails = []


def check(label, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + label + ("   " + str(detail)[:110] if detail else ""),
          flush=True)
    if not cond:
        fails.append(label)


try:
    h = tool("server_health", {}) or {}
    print("health:", json.dumps(h), flush=True)
    rows = tool("list_funcs", {"queries": {"offset": 0, "count": 5}})
    data = rows[0]["data"] if isinstance(rows, list) else rows["data"]
    fea = data[0].get("start") or data[0].get("addr")
    fname = data[0].get("name")
    print(f"using {fea} ({fname})\n", flush=True)

    # ---- types -----------------------------------------------------------------------
    r = tool("declare_type", {"decls": "struct hx_probe_t { int a; char b[8]; void *c; };"}) or {}
    check("declare_type accepts a struct", r.get("failed") == 0, json.dumps(r)[:120])

    r = tool("type_inspect", {"queries": {"name": "hx_probe_t", "include_members": True}})
    e = r[0] if isinstance(r, list) and r else {}
    check("type_inspect reports size and members",
          e.get("kind") == "struct" and e.get("size") == 24 and e.get("member_count") == 3,
          f"kind={e.get('kind')} size={e.get('size')} members={e.get('member_count')}")
    names = [m.get("name") for m in (e.get("members") or [])]
    check("type_inspect member names and offsets",
          names == ["a", "b", "c"] and [m["offset"] for m in e["members"]] == [0, 4, 16],
          f"{names} {[m.get('offset') for m in (e.get('members') or [])]}")

    r = tool("type_query", {"queries": {"filter": "hx_probe", "include_decl": True}}) or {}
    check("type_query finds the declared type", (r.get("total_matching") or 0) >= 1,
          f"total={r.get('total_matching')}")

    r = tool("enum_upsert", {"queries": {"name": "hx_enum_t",
                                         "members": [{"name": "HX_A", "value": 1},
                                                     {"name": "HX_B", "value": "0x10"}]}}) or {}
    check("enum_upsert creates an enum", r.get("status") == "ok" and r.get("added") == 2,
          json.dumps(r)[:110])
    r = tool("enum_upsert", {"queries": {"name": "hx_enum_t",
                                         "members": [{"name": "HX_B", "value": "0x20"},
                                                     {"name": "HX_C", "value": 3}]}}) or {}
    check("enum_upsert is idempotent (updates, does not replace)",
          r.get("existed") is True and r.get("added") == 1 and r.get("updated") == 1
          and r.get("member_count") == 3, json.dumps(r)[:130])
    # The reported count was once taken after create_enum() had consumed the data, so it read 0 on a
    # successful upsert. Ask the type library what actually landed rather than trusting the report.
    r = tool("type_inspect", {"queries": {"name": "hx_enum_t", "include_members": True}})
    e = r[0] if isinstance(r, list) and r else {}
    got = {m.get("name"): m.get("value") for m in (e.get("members") or [])}
    check("the enum really holds the merged members",
          e.get("kind") == "enum" and got == {"HX_A": "0x1", "HX_B": "0x20", "HX_C": "0x3"},
          f"kind={e.get('kind')} {got}")

    # ---- stack frame -----------------------------------------------------------------
    r = tool("declare_stack", {"items": {"addr": fea, "offset": "0", "name": "hx_slot",
                                         "ty": "int"}})
    e = r[0] if isinstance(r, list) and r else {}
    stack_ok = e.get("status") == "ok"
    check("declare_stack names a stack slot", stack_ok, json.dumps(e)[:120])
    if stack_ok:
        r = tool("delete_stack", {"items": {"addr": fea, "name": "hx_slot"}})
        e = r[0] if isinstance(r, list) and r else {}
        check("delete_stack removes it again", e.get("status") == "ok", json.dumps(e)[:120])

    # ---- graph and profile -----------------------------------------------------------
    r = tool("callgraph", {"roots": fea, "max_depth": 3}) or {}
    check("callgraph returns the root plus edges",
          (r.get("node_count") or 0) >= 1 and "edges" in r,
          f"nodes={r.get('node_count')} edges={r.get('edge_count')} truncated={r.get('truncated')}")

    r = tool("func_profile", {"queries": {"addr": fea, "include_lists": True}}) or {}
    fs = (r.get("functions") or [{}])[0]
    check("func_profile reports size, blocks and degree",
          fs.get("size", 0) > 0 and fs.get("blocks", 0) > 0 and "callees" in fs,
          f"size={fs.get('size')} blocks={fs.get('blocks')} callees={fs.get('callees')} "
          f"callers={fs.get('callers')}")

    r = tool("export_funcs", {"addrs": [fea], "format": "prototypes"}) or {}
    check("export_funcs emits prototypes text",
          bool(r.get("text")) and r["text"].rstrip().endswith(";"), repr(r.get("text"))[:110])
    r = tool("export_funcs", {"addrs": [fea], "format": "json"}) or {}
    check("export_funcs json carries the name",
          (r.get("functions") or [{}])[0].get("name") == fname,
          json.dumps(r.get("functions"))[:110])

    # ---- search and strings ----------------------------------------------------------
    r = tool("search_text", {"pattern": "call", "limit": 5}) or {}
    check("search_text finds call instructions", (r.get("hits") or 0) > 0,
          f"hits={r.get('hits')} scanned={r.get('items_scanned')}")
    r = tool("search_text", {"pattern": "zzz_no_such_mnemonic_zzz", "limit": 5}) or {}
    check("search_text reports zero for a miss", r.get("hits") == 0, json.dumps(r)[:90])

    r = tool("list_strings", {"limit": 5}) or {}
    check("list_strings enumerates strings", (r.get("total_strings") or 0) > 0,
          f"total={r.get('total_strings')} returned={len(r.get('strings') or [])}")
    strs = r.get("strings") or []
    if strs:
        needle = strs[0]["text"][:4]
        r2 = tool("list_strings", {"filter": needle, "limit": 5}) or {}
        check("list_strings filter narrows the result",
              (r2.get("matched") or 0) >= 1 and (r2.get("matched") or 0) <= (r.get("total_strings") or 0),
              f"filter={needle!r} matched={r2.get('matched')}")

    # ---- integers --------------------------------------------------------------------
    r = tool("int_convert", {"inputs": {"text": "0x41424344", "size": 4}})
    e = r[0] if isinstance(r, list) and r else {}
    check("int_convert gives hex, decimal, binary and ascii",
          e.get("hex") == "0x41424344" and e.get("decimal") == 1094861636
          and e.get("ascii_le") == "DCBA" and e.get("binary", "").count("_") == 3,
          f"{e.get('hex')} {e.get('decimal')} {e.get('ascii_le')!r}")
    r = tool("int_convert", {"inputs": {"text": "-1", "size": 2}})
    e = r[0] if isinstance(r, list) and r else {}
    check("int_convert sign-extends", e.get("signed") == -1 and e.get("decimal") == 65535,
          f"signed={e.get('signed')} decimal={e.get('decimal')}")

    r = tool("get_int", {"queries": {"addr": fea, "ty": "u32"}})
    le = (r[0] if isinstance(r, list) and r else {})
    r = tool("get_int", {"queries": {"addr": fea, "ty": "u32be"}})
    be = (r[0] if isinstance(r, list) and r else {})
    check("get_int reads little-endian", "value" in le, json.dumps(le)[:100])
    check("get_int big-endian differs from little-endian",
          le.get("value") != be.get("value"), f"le={le.get('hex')} be={be.get('hex')}")
    r = tool("get_int", {"queries": {"addr": fea, "ty": "nonsense"}})
    e = r[0] if isinstance(r, list) and r else {}
    check("get_int rejects a bad width", bool(e.get("error")), e.get("error"))

    # write into the copy, read it back, restore
    orig = le.get("value")
    r = tool("put_int", {"items": {"addr": fea, "ty": "u32", "value": "0xDEADBEEF"}})
    e = r[0] if isinstance(r, list) and r else {}
    check("put_int reports success and saved=false",
          e.get("status") == "ok" and e.get("saved") is False, json.dumps(e)[:110])
    r = tool("get_int", {"queries": {"addr": fea, "ty": "u32"}})
    e = r[0] if isinstance(r, list) and r else {}
    check("put_int actually changed the bytes", e.get("hex") == "0xdeadbeef", e.get("hex"))
    tool("put_int", {"items": {"addr": fea, "ty": "u32", "value": str(orig)}})

    # ---- globals, bookmarks, comments -------------------------------------------------
    g = tool("list_globals", {"limit": 3}) or {}
    gl = (g.get("globals") or [])
    if gl:
        r = tool("get_global_value", {"queries": gl[0]["addr"]})
        e = r[0] if isinstance(r, list) and r else {}
        check("get_global_value reports size and a value or a reason",
              "size" in e and ("value" in e or "string" in e or "note" in e or "error" in e),
              json.dumps(e)[:120])

    r = tool("add_bookmark", {"addr": fea, "name": "probe"}) or {}
    check("add_bookmark takes a slot",
          r.get("status") == "ok" and r.get("title") == "hexport: probe", json.dumps(r)[:110])

    r = tool("append_comments", {"items": {"addr": fea, "comment": "hx first"}})
    e = r[0] if isinstance(r, list) and r else {}
    check("append_comments writes", e.get("status") == "ok", json.dumps(e)[:110])
    r = tool("append_comments", {"items": {"addr": fea, "comment": "hx first"}})
    e = r[0] if isinstance(r, list) and r else {}
    check("append_comments dedupes identical text", e.get("status") == "skipped", json.dumps(e)[:110])
    r = tool("append_comments", {"items": {"addr": fea, "comment": "hx second"}})
    e = r[0] if isinstance(r, list) and r else {}
    check("append_comments adds a different line", e.get("status") == "ok", json.dumps(e)[:110])

    # ---- read_struct -------------------------------------------------------------------
    tool("set_type", {"addr": fea, "decl": "struct hx_probe_t;"})
    r = tool("read_struct", {"queries": {"addr": fea, "struct": "hx_probe_t"}})
    e = r[0] if isinstance(r, list) and r else {}
    flds = e.get("fields") or []
    check("read_struct reads fields at an address",
          len(flds) == 3 and flds[0].get("name") == "a" and "value" in flds[0],
          json.dumps(flds)[:150])
    r = tool("read_struct", {"queries": {"addr": fea, "struct": "no_such_struct_t"}})
    e = r[0] if isinstance(r, list) and r else {}
    check("read_struct refuses an unknown struct", bool(e.get("error")), e.get("error"))
finally:
    print("\nclose:", json.dumps(tool("close_database", {"save": False})), flush=True)
    p.stdin.close()
    p.wait(timeout=600)
    after = sha(DB) if os.path.exists(DB) else "MISSING"
    print("copy unchanged on disk:", after == before, flush=True)
    print("SOURCE untouched:", sha(SRC) == before, flush=True)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{'ALL PASS' if not fails else str(len(fails)) + ' FAILED: ' + ', '.join(fails)}")
    sys.exit(1 if fails else 0)
