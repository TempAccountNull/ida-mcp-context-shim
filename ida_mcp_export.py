#!/usr/bin/env python3
"""Export the current IDA function and its reachable callees through ida-pro-mcp.

Uses curl for Streamable HTTP MCP JSON-RPC requests, as requested.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


class VerboseLogger:
    """Thread-safe diagnostic logger with six verbosity levels."""

    def __init__(self, level: int = 0):
        self.level = max(0, min(6, int(level)))
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.panel = None

    def enabled(self, level: int) -> bool:
        return self.level >= level

    def attach_panel(self, panel: Any) -> None:
        self.panel = panel

    def log(self, level: int, category: str, message: str) -> None:
        if not self.enabled(level):
            return
        elapsed = format_duration(time.monotonic() - self.started)
        thread_name = threading.current_thread().name
        line = f"[V{level}] [{elapsed}] [{thread_name}] [{category}] {message}"
        with self.lock:
            if self.panel is not None:
                self.panel.add(level, thread_name, category, message, line)
            else:
                print(line, flush=True)


VERBOSE = VerboseLogger(0)


def vlog(level: int, category: str, message: str) -> None:
    VERBOSE.log(level, category, message)


@dataclass
class RunStats:
    started: float = field(default_factory=time.monotonic)
    discovery_started: float = 0.0
    discovery_finished: float = 0.0
    export_started: float = 0.0
    export_finished: float = 0.0
    retry_attempts: int = 0
    retried_successfully: int = 0
    health_checks: int = 0
    health_failures: int = 0
    health_recoveries: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def increment(self, name: str, amount: int = 1) -> None:
        with self.lock:
            setattr(self, name, getattr(self, name) + amount)

    def elapsed(self) -> float:
        return max(0.0, time.monotonic() - self.started)


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


class McpError(RuntimeError):
    pass


class FunctionTimeoutError(McpError):
    pass


@dataclass
class FunctionInfo:
    addr: str
    name: str
    depth: int
    source: str


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "function"


def addr_key(value: str) -> int | str:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return value.lower()


class CurlMcpClient:
    def __init__(self, server: str, curl: str = "curl.exe", timeout: int = 180):
        if server.isdigit():
            server = f"http://127.0.0.1:{server}/mcp"
        elif not server.startswith(("http://", "https://")):
            server = f"http://{server}"
        if not server.rstrip("/").endswith("/mcp"):
            server = server.rstrip("/") + "/mcp"
        self.url = server
        self.curl = curl
        self.timeout = timeout
        self.session_id: str | None = None
        self.request_id = 0
        vlog(2, "MCP", f"Created client url={self.url} timeout={self.timeout}s curl={self.curl}")

    def _post(self, method: str, params: dict[str, Any] | None = None, *, notification: bool = False) -> Any:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if not notification:
            self.request_id += 1
            payload["id"] = self.request_id
        if params is not None:
            payload["params"] = params

        request_started = time.monotonic()
        vlog(3, "MCP", f"POST method={method} request_id={payload.get('id', 'notification')} session={self.session_id or '-'}")
        if VERBOSE.enabled(6):
            vlog(6, "MCP-PAYLOAD", json.dumps(payload, ensure_ascii=False))

        with tempfile.TemporaryDirectory(prefix="ida_mcp_export_") as td:
            body_path = Path(td) / "request.json"
            header_path = Path(td) / "headers.txt"
            response_path = Path(td) / "response.bin"
            body_path.write_text(json.dumps(payload), encoding="utf-8")

            cmd = [
                self.curl,
                "--silent", "--show-error", "--fail-with-body",
            ]
            if self.timeout > 0:
                cmd += ["--max-time", str(self.timeout)]
            cmd += [
                "--dump-header", str(header_path),
                "--output", str(response_path),
                "--request", "POST",
                "--header", "Content-Type: application/json",
                "--header", "Accept: application/json, text/event-stream",
            ]
            if self.session_id:
                cmd += ["--header", f"Mcp-Session-Id: {self.session_id}"]
            cmd += ["--data-binary", f"@{body_path}", self.url]

            if VERBOSE.enabled(6):
                safe_cmd = ["<request-body-file>" if str(x).startswith("@") else str(x) for x in cmd]
                vlog(6, "CURL", "command=" + subprocess.list2cmdline(safe_cmd))
            try:
                completed = subprocess.run(cmd, capture_output=True, text=True, timeout=(self.timeout + 5) if self.timeout > 0 else None)
            except subprocess.TimeoutExpired as exc:
                raise McpError(f"MCP request {method!r} exceeded the process timeout") from exc
            raw_headers = header_path.read_text(encoding="utf-8", errors="replace") if header_path.exists() else ""
            raw_body = response_path.read_text(encoding="utf-8", errors="replace") if response_path.exists() else ""
            duration = time.monotonic() - request_started
            vlog(3, "MCP", f"POST complete method={method} rc={completed.returncode} duration={duration:.3f}s response_bytes={len(raw_body.encode('utf-8', errors='replace'))}")
            if VERBOSE.enabled(6):
                vlog(6, "MCP-HEADERS", raw_headers.strip() or "<empty>")
            if completed.returncode != 0:
                detail = raw_body.strip() or completed.stderr.strip() or f"curl exit code {completed.returncode}"
                raise McpError(f"MCP request {method!r} failed: {detail}")

            match = re.search(r"(?im)^Mcp-Session-Id:\s*(\S+)\s*$", raw_headers)
            if match:
                self.session_id = match.group(1)

            # JSON-RPC notifications do not have a response object. Depending on
            # the MCP HTTP implementation, a successful notification may return
            # an empty body, plain text such as "Accepted", or HTTP 202 content.
            # curl --fail-with-body already verified that the HTTP request did not
            # fail, so never attempt to JSON-decode a notification response.
            if notification:
                return None
            return self._decode_response(raw_body, method)

    @staticmethod
    def _decode_response(raw: str, method: str) -> Any:
        raw = raw.strip()
        if not raw:
            raise McpError(f"Empty response for {method!r}")

        # Streamable HTTP may return JSON directly or an SSE event stream.
        if raw.startswith("event:") or "\ndata:" in raw:
            data_lines = []
            for line in raw.splitlines():
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
            candidates = [line for line in data_lines if line and line != "[DONE]"]
            if not candidates:
                raise McpError(f"No JSON data in SSE response for {method!r}")
            raw = candidates[-1]

        try:
            message = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise McpError(f"Invalid JSON response for {method!r}: {exc}\n{raw[:1000]}") from exc
        if "error" in message:
            err = message["error"]
            raise McpError(f"MCP error {err.get('code')}: {err.get('message')}")
        return message.get("result")

    def _download_json(self, url: str) -> Any:
        """Download a full cached ida-pro-mcp tool result without preview truncation."""
        started = time.monotonic()
        vlog(3, "MCP-DOWNLOAD", f"Downloading full truncated result from {url}")
        cmd = [
            self.curl,
            "--silent", "--show-error", "--fail-with-body",
        ]
        if self.timeout > 0:
            cmd += ["--max-time", str(self.timeout)]
        cmd += ["--header", "Accept: application/json"]
        if self.session_id:
            cmd += ["--header", f"Mcp-Session-Id: {self.session_id}"]
        cmd.append(url)
        try:
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=(self.timeout + 5) if self.timeout > 0 else None)
        except subprocess.TimeoutExpired as exc:
            raise McpError(f"MCP download exceeded the process timeout: {url}") from exc
        vlog(3, "MCP-DOWNLOAD", f"Download complete rc={completed.returncode} duration={time.monotonic()-started:.3f}s bytes={len(completed.stdout.encode('utf-8', errors='replace'))}")
        if completed.returncode != 0:
            detail = completed.stdout.strip() or completed.stderr.strip() or f"curl exit code {completed.returncode}"
            raise McpError(f"Unable to download full MCP output from {url}: {detail}")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise McpError(f"Full MCP output was not valid JSON: {url}: {exc}") from exc

    def initialize(self) -> dict[str, Any]:
        result = self._post("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ida-mcp-export-shim", "version": "1.0.0"},
        })
        self._post("notifications/initialized", notification=True)
        return result

    def list_tools(self) -> dict[str, dict[str, Any]]:
        result = self._post("tools/list")
        return {tool["name"]: tool for tool in result.get("tools", [])}

    def read_resource(self, uri: str) -> Any:
        result = self._post("resources/read", {"uri": uri})
        contents = result.get("contents", [])
        if not contents:
            raise McpError(f"Resource {uri!r} returned no contents")
        item = contents[0]
        text = item.get("text")
        if text is None:
            return item
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        vlog(3, "TOOL", f"Calling {name} arguments={json.dumps(arguments, ensure_ascii=False)}")
        result = self._post("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            text = "\n".join(x.get("text", "") for x in result.get("content", []) if x.get("type") == "text")
            raise McpError(f"Tool {name!r} failed: {text or result}")

        # ida-pro-mcp intentionally previews tool results larger than 50,000
        # serialized characters. The complete object is cached and exposed at
        # _meta.ida_mcp.download_url. Always follow that URL before parsing.
        meta = (result.get("_meta") or {}).get("ida_mcp") or {}
        if meta.get("output_truncated"):
            download_url = meta.get("download_url")
            if not download_url:
                raise McpError(f"Tool {name!r} was truncated but supplied no download URL")
            vlog(4, "TOOL", f"{name} output was truncated; following download URL")
            return self._download_json(str(download_url))

        if "structuredContent" in result:
            data = result["structuredContent"]
            if isinstance(data, dict) and set(data) == {"result"}:
                return data["result"]
            return data
        texts = [x.get("text", "") for x in result.get("content", []) if x.get("type") == "text"]
        if not texts:
            return None
        joined = "\n".join(texts)
        try:
            return json.loads(joined)
        except json.JSONDecodeError:
            return joined


def extract_cursor_function(cursor: Any) -> tuple[str, str]:
    if not isinstance(cursor, dict):
        raise McpError(f"Unexpected ida://cursor payload: {cursor!r}")
    func = cursor.get("function") or cursor.get("func") or {}
    if isinstance(func, dict):
        addr = func.get("start") or func.get("start_ea") or func.get("addr")
        name = func.get("name")
    else:
        addr = None
        name = None
    addr = addr or cursor.get("addr") or cursor.get("ea")
    if not addr:
        raise McpError("IDA cursor is not inside a recognized function. Move the cursor into the function or pass --function.")
    if isinstance(addr, int):
        addr = hex(addr)
    return str(addr), str(name or addr)


def normalize_tool_item(data: Any) -> Any:
    # Some typed outputs are wrapped under their return type key by schema generation.
    if isinstance(data, dict) and len(data) == 1:
        only = next(iter(data.values()))
        if isinstance(only, (dict, list)):
            return only
    return data


def resolve_function_identity(client: CurlMcpClient, query: str) -> tuple[str, str] | None:
    """Resolve an address/name/label to the containing canonical IDA function."""
    vlog(5, "RESOLVE", f"Resolving target {query}")
    result = normalize_tool_item(client.call_tool("lookup_funcs", {"queries": query}))
    if isinstance(result, list) and result:
        entry = result[0]
        fn = entry.get("fn") or {}
        if fn:
            addr = fn.get("addr") or fn.get("start_ea") or fn.get("start")
            name = fn.get("name") or query
            if addr is not None:
                resolved = (str(addr), str(name))
                vlog(5, "RESOLVE", f"Resolved {query} -> {resolved[1]} @ {resolved[0]}")
                return resolved
    vlog(5, "RESOLVE", f"Unable to resolve {query}")
    return None


def get_function_identity(client: CurlMcpClient, query: str) -> tuple[str, str]:
    resolved = resolve_function_identity(client, query)
    return resolved if resolved is not None else (query, query)


def render_disasm_page(result: Any) -> tuple[list[str], dict[str, Any]]:
    result = normalize_tool_item(result)
    if not isinstance(result, dict):
        raise McpError(f"Unexpected disasm result: {result!r}")
    if result.get("error"):
        raise McpError(str(result["error"]))

    asm = result.get("asm")
    if not isinstance(asm, dict):
        raise McpError(f"Disasm returned no assembly object: {result!r}")

    lines: list[str] = []
    for item in asm.get("lines", []):
        if isinstance(item, str):
            lines.append(item)
            continue
        addr = str(item.get("addr", ""))
        insn = str(item.get("instruction", ""))
        label = item.get("label")
        if label:
            lines.append(f"\n{label}:")
        line = f"{addr:>16}  {insn}" if addr else insn
        comments = item.get("comments") or []
        if isinstance(comments, str):
            comments = [comments]
        if comments:
            line += "  ; " + " | ".join(str(x) for x in comments)
        refs = item.get("refs") or []
        if refs:
            line += "  ; refs: " + json.dumps(refs, ensure_ascii=False)
        lines.append(line)
    return lines, result.get("cursor") or {"done": True}


def fetch_full_disasm(client: CurlMcpClient, addr: str, page_size: int) -> str:
    offset = 0
    page = 0
    vlog(2, "EXPORT-DISASM", f"Start addr={addr} page_size={page_size}")
    output: list[str] = []
    while True:
        raw = client.call_tool("disasm", {
            "addr": addr,
            "max_instructions": page_size,
            "offset": offset,
            "include_total": offset == 0,
        })
        lines, cursor = render_disasm_page(raw)
        page += 1
        output.extend(lines)
        vlog(4, "EXPORT-DISASM", f"addr={addr} page={page} offset={offset} lines={len(lines)} total_lines={len(output)} done={bool(cursor.get('done'))}")
        if cursor.get("done"):
            break
        next_offset = cursor.get("next")
        if next_offset is None or int(next_offset) <= offset:
            raise McpError(f"Invalid disasm cursor for {addr}: {cursor}")
        offset = int(next_offset)
    vlog(2, "EXPORT-DISASM", f"Complete addr={addr} pages={page} lines={len(output)}")
    return "\n".join(output).rstrip() + "\n"


def fetch_decompile(client: CurlMcpClient, addr: str) -> str:
    vlog(2, "EXPORT-DECOMPILE", f"Start addr={addr}")
    result = normalize_tool_item(client.call_tool("decompile", {"addr": addr, "include_addresses": True}))
    if not isinstance(result, dict):
        return str(result)
    if result.get("error") and not result.get("code"):
        return f"/* Decompilation failed: {result['error']} */\n"
    code = str(result.get("code") or "/* No pseudocode returned. */") + "\n"
    vlog(2, "EXPORT-DECOMPILE", f"Complete addr={addr} chars={len(code)}")
    return code


def fetch_callees(client: CurlMcpClient, addr: str) -> list[dict[str, Any]]:
    result = normalize_tool_item(client.call_tool("callees", {"addrs": addr, "limit": 500}))
    if isinstance(result, list) and result:
        return list(result[0].get("callees") or [])
    if isinstance(result, dict):
        return list(result.get("callees") or [])
    return []




def fetch_direct_code_edges(client: CurlMcpClient, addr: str, page_size: int, function_timeout: int = 300) -> list[dict[str, str]]:
    """Return direct CALL and cross-function JMP targets in instruction order.

    The normal ``callees`` tool does not include tail transfers implemented as
    ``jmp other_function``. This walks the real disassembly and resolves each
    direct target to its containing canonical IDA function. Register/memory
    indirect transfers are intentionally skipped because they have no concrete
    static destination.
    """
    started = time.monotonic()
    deadline = started + function_timeout if function_timeout > 0 else None
    vlog(2, "DISCOVERY", f"Start function={addr} page_size={page_size} function_timeout={function_timeout}s")

    def check_deadline() -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise FunctionTimeoutError(f"Discovery for {addr} exceeded {function_timeout} seconds")

    offset = 0
    page = 0
    instruction_count = 0
    candidates: list[tuple[str, str, str]] = []
    candidate_keys: set[tuple[str, str]] = set()
    while True:
        check_deadline()
        raw = normalize_tool_item(client.call_tool("disasm", {
            "addr": addr,
            "max_instructions": page_size,
            "offset": offset,
            "include_total": offset == 0,
        }))
        if not isinstance(raw, dict) or not isinstance(raw.get("asm"), dict):
            raise McpError(f"Unexpected disasm result while discovering edges for {addr}: {raw!r}")
        page += 1
        page_lines = raw["asm"].get("lines", [])
        instruction_count += len(page_lines)
        vlog(4, "DISCOVERY-PAGE", f"function={addr} page={page} offset={offset} instructions={len(page_lines)} total_instructions={instruction_count}")
        for item in page_lines:
            if not isinstance(item, dict):
                continue
            instruction = str(item.get("instruction") or "").strip()
            match = re.match(r"^(call|jmp)\s+(.+?)\s*$", instruction, re.IGNORECASE)
            if not match:
                continue
            kind = "call" if match.group(1).lower() == "call" else "tail_jump"
            operand = match.group(2).split(";", 1)[0].strip()
            operand = re.sub(r"^(?:short|near|far)\s+", "", operand, flags=re.IGNORECASE)
            operand = re.sub(r"^(?:cs|ds|ss|es|fs|gs):", "", operand, flags=re.IGNORECASE)
            # Skip register, pointer, and memory-indirect transfers.
            if re.search(r"[\[\]]", operand) or re.fullmatch(
                r"(?:r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|10|11|12|13|14|15)|e(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][lh])",
                operand, re.IGNORECASE,
            ):
                continue
            # Remove IDA decorations while preserving a symbol or address.
            operand = operand.split()[0].rstrip(",")
            if operand:
                key = (kind, operand.lower())
                if key not in candidate_keys:
                    candidate_keys.add(key)
                    candidates.append((kind, operand, str(item.get("addr") or "")))
                    vlog(6, "DISCOVERY-CANDIDATE", f"function={addr} type={kind} instruction={item.get('addr') or '-'} target={operand}")
        cursor = raw.get("cursor") or {"done": True}
        if cursor.get("done"):
            break
        next_offset = cursor.get("next")
        if next_offset is None or int(next_offset) <= offset:
            raise McpError(f"Invalid disasm cursor while discovering edges for {addr}: {cursor}")
        offset = int(next_offset)

    vlog(4, "DISCOVERY", f"Scanned function={addr} pages={page} instructions={instruction_count} unique_candidates={len(candidates)}")
    check_deadline()
    current = resolve_function_identity(client, addr)
    current_key = addr_key(current[0] if current else addr)
    edges: list[dict[str, str]] = []
    seen_edges: set[tuple[str, int | str]] = set()
    for candidate_index, (kind, target, insn_addr) in enumerate(candidates, 1):
        check_deadline()
        if candidate_index == 1 or candidate_index % 25 == 0 or candidate_index == len(candidates):
            vlog(4, "DISCOVERY-PROGRESS", f"function={addr} resolving={candidate_index}/{len(candidates)} edges={len(edges)} target={target}")
        vlog(5, "DISCOVERY-RESOLVE", f"function={addr} candidate={candidate_index}/{len(candidates)} type={kind} target={target} instruction={insn_addr or '-'}")
        resolved = resolve_function_identity(client, target)
        if resolved is None:
            vlog(5, "DISCOVERY-SKIP", f"function={addr} unresolved target={target}")
            continue
        target_addr, target_name = resolved
        target_key = addr_key(target_addr)
        # A JMP to a loc_ label inside the same function is ordinary internal
        # control flow, not another function.
        if kind == "tail_jump" and target_key == current_key:
            vlog(5, "DISCOVERY-SKIP", f"function={addr} internal tail jump target={target_name} @ {target_addr}")
            continue
        edge_key = (kind, target_key)
        if edge_key in seen_edges:
            vlog(5, "DISCOVERY-SKIP", f"function={addr} duplicate edge type={kind} target={target_name} @ {target_addr}")
            continue
        seen_edges.add(edge_key)
        edges.append({
            "type": kind,
            "addr": target_addr,
            "name": target_name,
            "instruction_addr": insn_addr,
        })
        vlog(5, "DISCOVERY-EDGE", f"function={addr} type={kind} -> {target_name} @ {target_addr}")
    vlog(2, "DISCOVERY", f"Complete function={addr} pages={page} instructions={instruction_count} candidates={len(candidates)} edges={len(edges)} duration={time.monotonic()-started:.3f}s")
    return edges


class Colors:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"


def enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def color(text: str, code: str) -> str:
    return f"{code}{text}{Colors.RESET}" if sys.stdout.isatty() else text


def status(stage: str, message: str, *, tone: str = "cyan") -> None:
    palette = {
        "cyan": Colors.CYAN,
        "green": Colors.GREEN,
        "yellow": Colors.YELLOW,
        "red": Colors.RED,
        "blue": Colors.BLUE,
        "magenta": Colors.MAGENTA,
    }
    prefix = color(f"[{stage}]", palette.get(tone, Colors.CYAN) + Colors.BOLD)
    print(f"{prefix} {message}", flush=True)


_console_lock = threading.Lock()


def console_print(message: str = "") -> None:
    with _console_lock:
        print(message, flush=True)


def format_function(info: FunctionInfo) -> str:
    """Render a function name and address with restrained, readable colors."""
    name = color(info.name, Colors.WHITE + Colors.BOLD)
    separator = color(" @ ", Colors.DIM)
    address = color(info.addr, Colors.CYAN)
    return f"{name}{separator}{address}"


class HealthMonitor:
    """Dedicated MCP health checker shared by discovery and export workers."""

    def __init__(self, args: argparse.Namespace, required_tools: set[str], stats: RunStats):
        self.args = args
        self.required_tools = required_tools
        self.stats = stats
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.healthy_event = threading.Event()
        self.healthy_event.set()
        self.state = "OK"
        self.last_ok = time.monotonic()
        self.last_error = ""
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.thread is None:
            self.thread = threading.Thread(target=self._run, name="ida-health", daemon=True)
            self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=2.0)

    def mark_initial_ok(self) -> None:
        with self.lock:
            self.state = "OK"
            self.last_ok = time.monotonic()
            self.last_error = ""
            self.healthy_event.set()

    def snapshot(self) -> tuple[str, float, str]:
        with self.lock:
            return self.state, max(0.0, time.monotonic() - self.last_ok), self.last_error

    def wait_until_healthy(self) -> None:
        while not self.stop_event.is_set():
            if self.healthy_event.wait(timeout=1.0):
                return
        raise McpError("Health monitor stopped while waiting for MCP recovery")

    def _check(self) -> None:
        with self.lock:
            previous_state = self.state
            self.state = "CHECK"
        self.stats.increment("health_checks")
        try:
            client = CurlMcpClient(
                self.args.server, curl=self.args.curl, timeout=max(1, self.args.health_timeout)
            )
            client.initialize()
            tools = client.list_tools()
            missing = sorted(self.required_tools - set(tools))
            if missing:
                raise McpError("missing tools: " + ", ".join(missing))
            with self.lock:
                self.state = "OK"
                self.last_ok = time.monotonic()
                self.last_error = ""
                self.healthy_event.set()
            if previous_state == "FAIL":
                self.stats.increment("health_recoveries")
        except Exception as exc:
            with self.lock:
                self.state = "FAIL"
                self.last_error = str(exc)
                self.healthy_event.clear()
            self.stats.increment("health_failures")

    def _run(self) -> None:
        interval = max(1, self.args.health_interval)
        while not self.stop_event.wait(interval):
            self._check()
            # After a failed scheduled check, do not make workers wait another
            # two minutes. Probe every 10 seconds until MCP recovers.
            while not self.stop_event.is_set() and not self.healthy_event.is_set():
                if self.stop_event.wait(10):
                    return
                self._check()




@dataclass
class DebugEvent:
    when: float
    level: int
    thread: str
    category: str
    message: str
    line: str


@dataclass
class WorkerDebugState:
    last_event: float = 0.0
    stage: str = "Waiting"
    category: str = "-"
    function: str = "-"
    detail: str = "No activity yet"
    request_method: str = "-"
    request_started: float = 0.0
    request_duration: float = 0.0
    request_bytes: int = 0
    request_rc: str = "-"
    page: int = 0
    offset: int = 0
    instructions: int = 0
    candidates_done: int = 0
    candidates_total: int = 0
    edges: int = 0
    retries: int = 0
    unresolved: int = 0
    duplicates: int = 0
    skipped: int = 0
    started: float = 0.0
    address: str = "-"


class LiveDebugPanel:
    """Detailed live verbose panel rendered above Discovery/Export Status.

    Verbosity is cumulative. Higher levels keep all lower-level information and
    add progressively deeper request, paging, target-resolution, and raw MCP
    diagnostics without replacing the live Discovery Status dashboard.
    """

    def __init__(self, level: int, max_events: int = 12):
        self.level = max(1, min(6, int(level)))
        self.max_events = max(4, max_events)
        self.lock = threading.Lock()
        self.events: deque[DebugEvent] = deque(maxlen=max(60, self.max_events * 6))
        self.workers: dict[str, WorkerDebugState] = {}
        self.category_counts: dict[str, int] = {}
        self.total_events = 0

    @staticmethod
    def _kv(message: str, key: str) -> str | None:
        match = re.search(rf"(?:^|\\s){re.escape(key)}=([^\\s]+)", message)
        return match.group(1) if match else None

    @staticmethod
    def _as_int(value: str | None, default: int = 0) -> int:
        if value is None:
            return default
        try:
            return int(value, 0)
        except (TypeError, ValueError):
            return default

    def _state_for(self, thread: str) -> WorkerDebugState:
        return self.workers.setdefault(thread, WorkerDebugState())

    def add(self, level: int, thread: str, category: str, message: str, line: str) -> None:
        now = time.monotonic()
        event = DebugEvent(now, level, thread, category, message, line)
        with self.lock:
            self.events.append(event)
            self.total_events += 1
            self.category_counts[category] = self.category_counts.get(category, 0) + 1

            # Track worker-specific activity. MCP messages are emitted from the
            # worker thread, so they also update that worker's current request.
            if thread.startswith(("ida-discover_", "ida-export_")):
                state = self._state_for(thread)
                state.last_event = now
                state.category = category
                state.detail = message.replace("\r", " ").replace("\n", " ")

                fn = self._kv(message, "function")
                if fn:
                    state.address = fn
                    if state.function == "-":
                        state.function = fn
                elif message.startswith(("Assigned ", "Finished ", "Failed ")):
                    match = re.search(r"^(?:Assigned|Finished|Failed)\s+([^\s]+)\s+@\s+([^\s]+)", message)
                    if match:
                        state.function = match.group(1)
                        state.address = match.group(2)
                    else:
                        match = re.search(r"^(?:Assigned|Finished|Failed)\s+([^\s]+)", message)
                        if match:
                            state.function = match.group(1)

                if category == "WORKER-DISCOVER":
                    state.stage = "Discovering"
                    if message.startswith("Assigned"):
                        state.started = now
                        state.page = 0
                        state.offset = 0
                        state.instructions = 0
                        state.candidates_done = 0
                        state.candidates_total = 0
                        state.edges = 0
                        state.unresolved = 0
                        state.duplicates = 0
                        state.skipped = 0
                    elif message.startswith("Finished"):
                        state.stage = "Completed"
                    elif message.startswith("Failed"):
                        state.stage = "Failed"
                elif category == "WORKER-EXPORT":
                    state.stage = "Exporting"
                    if message.startswith("Finished"):
                        state.stage = "Completed"
                elif category == "DISCOVERY-PAGE":
                    state.stage = "Reading disassembly"
                    state.page = self._as_int(self._kv(message, "page"), state.page)
                    state.offset = self._as_int(self._kv(message, "offset"), state.offset)
                    state.instructions = self._as_int(
                        self._kv(message, "total_instructions"),
                        self._as_int(self._kv(message, "instructions"), state.instructions),
                    )
                elif category == "DISCOVERY-PROGRESS":
                    state.stage = "Resolving targets"
                    resolving = self._kv(message, "resolving")
                    if resolving and "/" in resolving:
                        left, right = resolving.split("/", 1)
                        state.candidates_done = self._as_int(left, state.candidates_done)
                        state.candidates_total = self._as_int(right, state.candidates_total)
                    state.edges = self._as_int(self._kv(message, "edges"), state.edges)
                elif category == "DISCOVERY-RESOLVE":
                    state.stage = "Resolving target"
                    candidate = self._kv(message, "candidate")
                    if candidate and "/" in candidate:
                        left, right = candidate.split("/", 1)
                        state.candidates_done = self._as_int(left, state.candidates_done)
                        state.candidates_total = self._as_int(right, state.candidates_total)
                elif category == "DISCOVERY-EDGE":
                    state.stage = "Adding edge"
                    state.edges += 1
                elif category == "DISCOVERY-SKIP":
                    state.stage = "Skipping target"
                    state.skipped += 1
                    if "unresolved" in message:
                        state.unresolved += 1
                    if "duplicate" in message:
                        state.duplicates += 1
                elif category == "EXPORT-DISASM":
                    state.stage = "Exporting assembly"
                    state.page = self._as_int(self._kv(message, "page"), state.page)
                elif category == "EXPORT-DECOMPILE":
                    state.stage = "Decompiling"
                elif category == "RETRY":
                    state.stage = "Retrying"
                    state.retries += 1
                elif category == "TIMEOUT":
                    state.stage = "Timed out"
                elif category == "MCP":
                    if message.startswith("POST method="):
                        state.stage = "Waiting for MCP"
                        state.request_method = self._kv(message, "method") or "-"
                        state.request_started = now
                        state.request_rc = "..."
                    elif message.startswith("POST complete"):
                        state.request_method = self._kv(message, "method") or state.request_method
                        duration = self._kv(message, "duration")
                        if duration:
                            try:
                                state.request_duration = float(duration.rstrip("s"))
                            except ValueError:
                                pass
                        state.request_bytes = self._as_int(self._kv(message, "response_bytes"), state.request_bytes)
                        state.request_rc = self._kv(message, "rc") or state.request_rc
                        state.request_started = 0.0
                elif category == "MCP-DOWNLOAD":
                    state.stage = "Downloading MCP result"
                elif category in {"MCP-PAYLOAD", "MCP-HEADERS", "CURL"}:
                    # Keep the useful stage instead of replacing it with "raw".
                    pass

    @staticmethod
    def _watch_state(age: float, request_age: float = 0.0) -> tuple[str, str]:
        # These labels are diagnostic hints, not proof that a worker is dead.
        effective_age = max(age, request_age)
        if effective_age < 30:
            return "LIVE", Colors.GREEN + Colors.BOLD
        if effective_age < 120:
            return "SLOW", Colors.YELLOW + Colors.BOLD
        if effective_age < 600:
            return "STALLED?", Colors.MAGENTA + Colors.BOLD
        return "FROZEN?", Colors.RED + Colors.BOLD

    @staticmethod
    def _trim(text: str, width: int) -> str:
        text = text.replace("\r", " ").replace("\n", " ")
        return text if len(text) <= width else text[: max(0, width - 3)] + "..."

    def _event_limit(self) -> int:
        return {1: 5, 2: 7, 3: 9, 4: 11, 5: 14, 6: 18}[self.level]

    def lines(self) -> list[str]:
        now = time.monotonic()
        with self.lock:
            events = list(self.events)[-self._event_limit():]
            workers = {k: WorkerDebugState(**vars(v)) for k, v in self.workers.items()}
            total_events = self.total_events
            counts = dict(self.category_counts)

        watched = {}
        state_counts = {"LIVE": 0, "SLOW": 0, "STALLED?": 0, "FROZEN?": 0}
        for name, worker in workers.items():
            age = now - worker.last_event if worker.last_event else 0.0
            request_age = now - worker.request_started if worker.request_started else 0.0
            watch, watch_color = self._watch_state(age, request_age)
            watched[name] = (watch, watch_color, age, request_age)
            state_counts[watch] += 1

        lines = [
            color(f"Debug Status (Verbose {self.level}/6)", Colors.YELLOW + Colors.BOLD),
            (
                f"Events: {total_events:,}  Workers tracked: {len(workers)}  "
                f"Live: {state_counts['LIVE']}  Slow: {state_counts['SLOW']}  "
                f"Stalled?: {state_counts['STALLED?']}  Frozen?: {state_counts['FROZEN?']}"
            ),
        ]

        # Every verbose level uses the same permanent live worker bar.
        # Higher levels expand each row with progressively deeper diagnostics.
        lines += [
            "",
            color("Worker Debug", Colors.YELLOW + Colors.BOLD),
        ]

        if self.level == 1:
            lines += [
                f"{'Worker':<18} {'Watch':<10} {'Progress Age':<12} {'Stage':<22} Function",
                f"{'-' * 18} {'-' * 10} {'-' * 12} {'-' * 22} {'-' * 42}",
            ]
        else:
            lines += [
                f"{'Worker':<18} {'Watch':<10} {'Progress Age':<12} {'Stage':<22} {'Function':<20} Detail",
                f"{'-' * 18} {'-' * 10} {'-' * 12} {'-' * 22} {'-' * 20} {'-' * 52}",
            ]

        if not workers:
            if self.level == 1:
                lines.append("-                  WAITING    00:00:00     Waiting                No worker activity yet")
            else:
                lines.append("-                  WAITING    00:00:00     Waiting                -                    No worker activity yet")
        else:
            for name in sorted(workers, key=LiveStatusBase._worker_sort_key):
                worker = workers[name]
                watch, watch_color, age, request_age = watched[name]
                function = self._trim(worker.function, 42 if self.level == 1 else 20)
                watch_pad = " " * max(0, 10 - len(watch))

                if self.level == 1:
                    lines.append(
                        f"{name:<18.18} {color(watch, watch_color)}{watch_pad} "
                        f"{format_duration(age):<12} {self._trim(worker.stage, 22):<22} {function}"
                    )
                    continue

                detail_parts = []
                if self.level >= 2:
                    detail_parts.append(worker.detail)
                if self.level >= 3 and worker.request_method != "-":
                    req_age = format_duration(request_age) if request_age else f"{worker.request_duration:.3f}s"
                    detail_parts.append(
                        f"MCP={worker.request_method} rc={worker.request_rc} age/dur={req_age} bytes={worker.request_bytes:,}"
                    )
                if self.level >= 4 and (worker.page or worker.instructions or worker.offset):
                    detail_parts.append(
                        f"page={worker.page} offset={worker.offset:,} insns={worker.instructions:,}"
                    )
                if self.level >= 5 and (worker.candidates_total or worker.edges or worker.skipped):
                    detail_parts.append(
                        f"targets={worker.candidates_done:,}/{worker.candidates_total:,} edges={worker.edges:,} "
                        f"skip={worker.skipped:,} unresolved={worker.unresolved:,} dup={worker.duplicates:,}"
                    )
                if worker.retries:
                    detail_parts.append(f"retries={worker.retries}")
                if not detail_parts:
                    detail_parts.append("-")
                detail = self._trim(" | ".join(detail_parts), 90)
                lines.append(
                    f"{name:<18.18} {color(watch, watch_color)}{watch_pad} "
                    f"{format_duration(age):<12} {self._trim(worker.stage, 22):<22} "
                    f"{function:<20} {detail}"
                )

        # Show a focused statistics block for the most noteworthy active worker.
        # Priority: FROZEN? > STALLED? > SLOW > longest-running LIVE.
        active = []
        priority = {"FROZEN?": 4, "STALLED?": 3, "SLOW": 2, "LIVE": 1}
        for name, worker in workers.items():
            if worker.stage in {"Completed", "Failed"} or worker.function == "-":
                continue
            watch, _watch_color, age, request_age = watched[name]
            elapsed = now - worker.started if worker.started else age
            active.append((priority.get(watch, 0), elapsed, name, worker, watch, age, request_age))

        if active:
            _prio, elapsed, name, worker, watch, age, request_age = max(active, key=lambda item: (item[0], item[1]))
            lines += [
                "",
                color("Current Function Statistics", Colors.YELLOW + Colors.BOLD),
                f"Worker: {name}  Watch: {watch}  Function: {worker.function}  Address: {worker.address}",
                f"Stage: {worker.stage}  Elapsed: {format_duration(elapsed)}  Last progress: {format_duration(age)} ago",
            ]
            if self.level >= 2:
                lines.append(f"Current detail: {self._trim(worker.detail, 150)}  Retries: {worker.retries}")
            if self.level >= 3:
                req_text = format_duration(request_age) if request_age else f"{worker.request_duration:.3f}s"
                lines.append(
                    f"MCP method: {worker.request_method}  Request age/duration: {req_text}  "
                    f"RC: {worker.request_rc}  Response bytes: {worker.request_bytes:,}"
                )
            if self.level >= 4:
                lines.append(
                    f"Pages read: {worker.page:,}  Offset: {worker.offset:,}  "
                    f"Instructions read: {worker.instructions:,}"
                )
            if self.level >= 5:
                lines.append(
                    f"Targets resolved: {worker.candidates_done:,}/{worker.candidates_total:,}  "
                    f"Accepted edges: {worker.edges:,}  Skipped: {worker.skipped:,}  "
                    f"Duplicates: {worker.duplicates:,}  Unresolved: {worker.unresolved:,}"
                )

        # V3+ includes aggregate MCP/request metrics. V4+ paging metrics. V5+
        # resolution metrics. V6 raw payload/header events remain in
        # the bounded recent-event table below.
        if self.level >= 3:
            mcp_total = counts.get("MCP", 0) + counts.get("MCP-DOWNLOAD", 0)
            lines += [
                "",
                color("Live Counters", Colors.YELLOW + Colors.BOLD),
                f"MCP events: {mcp_total:,}  Retries: {counts.get('RETRY', 0):,}  "
                f"Timeouts: {counts.get('TIMEOUT', 0):,}  Failures: "
                f"{counts.get('WORKER-DISCOVER', 0) + counts.get('WORKER-EXPORT', 0):,} worker lifecycle events",
            ]
        if self.level >= 4:
            lines.append(
                f"Disassembly pages: {counts.get('DISCOVERY-PAGE', 0) + counts.get('EXPORT-DISASM', 0):,}  "
                f"Progress checkpoints: {counts.get('DISCOVERY-PROGRESS', 0):,}  "
                f"Full-result downloads: {counts.get('MCP-DOWNLOAD', 0):,}"
            )
        if self.level >= 5:
            lines.append(
                f"Resolved edges: {counts.get('DISCOVERY-EDGE', 0):,}  "
                f"Resolution attempts: {counts.get('DISCOVERY-RESOLVE', 0):,}  "
                f"Skipped targets: {counts.get('DISCOVERY-SKIP', 0):,}"
            )
        if self.level >= 6:
            lines.append(
                f"Raw payloads: {counts.get('MCP-PAYLOAD', 0):,}  Headers: {counts.get('MCP-HEADERS', 0):,}  "
                f"Curl commands: {counts.get('CURL', 0):,}"
            )

        lines += [
            "",
            color(f"Recent Debug Events (latest {self._event_limit()})", Colors.YELLOW + Colors.BOLD),
            f"{'Age':<10} {'V':<3} {'Worker':<18} {'Category':<22} Message",
            f"{'-' * 10} {'-' * 3} {'-' * 18} {'-' * 22} {'-' * 78}",
        ]
        if not events:
            lines.append("00:00:00  -   -                  -                      No debug events yet")
        else:
            for event in events:
                age = now - event.when
                message_width = 140 if self.level == 6 else 105
                lines.append(
                    f"{format_duration(age):<10} {event.level:<3} {event.thread:<18.18} "
                    f"{event.category:<22.22} {self._trim(event.message, message_width)}"
                )
        lines.append("")
        return lines


@dataclass
class WorkerActivity:
    state: str = "Idle"
    info: FunctionInfo | None = None
    started: float = 0.0
    detail: str = ""


class LiveStatusBase:
    """Fixed multi-line worker dashboard that redraws in place."""

    def __init__(self, health: HealthMonitor, stats: RunStats, workers: int, prefix: str):
        self.health = health
        self.stats = stats
        self.worker_count = workers
        self.worker_prefix = prefix
        self.finished = False
        self.rendered_lines = 0
        self.last_draw = 0.0
        self.workers: dict[str, WorkerActivity] = {
            f"{prefix}_{index}": WorkerActivity() for index in range(workers)
        }
        self.stop_event = threading.Event()
        self.ticker = threading.Thread(target=self._tick, daemon=True)
        self.ticker.start()

    @staticmethod
    def _duration(seconds: float) -> str:
        return format_duration(seconds)

    @staticmethod
    def _strip_ansi(text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def _health_text(self) -> str:
        state, age, _ = self.health.snapshot()
        if state == "OK":
            return color(f"OK {self._duration(age)} ago", Colors.GREEN + Colors.BOLD)
        if state == "CHECK":
            return color("CHECKING", Colors.YELLOW + Colors.BOLD)
        return color("FAILED - waiting for recovery", Colors.RED + Colors.BOLD)

    def _active_count(self) -> int:
        return sum(1 for activity in self.workers.values() if activity.state != "Idle")

    def _set_worker(self, state: str, info: FunctionInfo | None, detail: str = "", *, preserve_start: bool = False) -> None:
        name = threading.current_thread().name
        activity = self.workers.setdefault(name, WorkerActivity())
        if not preserve_start or activity.started <= 0:
            activity.started = time.monotonic()
        activity.state = state
        activity.info = info
        activity.detail = detail

    def _clear_worker(self) -> None:
        name = threading.current_thread().name
        self.workers[name] = WorkerActivity()

    def _worker_rows(self) -> list[str]:
        rows = [
            f"{'Worker':<18} {'State':<14} {'Elapsed':<10} Function",
            f"{'-' * 18} {'-' * 14} {'-' * 10} {'-' * 72}",
        ]
        now = time.monotonic()
        for name in sorted(self.workers, key=self._worker_sort_key):
            activity = self.workers[name]
            if activity.state == "Idle" or activity.info is None:
                state = color("Idle", Colors.DIM)
                elapsed = "00:00:00"
                function_text = "-"
            else:
                state_color = {
                    "Scanning": Colors.MAGENTA,
                    "Waiting": Colors.MAGENTA,
                    "Retrying": Colors.YELLOW,
                    "Preparing": Colors.YELLOW,
                    "Disassembling": Colors.BLUE,
                    "Decompiling": Colors.MAGENTA,
                    "Writing": Colors.CYAN,
                }.get(activity.state, Colors.WHITE)
                state = color(activity.state, state_color + Colors.BOLD)
                elapsed = self._duration(now - activity.started)
                function_text = f"{activity.info.name} @ {activity.info.addr}"
                if activity.detail:
                    function_text += f"  {activity.detail}"
            # ANSI color codes do not consume console columns, so pad the plain
            # state first and then color it.
            plain_state = activity.state if activity.state != "Idle" else "Idle"
            state_pad = " " * max(0, 14 - len(plain_state))
            rows.append(f"{name:<18} {state}{state_pad} {elapsed:<10} {function_text}")
        return rows

    @staticmethod
    def _worker_sort_key(name: str) -> tuple[str, int]:
        match = re.search(r"_(\d+)$", name)
        return name.rsplit("_", 1)[0], int(match.group(1)) if match else 999999

    def _draw_locked(self, lines: list[str]) -> None:
        if not sys.stdout.isatty():
            return
        now = time.monotonic()
        if self.last_draw and now - self.last_draw < 0.20:
            return
        self.last_draw = now
        if self.rendered_lines:
            sys.stdout.write(f"\x1b[{self.rendered_lines}F")
        for line in lines:
            sys.stdout.write("\x1b[2K")
            sys.stdout.write(line)
            sys.stdout.write("\n")
        sys.stdout.flush()
        self.rendered_lines = len(lines)

    def _tick(self) -> None:
        while not self.stop_event.wait(1.0):
            with _console_lock:
                if not self.finished:
                    self._render_locked()

    def close(self) -> None:
        self.finished = True
        self.stop_event.set()
        self.ticker.join(timeout=1.5)

    def _render_locked(self) -> None:
        raise NotImplementedError


class DiscoveryStatusLine(LiveStatusBase):
    def __init__(self, root: FunctionInfo, health: HealthMonitor, stats: RunStats, workers: int):
        self.found = 1
        self.queued = 1
        self.scanned = 0
        self.root = root
        super().__init__(health, stats, workers, "ida-discover")
        with _console_lock:
            self._render_locked()

    def _render_locked(self) -> None:
        debug_lines = VERBOSE.panel.lines() if VERBOSE.panel is not None else []
        lines = [
            *debug_lines,
            color("Discovery Status", Colors.CYAN + Colors.BOLD),
            (
                f"Found: {color(f'{self.found:,}', Colors.GREEN + Colors.BOLD)}  "
                f"Queued: {color(f'{self.queued:,}', Colors.YELLOW + Colors.BOLD)}  "
                f"Active: {color(f'{self._active_count():,}', Colors.BLUE + Colors.BOLD)}  "
                f"Processed: {color(f'{self.scanned:,}', Colors.WHITE + Colors.BOLD)}  "
                f"Elapsed: {color(format_duration(self.stats.elapsed()), Colors.WHITE + Colors.BOLD)}  "
                f"Health: {self._health_text()}"
            ),
            "",
            *self._worker_rows(),
        ]
        self._draw_locked(lines)

    def worker_started(self, info: FunctionInfo) -> None:
        with _console_lock:
            self.queued = max(0, self.queued - 1)
            self._set_worker("Scanning", info)
            self._render_locked()

    def worker_retry(self, info: FunctionInfo, attempt: int, retries: int, delay: float) -> None:
        with _console_lock:
            self._set_worker("Retrying", info, f"attempt {attempt}/{retries}, retry in {delay:g}s", preserve_start=True)
            self._render_locked()

    def worker_finished(self, info: FunctionInfo) -> None:
        with _console_lock:
            self._clear_worker()
            self.scanned += 1
            self._render_locked()

    def add_discovered(self, info: FunctionInfo) -> None:
        with _console_lock:
            self.found += 1
            self.queued += 1
            self._render_locked()

    def finish(self, total: int) -> None:
        with _console_lock:
            self.found = total
            self.queued = 0
            for name in list(self.workers):
                self.workers[name] = WorkerActivity()
            self.last_draw = 0.0
            self._render_locked()
        self.close()


class ExportStatusLine(LiveStatusBase):
    def __init__(self, total: int, health: HealthMonitor, stats: RunStats, workers: int):
        self.total = total
        self.completed = 0
        super().__init__(health, stats, workers, "ida-export")
        with _console_lock:
            self._render_locked()

    def _render_locked(self) -> None:
        debug_lines = VERBOSE.panel.lines() if VERBOSE.panel is not None else []
        lines = [
            *debug_lines,
            color("Export Status", Colors.CYAN + Colors.BOLD),
            (
                f"Completed: {color(f'{self.completed:,}/{self.total:,}', Colors.GREEN + Colors.BOLD)}  "
                f"Active: {color(f'{self._active_count():,}', Colors.BLUE + Colors.BOLD)}  "
                f"Remaining: {color(f'{max(0, self.total - self.completed):,}', Colors.YELLOW + Colors.BOLD)}  "
                f"Elapsed: {color(format_duration(self.stats.elapsed()), Colors.WHITE + Colors.BOLD)}  "
                f"Health: {self._health_text()}"
            ),
            "",
            *self._worker_rows(),
        ]
        self._draw_locked(lines)

    def notify(self, stage: str, info: FunctionInfo, detail: str = "") -> None:
        with _console_lock:
            if stage == "Completed":
                self.completed += 1
                self._clear_worker()
            else:
                self._set_worker(stage, info, detail, preserve_start=(stage != "Preparing"))
            self._render_locked()

    def retry(self, info: FunctionInfo, attempt: int, retries: int, delay: float) -> None:
        with _console_lock:
            self._set_worker("Retrying", info, f"attempt {attempt}/{retries}, retry in {delay:g}s", preserve_start=True)
            self._render_locked()

    def finish(self) -> None:
        with _console_lock:
            for name in list(self.workers):
                self.workers[name] = WorkerActivity()
            self.last_draw = 0.0
            self._render_locked()
        self.close()

def make_client(args: argparse.Namespace) -> CurlMcpClient:
    client = CurlMcpClient(args.server, curl=args.curl, timeout=args.timeout)
    client.initialize()
    return client


class ThreadClients:
    """One initialized MCP client/session per worker thread."""
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.local = threading.local()

    def get(self) -> CurlMcpClient:
        client = getattr(self.local, "client", None)
        if client is None:
            client = make_client(self.args)
            self.local.client = client
        return client

    def reset(self) -> None:
        self.local.client = None


def run_with_retry(
    clients: ThreadClients, health: HealthMonitor, operation: Callable[[], Any],
    *, retries: int, retry_delay: float, stats: RunStats, on_retry: Callable[[int, int, float], None] | None = None,
) -> Any:
    last_error: Exception | None = None
    had_retry = False
    for attempt in range(retries + 1):
        vlog(4, "RETRY", f"Attempt {attempt + 1}/{retries + 1}")
        health.wait_until_healthy()
        try:
            result = operation()
            if had_retry:
                stats.increment("retried_successfully")
            return result
        except FunctionTimeoutError as exc:
            vlog(1, "TIMEOUT", str(exc))
            raise
        except Exception as exc:
            last_error = exc
            vlog(2, "RETRY", f"Attempt {attempt + 1}/{retries + 1} failed: {type(exc).__name__}: {exc}")
            clients.reset()
            if attempt >= retries:
                break
            had_retry = True
            stats.increment("retry_attempts")
            delay = max(0.0, retry_delay) * (attempt + 1)
            if on_retry:
                on_retry(attempt + 1, retries, delay)
            if delay:
                vlog(2, "RETRY", f"Sleeping {delay:g}s before retry")
                time.sleep(delay)
    assert last_error is not None
    raise last_error


def write_section(fp, title: str, info: FunctionInfo, body: str) -> None:
    bar = "=" * 100
    fp.write(f"{bar}\n{title}\n")
    fp.write(f"Name: {info.name}\nAddress: {info.addr}\nDepth: {info.depth}\nDiscovered from: {info.source}\n")
    fp.write(f"{bar}\n\n{body.rstrip()}\n\n")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export an IDA function and every reachable internal function through ida-pro-mcp.")
    p.add_argument("--server", default="13337", help="MCP port, host:port, or full URL (default: 13337)")
    roots = p.add_mutually_exclusive_group()
    roots.add_argument("--function", help="Function name or address. Omit to use the current IDA cursor function.")
    roots.add_argument("--address", help="Explicit root address, with or without 0x (example: 0x7FF6E3BF5C90).")
    p.add_argument("--output", default="ida_exports", help="Parent output directory")
    p.add_argument("--page-size", type=int, default=50000, help="Instructions per disasm request, max 50000")
    p.add_argument("--include-external", action="store_true", help="Attempt to export external/import functions too")
    p.add_argument("--workers", type=int, default=0, help="Concurrent MCP workers; 0 selects automatically")
    p.add_argument("--timeout", type=int, default=600, help="Per-request curl timeout in seconds; 0 disables request timeouts")
    p.add_argument("--function-timeout", type=int, default=300, help="Maximum total discovery time for one function in seconds; 0 disables (default: 300)")
    p.add_argument("--retries", type=int, default=3, help="Retries after a timed-out or failed MCP operation (default: 3)")
    p.add_argument("--retry-delay", type=float, default=5.0, help="Base retry delay in seconds (default: 5)")
    p.add_argument("--health-interval", type=int, default=120, help="MCP health-check interval in seconds (default: 120)")
    p.add_argument("--health-timeout", type=int, default=20, help="Timeout for each health check in seconds (default: 20)")
    p.add_argument("--curl", default="curl.exe" if os.name == "nt" else "curl", help="curl executable")
    p.add_argument("--list-tools", action="store_true", help="Print enabled MCP tools and exit")
    p.add_argument(
        "--verbose", nargs="?", const=1, default=0, type=int, choices=range(0, 7), metavar="LEVEL",
        help="Enable diagnostic output at level 1-6. --verbose alone selects level 1.",
    )
    # Accepted for compatibility, but unlimited traversal remains mandatory.
    p.add_argument("--depth", type=int, default=-1, help=argparse.SUPPRESS)
    p.add_argument("--max-functions", type=int, default=0, help=argparse.SUPPRESS)
    return p.parse_args()


def auto_workers(requested: int) -> int:
    if requested > 0:
        return max(1, min(32, requested))
    cpu = os.cpu_count() or 8
    return max(4, min(16, cpu - 2))


def discover_one(
    pool: ThreadClients, health: HealthMonitor, info: FunctionInfo, page_size: int,
    retries: int, retry_delay: float, stats: RunStats, function_timeout: int, progress: DiscoveryStatusLine | None = None,
) -> tuple[FunctionInfo, list[dict[str, str]], str | None]:
    vlog(2, "WORKER-DISCOVER", f"Assigned {info.name} @ {info.addr} depth={info.depth} source={info.source}")
    if progress:
        progress.worker_started(info)
    try:
        edges = run_with_retry(
            pool, health, lambda: fetch_direct_code_edges(pool.get(), info.addr, page_size, function_timeout),
            retries=retries, retry_delay=retry_delay, stats=stats,
            on_retry=(lambda attempt, maximum, delay: progress.worker_retry(info, attempt, maximum, delay)) if progress else None,
        )
        vlog(2, "WORKER-DISCOVER", f"Finished {info.name} @ {info.addr} edges={len(edges)}")
        return info, edges, None
    except Exception as exc:
        vlog(1, "WORKER-DISCOVER", f"Failed {info.name} @ {info.addr}: {type(exc).__name__}: {exc}")
        return info, [], str(exc)
    finally:
        if progress:
            progress.worker_finished(info)

def discover_all_functions_parallel(
    clients: ThreadClients,
    health: HealthMonitor,
    root: FunctionInfo,
    page_size: int,
    workers: int,
    retries: int,
    retry_delay: float,
    stats: RunStats,
    function_timeout: int,
    progress: DiscoveryStatusLine | None = None,
) -> tuple[list[FunctionInfo], list[dict[str, str]], list[dict[str, str]]]:
    """Parallel breadth-first graph discovery with canonical-address deduplication."""
    discovered: list[FunctionInfo] = [root]
    edges: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    seen: set[int | str] = {addr_key(root.addr)}
    frontier: list[FunctionInfo] = [root]
    level = 0

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ida-discover") as executor:
        while frontier:
            vlog(1, "DISCOVERY-LEVEL", f"Submitting depth={level} functions={len(frontier)} discovered_total={len(discovered)}")
            # Submit the entire graph level concurrently, but consume results in
            # frontier order so discovery output and assigned discovery order stay
            # deterministic across runs. Slow earlier functions do not stop later
            # workers from running; only their console publication is buffered.
            futures = {
                executor.submit(discover_one, clients, health, info, page_size, retries, retry_delay, stats, function_timeout, progress): index
                for index, info in enumerate(frontier)
            }
            completed_results: dict[int, tuple[FunctionInfo, list[dict[str, str]], str | None]] = {}
            for future in as_completed(futures):
                completed_results[futures[future]] = future.result()
            next_frontier: list[FunctionInfo] = []
            for index in range(len(frontier)):
                parent, found_edges, error = completed_results[index]
                if error:
                    failures.append({"addr": parent.addr, "name": parent.name, "stage": "discover", "error": error})
                    continue
                for edge in found_edges:
                    key = addr_key(edge["addr"])
                    duplicate = key in seen
                    edges.append({
                        "caller_addr": parent.addr,
                        "caller_name": parent.name,
                        "callee_addr": edge["addr"],
                        "callee_name": edge["name"],
                        "edge_type": edge["type"],
                        "instruction_addr": edge.get("instruction_addr", ""),
                        "duplicate": str(duplicate).lower(),
                    })
                    if duplicate:
                        continue
                    seen.add(key)
                    child = FunctionInfo(edge["addr"], edge["name"], parent.depth + 1, parent.name)
                    discovered.append(child)
                    next_frontier.append(child)
                    if progress:
                        progress.add_discovered(child)
            vlog(1, "DISCOVERY-LEVEL", f"Completed depth={level} next_frontier={len(next_frontier)} discovered_total={len(discovered)} failures={len(failures)}")
            level += 1
            frontier = next_frontier
    return discovered, edges, failures


def export_one(
    clients: ThreadClients, health: HealthMonitor, info: FunctionInfo, page_size: int,
    retries: int, retry_delay: float, stats: RunStats,
    progress: ExportStatusLine | None = None,
) -> tuple[FunctionInfo, str, str, list[dict[str, str]]]:
    vlog(2, "WORKER-EXPORT", f"Assigned {info.name} @ {info.addr} depth={info.depth}")
    if progress:
        progress.notify("Preparing", info)
    local_failures: list[dict[str, str]] = []
    try:
        if progress:
            progress.notify("Disassembling", info)
        asm = run_with_retry(
            clients, health, lambda: fetch_full_disasm(clients.get(), info.addr, page_size),
            retries=retries, retry_delay=retry_delay, stats=stats,
            on_retry=(lambda attempt, maximum, delay: progress.retry(info, attempt, maximum, delay)) if progress else None,
        )
    except Exception as exc:
        asm = f"; Disassembly failed after {retries + 1} attempts: {exc}\n"
        local_failures.append({"addr": info.addr, "name": info.name, "stage": "disasm", "error": str(exc)})
    try:
        if progress:
            progress.notify("Decompiling", info)
        pseudo = run_with_retry(
            clients, health, lambda: fetch_decompile(clients.get(), info.addr),
            retries=retries, retry_delay=retry_delay, stats=stats,
            on_retry=(lambda attempt, maximum, delay: progress.retry(info, attempt, maximum, delay)) if progress else None,
        )
    except Exception as exc:
        pseudo = f"/* Decompilation failed after {retries + 1} attempts: {exc} */\n"
        local_failures.append({"addr": info.addr, "name": info.name, "stage": "decompile", "error": str(exc)})
    if progress:
        progress.notify("Completed", info)
    vlog(2, "WORKER-EXPORT", f"Finished {info.name} @ {info.addr} asm_chars={len(asm)} pseudo_chars={len(pseudo)} failures={len(local_failures)}")
    return info, asm, pseudo, local_failures

def main() -> int:
    global VERBOSE
    args = parse_args()
    VERBOSE = VerboseLogger(args.verbose)
    stats = RunStats()
    vlog(1, "STARTUP", f"Arguments: {vars(args)}")
    enable_windows_ansi()
    args.page_size = min(50000, max(1, args.page_size))
    workers = auto_workers(args.workers)

    control = CurlMcpClient(args.server, curl=args.curl, timeout=args.timeout)
    init = control.initialize()
    tools = control.list_tools()
    required = {"lookup_funcs", "disasm", "decompile"}
    missing = sorted(required - set(tools))
    if missing:
        raise McpError("Required tools are disabled or unavailable: " + ", ".join(missing))
    if args.list_tools:
        print("\n".join(sorted(tools)))
        return 0

    if args.address:
        address = args.address.strip()
        if not address.lower().startswith("0x"):
            address = "0x" + address
        try:
            int(address, 0)
        except ValueError as exc:
            raise McpError(f"Invalid --address value: {args.address}") from exc
        root_addr, root_name = get_function_identity(control, address)
    elif args.function:
        root_addr, root_name = get_function_identity(control, args.function)
    else:
        root_addr, root_name = extract_cursor_function(control.read_resource("ida://cursor"))
        root_addr, resolved_name = get_function_identity(control, root_addr)
        if resolved_name != root_addr:
            root_name = resolved_name

    stem = safe_name(root_name)
    out_dir = Path(args.output).resolve() / f"function_{stem}"
    out_dir.mkdir(parents=True, exist_ok=True)
    main_path = out_dir / f"Main_{stem}_function_we_are_in.txt"
    referenced_asm_path = out_dir / f"Extracted_referenced_functions_in_{stem}.txt"
    called_pseudo_path = out_dir / f"Extracted_called_functions_{stem}_pseudocode.txt"
    manifest_path = out_dir / f"Manifest_{stem}.json"

    worker_mode = "manual" if args.workers > 0 else "auto"

    console_print(f"{color('IDA MCP:', Colors.CYAN + Colors.BOLD)} {color(control.url, Colors.WHITE)}")
    server_text = f"{init.get('serverInfo', {}).get('name', 'unknown')} {init.get('serverInfo', {}).get('version', '')}".rstrip()
    console_print(f"{color('Server:', Colors.CYAN + Colors.BOLD)}  {color(server_text, Colors.WHITE)}")
    console_print(f"{color('Workers:', Colors.CYAN + Colors.BOLD)} {color(str(workers), Colors.WHITE + Colors.BOLD)} {color(f'({worker_mode})', Colors.DIM)}")
    if args.verbose:
        console_print(f"{color('Verbose:', Colors.CYAN + Colors.BOLD)} level {args.verbose} (live Debug Status enabled above worker status)")
    root_display = format_function(FunctionInfo(root_addr, root_name, 0, ''))
    console_print(f"{color('Root:', Colors.CYAN + Colors.BOLD)}    {root_display}")

    root_source = "--address" if args.address else ("--function" if args.function else "IDA cursor")
    root = FunctionInfo(root_addr, root_name, 0, root_source)
    clients = ThreadClients(args)
    health = HealthMonitor(args, required, stats)
    health.mark_initial_ok()
    health.start()

    if args.verbose and sys.stdout.isatty():
        VERBOSE.attach_panel(LiveDebugPanel(args.verbose, max_events={1: 5, 2: 7, 3: 9, 4: 11, 5: 14, 6: 18}[args.verbose]))
    stats.discovery_started = time.monotonic()
    discovery_status = DiscoveryStatusLine(root, health, stats, workers) if sys.stdout.isatty() else None
    if not sys.stdout.isatty():
        console_print(color("Discovering reachable functions...", Colors.CYAN + Colors.BOLD))
    all_functions, graph_edges, failures = discover_all_functions_parallel(
        clients, health, root, args.page_size, workers, args.retries, args.retry_delay, stats, args.function_timeout, discovery_status
    )
    if discovery_status:
        discovery_status.finish(len(all_functions))
    stats.discovery_finished = time.monotonic()
    console_print(f"{color('Functions discovered:', Colors.CYAN + Colors.BOLD)} {color(str(len(all_functions)), Colors.GREEN + Colors.BOLD)}")
    results: dict[int | str, tuple[FunctionInfo, str, str]] = {}
    total = len(all_functions)
    stats.export_started = time.monotonic()
    export_status = ExportStatusLine(total, health, stats, workers) if sys.stdout.isatty() else None
    if args.verbose:
        vlog(1, "EXPORT", f"Starting export of {total} functions with {workers} workers")
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ida-export") as executor:
        # Work remains fully concurrent. Every worker updates the same in-place
        # status line as it changes stage; final files are still written later in
        # deterministic discovery order.
        ordered_futures = [
            executor.submit(export_one, clients, health, info, args.page_size, args.retries, args.retry_delay, stats, export_status)
            for info in all_functions
        ]
        for future in ordered_futures:
            info, asm, pseudo, local_failures = future.result()
            failures.extend(local_failures)
            results[addr_key(info.addr)] = (info, asm, pseudo)
    if export_status:
        export_status.finish()
    vlog(1, "EXPORT", f"Export extraction complete functions={len(results)} failures={len(failures)}")
    stats.export_finished = time.monotonic()
    health.stop()

    exported: list[dict[str, Any]] = []
    # Preserve deterministic discovery order in output files even though extraction is concurrent.
    with main_path.open("w", encoding="utf-8", newline="\n") as main_fp, \
         referenced_asm_path.open("w", encoding="utf-8", newline="\n") as asm_fp, \
         called_pseudo_path.open("w", encoding="utf-8", newline="\n") as pseudo_fp:
        for info in all_functions:
            _, asm, pseudo = results[addr_key(info.addr)]
            if info.depth == 0:
                write_section(main_fp, "MAIN FUNCTION ASSEMBLY", info, asm)
                write_section(main_fp, "MAIN FUNCTION PSEUDOCODE", info, pseudo)
            else:
                write_section(asm_fp, "REFERENCED/CALLED FUNCTION ASSEMBLY", info, asm)
                write_section(pseudo_fp, "CALLED FUNCTION PSEUDOCODE", info, pseudo)
            exported.append({"addr": info.addr, "name": info.name, "depth": info.depth, "source": info.source})

    manifest = {
        "server": control.url,
        "root": {"addr": root.addr, "name": root.name},
        "recursive_traversal": "all_reachable_direct_calls_and_cross_function_tail_jumps",
        "parallel_workers": workers,
        "request_timeout_seconds": args.timeout,
        "retries": args.retries,
        "retry_delay_seconds": args.retry_delay,
        "health_interval_seconds": args.health_interval,
        "timing": {
            "discovery_seconds": round(stats.discovery_finished - stats.discovery_started, 3),
            "export_seconds": round(stats.export_finished - stats.export_started, 3),
            "total_seconds": round(stats.export_finished - stats.started, 3),
        },
        "retry_statistics": {
            "retry_attempts": stats.retry_attempts,
            "operations_recovered_after_retry": stats.retried_successfully,
        },
        "health_statistics": {
            "checks": stats.health_checks,
            "failed_checks": stats.health_failures,
            "recoveries": stats.health_recoveries,
        },
        "graph_edges": graph_edges,
        "include_external": args.include_external,
        "discovered_function_count": len(all_functions),
        "exported_function_count": len(exported),
        "queue_exhausted": True,
        "function_limit_reached": False,
        "failures": failures,
        "exported_functions": exported,
        "files": {
            "main": str(main_path),
            "referenced_assembly": str(referenced_asm_path),
            "called_pseudocode": str(called_pseudo_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    failed_functions = {addr_key(item.get("addr", "")) for item in failures if item.get("addr")}
    fully_successful = max(0, len(exported) - len(failed_functions))
    partial_or_failed = len(failed_functions)
    output_size = sum(path.stat().st_size for path in (main_path, referenced_asm_path, called_pseudo_path, manifest_path) if path.exists())

    console_print(color("=" * 60, Colors.CYAN))
    console_print(color("Export Summary", Colors.CYAN + Colors.BOLD))
    console_print(color("=" * 60, Colors.CYAN))
    console_print(f"Functions discovered : {len(all_functions):,}")
    console_print(f"Function records     : {len(exported):,}")
    console_print(f"Fully successful     : {fully_successful:,}")
    console_print(f"Partial/failed       : {partial_or_failed:,}")
    console_print(f"Failure operations   : {len(failures):,}")
    console_print(f"Retry attempts       : {stats.retry_attempts:,}")
    console_print(f"Recovered by retry   : {stats.retried_successfully:,}")
    console_print(f"Health checks        : {stats.health_checks:,}")
    console_print(f"Health failures      : {stats.health_failures:,}")
    console_print(f"Health recoveries    : {stats.health_recoveries:,}")
    console_print(f"Discovery time       : {format_duration(stats.discovery_finished - stats.discovery_started)}")
    console_print(f"Export time          : {format_duration(stats.export_finished - stats.export_started)}")
    console_print(f"Total runtime        : {format_duration(stats.export_finished - stats.started)}")
    console_print(f"Output size          : {output_size / (1024 * 1024):,.2f} MB")
    console_print(color("=" * 60, Colors.CYAN))
    if failures:
        status("WARN", f"{len(failures):,} extraction/discovery failures; see manifest", tone="yellow")
    console_print(color("Created:", Colors.CYAN + Colors.BOLD))
    console_print(f"  {color(str(main_path), Colors.GREEN)}")
    console_print(f"  {color(str(referenced_asm_path), Colors.GREEN)}")
    console_print(f"  {color(str(called_pseudo_path), Colors.GREEN)}")
    console_print(f"  {color(str(manifest_path), Colors.GREEN)}")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (McpError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
