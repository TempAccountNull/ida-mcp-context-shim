# hexport

A small, fast, self-contained **headless IDA MCP server** in C++ on top of
[`idalib`](https://docs.hex-rays.com/core/idalib/getting-started) (IDA-as-a-library).
It opens a database in-process and serves the exact set of tools our exporter needs —
no IDA GUI, no plugin install, no Python server, no third-party runtime.

Because everything runs in one process against idalib directly, the whole class of
problems that come with the out-of-process model disappears: no MCP output-preview
cache, no Hex-Rays `cfunc` cache blow-up (we manage it directly), no 120 s sync
timeouts, and no per-call HTTP/`curl` overhead.

## Credits

- The MCP wire protocol and the **tool set / result shapes** are modeled on
  [**mrexodia/ida-pro-mcp**](https://github.com/mrexodia/ida-pro-mcp) — hexport is an
  independent, dedicated reimplementation for our export workflow, kept
  drop-in-compatible with our existing exporter. Full credit to mrexodia for the
  reference design.
- Built on Hex-Rays' IDA SDK / `idalib`.

## Status / roadmap

- [x] **M1 — idalib core.** Builds via MSBuild (`hexport.vcxproj`) and opens a
      `.i64`/binary headlessly, enumerating functions (`src/main.cpp`). Validated:
      `functions: 60` on a test database. Toolchain, SDK link, and license all confirmed.
- [x] **M2 — MCP JSON-RPC core.** `initialize`/`tools/list`/`tools/call`/`resources/read`
      over stdio, on the idalib thread. Structured as a PCH + `Mcp` (protocol) and
      `McpCommands` (tools) using the SDK's own JSON (`parsejson`, no external lib).
      Validated: clean `serverInfo.name="hexport"`, `server_health` (module normalized
      `hexx64 - Copy.dll` -> `hexx64.dll`), and `list_funcs` in the exporter's shape.
- [x] **M3 — full toolset + DB lifecycle.** `disasm` (full, paged, labels+comments),
      `decompile` (full Hex-Rays pseudocode), `analyze_batch`, `list_funcs`,
      `entity_query`, `lookup_funcs`, `force_recompile`, and `open_database` /
      `close_database` / `list_databases` (open/close at any time, or `--open`/`--close`).
      Validated: real pseudocode + disasm, `truncated:false`. String dispatch (tools,
      methods, CLI flags) is a `switch` on a constexpr hash; the tool list is one
      `HEXPORT_TOOLS(X)` macro. **Live per-function status on stderr** while analyzing
      (`[hexport] 1/60  decompile  wWinMain @ 0x140001000`).
- [ ] **M4 — transports + wiring.** `--http` (per-instance ports 13337, 13338, …)
      alongside `--stdio`, plus `start_mcp.cmd`; then point the exporter's `--server` at it.

## Prerequisites

- IDA Pro 9.x with a valid **idalib** license (launch IDA once to accept terms; run the
  idalib activation per Hex-Rays docs).
- **Visual Studio 2022** (MSBuild + the v143 C++ toolset) and **git**. No CMake, Ninja,
  Rust, or LLVM — just MSBuild and a hand-written `.vcxproj`.
- The IDA **SDK is fetched automatically** into `src/dep/ida-sdk` on first build — you do
  not install it separately.

## Build

```cmd
build.cmd
```

`build.cmd` runs `setup_sdk.cmd`, then builds `hexport.vcxproj` (Release|x64) with MSBuild
(located via `vswhere`). The build is self-contained: `IdaSdk` resolves to
`src\dep\ida-sdk\src` relative to the project — no absolute paths. Override with
`/p:IdaSdk=<path>\src` to point at your own copy.

### SDK setup (`setup_sdk.cmd`, idempotent)

1. If `src/dep/ida-sdk` is missing, it `git clone`s
   <https://github.com/HexRaysSA/ida-sdk> into it; if it is already there, the pull is
   skipped.
2. It applies a **required fixup**. The SDK ships a few import libs only in the
   static-CRT (`_s`) lib folders, but the build links the dynamic-CRT folders — so the
   missing files must be copied across first, or the link fails with unresolved
   externals:
   - `x64_win_64_s\pro.lib` → `x64_win_64\`
   - `x86_win_32_s\{compress.lib, dumb.obj, int128.lib, pro.lib, unicode.lib}` → `x64_win_32\`

## Run (M1)

```cmd
set PATH=C:\Program Files\IDA Professional 9.4;%PATH%
build\hexport.exe "D:\path\to\your.i64"
```

M1 is validated: it opens the `.i64` headlessly via idalib and prints the function count
and the first few functions (e.g. `functions: 60` on a test database). idalib's own
console logging (and any GUI-only plugins that fail to load headlessly) is cosmetic; it
gets silenced in M2 so the stdio transport stays clean. M2–M4 build the MCP server on
this foundation.
