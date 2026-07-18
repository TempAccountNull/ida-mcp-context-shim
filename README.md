# Legal Disclaimer

> The shim is being provided for educational purposes only to help aid research against bad actors. Misusing it outside its original intentions may be illegal and is your responsibility. The owner of this repository cannot and will not be held liable for any consequences. Always follow your local laws and use this toolkit responsibly.

---

# IDA MCP Recursive Export Shim

> Export the complete reachable function context from IDA Pro through `ida-pro-mcp` instead of analyzing one function at a time.

The IDA MCP Recursive Export Shim is a multithreaded command-line utility that communicates directly with an `ida-pro-mcp` server. It starts from the function under the current IDA cursor, an explicit address, or a function name; recursively follows direct `CALL` instructions and cross-function tail `JMP` instructions; and exports assembly, Hex-Rays pseudocode, graph relationships, failures, timing, retries, health data, and run statistics.

<img width="1167" height="1142" alt="image" src="https://github.com/user-attachments/assets/ba591a17-5e17-49c0-880c-9a994ba2d318" />


## Requirements

| Requirement | Description |
|---|---|
| Python | Python 3.10 or newer |
| IDA Pro | The target database must be open |
| ida-pro-mcp | Must be running and connected to the intended IDA instance |
| curl | `curl.exe` on modern Windows, or `curl` on another platform |
| Hex-Rays | Optional, but required for pseudocode output |

No third-party Python packages are required.

## Quick Start

```cmd
run_export.cmd
run_export.cmd --server 13339
run_export.cmd --server 13339 --address 0x7FF6E3BF5C90
run_export.cmd --server 13339 --function UpdatePlayerStates
```

If neither `--address` nor `--function` is supplied, the exporter uses the function under the current IDA cursor.

The tested diagnostic form used during development is:

```cmd
run_export.cmd --server 13338 --function draw_debug_info --verbose 6 --timeout 30
```

Use the same command with any verbose level from `1` through `6`:

```cmd
run_export.cmd --server 13338 --function draw_debug_info --verbose 1 --timeout 30
run_export.cmd --server 13338 --function draw_debug_info --verbose 2 --timeout 30
run_export.cmd --server 13338 --function draw_debug_info --verbose 3 --timeout 30
run_export.cmd --server 13338 --function draw_debug_info --verbose 4 --timeout 30
run_export.cmd --server 13338 --function draw_debug_info --verbose 5 --timeout 30
run_export.cmd --server 13338 --function draw_debug_info --verbose 6 --timeout 30
```

## Three Console Stages

The exporter keeps the startup header visible and labels the active stage exactly as follows:

```text
Current stage: Scanning Functions
Current stage: Exporting Disassembly
Current stage: Finalize Results
```

### Scanning Functions

The exporter recursively discovers reachable functions, follows direct calls and cross-function tail jumps, resolves targets, deduplicates addresses, and builds the graph.

### Exporting Disassembly

The exporter retrieves the complete assembly and Hex-Rays pseudocode for every discovered function using the configured worker pool.

### Finalize Results

The exporter writes the four output files, creates the manifest, calculates final statistics, and prints the summary.

At a stage transition, the completed stage is removed and the fixed startup header is redrawn with only the new current stage. During normal live updates inside a stage, the dashboard is redrawn in place rather than clearing the entire console. This avoids flashing, prevents old dashboard frames from accumulating, and keeps only current information visible.

## What the Exporter Does

1. Connects to the selected `ida-pro-mcp` server.
2. Verifies that `lookup_funcs`, `disasm`, and `decompile` are enabled.
3. Resolves the root from `--address`, `--function`, or the current IDA cursor.
4. Recursively disassembles reachable functions.
5. Follows direct `CALL` instructions and cross-function tail `JMP` instructions.
6. Ignores local jumps such as `loc_xxx` when they remain inside the current function.
7. Deduplicates functions by canonical address.
8. Exports assembly and Hex-Rays pseudocode with multiple MCP workers.
9. Automatically follows `_meta.ida_mcp.download_url` when MCP returns a truncated preview.
10. Retries transient failures and recreates the affected worker session before retrying.
11. Monitors MCP health and pauses new work while the server is unavailable.
12. Writes deterministic output files and a JSON manifest.

# Command-Line Arguments

The table below lists every command-line argument accepted by the current exporter, including the two hidden compatibility arguments.

| Argument | Accepted value | Default | Description |
|:--|:--|:--|:--|
| **`--server`** | Port, `host:port`, or full URL | `13337` | Selects the `ida-pro-mcp` endpoint. A port such as `13339` becomes `http://127.0.0.1:13339/mcp`. A host and port such as `192.168.1.10:13337` becomes `http://192.168.1.10:13337/mcp`. A full HTTP or HTTPS URL is accepted. `/mcp` is appended when missing. |
| **`--function`** | Function name or address | Current IDA cursor | Selects the root by IDA function name or address. Examples: `UpdatePlayerStates`, `sub_7FF6E3BF5C90`, or `0x7FF6E3BF5C90`. Cannot be combined with `--address`. |
| **`--address`** | Numeric address | Current IDA cursor | Selects the root using an explicit address. The `0x` prefix is optional. Cannot be combined with `--function`. |
| **`--output`** | Directory path | `ida_exports` | Sets the parent output directory. The exporter creates `function_<RootFunction>` inside it. Relative paths are resolved from the current working directory. |
| **`--page-size`** | Integer from `1` to `50000` | `50000` | Sets the maximum disassembly instructions requested per page. Values outside the supported range are clamped. Smaller values generate more MCP requests. |
| **`--include-external`** | Flag | Disabled | Accepted and recorded in the manifest. In the current build, it does not yet change traversal filtering. |
| **`--workers`** | Integer | `0` meaning automatic | Sets concurrent MCP worker threads. Automatic mode uses the CPU count and chooses from 4 through 16 workers. Manual values are clamped to 1 through 32. Each worker owns a separate initialized MCP session. |
| **`--timeout`** | Seconds | `600` | Limits one curl/MCP request. Use `0` to disable per-request timeouts. This does not limit the complete discovery pass for one function. |
| **`--function-timeout`** | Seconds | `300` | Limits the complete discovery pass for one function, including paging and target-resolution requests. Use `0` to disable it. |
| **`--retries`** | Integer | `3` | Sets retries after a timed-out or failed MCP operation. The affected worker session is reset before retrying. |
| **`--retry-delay`** | Seconds; decimals allowed | `5.0` | Sets the base retry delay. The delay is multiplied by the attempt number. Defaults produce waits of 5, 10, and 15 seconds. |
| **`--health-interval`** | Seconds | `120` | Sets how often the dedicated health monitor checks MCP availability. |
| **`--health-timeout`** | Seconds | `20` | Sets the maximum duration of an individual health-check request. |
| **`--curl`** | Executable name or path | `curl.exe` on Windows; `curl` elsewhere | Overrides the curl executable. Example: `--curl C:\Tools\curl\bin\curl.exe`. |
| **`--list-tools`** | Flag | Disabled | Connects to MCP, verifies required tools, prints enabled MCP tool names in sorted order, and exits without exporting. |
| **`--verbose`** | Optional level `0` through `6` | `0` | Enables progressive diagnostics. `--verbose` without a number selects level 1. Higher levels include all lower-level information. |
| **`--no-console-resize`** | Flag | Disabled | Disables all automatic Windows console font and window resizing. Use this when you prefer your current Command Prompt dimensions or when a console host does not support the legacy Windows APIs. |
| **`--depth`** | Integer | `-1` | Hidden compatibility argument. Accepted but does not limit traversal. The complete reachable graph is always walked. |
| **`--max-functions`** | Integer | `0` | Hidden compatibility argument. Accepted but does not cap discovered functions. |

## Complete Syntax

```cmd
run_export.cmd [--server <endpoint>] [--function <name-or-address> | --address <address>] [--output <directory>] [--page-size <count>] [--include-external] [--workers <count>] [--timeout <seconds>] [--function-timeout <seconds>] [--retries <count>] [--retry-delay <seconds>] [--health-interval <seconds>] [--health-timeout <seconds>] [--curl <path>] [--list-tools] [--verbose [0-6]] [--no-console-resize]
```

## Root Selection Rules

| Command | Root used |
|---|---|
| `run_export.cmd` | Function under the current IDA cursor |
| `run_export.cmd --function UpdatePlayerStates` | IDA function named `UpdatePlayerStates` |
| `run_export.cmd --function sub_7FF6E3BF5C90` | IDA function with that generated name |
| `run_export.cmd --function 0x7FF6E3BF5C90` | Function resolved from that address |
| `run_export.cmd --address 7FF6E3BF5C90` | Function resolved from that numeric address |

`--function` and `--address` are mutually exclusive. Supplying both fails during argument parsing before MCP is contacted.

# Verbose Diagnostics

Pass `--verbose` or `--verbose LEVEL` to display a live **Debug Status** panel above the normal **Discovery Status** or **Export Status** dashboard. Each level includes all information from lower levels.

| Level | Information added |
|---:|---|
| `0` | Normal dashboard only; verbose diagnostics are disabled. |
| `1` | Worker watchdog state, progress age, current operation, function lifecycle events, graph-level progress, and failures. |
| `2` | Worker assignments, detailed operation activity, retries, stage changes, and worker start/finish events. |
| `3` | MCP methods and tool calls, request duration, curl return code, response byte count, and request timing. |
| `4` | Disassembly page number, page offset, instruction totals, paging progress, and unique candidate totals. |
| `5` | Target resolution, accepted graph edges, duplicate edges, skipped targets, unresolved targets, and traversal counters. |
| `6` | Curl command construction, JSON-RPC payloads, response headers, and individual `CALL`/`JMP` candidate diagnostics. Response-body previews are intentionally not displayed. |

Useful commands:

```cmd
:: Default live dashboard
run_export.cmd --server 13338 --function draw_debug_info

:: Worker and watchdog diagnostics
run_export.cmd --server 13338 --function draw_debug_info --verbose 1 --timeout 30

:: Detailed worker activity
run_export.cmd --server 13338 --function draw_debug_info --verbose 2 --timeout 30

:: MCP request diagnostics
run_export.cmd --server 13338 --function draw_debug_info --verbose 3 --timeout 30

:: Paging diagnostics
run_export.cmd --server 13338 --function draw_debug_info --verbose 4 --timeout 30

:: Target and graph diagnostics
run_export.cmd --server 13338 --function draw_debug_info --verbose 5 --timeout 30

:: Full payload, curl, and header diagnostics
run_export.cmd --server 13338 --function draw_debug_info --verbose 6 --timeout 30
```

The live panel is attached only when standard output is an interactive terminal. When output is redirected to a file or pipe, the in-place dashboard is not attached.

## Windows Console Layout

Automatic resizing applies only to an interactive Windows console and can be disabled with `--no-console-resize`.

| Verbose level | Automatic layout |
|---:|---|
| `0` | Existing console layout is retained. |
| `1` | Existing font and window size are retained. |
| `2` through `6` | Uses the shared tested layout described below. |

For Verbose 2 through 6, the exporter attempts to use:

```text
Font height:       13 pixels
Console columns:   200
Console rows:      86
Outer window size: 1200 x 1181 pixels
```

The same readable size is used for every level from 2 through 6; higher verbose levels do not progressively shrink the text. The original font, buffer, visible window, and outer window dimensions are restored automatically when the exporter exits.

Classic Command Prompt supports these legacy APIs most reliably. Windows Terminal and other ConPTY hosts may reject some or all resize operations; in that case, the exporter keeps the current layout and continues normally.

To keep your current console layout:

```cmd
run_export.cmd --server 13338 --function draw_debug_info --verbose 6 --timeout 30 --no-console-resize
```

## In-Place Redraw and No Flicker

During a live stage, the exporter anchors the frame at the top of the console and replaces the current rows instead of appending a new dashboard every second. The cursor is hidden while the live dashboard is active and restored when the panel closes.

A complete console-buffer clear is used only when switching between the three major stages. This removes obsolete stage information without causing a full-screen flash on every live update.

## Diagnostic Color Scheme

Colors are semantic and are applied consistently across Worker Debug, Current Function Statistics, Recent Debug Events, Discovery/Export Status, and the lower worker table.

| Data | Color behavior |
|---|---|
| `LIVE`, `OK`, successful completions, `rc=0` | Green |
| Failed operations, timeouts, unresolved failures, nonzero error codes | Red |
| Waiting, retries, page sizes, page counts, offsets, limits | Yellow |
| Addresses and byte/timing fields | Cyan |
| Request IDs and numeric request fields | Yellow |
| Session IDs and targets | Magenta |
| Discovery/disassembly/export stages | Stage-specific blue or magenta |
| `POST` and other HTTP verbs | Colored separately from `Calling` tool messages |
| Event categories | Category-specific colors |

Both `key=value` fields and JSON-style fields are colored, including examples such as:

```text
offset=0
page_size=50000
target=sub_7FF6E3BF5C90
"offset": 0
"addr": "0x7ff6e3bf5c90"
```

Rows are shortened only at complete field boundaries. Unreadable partial tails such as `re...` or `rc...` are removed rather than printed.

## Worker Watchdog States

Watchdog labels are based on the time since a worker's most recent progress event.

| State | Progress age | Meaning |
|---|---:|---|
| `LIVE` | Less than 30 seconds | Recent progress was observed. |
| `SLOW` | 30 seconds to less than 2 minutes | The operation is taking longer than normal but may still be progressing. |
| `STALLED?` | 2 minutes to less than 10 minutes | No recent progress event has been observed. Investigation may be useful. |
| `FROZEN?` | 10 minutes or longer | The worker has been quiet for a long period. This is a warning, not proof that IDA or MCP is dead. |

Large or heavily obfuscated functions can legitimately remain in a warning state while IDA is working.

## Current Function Statistics

The dashboard focuses on the most concerning active worker in this order:

1. `FROZEN?`
2. `STALLED?`
3. `SLOW`
4. Longest-running `LIVE` worker

| Statistic | Description |
|---|---|
| Worker | Worker thread selected for detailed display |
| Function | Current function name |
| Address | Current function address |
| Stage | Current discovery or export operation |
| Elapsed | Total time spent on the current assignment |
| Last progress | Time since the worker last reported progress |
| Instructions read | Cumulative disassembly instructions processed |
| Pages read | Disassembly pages fetched |
| CALL/JMP counts | Candidate call and tail-jump instructions observed |
| Unique targets | Deduplicated candidate targets found |
| Resolved targets | Targets successfully resolved to functions |
| Accepted edges | New graph edges added |
| Duplicates | Already-known functions or edges encountered again |
| Skipped | Local, unsupported, or intentionally ignored targets |
| Unresolved | Candidate targets that could not be resolved |
| Retries | Retry attempts associated with the selected worker |
| MCP request | Most recent MCP operation and timing information |

# Timeout, Retry, and Health Behavior

`--timeout` and `--function-timeout` control different scopes.

| Setting | Scope |
|---|---|
| `--timeout` | One curl/MCP request |
| `--function-timeout` | Complete recursive discovery pass for one function |

Recommended diagnostic command:

```cmd
run_export.cmd ^
  --server 13339 ^
  --address 0x7FF6E3BF5C90 ^
  --timeout 30 ^
  --function-timeout 300 ^
  --retries 3 ^
  --retry-delay 5 ^
  --health-interval 120 ^
  --health-timeout 20 ^
  --verbose 4
```

With `--retries 3 --retry-delay 5`, retry delays are:

| Retry | Delay |
|---:|---:|
| 1 | 5 seconds |
| 2 | 10 seconds |
| 3 | 15 seconds |

Each worker owns its own MCP session. When an operation is retried, the affected worker resets and initializes a fresh session before attempting the operation again.

# Live Dashboard

The exporter uses fixed worker rows that are updated in place. Completed workers return to `Idle`, their elapsed timer resets, and the row is reused for the next assignment.

```text
Discovery Status
Found: 1,653  Queued: 563  Active: 15  Processed: 1,090  Elapsed: 00:01:31  Health: OK 00:01:30 ago

Worker             State          Elapsed    Function
------------------ -------------- ---------- ------------------------------------------------------------------------
ida-discover_0     Scanning       00:00:04   sub_7FF6E34D4BC0 @ 0x7ff6e34d4bc0
ida-discover_1     Retrying       00:00:17   sub_7FF6E329DE60 @ 0x7ff6e329de60  attempt 1/3, retry in 5s
ida-discover_2     Idle           00:00:00   -
```

# Output Files

Each run creates a directory named after the resolved root function.

```text
ida_exports/
└── function_<RootFunction>/
    ├── Main_<RootFunction>_function_we_are_in.txt
    ├── Extracted_referenced_functions_in_<RootFunction>.txt
    ├── Extracted_called_functions_<RootFunction>_pseudocode.txt
    └── Manifest_<RootFunction>.json
```

| File | Description | Primary use |
|---|---|---|
| **`Main_<RootFunction>_function_we_are_in.txt`** | Selected root function metadata, assembly, and Hex-Rays pseudocode when available. | Entry point for analysis. |
| **`Extracted_referenced_functions_in_<RootFunction>.txt`** | Assembly for every recursively discovered reachable function in deterministic discovery order. | Low-level reverse engineering, signature work, and instruction verification. |
| **`Extracted_called_functions_<RootFunction>_pseudocode.txt`** | Hex-Rays pseudocode for the recursively discovered functions. | High-level logic analysis, documentation, and LLM-assisted review. |
| **`Manifest_<RootFunction>.json`** | Machine-readable root information, worker/request settings, timing, retries, health data, graph edges, failures, exported functions, and output paths. | Automation, validation, dashboards, and troubleshooting. |

# Final Statistics

At completion, the exporter reports:

| Statistic | Meaning |
|---|---|
| Functions discovered | Unique reachable functions found during traversal |
| Function records | Function entries written to the export set |
| Fully successful | Functions with no final discovery, disassembly, or decompilation failure |
| Partial/failed | Unique functions with at least one final failed operation |
| Failure operations | Total failed stages; one function can contribute more than one failure |
| Retry attempts | Total retry attempts across operations |
| Recovered by retry | Operations that initially failed and later succeeded |
| Health checks | MCP health probes performed |
| Health failures | Failed health probes |
| Health recoveries | Transitions from unhealthy back to healthy |
| Discovery time | Time spent finding the reachable graph |
| Export time | Time spent extracting full assembly and pseudocode |
| Total runtime | Complete run time |
| Output size | Combined size of the generated files |

# Command Examples

| Goal | Command |
|---|---|
| Export current cursor function | `run_export.cmd --server 13339` |
| Export by address | `run_export.cmd --server 13339 --address 0x7FF6E3BF5C90` |
| Export by function name | `run_export.cmd --server 13339 --function UpdatePlayerStates` |
| Use eight workers | `run_export.cmd --server 13339 --function UpdatePlayerStates --workers 8` |
| Use a custom output directory | `run_export.cmd --output E:\IDAExports --function UpdatePlayerStates` |
| Allow fifteen minutes per request | `run_export.cmd --timeout 900 --function UpdatePlayerStates` |
| Disable request timeout | `run_export.cmd --timeout 0 --function UpdatePlayerStates` |
| Disable per-function discovery timeout | `run_export.cmd --function-timeout 0 --function UpdatePlayerStates` |
| Increase retries | `run_export.cmd --retries 5 --function UpdatePlayerStates` |
| Check health every minute | `run_export.cmd --health-interval 60 --function UpdatePlayerStates` |
| Show enabled MCP tools | `run_export.cmd --server 13339 --list-tools` |
| Worker diagnostics | `run_export.cmd --function UpdatePlayerStates --verbose 2` |
| MCP request diagnostics | `run_export.cmd --function UpdatePlayerStates --verbose 3` |
| Paging diagnostics | `run_export.cmd --function UpdatePlayerStates --verbose 4` |
| Target/graph diagnostics | `run_export.cmd --function UpdatePlayerStates --verbose 5` |
| Full communication diagnostics | `run_export.cmd --function UpdatePlayerStates --verbose 6` |
| Keep current console size | `run_export.cmd --function UpdatePlayerStates --verbose 6 --no-console-resize` |

# Troubleshooting

| Problem | Suggested action |
|---|---|
| `curl` is not found | Add curl to `PATH` or pass `--curl <full-path>`. |
| Connection refused | Confirm `ida-pro-mcp` is running on the selected host and port. |
| Required MCP tool missing | Run `--list-tools` and verify `lookup_funcs`, `disasm`, and `decompile`. |
| IDA becomes unstable with many workers | Reduce the count, for example `--workers 8` or `--workers 4`. |
| A worker appears frozen | Use `--verbose 4` to inspect page, instruction, and target-resolution progress. |
| One function repeatedly times out | Increase `--function-timeout`, reduce `--page-size`, or inspect the function manually. |
| Individual MCP requests time out | Increase `--timeout`; keep it finite so retries can activate. |
| Pseudocode is missing | Confirm Hex-Rays is installed and the function decompiles in IDA. |
| Automatic window resizing does not occur | Use classic `cmd.exe`. Windows Terminal/ConPTY may ignore legacy console APIs. |
| The automatic layout is not desired | Add `--no-console-resize`. |
| Text wraps at Verbose 6 | Use the automatic 1200 x 1181 layout in classic Command Prompt or widen the terminal manually. |
| Live panel does not appear when redirected | This is expected; the in-place panel requires an interactive terminal. |

Press `Ctrl+C` to stop the exporter intentionally.

# Designed For

- Reverse engineering
- Binary analysis
- Vulnerability research
- Malware analysis
- Program documentation
- Call-graph exploration
- LLM-assisted code understanding

# License

MIT

# Acknowledgements

A huge thank you to **mrexodia** for creating the excellent [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) project. This exporter uses that plugin as its communication layer to recursively discover, extract, and organize large portions of an IDA database into a format that is easier for both humans and language models to understand.
