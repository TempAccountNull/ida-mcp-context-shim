# Legal Disclaimer

> The shim is being provided for educational purposes only to help aid research against bad actors. Misusing it outside its original intentions may be illegal and is your responsibility. The owner of this repository cannot and will not be held liable for any consequences. Always follow your local laws and use this toolkit responsibly.

---

# IDA MCP Recursive Export Shim

> Export the complete reachable function context from IDA Pro through `ida-pro-mcp` instead of analyzing one function at a time.

The IDA MCP Recursive Export Shim is a multithreaded command-line utility that communicates directly with an `ida-pro-mcp` server. It starts from the function under the current IDA cursor, an explicit address, or a function name; recursively follows direct `CALL` instructions and cross-function tail `JMP` instructions; and exports assembly, Hex-Rays pseudocode, graph relationships, failures, timing, and run statistics.

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

## What the Exporter Does

| Stage | Description |
|---:|---|
| 1 | Connects to the selected `ida-pro-mcp` server and verifies that the required MCP tools are available. |
| 2 | Resolves the root function from `--address`, `--function`, or the current IDA cursor. |
| 3 | Recursively disassembles reachable functions. |
| 4 | Follows direct `CALL` instructions and cross-function tail `JMP` instructions. |
| 5 | Ignores local jumps such as `loc_xxx`. |
| 6 | Deduplicates functions by canonical address. |
| 7 | Exports assembly and Hex-Rays pseudocode using multiple workers. |
| 8 | Downloads the complete result automatically when MCP returns a truncated preview with a download URL. |
| 9 | Retries transient failures and resets the affected worker session before retrying. |
| 10 | Monitors MCP health and pauses new work while the server is unavailable. |
| 11 | Writes deterministic output files and a JSON manifest after processing completes. |

# Command-Line Arguments

The table below lists **every command-line argument accepted by the current exporter**, including the two hidden compatibility arguments. Arguments marked as flags do not take a value.

| Argument | Accepted value | Default | Description |
|:--|:--|:--|:--|
| **`--server`** | Port, `host:port`, or full URL | `13337` | Selects the `ida-pro-mcp` endpoint. A port such as `13339` becomes `http://127.0.0.1:13339/mcp`. A host and port such as `192.168.1.10:13337` becomes `http://192.168.1.10:13337/mcp`. A full HTTP or HTTPS URL is also accepted. The exporter appends `/mcp` when it is missing. |
| **`--function`** | Function name or address | Current IDA cursor | Selects the root by IDA function name or address. Examples include `UpdatePlayerStates`, `sub_7FF6E3BF5C90`, and `0x7FF6E3BF5C90`. This argument cannot be used together with `--address`. |
| **`--address`** | Numeric address | Current IDA cursor | Selects the root using an explicit address. The `0x` prefix is optional. The value must be a valid hexadecimal or numeric address. This argument cannot be used together with `--function`. |
| **`--output`** | Directory path | `ida_exports` | Sets the parent output directory. The exporter creates `function_<RootFunction>` inside this directory. Relative paths are resolved from the current working directory. |
| **`--page-size`** | Integer from `1` to `50000` | `50000` | Sets the maximum number of disassembly instructions requested per page. Smaller values generate more MCP requests; larger values reduce paging overhead. Values outside the supported range are clamped. |
| **`--include-external`** | Flag | Disabled | Requests inclusion of external or imported functions when resolvable. In the current build, the value is accepted and written to the manifest, but it does not yet alter traversal filtering. |
| **`--workers`** | Integer | `0` meaning automatic | Sets the number of concurrent MCP worker threads. Automatic selection uses the CPU count and chooses between 4 and 16 workers. A manually supplied value is clamped to the range 1 through 32. Each worker owns a separate initialized MCP session. |
| **`--timeout`** | Seconds | `600` | Limits one curl or MCP request. Use `0` to disable the per-request timeout. This setting does not limit the complete discovery time for a function; use `--function-timeout` for that. |
| **`--function-timeout`** | Seconds | `300` | Limits the complete discovery pass for one function, including all disassembly pages and target-resolution requests. Use `0` to disable this deadline. It applies to discovery, not the later full assembly and pseudocode export stage. |
| **`--retries`** | Integer | `3` | Sets how many times a failed or timed-out MCP operation is retried. Before retrying, the affected worker resets and reinitializes its MCP session. |
| **`--retry-delay`** | Seconds; decimals allowed | `5.0` | Sets the base retry delay. The delay increases by attempt number. With the default value, retries wait 5, 10, and 15 seconds. |
| **`--health-interval`** | Seconds | `120` | Sets how often the dedicated health monitor checks whether the MCP server is available during an export. |
| **`--health-timeout`** | Seconds | `20` | Sets the maximum time allowed for an individual health-check request. The health client always uses a timeout of at least one second. |
| **`--curl`** | Executable name or path | `curl.exe` on Windows; `curl` elsewhere | Overrides the curl executable used for MCP communication. This is useful when curl is not in `PATH` or when a specific curl build must be used. Example: `--curl C:\Tools\curl\bin\curl.exe`. |
| **`--list-tools`** | Flag | Disabled | Connects to MCP, verifies the required tools, prints all enabled MCP tool names in sorted order, and exits without resolving or exporting a root function. |
| **`--verbose`** | Optional level from `0` through `6` | `0` | Enables progressive diagnostics. Using `--verbose` without a number selects level 1. Higher levels include all information from lower levels. The complete level breakdown appears in the **Verbose Diagnostics** section. |
| **`--depth`** | Integer | `-1` | Hidden compatibility argument retained for older command lines. It is accepted but does not limit traversal. The exporter always walks the complete reachable function graph. |
| **`--max-functions`** | Integer | `0` | Hidden compatibility argument retained for older command lines. It is accepted but does not cap the number of discovered functions. |

### Complete syntax

```cmd
run_export.cmd [--server <endpoint>] [--function <name-or-address> | --address <address>] [--output <directory>] [--page-size <count>] [--include-external] [--workers <count>] [--timeout <seconds>] [--function-timeout <seconds>] [--retries <count>] [--retry-delay <seconds>] [--health-interval <seconds>] [--health-timeout <seconds>] [--curl <path>] [--list-tools] [--verbose [0-6]]
```

## Root Selection Rules

| Command | Root used |
|---|---|
| `run_export.cmd` | Function under the current IDA cursor |
| `run_export.cmd --function UpdatePlayerStates` | IDA function named `UpdatePlayerStates` |
| `run_export.cmd --function sub_7FF6E3BF5C90` | IDA function with that generated name |
| `run_export.cmd --function 0x7FF6E3BF5C90` | Function resolved from that address |
| `run_export.cmd --address 7FF6E3BF5C90` | Function resolved from that numeric address |

`--function` and `--address` are mutually exclusive. Supplying both causes argument parsing to fail before connecting to MCP.

# Verbose Diagnostics

Pass `--verbose` or `--verbose LEVEL` to display a live **Debug Status** panel above the normal **Discovery Status** or **Export Status** dashboard. Each level includes the information from all lower levels.

| Level | Information added |
|---:|---|
| `0` | Normal dashboard only; verbose diagnostics are disabled. |
| `1` | Worker watchdog state, progress age, current stage, current function, lifecycle events, graph-level progress, and failures. |
| `2` | Worker assignments, operation details, retries, stage transitions, and worker start/finish activity. |
| `3` | MCP methods and tool calls, request duration, curl return code, response byte count, and request-level timing. |
| `4` | Disassembly page number, page offset, instruction totals, paging progress, and unique candidate totals. Recommended when a worker appears stuck. |
| `5` | Target resolution, accepted graph edges, duplicate edges, skipped targets, unresolved targets, and detailed traversal counters. |
| `6` | Curl command construction, JSON-RPC request payloads, response headers, and individual `CALL`/`JMP` candidate diagnostics. Response-body previews are intentionally not displayed. |

Examples:

```cmd
run_export.cmd --server 13339 --address 0x7FF6E3BF5C90 --verbose
run_export.cmd --server 13339 --address 0x7FF6E3BF5C90 --verbose 4
run_export.cmd --server 13339 --address 0x7FF6E3BF5C90 --timeout 30 --function-timeout 300 --verbose 6
```

The live verbose panel is enabled only when standard output is an interactive terminal. When output is redirected to a file or pipe, verbose events can still be emitted, but the in-place terminal panel is not attached.

## Worker Watchdog States

Watchdog labels are based on the time since the worker's most recent progress event.

| State | Progress age | Meaning |
|---|---:|---|
| `LIVE` | Less than 30 seconds | Recent progress was observed. |
| `SLOW` | 30 seconds to less than 2 minutes | The operation is taking longer than normal but may still be progressing. |
| `STALLED?` | 2 minutes to less than 10 minutes | No recent progress event has been observed. Investigation may be useful. |
| `FROZEN?` | 10 minutes or longer | The worker has been quiet for a long period. This is a warning, not proof that IDA or MCP is dead. |

Large or heavily obfuscated functions can legitimately remain in a warning state while IDA is working.

## Current Function Statistics

When verbose output is enabled, the dashboard shows a **Current Function Statistics** panel. It automatically focuses on the most concerning active worker in this order:

1. `FROZEN?`
2. `STALLED?`
3. `SLOW`
4. Longest-running `LIVE` worker

| Statistic | Description |
|---|---|
| Worker | Worker thread currently selected for detailed display |
| Function | Current function name |
| Address | Current function address |
| Stage | Current discovery or export stage |
| Elapsed | Total time spent on the current assignment |
| Last progress | Time since the worker last reported measurable progress |
| Instructions read | Cumulative disassembly instructions processed for the current function |
| Pages downloaded | Number of disassembly pages fetched |
| CALL instructions | Direct call candidates observed |
| JMP instructions | Jump candidates observed and considered for tail-call traversal |
| Unique targets | Deduplicated candidate targets found |
| Resolved targets | Targets successfully resolved to functions |
| Accepted edges | New call-graph edges added |
| Duplicates | Already-known edges or functions encountered again |
| Skipped | Local, unsupported, or intentionally ignored targets |
| Unresolved | Candidate targets that could not be resolved |
| Retries | Retry attempts associated with the selected worker operation |
| MCP request | Most recent MCP method or tool operation |

# Timeout and Retry Behavior

`--timeout` and `--function-timeout` control different scopes.

| Setting | Scope |
|---|---|
| `--timeout` | One curl/MCP request |
| `--function-timeout` | The complete recursive discovery pass for one function |

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

# Live Dashboard

The exporter uses fixed worker rows that are redrawn in place. Completed workers return to `Idle`, their elapsed timer resets, and the row is reused for the next assignment. This prevents stale functions from remaining visible and avoids a continuously scrolling console.

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
| **`Main_<RootFunction>_function_we_are_in.txt`** | Contains the selected root function, including identifying metadata, its assembly, and its Hex-Rays pseudocode when available. | First file to open when beginning analysis of the selected function. |
| **`Extracted_referenced_functions_in_<RootFunction>.txt`** | Contains assembly for every recursively discovered reachable function, written in deterministic discovery order. | Low-level reverse engineering, instruction verification, signature work, and complete call-context review. |
| **`Extracted_called_functions_<RootFunction>_pseudocode.txt`** | Contains Hex-Rays pseudocode for the same recursively discovered functions. | High-level logic analysis, documentation, and LLM-assisted understanding. |
| **`Manifest_<RootFunction>.json`** | Contains machine-readable root data, worker settings, request and health settings, timing, retries, health statistics, graph edges, failures, exported functions, and output paths. | Automation, validation, troubleshooting, dashboards, and downstream tooling. |

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
| Recovered by retry | Operations that failed initially and later succeeded |
| Health checks | MCP health probes performed |
| Health failures | Failed health probes |
| Health recoveries | Transitions from unhealthy back to healthy |
| Discovery time | Time spent finding the reachable call graph |
| Export time | Time spent extracting full assembly and pseudocode |
| Total runtime | Complete run time |
| Output size | Combined size of the four generated files |

# Examples

| Goal | Command |
|---|---|
| Export current cursor function | `run_export.cmd --server 13339` |
| Export by address | `run_export.cmd --server 13339 --address 0x7FF6E3BF5C90` |
| Export by function name | `run_export.cmd --server 13339 --function UpdatePlayerStates` |
| Use eight workers | `run_export.cmd --server 13339 --address 0x7FF6E3BF5C90 --workers 8` |
| Use a custom output directory | `run_export.cmd --output E:\IDAExports --function UpdatePlayerStates` |
| Allow fifteen minutes per request | `run_export.cmd --timeout 900 --function UpdatePlayerStates` |
| Disable request timeout | `run_export.cmd --timeout 0 --function UpdatePlayerStates` |
| Disable per-function discovery timeout | `run_export.cmd --function-timeout 0 --function UpdatePlayerStates` |
| Increase retries | `run_export.cmd --retries 5 --function UpdatePlayerStates` |
| Check health every minute | `run_export.cmd --health-interval 60 --function UpdatePlayerStates` |
| Show enabled MCP tools | `run_export.cmd --server 13339 --list-tools` |
| Use detailed paging diagnostics | `run_export.cmd --function UpdatePlayerStates --verbose 4` |
| Use full communication diagnostics | `run_export.cmd --function UpdatePlayerStates --verbose 6` |

# Troubleshooting

| Problem | Suggested action |
|---|---|
| `curl` is not found | Confirm modern Windows curl is available, add curl to `PATH`, or pass `--curl <full-path>`. |
| Connection refused | Confirm `ida-pro-mcp` is running on the selected host and port. |
| Required MCP tool missing | Run `--list-tools` and verify that `lookup_funcs`, `disasm`, and `decompile` are enabled. |
| IDA becomes unstable with many workers | Reduce the count, for example `--workers 8` or `--workers 4`. |
| A worker appears frozen | Use `--verbose 4` to inspect page, instruction, and target-resolution progress. |
| One function repeatedly times out | Increase `--function-timeout`, reduce `--page-size`, or inspect the function manually in IDA. |
| Individual MCP requests time out | Increase `--timeout`; keep it finite so automatic retries can activate. |
| Pseudocode is missing | Confirm Hex-Rays is installed and the function can be decompiled in IDA. |

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
