============================================================
Acknowledgements
============================================================

A huge thank you to mrexodia for creating the excellent
ida-pro-mcp project.

This shim builds on top of that plugin by using it as the
communication layer to recursively discover, export, and
organize large portions of an IDA database into a format
that's easier for both humans and LLMs to understand.

Project:
https://github.com/mrexodia/ida-pro-mcp

IDA MCP Recursive Exporter
==========================

Exports every function reachable from a selected root function in IDA Pro through ida-pro-mcp.

REQUIREMENTS
------------

- IDA Pro with the target database open
- ida-pro-mcp running and connected to that IDA instance
- Python 3.10 or newer
- curl available in PATH

BASIC USAGE
-----------

Use the function currently selected in IDA:

run_export.cmd --server 13339

Use an explicit function address:

run_export.cmd --server 13339 --address 0x7FF6E3BF5C90

The 0x prefix is optional:

run_export.cmd --server 13339 --address 7FF6E3BF5C90

Use an IDA function name:

run_export.cmd --server 13339 --function sub_7FF6E3BF5C90

--address and --function cannot be used together. If neither is supplied, the exporter uses the function under the current IDA cursor.

RECOMMENDED COMMAND
-------------------

run_export.cmd ^
  --server 13339 ^
  --address 0x7FF6E3BF5C90 ^
  --timeout 600 ^
  --retries 3 ^
  --retry-delay 5 ^
  --health-interval 120 ^
  --health-timeout 20

COMMAND-LINE OPTIONS
--------------------

--server <port|host:port|URL>
    ida-pro-mcp server. Default: 13337

--address <address>
    Explicit root address, with or without 0x.

--function <name|address>
    Root function name or address.

--output <directory>
    Parent output directory. Default: ida_exports

--workers <count>
    Number of concurrent MCP workers. Default: 0, which selects automatically.
    The automatic maximum is 16 workers.

--timeout <seconds>
    Maximum time for one MCP request. Default: 600.
    Use 0 to disable request timeouts, although a finite timeout is recommended so retries can activate.

--retries <count>
    Number of retries after a request failure. Default: 3.

--retry-delay <seconds>
    Base delay between retries. Default: 5.
    Delays increase by attempt: 5, 10, and 15 seconds with the defaults.

--health-interval <seconds>
    Interval between MCP health checks. Default: 120 seconds.

--health-timeout <seconds>
    Maximum time allowed for one health check. Default: 20 seconds.

--page-size <count>
    Maximum instructions requested per disassembly page. Default and maximum: 50000.

--include-external
    Attempts to include external or imported functions when resolvable.

--list-tools
    Prints enabled MCP tools and exits.

WHAT IT DOES
------------

1. Connects to ida-pro-mcp.
2. Resolves the root from --address, --function, or the current IDA cursor.
3. Recursively disassembles reachable functions.
4. Follows direct CALL instructions and cross-function tail JMP instructions.
5. Ignores local jumps such as loc_xxx.
6. Deduplicates functions by canonical address.
7. Exports assembly and Hex-Rays pseudocode.
8. Downloads complete MCP results when ida-pro-mcp returns a truncated preview with a download URL.
9. Retries transient request failures.
10. Checks MCP health every two minutes by default.
11. Records failures, timing, retries, health checks, and exported functions in the manifest.

LIVE STATUS
-----------

Discovery example:

Discovering  Found 3,006  Queued 28  Active 2  Elapsed 00:12:18  Health OK 1m42s  Waiting ida-discover_7 12m18s  sub_7FF6E3A2BF70 @ 0x7ff6e3a2bf70

Export example:

Exporting  45,012/95,509  Active 16  Elapsed 00:48:31  Health OK 0m37s  Waiting ida-export_4 3m12s  sub_7FF6E4123450 @ 0x7ff6e4123450

The live line shows:

- total elapsed runtime
- functions found
- queued work
- active workers
- time since the last successful health check
- the longest-running worker
- how long that worker has been waiting
- the function assigned to that worker

A growing worker timer means the exporter is waiting on that IDA/MCP request and is not silently frozen.

HEALTH CHECKS
-------------

Every 120 seconds by default, a dedicated session verifies that ida-pro-mcp can initialize and provide the required tools.

The live line may show:

Health CHECK
Health OK 0m00s
Health FAIL

When health fails, new operations pause. Recovery checks run every 10 seconds until MCP is available again, then processing resumes.

RETRIES
-------

Failed operations retry automatically. With the defaults:

Retry 1: wait 5 seconds
Retry 2: wait 10 seconds
Retry 3: wait 15 seconds

A worker session is reset before retrying so a damaged MCP session is not reused.

FINAL STATISTICS
----------------

At the end of the run, the exporter prints a summary similar to:

============================================================
Export Summary
============================================================
Functions discovered : 95,509
Function records     : 95,509
Fully successful     : 95,500
Partial/failed       : 9
Failure operations   : 12
Retry attempts       : 27
Recovered by retry   : 18
Health checks        : 42
Health failures      : 1
Health recoveries    : 1
Discovery time       : 00:14:38
Export time          : 01:02:17
Total runtime        : 01:16:55
Output size          : 295.50 MB
============================================================

Definitions:

Fully successful
    Function records with no final discovery, disassembly, or decompilation failure.

Partial/failed
    Unique functions that still had at least one failed operation after all retries.

Failure operations
    Total final failed stages. One function can have more than one failed stage.

Retry attempts
    Total retry attempts made across discovery, disassembly, and decompilation.

Recovered by retry
    Operations that initially failed but later completed successfully.

Health failures
    Failed health-check probes.

Health recoveries
    Times the health monitor transitioned from failed back to healthy.

OUTPUT FILES
------------

ida_exports\
  function_<root>\
    Main_<root>_function_we_are_in.txt
    Extracted_referenced_functions_in_<root>.txt
    Extracted_called_functions_<root>_pseudocode.txt
    Manifest_<root>.json

The manifest also contains timing, retry, health, graph-edge, failure, and exported-function data.

EXAMPLES
--------

Current cursor function:

run_export.cmd --server 13339

Explicit address:

run_export.cmd --server 13339 --address 0x7FF6E3BF5C90

Function name:

run_export.cmd --server 13339 --function UpdatePlayerStates

Use eight workers:

run_export.cmd --server 13339 --address 0x7FF6E3BF5C90 --workers 8

Allow fifteen minutes per request and five retries:

run_export.cmd --server 13339 --address 0x7FF6E3BF5C90 --timeout 900 --retries 5

Check health every minute:

run_export.cmd --server 13339 --address 0x7FF6E3BF5C90 --health-interval 60

TROUBLESHOOTING
---------------

If IDA temporarily freezes during a large or obfuscated function, watch the longest worker timer and health state. IDA may resume and complete the request normally.

If curl reports connection refused, confirm that ida-pro-mcp is still running on the selected port. The exporter will retry request failures and pause new work when the health monitor detects an outage.

If 16 workers make IDA unstable, reduce the count:

run_export.cmd --server 13339 --address 0x7FF6E3BF5C90 --workers 8

Press Ctrl+C to stop the exporter intentionally.

MULTI-WORKER LIVE DASHBOARD
---------------------------

Discovery and export now display a fixed dashboard with one row for every worker.
The dashboard is redrawn in place and does not append a new status line for every update.

Example:

Discovery Status
Found: 1,653  Queued: 563  Active: 15  Processed: 1,090  Elapsed: 00:01:31  Health: OK 00:01:30 ago

Worker             State          Elapsed    Function
------------------ -------------- ---------- ------------------------------------------------------------------------
ida-discover_0     Scanning       00:00:04   sub_7FF6E34D4BC0 @ 0x7ff6e34d4bc0
ida-discover_1     Retrying       00:00:17   sub_7FF6E329DE60 @ 0x7ff6e329de60  attempt 1/3, retry in 5s
ida-discover_2     Idle           00:00:00   -

When a worker finishes:

- its previous function name is removed immediately
- its state becomes Idle
- its elapsed time resets to 00:00:00
- its function field becomes -
- the same row is reused when that worker receives another function

This makes each worker's current state clear without leaving stale information on screen.
The dashboard redraw is rate-limited to avoid slowing large exports while still updating continuously.
