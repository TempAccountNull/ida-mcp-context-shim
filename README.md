# IDA MCP Recursive Export Shim

> Export complete function context from IDA Pro through `ida-pro-mcp` instead of analyzing one function at a time.

The IDA MCP Recursive Export Shim is a multithreaded command-line utility that communicates directly with an `ida-pro-mcp` server. Starting from either the current function in IDA or a user-specified address, it recursively discovers every reachable function, exports assembly and Hex-Rays pseudocode, and organizes everything into a structure that is easy for humans and LLMs to consume.

---

# Why?

I thought of a really cool kickass idea and put it to work. It helps an LLM understand the full context of a function instead of trying to reason about one isolated function at a time with no knowledge of the surrounding code. Rather than exporting a single function, the shim walks the entire call graph and gathers everything related into one organized package.

The end result is a complete snapshot of the code surrounding your starting point. This gives an LLM significantly more context about how data flows through the program, where functions are called from, what helpers they rely on, and how the overall subsystem works together.

---

# Requirements

- Windows 10 (1803+) or Windows 11
- Python 3.10+
- IDA Pro
- ida-pro-mcp
- Hex-Rays (optional, for pseudocode export)

No third-party Python packages are required.
Uses the curl.exe included with modern Windows installations.

# Features

- Recursive function discovery
- Current cursor or explicit address support
- Function name support
- Parallel exports using multiple workers
- Assembly export
- Hex-Rays pseudocode export
- Automatic large response handling
- Retry failed requests
- Automatic MCP health monitoring
- Live worker dashboard
- Final statistics
- JSON manifest generation
- Organized output directories

---

# Requirements

- IDA Pro
- ida-pro-mcp running
- Python 3.10+
- Hex-Rays (optional but recommended)

---

# Starting the MCP Server

Example:

```text
python server.py --host 127.0.0.1 --port 13337
```

---

# Usage

```text
run_export.cmd [options]
```

or

```text
python ida_mcp_export.py [options]
```

---

# Command Line Options

## Server

Select the MCP server port.

```text
--server <port>
```

Example

```text
run_export.cmd --server 13339
```

Default

```text
13337
```

---

## Start From Current Cursor

If nothing is specified the exporter starts from the function currently selected in IDA.

```text
run_export.cmd
```

---

## Start From Address

Specify an explicit function address.

```text
--address <address>
```

Example

```text
run_export.cmd --address 0x7FF6E3BF5C90
```

---

## Start From Function Name

Specify a function name.

```text
--function <name>
```

Example

```text
run_export.cmd --function InitializePlayerSimulation
```

---

## Worker Count

Override automatic worker selection.

```text
--workers <count>
```

Example

```text
run_export.cmd --workers 8
```

Default

```text
Automatic
```

---

## Request Timeout

Maximum time allowed for an MCP request.

```text
--timeout <seconds>
```

Example

```text
run_export.cmd --timeout 60
```

---

## Retry Count

Retry failed MCP requests.

```text
--retries <count>
```

Example

```text
run_export.cmd --retries 5
```

---

## Retry Delay

Delay between retry attempts.

```text
--retry-delay <seconds>
```

Example

```text
run_export.cmd --retry-delay 10
```

---

## Health Check Interval

How often the exporter checks whether the MCP server is still alive.

```text
--health-interval <seconds>
```

Example

```text
run_export.cmd --health-interval 120
```

---

## Health Timeout

Maximum time allowed for a health check.

```text
--health-timeout <seconds>
```

Example

```text
run_export.cmd --health-timeout 10
```

---

# Live Dashboard

The exporter provides a continuously updating dashboard showing exactly what every worker is doing.

Example

```text
Discovery Status

Functions Found
Functions Queued
Functions Processed

Workers Active
Workers Idle

Elapsed Time

Health Status

Worker             State          Time        Current Function
--------------------------------------------------------------------
Worker 00          Scanning       00:00:04    InitializeRenderer
Worker 01          Processing     00:00:15    RenderFrame
Worker 02          Idle           00:00:00    -
Worker 03          Retrying       00:00:05    LoadTexture
```

Worker rows are reused.

When a worker finishes its current function the row is cleared immediately.

The worker stays in the same position so the display never jumps around while running.

---

# Output Structure

```
ida_exports/

    function_<root>/

        Main_<root>.txt

        Extracted_referenced_functions.txt

        Extracted_called_functions_pseudocode.txt

        Manifest.json
```

---

# Manifest

Each export produces a JSON manifest containing

- Root function
- Function count
- Exported files
- Failed functions
- Retry statistics
- Health events
- Elapsed time
- Export statistics

---

# Final Statistics

Example

```text
========================================================

Export Summary

========================================================

Functions Discovered

Functions Exported

Functions Failed

Retry Attempts

Recovered Retries

Health Checks

Health Recoveries

Discovery Time

Export Time

Total Runtime

Output Size

========================================================
```

---

# Typical Examples

Export current function

```text
run_export.cmd
```

Export from another server

```text
run_export.cmd --server 13339
```

Export from an address

```text
run_export.cmd --address 0x7FF6E3BF5C90
```

Export from a function name

```text
run_export.cmd --function InitializePlayerSimulation
```

Use eight workers

```text
run_export.cmd --workers 8
```

Increase timeout

```text
run_export.cmd --timeout 120
```

Increase retries

```text
run_export.cmd --retries 5
```

---

# Designed For

- Reverse engineering
- Binary analysis
- Malware analysis
- Vulnerability research
- Documentation
- Code understanding
- LLM-assisted reverse engineering

---

# License

MIT

---

# Acknowledgements

A huge thank you to **mrexodia** for creating the excellent **ida-pro-mcp** project.

This shim builds on top of that plugin by using it as the communication layer to recursively discover, export, and organize large portions of an IDA database into a format that's easier for both humans and LLMs to understand.

Repository:
https://github.com/mrexodia/ida-pro-mcp