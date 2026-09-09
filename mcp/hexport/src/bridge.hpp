// Bridge - the MCP front end, split off from the headless worker that owns the database.
//
// One process speaks MCP to the client and owns no database; N child processes each own exactly one
// database and speak the same newline-delimited JSON-RPC on their stdin/stdout. The bridge routes
// between them.
//
// What this buys, and what it does not:
//
//   NOT SPEED, for a single database. The work is Hex-Rays decompiling inside one IDA instance and
//   every SDK call that touches a database runs on that instance's single thread (execute_sync with
//   MFF_READ/MFF_WRITE). Putting a router in front adds no cores. Measured before building this:
//   a bare driver over one worker takes 278.8s for hexx64.dll's 10,109 functions and the full
//   exporter takes 277s, so there is no transport overhead left to remove either.
//
//   RELIABILITY. A worker that hangs or dies takes its database with it, not the session: the
//   bridge notices and restarts it, and the client's connection survives. Today a dead hexport
//   ends the whole export.
//
//   THROUGHPUT ACROSS DATABASES. A database is locked by whoever opens it, so N workers on ONE
//   database is impossible without N copies (374 MB each for hexx64, and 6 GB databases exist).
//   N workers on N DIFFERENT databases costs nothing extra and scales linearly. That is the shape
//   of parallelism this architecture actually unlocks.
#pragma once
#include "pch.h"

// Runs the MCP protocol on stdin/stdout, forwarding tool calls to headless worker processes.
// worker_exe is the hexport binary to spawn with --stdio; nullptr means "this executable".
int run_bridge(const char *worker_exe, const char *initial_db);
