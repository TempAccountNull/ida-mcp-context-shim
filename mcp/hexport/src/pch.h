// Precompiled header: the heavy IDA SDK headers compile once here so every other
// translation unit (mcp, mcp_commands, main) builds fast. Add new SDK headers here.
#pragma once

// STL first, before the SDK headers below. The IDA SDK poisons the C stdio symbols
// (fgetc/fputc/...), and the MSVC STL uses them internally, so any STL header pulled in
// AFTER the SDK fails to compile. Include everything we need here, up front.
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <regex>
#include <functional>
#include <iostream>

// Winsock2 for the M4 HTTP transport. It MUST precede any <windows.h> (pulled in by the
// SDK headers below): including it first sets the _WINSOCKAPI_ guard so windows.h skips the
// legacy winsock.h, avoiding the winsock1/winsock2 redefinition clash.
#include <winsock2.h>
#include <ws2tcpip.h>

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <idalib.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <lines.hpp>
#include <frame.hpp>    // stack frames
#include <gdl.hpp>      // qflow_chart_t, for basic blocks
#include <strlist.hpp>  // build_strlist, for list_strings
#include <moves.hpp>    // bookmarks_t, for add_bookmark
#include <hexrays.hpp>
#include <parsejson.hpp>
