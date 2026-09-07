// Precompiled header: the heavy IDA SDK headers compile once here so every other
// translation unit (mcp, mcp_commands, main) builds fast. Add new SDK headers here.
#pragma once

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <regex>
#include <functional>

#include <pro.h>
#include <ida.hpp>
#include <idalib.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <lines.hpp>
#include <parsejson.hpp>
