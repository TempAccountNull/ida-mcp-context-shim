// Compile-time FNV-1a string hash + a "_h" literal, so string dispatch (tool names,
// JSON-RPC methods, CLI flags) is a switch/default instead of an if-chain. constexpr =>
// usable in case labels and safe to include in multiple translation units.
#pragma once
#include "pch.h"

constexpr uint64 str_hash(const char *s, uint64 h = 1469598103934665603ULL)
{
  return (*s != '\0') ? str_hash(s + 1, (h ^ uint64(uint8(*s))) * 1099511628211ULL) : h;
}

constexpr uint64 operator""_h(const char *s, size_t) { return str_hash(s); }
