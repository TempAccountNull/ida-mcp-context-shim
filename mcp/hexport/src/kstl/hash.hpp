// kstl::hash<K> -- the default hasher for our maps. IDENTITY for integer keys (exactly what
// phmap/absl do: for ints the raw value is the hash, and the map's own Fibonacci mix scrambles
// it). Removing FNV from the integer path was the single biggest lookup speedup -- it was the
// main reason phmap beat us. Everything else goes through hash_bytes below. No includes.
#pragma once
#include "intrin/x64.hpp"   // _umul128: the 64x64->128 multiply behind hash_mix, one MUL instruction

namespace kstl {

namespace detail {

// Fold a 128-bit product back to 64 bits. One multiply avalanches every input bit into both
// halves, so xor-ing them gives a well-distributed result cheaply.
inline unsigned long long hash_mix(unsigned long long a, unsigned long long b) noexcept
{
  unsigned long long hi;
  unsigned long long lo = _umul128(a, b, &hi);
  return lo ^ hi;
}

// Hash n bytes, EIGHT at a time. FNV-1a (the obvious byte loop) costs one dependent 3-cycle
// multiply per byte, which is fine for 4 bytes and terrible for a symbol name: measured 48 ns for
// a 96-char key versus 7.4 ns here, and 2x even at 24 chars. Distribution is equivalent -- both
// spread 200k keys over the same number of buckets.
//
// Unaligned 8-byte reads are deliberate and fine on x86-64. Only bytes inside [p, p+n) are ever
// read: the tail overlaps back into the string rather than reading past it.
inline unsigned long long hash_bytes(const char *p, unsigned n) noexcept
{
  const unsigned long long S0 = 0x9E3779B97F4A7C15ull;
  const unsigned long long S1 = 0xC2B2AE3D27D4EB4Full;
  unsigned long long h = S0 ^ (static_cast<unsigned long long>(n) * S1);
  while ( n >= 8 )
  {
    h = hash_mix(h ^ *reinterpret_cast<const unsigned long long *>(p), S1);
    p += 8;
    n -= 8;
  }
  if ( n >= 4 )
  {
    unsigned long long lo = *reinterpret_cast<const unsigned *>(p);
    unsigned long long hi = *reinterpret_cast<const unsigned *>(p + n - 4);
    h = hash_mix(h ^ (lo | (hi << 32)), S1);
  }
  else if ( n != 0 )
  {
    unsigned long long t = static_cast<unsigned long long>(static_cast<unsigned char>(p[0]))
                         | (static_cast<unsigned long long>(static_cast<unsigned char>(p[n >> 1])) << 8)
                         | (static_cast<unsigned long long>(static_cast<unsigned char>(p[n - 1])) << 16);
    h = hash_mix(h ^ t, S1);
  }
  return hash_mix(h, S0);
}

}  // namespace detail

// Any key with no specialization: hash its object representation. (As with any such hasher, a
// type with padding bytes must not rely on this -- padding is indeterminate.)
template <class K>
struct hash
{
  unsigned long long operator()(const K &k) const noexcept
  {
    return detail::hash_bytes(reinterpret_cast<const char *>(&k), sizeof(K));
  }
};

// Integer keys -> identity. The map multiplies by 2^64/phi internally, so distribution is fine.
template <> struct hash<int>                { unsigned long long operator()(int v) const noexcept { return static_cast<unsigned>(v); } };
template <> struct hash<unsigned>           { unsigned long long operator()(unsigned v) const noexcept { return v; } };
template <> struct hash<long>               { unsigned long long operator()(long v) const noexcept { return static_cast<unsigned long>(v); } };
template <> struct hash<unsigned long>      { unsigned long long operator()(unsigned long v) const noexcept { return v; } };
template <> struct hash<long long>          { unsigned long long operator()(long long v) const noexcept { return static_cast<unsigned long long>(v); } };
template <> struct hash<unsigned long long> { unsigned long long operator()(unsigned long long v) const noexcept { return v; } };

}  // namespace kstl
