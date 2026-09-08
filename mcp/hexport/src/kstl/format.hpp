// kstl formatting -- our own number->text and type-safe concatenating format(), building into
// a kstl::string. No STL, no <cstdio>/<charconv>/<format>, no snprintf (which the SDK poisons).
// Header-only and inline: number formatting is hot, so it folds into the caller.
//
//   kstl::string line = kstl::format("[hexport] ", n, "/", total, " @ 0x", kstl::hex(ea),
//                                    "  ", kstl::fixed(secs, 1), "s");
#pragma once
#include "string_view.hpp"   // pulls in string.hpp; lets format() accept string_view too

namespace kstl {

// ---- primitive number -> text ----

// "00" "01" ... "99". Converting two digits per step halves the number of divisions, and each
// division is a serial dependency (the next digit needs the previous quotient), so this is the
// part worth halving -- not the copy.
inline const char DIGITS2[201] =
  "00010203040506070809" "10111213141516171819"
  "20212223242526272829" "30313233343536373839"
  "40414243444546474849" "50515253545556575859"
  "60616263646566676869" "70717273747576777879"
  "80818283848586878889" "90919293949596979899";

// Writes v's digits back-to-front into buf[0..24) and returns the index the number starts at.
inline int uint_to_buf(char *buf, unsigned long long v) noexcept
{
  int n = 24;
  while ( v >= 100 )
  {
    unsigned d = unsigned(v % 100) * 2;
    v /= 100;
    buf[--n] = DIGITS2[d + 1];
    buf[--n] = DIGITS2[d];
  }
  if ( v >= 10 )
  {
    unsigned d = unsigned(v) * 2;
    buf[--n] = DIGITS2[d + 1];
    buf[--n] = DIGITS2[d];
  }
  else
  {
    buf[--n] = char('0' + unsigned(v));
  }
  return n;
}

inline void append_uint(string &s, unsigned long long v)
{
  char tmp[24];
  int n = uint_to_buf(tmp, v);
  s.append(tmp + n, unsigned(24 - n));           // one grow-check + one copy (not per-digit)
}

inline void append_int(string &s, long long v)
{
  if ( v < 0 )
  {
    s.push_back('-');
    append_uint(s, (unsigned long long)(-(v + 1)) + 1);   // negate without overflowing at min
  }
  else
  {
    append_uint(s, (unsigned long long)v);
  }
}

inline void append_uint_padded(string &s, unsigned long long v, unsigned width)
{
  char tmp[24];
  int n = uint_to_buf(tmp, v);
  while ( unsigned(24 - n) < width && n > 0 )     // leading zeros to reach `width`
    tmp[--n] = '0';
  s.append(tmp + n, unsigned(24 - n));
}

inline void append_hex(string &s, unsigned long long v, unsigned min_digits = 0)
{
  char tmp[24];
  int n = 24;
  do
  {
    unsigned d = unsigned(v & 0xF);
    tmp[--n] = char(d < 10 ? '0' + d : 'a' + (d - 10));
    v >>= 4;
  } while ( v != 0 );
  while ( unsigned(24 - n) < min_digits && n > 0 )
    tmp[--n] = '0';
  s.append(tmp + n, unsigned(24 - n));
}

// Fixed-point double. Good for display values (durations, rates); not a full float printer
// (no inf/huge-magnitude handling beyond u64 range -- callers here stay well inside it).
inline void append_double(string &s, double d, unsigned precision = 6)
{
  if ( d != d )   // NaN
  {
    s.append("nan");
    return;
  }
  if ( d < 0 )
  {
    s.push_back('-');
    d = -d;
  }
  unsigned long long pow10 = 1;
  for ( unsigned i = 0; i < precision; ++i )
    pow10 *= 10;
  unsigned long long ip = (unsigned long long)d;
  double frac = d - double(ip);
  unsigned long long fp = (unsigned long long)(frac * double(pow10) + 0.5);
  if ( fp >= pow10 )   // rounding carried into the integer part
  {
    ip += 1;
    fp -= pow10;
  }
  append_uint(s, ip);
  if ( precision != 0 )
  {
    s.push_back('.');
    append_uint_padded(s, fp, precision);
  }
}

// ---- format specifiers (wrap a value to pick a representation) ----

struct Hex   { unsigned long long v; unsigned width; };
struct Pad   { unsigned long long v; unsigned width; };
struct Fixed { double v; unsigned prec; };

inline Hex hex(unsigned long long v, unsigned width = 0) { return Hex{ v, width }; }
inline Pad pad(unsigned long long v, unsigned width)     { return Pad{ v, width }; }
inline Fixed fixed(double v, unsigned prec = 6)          { return Fixed{ v, prec }; }

// ---- type-dispatched append (exact overloads => no signed/unsigned ambiguity) ----

inline void append_arg(string &s, const char *v)        { s.append(v); }
inline void append_arg(string &s, const string &v)      { s.append(v); }
inline void append_arg(string &s, string_view v)        { s.append(v.data(), v.size()); }
inline void append_arg(string &s, char v)               { s.push_back(v); }
inline void append_arg(string &s, bool v)               { s.append(v ? "true" : "false"); }
inline void append_arg(string &s, int v)                { append_int(s, v); }
inline void append_arg(string &s, unsigned v)           { append_uint(s, v); }
inline void append_arg(string &s, long v)               { append_int(s, v); }
inline void append_arg(string &s, unsigned long v)      { append_uint(s, v); }
inline void append_arg(string &s, long long v)          { append_int(s, v); }
inline void append_arg(string &s, unsigned long long v) { append_uint(s, v); }
inline void append_arg(string &s, double v)             { append_double(s, v, 6); }
inline void append_arg(string &s, const void *p)        { s.append("0x"); append_hex(s, (unsigned long long)p); }
inline void append_arg(string &s, Hex h)                { append_hex(s, h.v, h.width); }
inline void append_arg(string &s, Pad p)                { append_uint_padded(s, p.v, p.width); }
inline void append_arg(string &s, Fixed f)              { append_double(s, f.v, f.prec); }

// ---- concatenating format(): append each argument in turn ----

template <class... A>
inline string format(const A &...a)
{
  string s;
  (append_arg(s, a), ...);   // C++17 fold
  return s;
}

}  // namespace kstl
