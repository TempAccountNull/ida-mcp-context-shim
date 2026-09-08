// kstl::string_view -- a non-owning {pointer, length} window over character data. Our own,
// from scratch, no STL, no #includes but our own string. Lets us parse/scan without copying;
// substr()/find() return views, so slicing allocates nothing.
#pragma once
#include "string.hpp"

namespace kstl {

class string_view
{
public:
  static const unsigned npos = 0xFFFFFFFFu;

  string_view() noexcept : _d(nullptr), _n(0) {}
  string_view(const char *s) noexcept : _d(s), _n(detail::strlen_(s)) {}
  string_view(const char *s, unsigned n) noexcept : _d(s), _n(n) {}
  string_view(const string &s) noexcept : _d(s.data()), _n(s.size()) {}

  const char *data() const noexcept { return _d; }
  unsigned size() const noexcept    { return _n; }
  bool empty() const noexcept       { return _n == 0; }
  char operator[](unsigned i) const noexcept { return _d[i]; }
  char front() const noexcept { return _d[0]; }
  char back() const noexcept  { return _d[_n - 1]; }
  const char *begin() const noexcept { return _d; }
  const char *end() const noexcept   { return _d + _n; }

  string_view substr(unsigned pos, unsigned len = npos) const noexcept
  {
    if ( pos > _n )
      pos = _n;
    unsigned rem = _n - pos;
    return string_view(_d + pos, len < rem ? len : rem);
  }

  void remove_prefix(unsigned n) noexcept
  {
    if ( n > _n )
      n = _n;
    _d += n;
    _n -= n;
  }

  void remove_suffix(unsigned n) noexcept
  {
    _n -= (n > _n ? _n : n);
  }

  unsigned find(char c, unsigned from = 0) const noexcept
  {
    for ( unsigned i = from; i < _n; ++i )
      if ( _d[i] == c )
        return i;
    return npos;
  }

  unsigned find(string_view sub, unsigned from = 0) const noexcept
  {
    if ( sub._n == 0 )
      return from <= _n ? from : npos;
    if ( sub._n > _n )
      return npos;
    for ( unsigned i = from; i + sub._n <= _n; ++i )
    {
      unsigned j = 0;
      while ( j < sub._n && _d[i + j] == sub._d[j] )
        ++j;
      if ( j == sub._n )
        return i;
    }
    return npos;
  }

  bool operator==(string_view o) const noexcept
  {
    if ( _n != o._n )
      return false;
    for ( unsigned i = 0; i < _n; ++i )
      if ( _d[i] != o._d[i] )
        return false;
    return true;
  }
  bool operator!=(string_view o) const noexcept { return !(*this == o); }

  bool starts_with(string_view p) const noexcept { return _n >= p._n && substr(0, p._n) == p; }
  bool ends_with(string_view p) const noexcept   { return _n >= p._n && substr(_n - p._n) == p; }

  string to_string() const { return string(_d, _n); }   // materialize into an owning string

private:
  const char *_d;
  unsigned _n;
};

}  // namespace kstl
