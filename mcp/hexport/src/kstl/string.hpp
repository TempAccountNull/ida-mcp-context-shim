// kstl::string -- our own string, written from scratch (the microsoft/STL source in ref/STL
// is reference only, never a dependency). Small String Optimization: short strings live inline
// with no allocation; longer ones move to a heap block that grows geometrically. No #includes,
// no STL, no API calls -- only core-language new[]/delete[].
//
// Everything is inline here EXCEPT the one cold, heavy method (_grow_to, which allocates) in
// string.cpp. That's exactly how the real STL stays fast while keeping a .cpp, and the
// benchmark proves it matters: out-of-lining the ctor/move/dtor made vector<string> ~50%
// slower until they were inlined.
#pragma once
#include "hash.hpp"   // detail::hash_bytes, for string_hash at the bottom

namespace kstl {

namespace detail {
inline unsigned strlen_(const char *s) noexcept
{
  unsigned n = 0;
  if ( s != nullptr )
    while ( s[n] != 0 )
      ++n;
  return n;
}
// Copy n bytes. MSVC rewrites this runtime-length loop into a call to the CRT memcpy, which is
// the right tool for a block of any real size. (Tried and rejected: a ladder of fixed-width
// moves for n < 16 to dodge that call. It won nothing on any benchmark and made this function
// too big to inline, which made string copies WORSE -- 3.2 ns vs 2.4 ns. Where the call actually
// did hurt is the SSO copy, and that is handled properly by copying the union whole; see _store.)
inline void memcpy_(char *dst, const char *src, unsigned n) noexcept
{
  for ( unsigned i = 0; i < n; ++i )
    dst[i] = src[i];
}
}  // namespace detail

class string
{
public:
  // chars kept inline before we heap-allocate (buffer is SSO_CAPACITY + 1 for the '\0').
  static const unsigned SSO_CAPACITY = 15;

  string() noexcept : _size(0), _cap(SSO_CAPACITY) { _store.buf[0] = 0; }

  string(const char *s) : _size(0), _cap(SSO_CAPACITY)
  {
    _store.buf[0] = 0;
    append(s, detail::strlen_(s));
  }

  string(const char *s, unsigned n) : _size(0), _cap(SSO_CAPACITY)
  {
    _store.buf[0] = 0;
    append(s, n);
  }

  string(const string &o) : _size(o._size), _cap(o._cap)
  {
    if ( o._large_mode() )
    {
      _size = 0;
      _cap = SSO_CAPACITY;
      _store.buf[0] = 0;
      append(o.data(), o._size);
    }
    else
    {
      _store = o._store;                                  // see the note on _store below
    }
  }

  string(string &&o) noexcept : _size(o._size), _cap(o._cap)
  {
    if ( o._large_mode() )
      _store.ptr = o._store.ptr;                          // steal the heap block
    else
      _store = o._store;
    o._size = 0;                                          // leave source as an empty small string
    o._cap = SSO_CAPACITY;
    o._store.buf[0] = 0;
  }

  string &operator=(const string &o)
  {
    if ( this != &o )
    {
      if ( !_large_mode() && !o._large_mode() )
      {
        _store = o._store;
        _size = o._size;
      }
      else
      {
        clear();
        append(o.data(), o._size);
      }
    }
    return *this;
  }

  string &operator=(string &&o) noexcept
  {
    if ( this != &o )
    {
      if ( _large_mode() )
        delete[] _store.ptr;
      _size = o._size;
      _cap = o._cap;
      if ( o._large_mode() )
        _store.ptr = o._store.ptr;
      else
        _store = o._store;
      o._size = 0;
      o._cap = SSO_CAPACITY;
      o._store.buf[0] = 0;
    }
    return *this;
  }

  string &operator=(const char *s)
  {
    clear();
    append(s, detail::strlen_(s));
    return *this;
  }

  ~string()
  {
    if ( _large_mode() )
      delete[] _store.ptr;
  }

  const char *c_str() const noexcept { return _large_mode() ? _store.ptr : _store.buf; }
  char *data() noexcept              { return _large_mode() ? _store.ptr : _store.buf; }
  const char *data() const noexcept  { return _large_mode() ? _store.ptr : _store.buf; }
  unsigned size() const noexcept     { return _size; }
  unsigned capacity() const noexcept { return _cap; }
  bool empty() const noexcept        { return _size == 0; }

  char operator[](unsigned i) const noexcept { return data()[i]; }
  char &operator[](unsigned i) noexcept      { return data()[i]; }
  char front() const noexcept                { return data()[0]; }
  char back() const noexcept                 { return data()[_size - 1]; }

  void clear() noexcept { _size = 0; data()[0] = 0; }
  void reserve(unsigned min_cap) { if ( min_cap > _cap ) _grow_to(min_cap); }

  // Keep _size/_cap in locals and store _size exactly once. Writing a char through a char* can
  // alias the string object itself, so the compiler must reload any member it re-reads after a
  // store: the obvious `d[_size++] = c; d[_size] = 0;` costs a read-modify-write plus two extra
  // reloads per call, and measured 0.54x against std::string. Addressing the terminator as
  // d[sz + 1] instead removes them.
  void push_back(char c)
  {
    unsigned sz = _size;
    unsigned cap = _cap;
    if ( sz == cap )             // buffer full (holds _cap chars + '\0'); the grow is the cold call
    {
      _grow_to(sz + 1);
      cap = _cap;
    }
    char *d = cap > SSO_CAPACITY ? _store.ptr : _store.buf;
    d[sz] = c;
    d[sz + 1] = 0;
    _size = sz + 1;
  }

  void pop_back() noexcept
  {
    if ( _size != 0 )
    {
      --_size;
      data()[_size] = 0;
    }
  }

  void append(const char *s, unsigned n)
  {
    if ( n == 0 )
      return;
    unsigned sz = _size;                    // same reload-avoidance as push_back
    if ( sz + n > _cap )
      _grow_to(sz + n);
    char *d = data();
    detail::memcpy_(d + sz, s, n);
    d[sz + n] = 0;
    _size = sz + n;
  }

  void append(const char *s)   { append(s, detail::strlen_(s)); }
  void append(const string &o) { append(o.data(), o._size); }

  string &operator+=(char c)          { push_back(c); return *this; }
  string &operator+=(const char *s)   { append(s);    return *this; }
  string &operator+=(const string &o) { append(o);    return *this; }

  // Eight bytes per compare. A byte loop costs one branch per character, which is why long keys
  // (symbol names) lost to std::string's vectorized compare in the hash-map benchmark. Only
  // bytes inside the strings are read: the tail overlaps backwards instead of running past.
  bool operator==(const string &o) const noexcept
  {
    if ( _size != o._size )
      return false;
    const char *a = data();
    const char *b = o.data();
    unsigned n = _size;
    while ( n >= 8 )
    {
      if ( *(const unsigned long long *)a != *(const unsigned long long *)b )
        return false;
      a += 8;
      b += 8;
      n -= 8;
    }
    if ( n >= 4 )
    {
      return *(const unsigned *)a == *(const unsigned *)b
          && *(const unsigned *)(a + n - 4) == *(const unsigned *)(b + n - 4);
    }
    for ( unsigned i = 0; i < n; ++i )
      if ( a[i] != b[i] )
        return false;
    return true;
  }

  bool operator==(const char *s) const noexcept
  {
    const char *d = data();
    unsigned i = 0;
    for ( ; i < _size; ++i )
      if ( s[i] == 0 || s[i] != d[i] )
        return false;
    return s[i] == 0;   // s must end exactly where we do
  }

  bool operator!=(const string &o) const noexcept { return !(*this == o); }
  bool operator!=(const char *s) const noexcept   { return !(*this == s); }

  static const unsigned npos = 0xFFFFFFFFu;

  unsigned find(char c, unsigned from = 0) const noexcept
  {
    const char *d = data();
    for ( unsigned i = from; i < _size; ++i )
      if ( d[i] == c )
        return i;
    return npos;
  }

  unsigned find(const char *sub, unsigned from = 0) const noexcept
  {
    unsigned m = detail::strlen_(sub);
    if ( m == 0 )
      return from <= _size ? from : npos;
    if ( m > _size )
      return npos;
    const char *d = data();
    for ( unsigned i = from; i + m <= _size; ++i )
    {
      unsigned j = 0;
      while ( j < m && d[i + j] == sub[j] )
        ++j;
      if ( j == m )
        return i;
    }
    return npos;
  }

  string substr(unsigned pos, unsigned len = npos) const
  {
    if ( pos > _size )
      pos = _size;
    unsigned rem = _size - pos;
    return string(data() + pos, len < rem ? len : rem);
  }

  bool starts_with(const char *p) const noexcept
  {
    const char *d = data();
    for ( unsigned i = 0; p[i] != 0; ++i )
      if ( i >= _size || d[i] != p[i] )
        return false;
    return true;
  }

  bool ends_with(const char *p) const noexcept
  {
    unsigned m = detail::strlen_(p);
    if ( m > _size )
      return false;
    const char *d = data() + (_size - m);
    for ( unsigned i = 0; i < m; ++i )
      if ( d[i] != p[i] )
        return false;
    return true;
  }

private:
  bool _large_mode() const noexcept { return _cap > SSO_CAPACITY; }  // capacity encodes the mode
  // Cold path (allocates), out-of-line in string.cpp. noinline is load-bearing: under /GL /LTCG
  // the compiler will otherwise inline this -- new, delete and their EH state -- into whatever
  // tight push_back/append loop called it.
  __declspec(noinline) void _grow_to(unsigned min_cap);

  // 16 bytes: inline buffer OR pointer to a heap block, never both.
  //
  // Copying a small string copies this union WHOLE (`_store = o._store`) rather than looping over
  // _size bytes. The loop looks cheaper but is not: its length is a runtime value, so MSVC turns
  // it into a call to the CRT memcpy, and a call per 12-byte copy cost ~37 ns inside a hash map.
  // The union copy is a fixed 16 bytes the compiler emits as two moves.
  union
  {
    char buf[SSO_CAPACITY + 1];
    char *ptr;
  } _store;
  unsigned _size;   // length, excludes the '\0'
  unsigned _cap;    // capacity, excludes the '\0'; _cap <= SSO_CAPACITY means small (inline) mode
};

inline string operator+(const string &a, const string &b)
{
  string r;
  r.reserve(a.size() + b.size());
  r.append(a);
  r.append(b);
  return r;
}
inline string operator+(const string &a, const char *b) { string r = a; r.append(b); return r; }
inline string operator+(const char *a, const string &b) { string r = a; r.append(b); return r; }
inline string operator+(const string &a, char c)        { string r = a; r.push_back(c); return r; }

// Lets a string be a hash_map key: hash_map<string, V, string_hash>. The work is in
// detail::hash_bytes (hash.hpp), which hashes eight bytes per multiply instead of one.
struct string_hash
{
  unsigned long long operator()(const string &s) const noexcept
  {
    return detail::hash_bytes(s.data(), s.size());
  }
};

}  // namespace kstl
