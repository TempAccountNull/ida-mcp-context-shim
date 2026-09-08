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
#include "hash.hpp"          // detail::hash_bytes, for string_hash at the bottom
#include "intrin/sse2.hpp"   // the 16-byte substring scan in detail::find_sub

namespace kstl {

namespace detail {
// Eight bytes per step instead of one. Every string(const char *), operator=(const char *) and
// append(const char *) runs this first, so a byte loop taxes the whole class: constructing from a
// 96-character C string measured 0.66x against std::string purely here.
//
// The SWAR test (v - 0x01..01) & ~v & 0x80..80 has a bit set in the low byte of any zero byte, and
// only there. The alignment prologue is not optional: reading eight bytes at once past the
// terminator is only safe if the read cannot cross into an unmapped page, and an ALIGNED 8-byte
// read never straddles a page boundary. An unaligned one can, so the loop must start aligned.
inline unsigned strlen_(const char *s) noexcept
{
  if ( s == nullptr )
    return 0;
  const char *p = s;
  while ( (reinterpret_cast<unsigned long long>(p) & 7) != 0 )   // reach an 8-byte boundary
  {
    if ( *p == 0 )
      return static_cast<unsigned>(p - s);
    ++p;
  }
  for ( ;; )
  {
    unsigned long long v = *reinterpret_cast<const unsigned long long *>(p);
    unsigned long long z = (v - 0x0101010101010101ull) & ~v & 0x8080808080808080ull;
    if ( z != 0 )
    {
      unsigned long idx;
      _BitScanForward64(&idx, z);            // lowest set bit -> the first zero byte
      return static_cast<unsigned>(p - s) + static_cast<unsigned>(idx >> 3);
    }
    p += 8;
  }
}
// Substring search, sixteen candidate positions per step. Shared by string::find and
// string_view::find so the two cannot drift apart.
//
// The trick is to test the needle's FIRST and LAST byte against sixteen offsets at once and AND the
// two masks: a position survives only if both ends match, which rejects essentially every wrong
// position without touching the middle. Testing both ends rather than just the first is what keeps
// a haystack that repeats the needle's first character from degenerating.
//
// A scalar version of exactly this was written first and measured no better than the plain nested
// loop it replaced -- 0.18x against std::string::find either way. That is worth remembering: the
// nested loop's cost was never the inner comparison, it was touching 4000 bytes one at a time, and
// no amount of early rejection fixes a scalar scan. Only doing sixteen at once does.
inline unsigned find_sub(const char *hay, unsigned n, const char *ned, unsigned m, unsigned from) noexcept
{
  const unsigned NPOS = 0xFFFFFFFFu;
  if ( m == 0 )
    return from <= n ? from : NPOS;
  if ( m > n || from > n - m )
    return NPOS;
  unsigned last = n - m;                       // last index a match can start at
  __m128i v0 = _mm_set1_epi8(ned[0]);
  __m128i vn = _mm_set1_epi8(ned[m - 1]);
  unsigned i = from;
  for ( ; i + 16 <= last + 1; i += 16 )
  {
    // Both loads stay inside the string: i+15 <= last = n-m, so i+m-1+15 <= n-1.
    __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i *>(hay + i));
    __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i *>(hay + i + m - 1));
    unsigned mask = static_cast<unsigned>(_mm_movemask_epi8(
        _mm_and_si128(_mm_cmpeq_epi8(a, v0), _mm_cmpeq_epi8(b, vn))));
    for ( ; mask != 0; mask &= mask - 1 )
    {
      unsigned long bit;
      _BitScanForward(&bit, mask);
      unsigned p = i + static_cast<unsigned>(bit);
      unsigned j = 1;
      while ( j + 1 < m && hay[p + j] == ned[j] )
        ++j;
      if ( j + 1 >= m )
        return p;
    }
  }
  for ( ; i <= last; ++i )                     // tail: fewer than 16 positions left
  {
    if ( hay[i] != ned[0] || hay[i + m - 1] != ned[m - 1] )
      continue;
    unsigned j = 1;
    while ( j + 1 < m && hay[i + j] == ned[j] )
      ++j;
    if ( j + 1 >= m )
      return i;
  }
  return NPOS;
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

  string(const char *s) : _size(0), _cap(SSO_CAPACITY) { _init(s, detail::strlen_(s)); }

  string(const char *s, unsigned n) : _size(0), _cap(SSO_CAPACITY) { _init(s, n); }

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

  // data() is NOT free: it tests _cap to pick the inline buffer or the heap block. Worse, writing a
  // char through the returned pointer can alias the string object itself, so the compiler is
  // obliged to redo that test after any store. Cache it in a local before any loop -- never call it
  // per iteration.
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
  char &front() noexcept                     { return data()[0]; }
  char &back() noexcept                      { return data()[_size - 1]; }

  char *begin() noexcept              { return data(); }
  char *end() noexcept                { return data() + _size; }
  const char *begin() const noexcept  { return data(); }
  const char *end() const noexcept    { return data() + _size; }
  const char *cbegin() const noexcept { return data(); }
  const char *cend() const noexcept   { return data() + _size; }

  // Checked accessor: nullptr for an out-of-range index, matching vector::at and hash_map::find.
  char *at(unsigned i) noexcept             { return i < _size ? data() + i : nullptr; }
  const char *at(unsigned i) const noexcept { return i < _size ? data() + i : nullptr; }

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
    if ( sz != cap )                      // fast path, with nothing after it to fall through to
    {
      char *d = cap > SSO_CAPACITY ? _store.ptr : _store.buf;
      d[sz] = c;
      d[sz + 1] = 0;
      _size = sz + 1;
      return;
    }
    _grow_to(sz + 1);            // cold: buffer full (holds _cap chars + '\0')
    char *d = _store.ptr;        // a grown string is always in large mode, so no mode test here
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
      if ( *reinterpret_cast<const unsigned long long *>(a) != *reinterpret_cast<const unsigned long long *>(b) )
        return false;
      a += 8;
      b += 8;
      n -= 8;
    }
    if ( n >= 4 )
    {
      return *reinterpret_cast<const unsigned *>(a) == *reinterpret_cast<const unsigned *>(b)
          && *reinterpret_cast<const unsigned *>(a + n - 4) == *reinterpret_cast<const unsigned *>(b + n - 4);
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

  // kstl::string is trivially relocatable: nothing points into the object -- the SSO buffer is
  // inline data and the heap pointer is not self-referential -- so two strings can be exchanged by
  // swapping their raw bytes. The generic three-move swap in algorithm.hpp runs operator=(string&&)
  // twice, and each of those re-tests the small/large mode and may call delete[]. Sorting moves
  // strings constantly, so this is on the hot path of every sort, insertion sort and vecswap.
  friend void swap(string &a, string &b) noexcept
  {
    struct raw_t { unsigned long long w[3]; };            // exactly sizeof(string); see the assert
    raw_t t = *reinterpret_cast<raw_t *>(&a);
    *reinterpret_cast<raw_t *>(&a) = *reinterpret_cast<raw_t *>(&b);
    *reinterpret_cast<raw_t *>(&b) = t;
  }

  bool operator!=(const string &o) const noexcept { return !(*this == o); }
  bool operator!=(const char *s) const noexcept   { return !(*this == s); }

  // Lexicographic three-way compare, eight bytes at a time, for sorting and ordered containers.
  // The byte swap is what makes a 64-bit compare agree with a byte loop: on a little-endian machine
  // the FIRST character of the string sits in the LOW byte of the word, so comparing the words as
  // integers would order by the last character first. Swapping puts them in comparison order. It
  // costs one BSWAP on the single word where the strings actually differ, not one per word.
  //
  // This existed nowhere before, so sorting strings meant hand-writing a byte-loop comparator at
  // the call site -- which is exactly what the benchmark did, and why sorting 100k strings measured
  // 0.38x against std::sort no matter which partition scheme was underneath it.
  int compare(const string &o) const noexcept
  {
    unsigned n = _size < o._size ? _size : o._size;
    const char *a = data();
    const char *b = o.data();
    unsigned i = 0;
    for ( ; i + 8 <= n; i += 8 )
    {
      unsigned long long x = *reinterpret_cast<const unsigned long long *>(a + i);
      unsigned long long y = *reinterpret_cast<const unsigned long long *>(b + i);
      if ( x != y )
        return _byteswap_uint64(x) < _byteswap_uint64(y) ? -1 : 1;
    }
    for ( ; i < n; ++i )
      if ( a[i] != b[i] )
        return static_cast<unsigned char>(a[i]) < static_cast<unsigned char>(b[i]) ? -1 : 1;
    if ( _size != o._size )
      return _size < o._size ? -1 : 1;   // a prefix sorts before the longer string
    return 0;
  }

  bool operator<(const string &o) const noexcept  { return compare(o) < 0; }
  bool operator>(const string &o) const noexcept  { return compare(o) > 0; }
  bool operator<=(const string &o) const noexcept { return compare(o) <= 0; }
  bool operator>=(const string &o) const noexcept { return compare(o) >= 0; }

  // Same three-way compare against a C string. A null pointer is treated as the empty string, the
  // way strlen_ already treats it -- an invalid argument gives a defined answer, not a fault.
  int compare(const char *s) const noexcept
  {
    unsigned m = detail::strlen_(s);
    unsigned n = _size < m ? _size : m;
    const char *a = data();
    for ( unsigned i = 0; i < n; ++i )
      if ( a[i] != s[i] )
        return static_cast<unsigned char>(a[i]) < static_cast<unsigned char>(s[i]) ? -1 : 1;
    if ( _size != m )
      return _size < m ? -1 : 1;
    return 0;
  }

  bool operator<(const char *s) const noexcept  { return compare(s) < 0; }
  bool operator>(const char *s) const noexcept  { return compare(s) > 0; }
  bool operator<=(const char *s) const noexcept { return compare(s) <= 0; }
  bool operator>=(const char *s) const noexcept { return compare(s) >= 0; }

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
    return detail::find_sub(data(), _size, sub, detail::strlen_(sub), from);
  }

  bool contains(const char *sub) const noexcept { return find(sub) != npos; }
  bool contains(char c) const noexcept          { return find(c) != npos; }

  unsigned rfind(char c) const noexcept
  {
    const char *d = data();
    for ( unsigned i = _size; i-- > 0; )
      if ( d[i] == c )
        return i;
    return npos;
  }

  unsigned rfind(const char *sub) const noexcept
  {
    unsigned m = detail::strlen_(sub);
    if ( m == 0 )
      return _size;
    if ( m > _size )
      return npos;
    const char *d = data();
    for ( unsigned i = _size - m + 1; i-- > 0; )
    {
      unsigned j = 0;
      while ( j < m && d[i + j] == sub[j] )
        ++j;
      if ( j == m )
        return i;
    }
    return npos;
  }

  unsigned find_first_of(const char *set, unsigned from = 0) const noexcept
  {
    const char *d = data();
    for ( unsigned i = from; i < _size; ++i )
      for ( const char *p = set; *p != 0; ++p )
        if ( d[i] == *p )
          return i;
    return npos;
  }

  unsigned find_last_of(const char *set) const noexcept
  {
    const char *d = data();
    for ( unsigned i = _size; i-- > 0; )
      for ( const char *p = set; *p != 0; ++p )
        if ( d[i] == *p )
          return i;
    return npos;
  }

  // Drop count characters at pos. Both are clamped rather than rejected, the way substr clamps.
  void erase(unsigned pos, unsigned count = npos)
  {
    if ( pos >= _size )
      return;
    unsigned rem = _size - pos;
    unsigned n = count < rem ? count : rem;
    if ( n == 0 )
      return;
    char *d = data();
    for ( unsigned i = pos; i + n < _size; ++i )
      d[i] = d[i + n];
    _size -= n;
    d[_size] = 0;
  }

  void resize(unsigned n, char fill = 0)
  {
    if ( n < _size )
    {
      char *d = this->data();          // bound once; shrinking cannot reallocate
      _size = n;
      d[n] = 0;
      return;
    }
    this->reserve(n);
    char *d = this->data();            // bound after reserve(): it can move the buffer
    for ( unsigned i = _size; i < n; ++i )
      d[i] = fill;
    _size = n;
    d[n] = 0;
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
  // Construct straight into a block of exactly the right size. Routing a construction through
  // append() means routing it through _grow_to, which is __declspec(noinline) on purpose -- it must
  // not be inlined into push_back loops -- so building a string from a C string paid an out-of-line
  // call and a doubling calculation for a length that was already known here.
  void _init(const char *s, unsigned n)
  {
    if ( n <= SSO_CAPACITY )
    {
      detail::memcpy_(_store.buf, s, n);
      _store.buf[n] = 0;
    }
    else
    {
      char *nb = new char[n + 1];
      detail::memcpy_(nb, s, n);
      nb[n] = 0;
      _store.ptr = nb;
      _cap = n;
    }
    _size = n;
  }

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

static_assert(sizeof(string) == 24, "string::swap exchanges exactly three 8-byte words");

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
