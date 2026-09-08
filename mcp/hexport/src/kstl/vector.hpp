// kstl::vector<T> -- our own vector, written from scratch (microsoft/STL in ref/STL is
// reference only). Same shape std::vector uses: three pointers {first, last, end} over a heap
// block that grows geometrically (1.5x). No STL, no #includes.
//
// Storage is raw (the ordinary global ::operator new / ::operator delete are implicitly
// declared in every TU, so no <new>). Elements are constructed/destroyed in place through our
// OWN tagged placement-new below -- a distinct signature, so it neither needs <new> nor
// collides with the standard operator new(size_t, void*). Trivially-copyable T takes a fast
// relocate-by-copy path; everything else is move-constructed + destroyed properly, so the
// vector holds any type (kstl::string, qstring, ...).
#pragma once

namespace kstl {
struct place_t {};   // tag that makes our placement-new unambiguous vs the standard one
}

inline void *operator new(unsigned long long, void *p, kstl::place_t) noexcept { return p; }
inline void operator delete(void *, void *, kstl::place_t) noexcept {}

namespace kstl {

template <class T>
class vector
{
public:
  vector() noexcept : _first(nullptr), _last(nullptr), _end(nullptr) {}

  vector(const vector &o) : _first(nullptr), _last(nullptr), _end(nullptr)
  {
    _copy_from(o._first, o.size());
  }

  vector(vector &&o) noexcept : _first(o._first), _last(o._last), _end(o._end)
  {
    o._first = o._last = o._end = nullptr;
  }

  vector &operator=(const vector &o)
  {
    if ( this != &o )
    {
      clear();
      _copy_from(o._first, o.size());
    }
    return *this;
  }

  vector &operator=(vector &&o) noexcept
  {
    if ( this != &o )
    {
      _free();
      _first = o._first;
      _last = o._last;
      _end = o._end;
      o._first = o._last = o._end = nullptr;
    }
    return *this;
  }

  ~vector() { _free(); }

  unsigned size() const noexcept     { return unsigned(_last - _first); }
  unsigned capacity() const noexcept { return unsigned(_end - _first); }
  bool empty() const noexcept        { return _first == _last; }

  T *data() noexcept              { return _first; }
  const T *data() const noexcept  { return _first; }
  T *begin() noexcept             { return _first; }
  T *end() noexcept               { return _last; }
  const T *begin() const noexcept { return _first; }
  const T *end() const noexcept   { return _last; }

  T &operator[](unsigned i) noexcept             { return _first[i]; }
  const T &operator[](unsigned i) const noexcept { return _first[i]; }
  T &front() noexcept                            { return *_first; }
  T &back() noexcept                             { return _last[-1]; }

  void clear() noexcept
  {
    _destroy(_first, _last);
    _last = _first;
  }

  void reserve(unsigned n)
  {
    if ( n > capacity() )
      _grow_to(n);
  }

  void push_back(const T &v)
  {
    if ( _last == _end )
      _grow_to(size() + 1);
    ::new ((void *)_last, place_t{}) T(v);            // copy-construct in place
    ++_last;
  }

  void push_back(T &&v)
  {
    if ( _last == _end )
      _grow_to(size() + 1);
    ::new ((void *)_last, place_t{}) T(static_cast<T &&>(v));   // move-construct in place
    ++_last;
  }

  template <class... A>
  T &emplace_back(A &&...a)
  {
    if ( _last == _end )
      _grow_to(size() + 1);
    ::new ((void *)_last, place_t{}) T(static_cast<A &&>(a)...);
    return *_last++;
  }

  void pop_back() noexcept
  {
    if ( _last != _first )
    {
      --_last;
      _last->~T();
    }
  }

  void resize(unsigned n)
  {
    if ( n < size() )
    {
      _destroy(_first + n, _last);
      _last = _first + n;
    }
    else if ( n > size() )
    {
      reserve(n);
      while ( size() < n )
      {
        ::new ((void *)_last, place_t{}) T();
        ++_last;
      }
    }
  }

  void resize(unsigned n, const T &value)
  {
    if ( n < size() )
    {
      _destroy(_first + n, _last);
      _last = _first + n;
    }
    else
    {
      reserve(n);
      while ( size() < n )
      {
        ::new ((void *)_last, place_t{}) T(value);
        ++_last;
      }
    }
  }

  void assign(unsigned count, const T &value)
  {
    clear();
    reserve(count);
    for ( unsigned i = 0; i < count; ++i )
      push_back(value);
  }

  void erase(unsigned pos) noexcept
  {
    unsigned n = size();
    if ( pos >= n )
      return;
    for ( unsigned j = pos; j + 1 < n; ++j )
      _first[j] = static_cast<T &&>(_first[j + 1]);   // shift the tail down one
    pop_back();                                        // destroy the vacated last slot
  }

  void insert(unsigned pos, const T &v)
  {
    unsigned n = size();
    if ( pos > n )
      pos = n;
    if ( _last == _end )
      _grow_to(n + 1);
    if ( n == 0 )
    {
      ::new ((void *)_last, place_t{}) T(v);
    }
    else
    {
      ::new ((void *)_last, place_t{}) T(static_cast<T &&>(_first[n - 1]));   // new last <- old last
      for ( unsigned j = n - 1; j > pos; --j )
        _first[j] = static_cast<T &&>(_first[j - 1]);                         // shift [pos..n-1) up one
      _first[pos] = v;
    }
    ++_last;
  }

private:
  static void _destroy(T *b, T *e) noexcept
  {
    if constexpr ( !__is_trivially_destructible(T) )
      for ( T *p = b; p != e; ++p )
        p->~T();
  }

  // noinline is load-bearing: this is the cold path, but push_back/emplace_back call it from
  // inside tight loops, and left alone the compiler inlines the whole allocate-and-relocate body
  // -- plus its EH state -- into that loop. Measured on kstl::string's equivalent, outlining the
  // grow took push_back from 0.95 to 0.58 ns/op.
  __declspec(noinline) void _grow_to(unsigned min_cap)
  {
    unsigned old_cap = capacity();
    unsigned geo = old_cap + old_cap / 2;                 // 1.5x geometric growth
    unsigned new_cap = geo < min_cap ? min_cap : geo;     // ...at least what's needed
    if ( new_cap == 0 )
      new_cap = 1;
    T *nb = static_cast<T *>(::operator new(static_cast<unsigned long long>(new_cap) * sizeof(T)));
    unsigned n = size();
    if constexpr ( __is_trivially_copyable(T) )
    {
      for ( unsigned i = 0; i < n; ++i )     // fast path: trivial relocate
        nb[i] = _first[i];
    }
    else
    {
      for ( unsigned i = 0; i < n; ++i )     // move old elements into new storage, destroy old
      {
        ::new ((void *)(nb + i), place_t{}) T(static_cast<T &&>(_first[i]));
        _first[i].~T();
      }
    }
    if ( _first != nullptr )
      ::operator delete(_first);
    _first = nb;
    _last = nb + n;
    _end = nb + new_cap;
  }

  void _copy_from(const T *src, unsigned n)
  {
    if ( n != 0 )
    {
      reserve(n);
      for ( unsigned i = 0; i < n; ++i )
        ::new ((void *)(_first + i), place_t{}) T(src[i]);
      _last = _first + n;
    }
  }

  void _free() noexcept
  {
    _destroy(_first, _last);
    if ( _first != nullptr )
      ::operator delete(_first);
    _first = _last = _end = nullptr;
  }

  T *_first;   // begin
  T *_last;    // begin + size
  T *_end;     // begin + capacity
};

}  // namespace kstl
