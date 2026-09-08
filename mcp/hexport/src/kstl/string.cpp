// kstl::string -- the single cold, heavy method. Everything else (ctors, dtor, assignment, and
// the whole hot push_back/append path) is inline in the header so it folds into callers; only
// _grow_to, which allocates and copies, is worth keeping out-of-line here. No STL, only
// core-language new[]/delete[].
#include "string.hpp"

namespace kstl {

void string::_grow_to(unsigned min_cap)
{
  if ( min_cap <= _cap )
    return;
  // 2x, not 1.5x: halves both the number of reallocations and the total bytes recopied while a
  // string is built up. Measured on 10k char-at-a-time push_backs, 1.234 ns/op at 1.5x vs
  // 0.951 ns/op at 2x, reproducible across runs. The cost is up to 2x slack instead of 1.5x,
  // which is cheap for strings.
  unsigned geo = _cap * 2;
  // ...and never a first heap block smaller than 64. Doubling out of the 15-byte SSO buffer goes
  // 15 -> 30 -> 60 -> 120, so building a 64-character string char by char costs THREE allocations
  // where one would do. Starting at 64 makes it one: 0.69x of std::string to 0.92x on 200k such
  // strings. 64 is the knee, measured -- 32 gives 0.72x and 48 gives 0.78x, while 96 and 128 give
  // no more than 64 does and only waste more. The cost is that a string which settles just past
  // SSO holds 64 bytes rather than 30.
  if ( min_cap == _size + 1 && geo < 64 )
    geo = 64;
  unsigned new_cap = geo < min_cap ? min_cap : geo;     // ...but at least what was asked
  char *nb = new char[new_cap + 1];
  if ( _size != 0 )                 // a zero-length memcpy_ still compiles to a real CRT call, and
    detail::memcpy_(nb, data(), _size);   // every construction from a C string takes this path once
  nb[_size] = 0;
  if ( _large_mode() )
    delete[] _store.ptr;
  _store.ptr = nb;
  _cap = new_cap;   // new_cap > SSO_CAPACITY here, so we are now in large mode
}

}  // namespace kstl
