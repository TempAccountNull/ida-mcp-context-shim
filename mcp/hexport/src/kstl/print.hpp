// kstl printing -- format the arguments into a kstl::string, then write the bytes to a file
// descriptor. Our own, no <cstdio>/<iostream> and no printf/fwrite (all of which the SDK
// poisons). The single output primitive is the CRT's low-level _write (fd 1 = stdout, 2 =
// stderr); we declare it ourselves so this header needs no <io.h>.
#pragma once
#include "format.hpp"

extern "C" int _write(int _FileHandle, const void *_Buf, unsigned int _MaxCharCount);

namespace kstl {

inline void write_fd(int fd, const char *p, unsigned n) noexcept
{
  if ( n != 0 )
    _write(fd, p, n);
}

inline void write_fd(int fd, const string &s) noexcept { write_fd(fd, s.data(), s.size()); }

template <class... A>
inline void print(const A &...a)   // -> stdout
{
  string s = format(a...);
  write_fd(1, s);
}

template <class... A>
inline void println(const A &...a)
{
  string s = format(a...);
  s.push_back('\n');
  write_fd(1, s);
}

template <class... A>
inline void eprint(const A &...a)   // -> stderr
{
  string s = format(a...);
  write_fd(2, s);
}

template <class... A>
inline void eprintln(const A &...a)
{
  string s = format(a...);
  s.push_back('\n');
  write_fd(2, s);
}

}  // namespace kstl
