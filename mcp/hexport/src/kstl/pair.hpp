// kstl::pair<A,B> -- our own two-field aggregate, from scratch. No STL, no #includes. Exists so
// hash_map can hand out {key, value} from an iterator without pulling in <utility>.
#pragma once

namespace kstl {

template <class A, class B>
struct pair
{
  A first;
  B second;

  pair() : first(), second() {}
  pair(const A &a, const B &b) : first(a), second(b) {}
  pair(A &&a, B &&b) : first(static_cast<A &&>(a)), second(static_cast<B &&>(b)) {}

  bool operator==(const pair &o) const { return first == o.first && second == o.second; }
  bool operator!=(const pair &o) const { return !(*this == o); }
  bool operator<(const pair &o) const
  {
    if ( first < o.first )
      return true;
    if ( o.first < first )
      return false;
    return second < o.second;
  }
  bool operator>(const pair &o) const  { return o < *this; }
  bool operator<=(const pair &o) const { return !(o < *this); }
  bool operator>=(const pair &o) const { return !(*this < o); }
};

template <class A, class B>
inline pair<A, B> make_pair(const A &a, const B &b) { return pair<A, B>(a, b); }

}  // namespace kstl
