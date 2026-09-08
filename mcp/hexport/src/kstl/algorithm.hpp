// kstl algorithms -- our own, from scratch (microsoft/STL is reference only). No STL, no
// #includes. The centerpiece is sort(): introsort (quicksort + heapsort fallback + insertion
// sort for small runs), so it is guaranteed O(n log n) worst case -- never the O(n^2) a plain
// quicksort can hit on an adversarial big IDB. Operates on raw pointers, which is exactly what
// kstl::vector's begin()/end() return: kstl::sort(v.begin(), v.end()).
#pragma once

namespace kstl {

template <class T>
inline void swap(T &a, T &b) noexcept
{
  T t = static_cast<T &&>(a);
  a = static_cast<T &&>(b);
  b = static_cast<T &&>(t);
}

template <class T>
inline const T &min(const T &a, const T &b) { return b < a ? b : a; }
template <class T>
inline const T &max(const T &a, const T &b) { return a < b ? b : a; }

template <class T, class C>
inline T *find_if(T *first, T *last, C pred)
{
  for ( ; first != last; ++first )
    if ( pred(*first) )
      return first;
  return last;
}

template <class T>
inline T *find(T *first, T *last, const T &value)
{
  for ( ; first != last; ++first )
    if ( *first == value )
      return first;
  return last;
}

template <class T>
inline void reverse(T *first, T *last)
{
  while ( first < last )
  {
    --last;
    if ( first == last )
      break;
    swap(*first, *last);
    ++first;
  }
}

// ---- sort internals ----

namespace detail {

template <class T, class C>
inline void insertion_sort(T *first, T *last, C comp)
{
  for ( T *i = first + 1; i < last; ++i )
  {
    T key = static_cast<T &&>(*i);
    T *j = i;
    while ( j > first && comp(key, *(j - 1)) )
    {
      *j = static_cast<T &&>(*(j - 1));
      --j;
    }
    *j = static_cast<T &&>(key);
  }
}

template <class T, class C>
inline void sift_down(T *a, unsigned root, unsigned n, C comp)
{
  for ( ;; )
  {
    unsigned child = 2 * root + 1;
    if ( child >= n )
      break;
    if ( child + 1 < n && comp(a[child], a[child + 1]) )
      ++child;
    if ( !comp(a[root], a[child]) )
      break;
    swap(a[root], a[child]);
    root = child;
  }
}

template <class T, class C>
inline void heap_sort(T *first, T *last, C comp)
{
  unsigned n = static_cast<unsigned>(last - first);
  for ( unsigned i = n / 2; i-- > 0; )
    sift_down(first, i, n, comp);
  for ( unsigned end = n; end > 1; )
  {
    --end;
    swap(first[0], first[end]);
    sift_down(first, 0, end, comp);
  }
}

template <class T, class C>
inline T *partition(T *first, T *last, C comp)
{
  T *pivot = last - 1;
  swap(*(first + (last - first) / 2), *pivot);   // middle element as pivot (good on sorted input)
  T *store = first;
  for ( T *p = first; p < pivot; ++p )
    if ( comp(*p, *pivot) )
    {
      swap(*p, *store);
      ++store;
    }
  swap(*store, *pivot);
  return store;   // [first,store) < pivot <= (store,last)
}

inline int ilog2(long n)
{
  int k = 0;
  while ( n > 1 )
  {
    n >>= 1;
    ++k;
  }
  return k;
}

template <class T, class C>
inline void introsort(T *first, T *last, int depth, C comp)
{
  const long SMALL = 16;
  while ( last - first > SMALL )
  {
    if ( depth == 0 )                     // recursion too deep -> guaranteed O(n log n) fallback
    {
      heap_sort(first, last, comp);
      return;
    }
    --depth;
    T *cut = partition(first, last, comp);
    introsort(cut + 1, last, depth, comp);   // recurse the right side
    last = cut;                              // loop on the left side
  }
}

}  // namespace detail

template <class T, class C>
inline void sort(T *first, T *last, C comp)
{
  if ( last - first > 1 )
  {
    detail::introsort(first, last, 2 * detail::ilog2(long(last - first)), comp);
    detail::insertion_sort(first, last, comp);   // finish the small runs left behind
  }
}

template <class T>
inline void sort(T *first, T *last)
{
  sort(first, last, [](const T &a, const T &b) { return a < b; });
}

// ---- binary search over a sorted range ----

template <class T, class C>
inline T *lower_bound(T *first, T *last, const T &value, C comp)
{
  while ( first < last )
  {
    T *mid = first + (last - first) / 2;
    if ( comp(*mid, value) )
      first = mid + 1;
    else
      last = mid;
  }
  return first;   // first position whose element is not < value
}

template <class T>
inline T *lower_bound(T *first, T *last, const T &value)
{
  return lower_bound(first, last, value, [](const T &a, const T &b) { return a < b; });
}

template <class T>
inline bool binary_search(T *first, T *last, const T &value)
{
  T *p = lower_bound(first, last, value);
  return p != last && !(value < *p);
}

// ---- linear-scan primitives ----

template <class T>
inline T *min_element(T *first, T *last)
{
  if ( first == last ) return last;
  T *m = first;
  for ( T *p = first + 1; p < last; ++p ) if ( *p < *m ) m = p;
  return m;
}

template <class T>
inline T *max_element(T *first, T *last)
{
  if ( first == last ) return last;
  T *m = first;
  for ( T *p = first + 1; p < last; ++p ) if ( *m < *p ) m = p;
  return m;
}

template <class T>
inline unsigned count(const T *first, const T *last, const T &value)
{
  unsigned c = 0;
  for ( ; first != last; ++first ) if ( *first == value ) ++c;
  return c;
}

template <class T, class P>
inline unsigned count_if(const T *first, const T *last, P pred)
{
  unsigned c = 0;
  for ( ; first != last; ++first ) if ( pred(*first) ) ++c;
  return c;
}

template <class T, class F>
inline F for_each(T *first, T *last, F f)
{
  for ( ; first != last; ++first ) f(*first);
  return f;
}

template <class T>
inline void fill(T *first, T *last, const T &value)
{
  for ( ; first != last; ++first ) *first = value;
}

template <class T>
inline T *copy(const T *first, const T *last, T *dst)
{
  while ( first != last ) *dst++ = *first++;
  return dst;
}

// Collapse consecutive equal elements (run this after sort() to dedup); returns the new logical
// end -- the caller trims the tail (e.g. while (v.size() > new_end - v.begin()) v.pop_back()).
template <class T>
inline T *unique(T *first, T *last)
{
  if ( first == last ) return last;
  T *result = first;
  for ( T *p = first + 1; p < last; ++p )
    if ( !(*result == *p) )
    {
      ++result;
      if ( result != p ) *result = static_cast<T &&>(*p);
    }
  return result + 1;
}

}  // namespace kstl
