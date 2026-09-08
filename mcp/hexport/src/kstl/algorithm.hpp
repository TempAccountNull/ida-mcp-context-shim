// kstl algorithms -- our own, from scratch. No STL, no #includes; microsoft/STL in ref/ is read
// for ideas, never included. Operates on raw pointers, which is what kstl::vector's begin()/end()
// return: kstl::sort(v.begin(), v.end()).
//
// sort() is a pdqsort-style introsort: ninther pivot sampled at n/8, a two-way partition costing
// one comparison per element, partition_left for duplicates, a bounded insertion sort for ranges
// that come back already ordered, and a monotonic-run check at the entry. Heapsort backstop keeps
// the worst case O(n log n). Six variants were built and measured to arrive at this; the tables and
// the rejected ones are in doc/sort-benchmarks.md rather than here.
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

// Median of three, selected rather than swapped into place: the array is untouched until the one
// pivot swap. A fixed pivot (first, last or middle) is a worst case for some common shape.
template <class T, class C>
inline T *median3(T *a, T *b, T *c, C comp)
{
  if ( comp(*a, *b) )
    return comp(*b, *c) ? b : (comp(*a, *c) ? c : a);
  return comp(*c, *b) ? b : (comp(*c, *a) ? c : a);
}

// SAFETY, for everything below: the scan loops carry no bounds test. They terminate because the
// pivot is a median -- at least one element in (first, last) is >= it, stopping the rightward scan,
// and once that scan has passed first+1 there is an element < the pivot to stop the leftward one.
// The single case where that does not hold is guarded explicitly. sortcmp.cpp checks this rather
// than trusting it: 6000 random arrays per shape sorted inside guard words, guards verified intact.

// Put the chosen pivot at *first. Nine samples spread at n/8 for a range over 16, three otherwise.
template <class T, class C>
inline void choose_pivot(T *first, T *last, C comp)
{
  long long n = last - first;
  T *pm = first + n / 2;
  if ( n > 16 )
  {
    // Tukey's ninther. Three-point sampling looks only at the ends and the middle, which structured
    // input defeats -- organ-pipe data hides its peak in the middle. Samples are SPREAD at n/8
    // rather than clustered as pdqsort does; clustering costs organ pipe 0.76x against 1.45x.
    //
    // The threshold is 16, not the 40 of Bentley and McIlroy's paper. Above ~32 the sub-ranges that
    // come out of partitioning a reversed array start splitting (n-2, 1, 1) and burn the depth
    // budget: at 128 a third of that input ends up in the heapsort backstop. Sweep in the doc.
    long long s = n / 8;
    T *lo = median3(first, first + s, first + 2 * s, comp);
    T *mi = median3(pm - s, pm, pm + s, comp);
    T *hi = median3(last - 1 - 2 * s, last - 1 - s, last - 1, comp);
    pm = median3(lo, mi, hi, comp);
  }
  else
  {
    pm = median3(first, pm, last - 1, comp);
  }
  swap(*first, *pm);
}

// Two-way partition around the pivot at *first. Returns where the pivot landed; sets *already when
// nothing had to cross it, which is the signature of data that was already in order.
template <class T, class C>
inline T *partition_right(T *first, T *last, C comp, bool *already)
{
  T pivot = *first;
  T *lo = first;
  T *hi = last;
  while ( comp(*++lo, pivot) )
  {
  }
  if ( lo - 1 == first )
  {
    while ( lo < hi && !comp(*--hi, pivot) )   // nothing below the pivot yet, so no left sentinel
    {
    }
  }
  else
  {
    while ( !comp(*--hi, pivot) )
    {
    }
  }
  *already = lo >= hi;
  while ( lo < hi )
  {
    swap(*lo, *hi);
    while ( comp(*++lo, pivot) )
    {
    }
    while ( !comp(*--hi, pivot) )
    {
    }
  }
  T *pivot_pos = lo - 1;
  *first = static_cast<T &&>(*pivot_pos);
  *pivot_pos = static_cast<T &&>(pivot);
  return pivot_pos;
}

// Partition putting everything EQUAL to the pivot on the left. Only valid when the pivot equals the
// parent's pivot, which is exactly when every element equal to it is inside this range. This is how
// duplicates stay linear without a second comparison per element taxing distinct data.
template <class T, class C>
inline T *partition_left(T *first, T *last, C comp)
{
  T pivot = *first;
  T *lo = first;
  T *hi = last;
  while ( comp(pivot, *--hi) )
  {
  }
  if ( hi + 1 == last )
  {
    while ( lo < hi && !comp(pivot, *++lo) )
    {
    }
  }
  else
  {
    while ( !comp(pivot, *++lo) )
    {
    }
  }
  while ( lo < hi )
  {
    swap(*lo, *hi);
    while ( comp(pivot, *--hi) )
    {
    }
    while ( !comp(pivot, *++lo) )
    {
    }
  }
  T *pivot_pos = hi;
  *first = static_cast<T &&>(*pivot_pos);
  *pivot_pos = static_cast<T &&>(pivot);
  return pivot_pos;
}

// Insertion sort that gives up after LIMIT element moves and says whether it finished. A caller
// that gets false must sort the range properly; the partial work is still a valid permutation.
// Called only when a partition reports the range was already partitioned, which random data
// essentially never does, so random input never pays for it.
template <class T, class C>
inline bool partial_insertion_sort(T *first, T *last, C comp)
{
  const long long LIMIT = 8;
  if ( last - first < 2 )
    return true;
  long long moves = 0;
  for ( T *cur = first + 1; cur != last; ++cur )
  {
    if ( !comp(*cur, *(cur - 1)) )
      continue;                                 // in order relative to its predecessor
    T tmp = static_cast<T &&>(*cur);
    T *j = cur;
    do
    {
      *j = static_cast<T &&>(*(j - 1));
      --j;
    } while ( j != first && comp(tmp, *(j - 1)) );
    *j = static_cast<T &&>(tmp);
    moves += cur - j;
    if ( moves > LIMIT )
      return false;
  }
  return true;
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

// leftmost says whether *(first-1) exists and holds the parent's pivot -- only then is the
// equal-pivot shortcut below available.
template <class T, class C>
inline void introsort(T *first, T *last, int depth, C comp, bool leftmost)
{
  const long SMALL = 16;
  while ( last - first > SMALL )
  {
    if ( depth == 0 )                     // recursion too deep -> guaranteed O(n log n) fallback
    {
      heap_sort(first, last, comp);
      return;
    }
    long long n = last - first;
    choose_pivot(first, last, comp);

    // *(first-1) is the parent's pivot and is <= everything here. If it is also not less than ours
    // the two are equal, so every element equal to it lies in this range: peel them off in one pass.
    if ( !leftmost && !comp(*(first - 1), *first) )
    {
      first = partition_left(first, last, comp) + 1;
      continue;
    }

    bool already = false;
    T *pivot_pos = partition_right(first, last, comp, &already);
    --depth;

    long long lsize = pivot_pos - first;
    long long rsize = last - (pivot_pos + 1);
    bool unbalanced = lsize < n / 8 || rsize < n / 8;
    if ( already && !unbalanced
      && partial_insertion_sort(first, pivot_pos, comp)
      && partial_insertion_sort(pivot_pos + 1, last, comp) )
      return;                             // the range was already ordered; nothing left to do

    // Recurse the smaller side, loop on the larger: live stack stays O(log n).
    if ( lsize < rsize )
    {
      introsort(first, pivot_pos, depth, comp, leftmost);
      first = pivot_pos + 1;
      leftmost = false;
    }
    else
    {
      introsort(pivot_pos + 1, last, depth, comp, false);
      last = pivot_pos;
    }
  }
  insertion_sort(first, last, comp);      // leaf: finish this small run here, not in a global pass
}

}  // namespace detail

template <class T, class C>
inline void sort(T *first, T *last, C comp)
{
  if ( last - first > 1 )
  {
    // One scan, in whichever direction the first pair points. Descending end to end means reverse
    // and return; never descending means already sorted, return. The second case is what an
    // all-equal array is -- the one shape every partition scheme here lost to std::sort. Both stop
    // at the first pair that breaks the pattern, so anything else pays two comparisons.
    // It recognises a run spanning the WHOLE range and nothing weaker.
    T *p = first + 1;
    if ( comp(*p, *(p - 1)) )
    {
      while ( p != last && comp(*p, *(p - 1)) )
        ++p;
      if ( p == last )
      {
        reverse(first, last);
        return;
      }
    }
    else
    {
      while ( p != last && !comp(*p, *(p - 1)) )
        ++p;
      if ( p == last )
        return;                          // already non-decreasing, which includes all-equal
    }
    detail::introsort(first, last, 2 * detail::ilog2(long(last - first)), comp, true);
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
