// kstl algorithms -- our own, from scratch (microsoft/STL is reference only). No STL, no
// #includes. The centerpiece is sort(): introsort (quicksort + heapsort fallback + insertion
// sort for small runs), so it is guaranteed O(n log n) worst case -- never the O(n^2) a plain
// quicksort can hit on an adversarial big IDB. Operates on raw pointers, which is exactly what
// kstl::vector's begin()/end() return: kstl::sort(v.begin(), v.end()).
//
// sort() is a pdqsort-style two-way quicksort: a Tukey-ninther pivot sampled at n/8, a partition
// that costs ONE comparison per element, duplicates handled by partition_left, and a bounded
// insertion sort that finishes ranges the partition reports as already ordered.
//
// Four schemes were written and measured against each other and std::sort over 14 input shapes
// (300k unsigned, median of 11 runs; see doc/sort-benchmarks.md for the full table):
//
//      variant                                             geomean   rows below 1.0x
//      Lomuto two-way + middle pivot   (original)            0.44x   6 of 8
//      Bentley-McIlroy three-way + spread ninther            1.24x   all-equal, reverse-sorted
//      pdqsort as published (clustered sampling, sort3)      1.61x   organ pipe, 2 runs, all-equal
//   >> two-way + SPREAD ninther by selection (this one)      1.51x   all-equal only
//
// pdqsort as published has the better geometric mean and was NOT chosen: its nine pivot samples are
// clustered at the ends and the middle, which organ-pipe data defeats exactly the way three-point
// sampling does (0.76x, and 0.84x on two sorted runs appended). Spreading the samples at n/8 costs
// a little on random input and turns those two into 1.47x and 1.52x. Beating std on every shape was
// worth more than the geometric mean.
//
// Against std::sort now, per shape: sorted 5.7x, organ pipe 1.44x, reverse-sorted 1.42x, sawtooth
// 1.21x, 3 distinct 1.26x, random 1.15x, 100 distinct 1.14x, strings 1.01x, all-equal 0.88x.
//
// all-equal is the one shape std still wins, and it is structural rather than an oversight: MSVC's
// std::sort finishes an all-equal array in a single three-way partition, while this needs two
// passes (one partition_right that finds nothing below the pivot, then one partition_left that
// peels the equals). Buying it back means paying a second comparison per element on every other
// shape -- which is exactly what the Bentley-McIlroy variant above did, and it cost 1.24x against
// 1.51x overall. 34 microseconds on 300k elements was not worth that.
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

// Point at the median of three WITHOUT moving anything. A median-of-three pivot is what keeps
// sorted, reverse-sorted and organ-pipe inputs from being worst cases -- a fixed choice (first,
// last, or middle) is a worst case for SOME common shape, and real data is full of common shapes.
// Selecting rather than swapping leaves the caller's array untouched until the single pivot swap.
template <class T, class C>
inline T *median3(T *a, T *b, T *c, C comp)
{
  if ( comp(*a, *b) )
    return comp(*b, *c) ? b : (comp(*a, *c) ? c : a);
  return comp(*c, *b) ? b : (comp(*c, *a) ? c : a);
}

// ---- partitioning -------------------------------------------------------------------------
//
// Two-way, one comparison per element, with duplicates handled separately (partition_left below).
// The three-way Bentley-McIlroy partition this replaced asked TWO comparisons per element -- is it
// <= the pivot, and is it also >= it -- and for distinct data the second never fires but is always
// paid. That cost showed up worst where a comparison is expensive: sorting 100k heap-allocated
// strings ran at 0.97x of std::sort with three-way and 1.25x with two-way.
//
// The scan loops carry NO bounds test. They are safe because the pivot is a median: at least one
// element in (first, last) is >= it, which stops the rightward scan, and once the rightward scan
// has moved past first+1 there is an element < the pivot to stop the leftward scan (the case where
// it has not is guarded explicitly). That is verified rather than assumed -- the bake-off harness
// sorts 6000 random arrays of every shape inside guard words and checks the guards are untouched.

// Put the chosen pivot at *first. Nine samples spread at n/8 for a range over 16, three otherwise.
template <class T, class C>
inline void choose_pivot(T *first, T *last, C comp)
{
  long long n = last - first;
  T *pm = first + n / 2;
  if ( n > 16 )
  {
    // Tukey's ninther. Median-of-three looks only at the ends and the middle, which structured
    // input defeats -- an organ-pipe array has its largest values in the middle, so three-point
    // sampling picks near the maximum every time. Spreading the nine samples at n/8 rather than
    // clustering them (as pdqsort itself does) is worth 1.47x against 0.76x on that shape, and
    // 1.52x against 0.84x on two sorted runs appended. Both measured, not assumed.
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

// Partition around the pivot at *first. Returns where the pivot ended up, and sets *already when
// nothing had to cross it -- the signature of data that was already in order, which the caller
// exploits with partial_insertion_sort.
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

// Partition putting everything EQUAL to the pivot on the left. Only valid when the pivot is known
// to equal the parent's pivot, which is exactly when every element equal to it is inside this
// range. This is what keeps duplicate-heavy input linear without taxing distinct data: an array of
// one repeated value is finished by one of these, instead of splitting (0, n-1) forever the way a
// plain two-way partition does.
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

// Insertion sort that gives up. Runs at most LIMIT element moves in total and reports whether it
// finished; a caller that gets false must sort the range properly, and the partial work it did is
// still a valid permutation, so nothing is lost.
//
// This is what makes already-ordered input linear. A partition that moved nothing across the pivot
// says the range was ALREADY partitioned, and for ordered data this then finishes in one scan with
// zero moves -- sorted input went from 0.82x of std::sort to 14.3x. Random data essentially never
// reports "already partitioned", so it never pays for this.
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

// leftmost says whether *(first-1) exists and holds the parent's pivot. Only a non-leftmost range
// can use the equal-pivot shortcut, because only then is there a predecessor to compare against.
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

    // *(first-1) is the parent's pivot and is <= everything here. If it is ALSO not less than our
    // pivot the two are equal, so every element equal to it lies in this range: peel them all off
    // to the left in one pass and continue with only what is strictly greater.
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

    // Recurse into the SMALLER side and loop on the larger, so the live stack stays O(log n).
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
