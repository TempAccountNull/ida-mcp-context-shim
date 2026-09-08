// kstl::hash_map<K,V> -- our own hash map, from scratch. Open addressing over a power-of-2 table
// with abseil-style triangular group probing, tombstones on erase. No STL; the only include is our
// vector.hpp, for the tagged placement-new (place_t) used to build entries in raw storage, so K and
// V may be any type.
//
// The design in one paragraph: a key's hash is multiplied by 2^64/phi and the top bits index an
// array of entries holding key and value together, alongside a dense array of one state byte per
// slot carrying a 7-bit fingerprint of the key. The home slot is addressed by the hash alone, so
// its entry load issues in PARALLEL with its state load -- that is the property everything else is
// arranged around. Misses and collisions fall into a triangular group probe, sixteen state bytes
// per SSE compare, and the fingerprint means an occupied-but-wrong slot touches the entry array
// with probability 1/128. Fill is 7/8, and a table filled by tombstones rebuilds at the same
// capacity rather than doubling, so erase/insert churn cannot grow the map.
//
// 146 win / 10 tie / 14 loss vs phmap (geomean 1.38x), 166 of 170 vs std::unordered_map.
// Measurements, rejected designs and the remaining losses: doc/hash-map-benchmarks.md.
#pragma once
#include "vector.hpp"
#include "pair.hpp"    // kstl::pair, for what an iterator dereferences to
#include "hash.hpp"     // kstl::hash<K> (identity for integers, hash_bytes for the rest)
#include "intrin/x64.hpp"    // _mm_prefetch, _BitScanForward/64 -- header-free, generated from the toolset
#include "intrin/sse2.hpp"   // __m128i and the SSE2 group scan; only these two families, not the umbrella
// (Prefetch hint values are MSVC's: 0 = NTA, 1 = T0, 2 = T1, 3 = T2. GCC/Clang number them
// differently -- T0 is 3 there.)

namespace kstl {

template <class K, class V, class H = hash<K>>
class hash_map
{
public:
  hash_map() noexcept : _state(nullptr), _ent(nullptr), _cap(0), _size(0), _tombs(0), _shift(0) {}

  hash_map(const hash_map &o) : hash_map() { reserve(o._size); _reinsert_from(o); }

  hash_map(hash_map &&o) noexcept
    : _state(o._state), _ent(o._ent), _cap(o._cap), _size(o._size), _tombs(o._tombs), _shift(o._shift)
  {
    o._state = nullptr; o._ent = nullptr;
    o._cap = 0; o._size = 0; o._tombs = 0; o._shift = 0;
  }

  hash_map &operator=(const hash_map &o)
  {
    if ( this != &o ) { this->_clear_and_free(); this->reserve(o._size); this->_reinsert_from(o); }
    return *this;
  }

  hash_map &operator=(hash_map &&o) noexcept
  {
    if ( this != &o )
    {
      this->_clear_and_free();
      _state = o._state; _ent = o._ent;
      _cap = o._cap; _size = o._size; _tombs = o._tombs; _shift = o._shift;
      o._state = nullptr; o._ent = nullptr;
      o._cap = 0; o._size = 0; o._tombs = 0; o._shift = 0;
    }
    return *this;
  }

  ~hash_map() { _clear_and_free(); }

  unsigned size() const noexcept         { return _size; }
  bool empty() const noexcept            { return _size == 0; }
  unsigned bucket_count() const noexcept { return _cap; }
  float load_factor() const noexcept     { return _cap == 0 ? 0.0f : static_cast<float>(_size) / static_cast<float>(_cap); }
  unsigned count(const K &key) const noexcept { return contains(key) ? 1u : 0u; }

  // Forward iterator over the occupied slots. for_each is still the fast way to walk the whole map
  // -- it reads the state array eight bytes at a time and prefetches ahead -- but an iterator is
  // what range-for and generic code need, so both exist.
  class iterator
  {
  public:
    iterator() noexcept : _m(nullptr), _i(0) {}
    iterator(hash_map *m, unsigned i) noexcept : _m(m), _i(i) { _skip(); }

    pair<const K &, V &> operator*() const noexcept
    {
      return pair<const K &, V &>(_m->_ent[_i].key, _m->_ent[_i].val);
    }
    const K &key() const noexcept { return _m->_ent[_i].key; }
    V &value() const noexcept     { return _m->_ent[_i].val; }

    iterator &operator++() noexcept { ++_i; _skip(); return *this; }
    bool operator==(const iterator &o) const noexcept { return _i == o._i; }
    bool operator!=(const iterator &o) const noexcept { return _i != o._i; }

  private:
    // Hoist the map's fields out of the loop. Written as _m->_cap / _m->_state[_i] this reloads
    // the map pointer, the capacity and the state pointer on every step -- three dependent loads
    // per slot skipped, on a walk whose whole job is skipping.
    void _skip() noexcept
    {
      const unsigned cap = _m->_cap;
      const unsigned char *st = _m->_state;
      unsigned i = _i;
      while ( i < cap && st[i] < FULL_MIN )
        ++i;
      _i = i;
    }
    hash_map *_m;
    unsigned _i;
  };

  class const_iterator
  {
  public:
    const_iterator() noexcept : _m(nullptr), _i(0) {}
    const_iterator(const hash_map *m, unsigned i) noexcept : _m(m), _i(i) { _skip(); }

    pair<const K &, const V &> operator*() const noexcept
    {
      return pair<const K &, const V &>(_m->_ent[_i].key, _m->_ent[_i].val);
    }
    const K &key() const noexcept   { return _m->_ent[_i].key; }
    const V &value() const noexcept { return _m->_ent[_i].val; }

    const_iterator &operator++() noexcept { ++_i; _skip(); return *this; }
    bool operator==(const const_iterator &o) const noexcept { return _i == o._i; }
    bool operator!=(const const_iterator &o) const noexcept { return _i != o._i; }

  private:
    // Hoist the map's fields out of the loop. Written as _m->_cap / _m->_state[_i] this reloads
    // the map pointer, the capacity and the state pointer on every step -- three dependent loads
    // per slot skipped, on a walk whose whole job is skipping.
    void _skip() noexcept
    {
      const unsigned cap = _m->_cap;
      const unsigned char *st = _m->_state;
      unsigned i = _i;
      while ( i < cap && st[i] < FULL_MIN )
        ++i;
      _i = i;
    }
    const hash_map *_m;
    unsigned _i;
  };

  iterator begin() noexcept             { return iterator(this, 0); }
  iterator end() noexcept               { return iterator(this, _cap); }
  const_iterator begin() const noexcept { return const_iterator(this, 0); }
  const_iterator end() const noexcept   { return const_iterator(this, _cap); }
  const_iterator cbegin() const noexcept { return const_iterator(this, 0); }
  const_iterator cend() const noexcept   { return const_iterator(this, _cap); }

  // Pre-size for at least n entries so a bulk insert never rehashes.
  void reserve(unsigned n)
  {
    unsigned need = MIN_CAP;
    while ( n > this->_max_fill(need) )
      need <<= 1;
    if ( need > _cap )
      this->_rehash(need);
  }

  V *find(const K &key) noexcept
  {
    if ( _cap == 0 )
      return nullptr;
    return this->_locate(key, H{}(key) * FIB);
  }

  const V *find(const K &key) const noexcept { return const_cast<hash_map *>(this)->find(key); }
  bool contains(const K &key) const noexcept { return const_cast<hash_map *>(this)->find(key) != nullptr; }

  // Start the cache-line fetches for `key`'s slot without looking it up -- lets a caller doing
  // bulk lookups pipeline: prefetch(next_key) while still processing the current one.
  void prefetch(const K &key) const noexcept
  {
    if ( _cap != 0 )
    {
      unsigned i = static_cast<unsigned>((H{}(key) * FIB) >> _shift);
      _pf(&_state[i]);
      _pf(&_ent[i]);
    }
  }

  V &operator[](const K &key)
  {
    unsigned i;
    const bool created = this->_emplace_slot(key, i);
    entry_t *e = this->_ent + i;      // bound after _emplace_slot: it can rehash and move _ent
    if ( created )
      ::new (static_cast<void *>(&e->val), place_t{}) V();
    return e->val;
  }

  bool insert(const K &key, const V &val)
  {
    unsigned i;
    const bool created = this->_emplace_slot(key, i);
    entry_t *e = this->_ent + i;      // bound after _emplace_slot: it can rehash and move _ent
    if ( created )
      ::new (static_cast<void *>(&e->val), place_t{}) V(val);
    else
      e->val = val;
    return created;
  }

  bool insert(const K &key, V &&val)
  {
    unsigned i;
    const bool created = this->_emplace_slot(key, i);
    entry_t *e = this->_ent + i;      // bound after _emplace_slot: it can rehash and move _ent
    if ( created )
      ::new (static_cast<void *>(&e->val), place_t{}) V(static_cast<V &&>(val));
    else
      e->val = static_cast<V &&>(val);
    return created;
  }

  // Overwrites an existing value; returns true when the key was new. Same thing insert() does, but
  // named the way the STL names it, so generic code reads the same.
  bool insert_or_assign(const K &key, const V &val) { return insert(key, val); }

  // Leaves an existing value alone. Returns true when the key was new.
  bool try_emplace(const K &key, const V &val)
  {
    unsigned i;
    if ( !this->_emplace_slot(key, i) )
      return false;
    ::new (static_cast<void *>(&this->_ent[i].val), place_t{}) V(val);
    return true;
  }

  // Construct the value in place from whatever V's constructor takes -- no temporary V is built.
  template <class... A>
  bool emplace(const K &key, A &&...a)
  {
    unsigned i;
    if ( !this->_emplace_slot(key, i) )
      return false;
    ::new (static_cast<void *>(&this->_ent[i].val), place_t{}) V(static_cast<A &&>(a)...);
    return true;
  }

  void swap(hash_map &o) noexcept
  {
    unsigned char *s = _state; entry_t *e = _ent;
    unsigned c = _cap, z = _size, t = _tombs, sh = _shift;
    _state = o._state; _ent = o._ent; _cap = o._cap; _size = o._size; _tombs = o._tombs; _shift = o._shift;
    o._state = s; o._ent = e; o._cap = c; o._size = z; o._tombs = t; o._shift = sh;
  }

  // Order-independent, as it must be: two maps holding the same pairs can have completely different
  // slot layouts, since layout depends on insertion order and on the capacity each grew through.
  bool operator==(const hash_map &o) const
  {
    if ( _size != o._size )
      return false;
    for ( const_iterator it = begin(); it != end(); ++it )
    {
      const V *v = o.find(it.key());
      if ( v == nullptr || !(*v == it.value()) )
        return false;
    }
    return true;
  }

  bool operator!=(const hash_map &o) const { return !(*this == o); }

  bool erase(const K &key) noexcept
  {
    if ( _cap == 0 )
      return false;
    V *v = this->_locate(key, H{}(key) * FIB);
    if ( v == nullptr )
      return false;
    // Slot index from the value pointer: step back to the entry, then offset from the array.
    entry_t *e = reinterpret_cast<entry_t *>(reinterpret_cast<char *>(v) - __builtin_offsetof(entry_t, val));
    unsigned i = static_cast<unsigned>(e - _ent);
    _ent[i].key.~K();
    _ent[i].val.~V();
    this->_set_state(i, TOMB);
    --_size;
    ++_tombs;
    return true;
  }

  void clear() noexcept
  {
    for ( unsigned i = 0; i < _cap; ++i )
    {
      if ( _state[i] >= FULL_MIN )
      {
        _ent[i].key.~K();
        _ent[i].val.~V();
      }
      _state[i] = EMPTY;
    }
    for ( unsigned i = 0; i < GROUP && _cap != 0; ++i )   // and the mirror tail
      _state[_cap + i] = EMPTY;
    _size = 0;
    _tombs = 0;
  }

  // Visit every live entry: f(const K&, V&). Order is unspecified.
  //
  // Eight state bytes at a time: an occupied slot is exactly one with the high bit set, so one
  // 8-byte load plus a mask gives every live slot in the group and the empties cost nothing. The
  // obvious per-slot `if` costs an unpredictable branch for each of them, which at half load is
  // a mispredict every other slot -- that was a 0.30x loss against phmap's grouped scan.
  template <class F>
  void for_each(F f)
  {
    // Reads _state/_ent/_cap through `this` rather than hoisting them into locals first. Hoisting
    // them looks obviously right -- f is opaque, so the compiler must otherwise reload all three
    // after every call to it -- and it was tried and measured SLOWER: iterate geomean 1.74x -> 1.48x
    // over the 22 iterate rows. Keeping three extra values live across an opaque call costs more
    // register pressure than rematerialising them from `this`, which is live anyway. Do not
    // "optimise" this back without re-running the iterate rows.
    unsigned i = 0;
    for ( ; i + 8 <= _cap; i += 8 )
    {
      // Pull the entry line for a slot some way ahead. Iteration is the one place where prefetching
      // is unambiguously right -- unlike find(), which must not touch an entry it may never read,
      // this walk is going to read every live entry in order, so the line is never wasted. The
      // distance is in bytes, not slots, so it stays a few lines ahead whatever the entry size.
      //
      // Worth 1.60x -> 1.82x/1.88x on the iterate geomean across all 22 rows (two runs), the largest
      // single move measured here, and the only change all session whose effect clearly exceeds the
      // noise: adding it moved the median iterate row by 0.17x where rerunning the SAME binary moves
      // one by 0.04x. It did NOT fix the row it was aimed at, 200k with 64-byte values (0.83x ->
      // 0.86x): with one entry per cache line and only 200k of them, that row is bound by the memory
      // stream itself and there is no latency left for a hint to hide, and the hardware prefetcher
      // already has a purely sequential walk figured out. The gain landed instead on the small and
      // mid-size maps, where several entries share a line -- 10k iterate went 2.4-2.8x to 4.5-4.9x.
      if ( i + PF_SLOTS < _cap )
        _pf(&_ent[i + PF_SLOTS]);
      unsigned long long occupied = *reinterpret_cast<const unsigned long long *>(_state + i) & MSBS;
      while ( occupied != 0 )
      {
        unsigned long idx;
        _BitScanForward64(&idx, occupied);
        unsigned j = i + (static_cast<unsigned>(idx) >> 3);
        f(_ent[j].key, _ent[j].val);
        occupied &= occupied - 1;                    // clear the slot we just visited
      }
    }
    for ( ; i < _cap; ++i )                          // tail: fewer than 8 slots left
      if ( _state[i] >= FULL_MIN )
        f(_ent[i].key, _ent[i].val);
  }

  template <class F>
  void for_each(F f) const
  {
    const_cast<hash_map *>(this)->for_each([&](const K &k, V &v) { f(k, v); });
  }

  // Diagnostics: the shape of the table, for benchmarks and for explaining a slow one. Walks the
  // whole table, so it is not for hot paths. Counts are in GROUP PROBES -- one probe tests sixteen
  // slots with a single SSE compare, so this, not a slot count, is what a lookup actually costs:
  //   hit_probe  = mean group probes to find a live key (1.0 = every key in its home group)
  //   miss_probe = mean group probes for an absent key from a uniformly random home, i.e. until a
  //                group containing an EMPTY (tombstones do not end a run)
  struct stats_t
  {
    unsigned capacity, size, tombstones;
    unsigned long long bytes;          // state array + entry array
    double load;                       // size / capacity
    double hit_probe, miss_probe;
    unsigned max_probe;                // longest hit chain
  };

  stats_t stats() const noexcept
  {
    stats_t s;
    s.capacity = _cap; s.size = _size; s.tombstones = _tombs;
    s.bytes = static_cast<unsigned long long>(_cap) * (sizeof(entry_t) + 1);
    s.load = _cap != 0 ? static_cast<double>(_size) / static_cast<double>(_cap) : 0.0;
    s.hit_probe = 0; s.miss_probe = 0; s.max_probe = 0;
    if ( _cap == 0 )
      return s;
    unsigned mask = _cap - 1;
    __m128i zero = _mm_setzero_si128();

    // Hits: replay the probe sequence from each live key's home until the group covering its slot.
    unsigned long long total = 0;
    for ( unsigned i = 0; i < _cap; ++i )
    {
      if ( _state[i] < FULL_MIN )
        continue;
      unsigned offset = static_cast<unsigned>((H{}(_ent[i].key) * FIB) >> _shift);
      unsigned step = 0, probes = 1;
      while ( ((i - offset) & mask) >= GROUP )
      {
        step += GROUP;
        offset = (offset + step) & mask;
        ++probes;
      }
      total += probes;
      if ( probes > s.max_probe )
        s.max_probe = probes;
    }
    s.hit_probe = _size != 0 ? static_cast<double>(total) / static_cast<double>(_size) : 0.0;

    // Misses: from each home, walk until a group holds an EMPTY. Sampled on big tables; this is a
    // diagnostic, not a hot path.
    unsigned stride = _cap > (1u << 16) ? (_cap >> 16) : 1u;
    unsigned long long msum = 0, n = 0;
    for ( unsigned h = 0; h < _cap; h += stride )
    {
      unsigned offset = h, step = 0, probes = 1;
      for ( ;; )
      {
        __m128i g = _mm_loadu_si128(reinterpret_cast<const __m128i *>(_state + offset));
        if ( _mm_movemask_epi8(_mm_cmpeq_epi8(g, zero)) != 0 )
          break;
        step += GROUP;
        offset = (offset + step) & mask;
        ++probes;
      }
      msum += probes;
      ++n;
    }
    s.miss_probe = n != 0 ? static_cast<double>(msum) / static_cast<double>(n) : 0.0;
    return s;
  }

private:
  // State byte: 0 = empty, 1 = tombstone, 0x80..0xFF = occupied with the key's 7-bit fingerprint.
  // The high bit is therefore exactly "this slot is occupied", which for_each scans in groups.
  enum : unsigned char { EMPTY = 0, TOMB = 1, FULL_MIN = 0x80 };
  static const unsigned long long MSBS = 0x8080808080808080ull;

  // One full SSE group. The state array carries GROUP extra bytes past _cap that MIRROR the first
  // GROUP, so a 16-byte load starting at ANY slot reads the wrapped-around slots correctly. Every
  // probe loads a group anchored at an arbitrary slot, so this tail is what makes the wrap free;
  // every write to a state byte goes through _set_state to keep it in sync.
  enum : unsigned { GROUP = 16, MIN_CAP = 16 };

  // THE PROBE SEQUENCE. Groups of GROUP slots: the first anchored exactly at the home slot, then
  // triangular jumps -- offsets home, +16, +48, +96, ... , the step growing by GROUP each time.
  // This is abseil's/phmap's sequence, and it is the reason they do not suffer primary clustering:
  // two keys that collide share only their first group and then diverge, where linear probing piles
  // them into one ever-growing run. Because cap is a power of two, the triangular offsets hit each
  // of the cap/GROUP distinct group anchors exactly once, so the walk covers every slot and always
  // terminates on an empty (max_fill keeps at least cap/8 of them free).
  //
  // Anchoring the first group AT the home slot -- not at a 16-aligned boundary, which is what would
  // let us drop the mirror -- is deliberate. It keeps slot `home` first in probe order, so an insert
  // puts a key there whenever it is free and a lookup can test it straight from the hash. That is
  // the parallel state+entry load _locate opens with, and it is what preserves the big-table hit
  // rows that a pure group scan gives up (a slot found through a loaded control byte serialises its
  // entry load behind it; a hash-derived slot does not).
  //
  // A lookup may stop at the first group containing an EMPTY. Insert always places in the first
  // group with a free slot, so nothing can live past an empty one; and erase writes TOMB, never
  // EMPTY, so an empty never appears where a probe run once passed through.
  void _set_state(unsigned i, unsigned char v) noexcept
  {
    _state[i] = v;
    if ( i < GROUP )
      _state[_cap + i] = v;
  }

  static const unsigned long long FIB = 0x9E3779B97F4A7C15ull;   // 2^64 / phi

  struct entry_t { K key; V val; };

  // Below this capacity the home probe's EMPTY early-out is dropped (see _locate). The threshold is
  // on the ENTRY array: that early-out trades an unpredictable branch for the SIMD work it skips,
  // and the trade only pays once a lookup is slow enough to hide a mispredict behind a cache miss.
  // Half a megabyte of entries is the measured crossover on this core -- a 144 KB table is L1/L2
  // resident and a lookup there costs 1-4 ns, so a ~4 ns mispredict doubles it, while a 1 MB table
  // already misses often enough to absorb one. Set at 2 MB instead it also switched the early-out
  // off for the 100k tables, which do not need it off: that cost ~12 rows their win (they fell to
  // ties) and 0.02 of the geometric mean.
  enum : unsigned { HOME_PROBE_MIN_CAP = static_cast<unsigned>((512ull << 10) / sizeof(entry_t)) };

  // How far ahead for_each prefetches, in slots: about 256 bytes of entries, never less than one
  // group so the hint always leads the eight slots being processed. Expressed in bytes rather than
  // slots so it stays a fixed distance in cache lines whatever the entry size -- 4 lines ahead for a
  // 64-byte value, 4 lines ahead for an 8-byte one.
  enum : unsigned { PF_SLOTS = (256u / sizeof(entry_t)) > 8u ? static_cast<unsigned>(256u / sizeof(entry_t)) : 8u };

  // How full a table is allowed to get before it grows: seven eighths, the same as phmap
  // (phmap.h: "We use 7/8th as maximum load factor", capacity - capacity/8).
  //
  // This bites at exactly the sizes where 7/8 and 2/3 land on different powers of two -- N=100k and
  // N=200k, where the old 2/3 forced a doubling phmap avoided and left our table 2.0x its memory.
  // That 2x was the entire 100k/200k loss band: hits lost even at probe 1.0 because the 2.2 MB
  // table spilled a cache the 1.1 MB one stayed inside. At 7/8 we take the same capacity phmap
  // does. At every other size both fractions choose the same power of two and nothing moves -- a
  // 1M table sits at load ~0.48 either way and never rehashes again regardless of this number.
  //
  // A LINEAR probe's unsuccessful search cost explodes as load -> 1 (~0.5*(1+1/(1-a)^2)), which is
  // why 2/3 was right back when this walked slot by slot: at 7/8 a random-key miss cost ~9 slots
  // against ~2, and the whole random-key column suffered for it. Triangular group probing is what
  // makes 7/8 affordable -- colliding keys diverge after their first group instead of piling into
  // one run -- so the fill and the probe sequence were adopted together and only make sense
  // together. Measured after the switch: 100k random miss went from 9.5 slots to 1.4 group probes.
  //
  // (History, kept so it is not re-derived: an early sweep found 7/8 "free" even for the linear
  // walk, but its keys were i*GOLD, which Fibonacci hashing turns into a perfect permutation --
  // zero collisions at any load, so load could not matter. Always re-check a probe-length result
  // against RANDOM keys.)
  static unsigned _max_fill(unsigned cap) noexcept { return cap - cap / 8; }   // 7/8

  // Live-entry ceiling under which a full table is rebuilt at the SAME capacity to shed tombstones
  // rather than doubled (see _emplace_slot). 25/32 = 0.78, below the 7/8 fill, so a table filled by
  // live entries still grows. Tiny tables give 0 here and always double, which is what we want:
  // rebuilding a 16-slot table to shed tombstones is not worth a pass over it.
  static unsigned _purge_limit(unsigned cap) noexcept { return (cap >> 5) * 25; }

  static unsigned _log2(unsigned v) noexcept
  {
    unsigned k = 0;
    while ( v > 1 ) { v >>= 1; ++k; }
    return k;
  }

  // Middle bits: the bucket takes the top bits, so these stay independent of the slot choice.
  static unsigned char _fp(unsigned long long m) noexcept
  {
    return static_cast<unsigned char>(FULL_MIN | ((m >> 24) & 0x7F));
  }

  static void _pf(const void *p) noexcept { _mm_prefetch(static_cast<const char *>(p), 1); }   // 1 = _MM_HINT_T0

  // The value of `key`, or nullptr: the plain linear walk, one slot at a time. Every slot's
  // address comes from the hash alone, so each state byte and its entry load in PARALLEL; that
  // is what makes large-table hits fast, and what any scheme that derives the slot from a loaded
  // control byte gives up.
  //
  // Returns the pointer, not a slot index, on purpose. A version returning an index (with a
  // sentinel for "absent") made find() re-test that sentinel after the loop -- the hit/miss
  // decision taken twice, the second time as a fresh unpredictable branch -- and cost 20-60% on
  // every miss-heavy row (1M spread 50%-miss 16.4 -> 21.6 ms). erase() recovers the slot from
  // the pointer instead.
  //
  // NOTE: do NOT prefetch the entry here. Measured: it speeds hits slightly, but a miss returns
  // at the first EMPTY without ever touching the entry array, so the prefetch is pure wasted
  // bandwidth -- 4M 50%-miss regressed 104 -> 139 ms. phmap makes the same call: prefetching is
  // a caller-driven API (see prefetch()), never inside find().
  //
  // Tried and rejected, measured on the full harness: after the first two direct probes, switch
  // to eight slots per step with SWAR (zero-byte tests for fingerprint and empty, with the bytes
  // before the start hidden as 0xFF so they can neither match nor borrow). It was slower at
  // EVERY size -- 10k random lookups 0.36/0.30/0.31x against 0.48/0.35/0.37x here, 100k random
  // 50%-miss 0.64x against 0.86x, 4M random miss 0.72x against ~0.9x. The extra ALU work of two
  // SWAR tests plus their own data-dependent branches costs more than the ~1.7 slots it replaces,
  // and it inherits the serialised entry load for any candidate it finds. The earlier pure group
  // scan (abseil encoding, groups from the home slot) is in the notes at the bottom.
  //
  // __forceinline is load-bearing. Left to the inliner, this loop -- one level below find() and
  // with two call sites -- stayed a call inside miss-heavy callers under /GL /LTCG, and the
  // caller's own test of the returned pointer became a second unpredictable branch: 1M random
  // 50%-miss 22.3 ms with the loop inline versus 25.7 ms as a call, hits unaffected, reproduced
  // in alternating runs. The generated loop itself was byte-for-byte identical either way.
  __forceinline V *_locate(const K &key, unsigned long long m) const noexcept
  {
    unsigned mask = _cap - 1;
    unsigned home = static_cast<unsigned>(m >> _shift);
    unsigned char fp = _fp(m);
    // Home slot first, straight from the hash: its state byte and its entry load issue in PARALLEL,
    // and this resolves the common hit with no SIMD at all. Insert puts a key at its home slot
    // whenever that slot is free, so this is where most hits are. The group scan below would find
    // them too -- these are pure optimisation -- but going through it costs a second movemask, the
    // trim, and a bit scan, and it makes the entry load wait on the group load instead of issuing
    // beside it.
    //
    // Both tests are branches on the key's data, and that is why they are split. `s0 == fp` is
    // predictable in the cases that matter: on a miss it is false ~127 times in 128, and on an
    // ordered key stream it correlates. `s0 == EMPTY` is not -- at a 0.61 fill it is a 39/61 coin
    // flip on random keys, and a mispredict costs more than an entire L2-resident lookup. That one
    // branch was the whole 10k-random loss, and it is invisible in the probe counts: 10k random,
    // clustered and spread have identical shape (cap 16384, load 0.61, hit probe 1.00) yet random
    // cost 2.8-4.2 ns/op against 1.1-1.6 for the ordered ones, purely because ordered keys make it
    // predict. So the empty early-out is kept only where a cache miss is big enough to hide the
    // mispredict and the SIMD it saves is worth the most.
    //
    // Gating BOTH tests on size instead was measured and is worse: it fixes 10k random misses but
    // costs every ordered all-hit row (10k clustered 1.42x -> 0.97x), scoring 141 win / 12 tie /
    // 17 loss at 1.33x against 153 / 4 / 13 at 1.37x. The hit test earns its keep everywhere.
    unsigned char s0 = _state[home];
    if ( s0 == fp && _ent[home].key == key )
      return &_ent[home].val;
    if ( _cap >= HOME_PROBE_MIN_CAP && s0 == EMPTY )
      return nullptr;
    // Walk the triangular group sequence (see the note on _set_state). One SSE compare gives the
    // group's fingerprint matches and another its empties; a candidate is checked against the real
    // key, and the first group holding an EMPTY ends the probe run and proves a miss without
    // touching another entry. Tombstones need no special case: they are neither a fingerprint match
    // nor an empty, so they neither match nor stop the scan. The home slot is re-examined here when
    // the probe above ran; that costs one redundant key compare on a 1-in-128 fingerprint collision
    // and saves masking its bit out on every single lookup.
    __m128i fpv = _mm_set1_epi8(static_cast<char>(fp));
    __m128i zero = _mm_setzero_si128();
    unsigned offset = home;
    unsigned step = 0;
    for ( ;; )
    {
      __m128i g = _mm_loadu_si128(reinterpret_cast<const __m128i *>(_state + offset));
      unsigned empties = static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(g, zero)));
      unsigned cand = static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(g, fpv)));
      // Only slots BEFORE the group's first empty are on the probe path, so trim to those. Insert
      // always takes the first free slot in a group and a slot never goes back to EMPTY (erase
      // writes TOMB), so no key can sit past an empty one -- a fingerprint match beyond it is
      // always a 1-in-128 false positive. Trimming is not an optimisation of last resort: without
      // it a miss on a half-empty group tests ~4x as many candidates, and every one is a real cache
      // miss into the entry array. It cost 1M spread all-miss 2.8 -> 5.7 ms when it was missing.
      if ( empties != 0 )
        cand &= (empties & (0u - empties)) - 1u;
      for ( ; cand != 0; cand &= cand - 1 )
      {
        unsigned long b;
        _BitScanForward(&b, cand);
        unsigned j = (offset + static_cast<unsigned>(b)) & mask;
        if ( _ent[j].key == key )
          return &_ent[j].val;
      }
      if ( empties != 0 )
        return nullptr;
      step += GROUP;
      offset = (offset + step) & mask;
    }
  }

  bool _emplace_slot(const K &key, unsigned &idx)
  {
    if ( _size + _tombs + 1 > this->_max_fill(_cap) )
    {
      // A full table is not necessarily a table that needs to GROW. Tombstones count toward the fill
      // (they have to -- a probe runs through them), so an insert/erase churn drives the table to
      // max_fill with a live set that never changes. Doubling on that is wrong twice over: the
      // memory is never given back, and a long-running churn doubles forever. Rehashing at the SAME
      // capacity drops every tombstone and puts the load back where the live entries alone put it.
      // Only genuine live growth doubles. (This is abseil's rule and its 25/32 threshold, which sits
      // below max_fill so a table that really is full still grows; the rebuild cannot re-trigger
      // because it clears _tombs and leaves _size + 1 under the limit.)
      unsigned grown = (_cap == 0) ? MIN_CAP : _cap * 2;
      this->_rehash(_cap != 0 && _size + 1 <= this->_purge_limit(_cap) ? _cap : grown);
    }
    unsigned long long m = H{}(key) * FIB;
    unsigned home = static_cast<unsigned>(m >> _shift);
    unsigned char fp = _fp(m);
    unsigned mask = _cap - 1;

    // Walk the same triangular group sequence the lookup does -- it MUST be the same, or a key would
    // be placed where no lookup ever probes. Sixteen slots per step: one SSE compare finds the
    // group's fingerprint candidates (checked against the real key, so a duplicate is caught before
    // anything is written), another finds its free slots, and a third its empties.
    //
    // The first free slot in probe order wins, tombstone or empty alike, so erases are reclaimed and
    // the table compacts. Because the first group is anchored at the home slot, that free slot IS
    // the home slot whenever the home slot is free -- which is what keeps the lookup's parallel
    // home probe hitting. A group holding an EMPTY proves the key absent (nothing can live past an
    // empty group), so the search stops there and places at the earliest free slot remembered.
    __m128i fpv = _mm_set1_epi8(static_cast<char>(fp));
    __m128i zero = _mm_setzero_si128();
    unsigned first_free = _cap;
    unsigned offset = home;
    unsigned step = 0;
    for ( ;; )
    {
      __m128i g = _mm_loadu_si128(reinterpret_cast<const __m128i *>(_state + offset));
      unsigned empties = static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(g, zero)));
      unsigned cand = static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(g, fpv)));
      if ( empties != 0 )                            // only slots before the first empty can hold it
        cand &= (empties & (0u - empties)) - 1u;
      for ( ; cand != 0; cand &= cand - 1 )
      {
        unsigned long b;
        _BitScanForward(&b, cand);
        unsigned j = (offset + static_cast<unsigned>(b)) & mask;
        if ( _ent[j].key == key ) { idx = j; return false; }
      }
      if ( first_free == _cap )
      {
        unsigned freem = (~static_cast<unsigned>(_mm_movemask_epi8(g))) & 0xFFFFu;   // EMPTY or TOMB: high bit clear
        if ( freem != 0 )
        {
          unsigned long b;
          _BitScanForward(&b, freem);
          first_free = (offset + static_cast<unsigned>(b)) & mask;
        }
      }
      if ( empties != 0 )
      {
        unsigned pos = first_free;
        if ( _state[pos] == TOMB )
          --_tombs;
        ::new (static_cast<void *>(&_ent[pos].key), place_t{}) K(key);
        this->_set_state(pos, fp);
        ++_size;
        idx = pos;
        return true;
      }
      step += GROUP;
      offset = (offset + step) & mask;
    }
  }

  // noinline for the same reason as kstl::vector::_grow_to: insert() calls this from bulk loops,
  // and inlining an allocate-plus-reinsert-everything body into that loop wrecks it.
  // Move one old entry into the new table, along the same triangular group sequence a lookup will
  // use. The rehash-specific shortcut: a fresh table holds no tombstones and every key is already
  // known unique, so there is nothing to compare -- the first EMPTY in the first group that has one
  // is exactly the slot the general insert would have chosen.
  void _move_into(unsigned char *ns, entry_t *ne, unsigned mask, unsigned new_shift,
                  unsigned i, unsigned long long m) noexcept
  {
    __m128i zero = _mm_setzero_si128();
    unsigned offset = static_cast<unsigned>(m >> new_shift);
    unsigned step = 0;
    unsigned j;
    for ( ;; )
    {
      __m128i g = _mm_loadu_si128(reinterpret_cast<const __m128i *>(ns + offset));
      unsigned empties = static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(g, zero)));
      if ( empties != 0 )
      {
        unsigned long b;
        _BitScanForward(&b, empties);
        j = (offset + static_cast<unsigned>(b)) & mask;
        break;
      }
      step += GROUP;
      offset = (offset + step) & mask;
    }
    ::new (static_cast<void *>(&ne[j].key), place_t{}) K(static_cast<K &&>(_ent[i].key));
    ::new (static_cast<void *>(&ne[j].val), place_t{}) V(static_cast<V &&>(_ent[i].val));
    ns[j] = _fp(m);
    if ( j < GROUP )
      ns[mask + 1 + j] = ns[j];          // keep the new table's mirror tail in sync
    _ent[i].key.~K();
    _ent[i].val.~V();
  }

  __declspec(noinline) void _rehash(unsigned new_cap)   // new_cap is a power of 2, >= MIN_CAP
  {
    unsigned char *ns = static_cast<unsigned char *>(::operator new(new_cap + GROUP));
    entry_t *ne = static_cast<entry_t *>(::operator new(static_cast<unsigned long long>(new_cap) * sizeof(entry_t)));
    for ( unsigned i = 0; i < new_cap + GROUP; ++i )
      ns[i] = EMPTY;
    unsigned mask = new_cap - 1;
    unsigned new_shift = 64u - _log2(new_cap);

    // Plain sequential pass. A software-pipelined version (hash 16 entries ahead, prefetch their
    // destination state and entry lines through a ring) was tried and measured against this loop
    // back-to-back, alternating, on 64-bit keys at 100k and 1M: identical to the millisecond
    // (2.68 vs 2.68, 24.96 vs 24.93, 35.46 vs 35.48). The growth path's cost is page-faulting the
    // fresh table and the sheer number of doublings, neither of which a prefetch can hide, and
    // out-of-order execution already overlaps these independent iterations. See the note on
    // _max_fill for what actually sets this cost.
    for ( unsigned i = 0; i < _cap; ++i )
    {
      if ( _state[i] < FULL_MIN )
        continue;
      this->_move_into(ns, ne, mask, new_shift, i, H{}(_ent[i].key) * FIB);
    }

    if ( _state != nullptr ) ::operator delete(_state);
    if ( _ent != nullptr )   ::operator delete(_ent);
    _state = ns; _ent = ne;
    _cap = new_cap;
    _shift = new_shift;
    _tombs = 0;
  }

  void _reinsert_from(const hash_map &o)
  {
    for ( unsigned i = 0; i < o._cap; ++i )
      if ( o._state[i] >= FULL_MIN )
        insert(o._ent[i].key, o._ent[i].val);
  }

  void _clear_and_free() noexcept
  {
    this->clear();
    if ( _state != nullptr ) ::operator delete(_state);
    if ( _ent != nullptr )   ::operator delete(_ent);
    _state = nullptr; _ent = nullptr;
    _cap = 0;
  }

  unsigned char *_state;   // one dense byte per slot: empty / tombstone / fingerprint
  entry_t *_ent;           // key and value adjacent -- one cache line per hit
  unsigned _cap;           // power of 2, at least MIN_CAP
  unsigned _size;          // live entries
  unsigned _tombs;         // tombstones
  unsigned _shift;         // 64 - log2(cap), for Fibonacci bucketing
};

// Everything that was measured and rejected, the rows that still lose and why, and how much a
// row is allowed to move between runs: doc/hash-map-benchmarks.md. Kept out of here so the
// class stays readable -- the comments below are only what a reader needs at the code.

}  // namespace kstl
