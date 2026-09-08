# kstl benchmark log

Every variant that was built and measured, its numbers, and whether it was kept. Anything not
marked **KEPT** is not in the tree — it was benchmark-only. Nothing lands in the library until it
has been measured against what it replaces.

Method: median of 11 interleaved runs against MSVC's `std::sort` / `std::string` / `std::vector`,
`/O2 /GL /LTCG`, 300k `unsigned` for sort shapes unless stated. `vs_std` above 1.00x means kstl is
faster. Harnesses: `bench/lib.cpp` (23 library rows) and `scratchpad/sortcmp.cpp` (14-shape sort
bake-off with a correctness gate).

Rerunning the same binary moves a row by a few percent and the win/tie/loss tally by about ±1 row,
so single-run differences under ~5% are not treated as real. Close decisions were run twice.

---

## 1. Where this started

`vector`, `string`, `algorithm` and `format` had never been benchmarked at all — only `hash_map`
had. First measurement:

**9 win / 1 tie / 12 loss vs std, geomean 0.78x.**

Worst rows: `sort` all-equal **0.09x**, `sort` 3-distinct 0.15x, `find` substring 0.18x,
`vector::insert(0)` 0.20x, `sort` organ pipe 0.44x.

Also found: `format.hpp` contained `inline void append_static_cast<double>(...)`, which is not legal
C++. It was committed and invisible because nothing in the project ever compiled that header.

## 2. Final state

**geomean 1.73x over 23 library rows — 21 win / 2 tie / 0 loss.**
Sort alone, over 14 shapes: **geomean 1.88x, 14 of 14 shapes beat `std::sort`**.

Nothing in the library is slower than the STL on any row that is measured.

| row | before | after |
|---|---|---|
| sort sorted | 0.82x | **7.69x** |
| sort reverse-sorted | 0.71x | **6.63x** |
| sort organ pipe | 0.44x | **1.41x** |
| sort 100k strings | 0.38x | **1.24x** |
| sort 3 distinct | 0.15x | **1.23x** |
| sort sawtooth 1k | 0.72x | 1.17x |
| sort all-equal | 0.09x | **1.14x** |
| sort random | 1.13x | 1.14x |
| sort 100 distinct | 0.74x | 1.12x |
| construct from char\* (len 11) | — | **2.00x** |
| construct from char\* (len 96) | 0.64x | **1.80x** |
| find substring in 4 KB | 0.18x | **2.28x** |
| vector::erase(0) | 2.64x | **3.04x** |
| push_back 64 chars | 0.86x | **1.17x** |
| append char\* (len 96) | 0.67x | 1.11x |
| push_back 200k strings | 1.00x | 1.06x |
| vector::insert(0) | 0.20x | 1.00x (tie) |
| format decimal / hex / line | 3.78x / 7.45x / 1.40x | 3.56x / 7.84x / 1.50x |

---

## 3. Sort: the full bake-off

Six schemes. All verified before being timed: 6000 random arrays each across 7 shapes, checked for
sortedness, identical multiset to `std::sort`, **and untouched guard words around the array** — the
two-way scans are deliberately unguarded, so an out-of-bounds *write* had to be testable.

| shape | Lomuto | B-McIlroy | pdq-A | pdq-B | pdq-C | pdq-D | **KEPT** |
|---|---|---|---|---|---|---|---|
| random | 1.13x | 1.10x | 1.19x | 1.19x | 1.15x | 1.26x | 1.19x |
| sorted | 0.82x | 9.01x | 13.97x | 13.99x | 14.02x | 13.93x | **22.08x** |
| reverse-sorted | 0.71x | 0.83x | 10.31x | 1.48x | 1.27x | 0.65x | **13.20x** |
| all-equal | 0.09x | 0.83x | 0.75x | 0.75x | 0.75x | 0.75x | **1.50x** |
| 3 distinct | 0.15x | 0.89x | 1.80x | 1.47x | 1.44x | 1.87x | 1.47x |
| 100 distinct | 0.74x | 1.17x | 1.18x | 1.19x | 1.12x | 1.27x | 1.20x |
| organ pipe | 0.44x | 1.28x | 0.76x | 1.52x | 0.96x | 0.78x | 1.49x |
| sawtooth 1k | 0.72x | 1.15x | 1.19x | 1.24x | 1.20x | 1.19x | 1.24x |
| nearly sorted | — | 1.05x | 1.15x | 1.24x | 0.83x | 1.01x | **1.25x** |
| sorted + rnd tail | — | 1.13x | 1.37x | 1.49x | 1.28x | 0.64x | 1.45x |
| 2 runs appended | — | 1.37x | 0.82x | 1.55x | 1.00x | 0.82x | 1.52x |
| many dups rnd | — | 1.14x | 1.13x | 1.20x | 1.13x | 1.18x | 1.19x |
| pipe of dups | — | 1.15x | 1.14x | 1.26x | 1.20x | 1.21x | 1.26x |
| 100k strings | 0.38x | 0.97x | 1.27x | 1.25x | 1.25x | 1.29x | 1.27x |
| **geomean** | — | 1.24x | 1.60x | 1.48x | 1.36x | 1.22x | **1.88x** |
| **shapes < 1.0x** | — | 2 | 3 | 1 | 2 | 4 | **0** |

Variants:

- **Lomuto** — the original: two-way, middle-element pivot. Quadratic on duplicates; only the
  introsort depth limit stopped it being a hang, which is why it read as "slow" not "broken".
- **Bentley-McIlroy** — three-way partition, spread ninther by selection. Fixes duplicates but asks
  **two** comparisons per element; for heap-allocated strings the second is a cache miss.
- **pdq-A** — pdqsort as published: two-way, clustered sampling, mutating `sort3`.
- **pdq-B** — two-way, nine samples spread at n/8, chosen by selection.
- **pdq-C** — spread sampling *with* mutating `sort3`.
- **pdq-D** — clustered sampling *with* selection.
- **KEPT** — pdq-B plus the monotonic-run entry scan.

### The 2×2 that made the pivot decision

pdq-A/B/C/D are the four corners of sampling × selection. Reverse-sorted, by corner:

| | clustered | spread |
|---|---|---|
| **mutating sort3** | pdq-A **10.31x** | pdq-C 1.27x |
| **selecting** | pdq-D 0.65x | pdq-B 1.48x |

Neither property alone explains pdq-A's result — it needs both. And the same clustering costs it
organ pipe (0.76x vs 1.52x), because pdqsort's nine samples sit at the ends and the middle, which is
exactly where organ-pipe data hides its peak.

### Why pdqsort as published was rejected

pdq-A had the better geometric mean (1.60x vs pdq-B's 1.48x), and it was tested inside the real
library before being turned down — twice each, all 23 rows:

| in-library | geomean | tally | organ pipe | reverse-sorted |
|---|---|---|---|---|
| pdq-A | 1.56x, 1.56x | 15W/4L, 15W/5L | **0.76x** | 6.07x |
| pdq-B | 1.50x, 1.48x | 17W/3L, 17W/4L | **1.48x** | 1.40x |
| **KEPT** | **1.73x, 1.72x** | **21W/0L** | **1.41x** | **6.63x** |

pdq-A's entire lead came from one row. Remove that single row from the geometric mean and the
ranking reverses — **pdq-A 1.35x against pdq-B 1.47x** — and pdq-B is ahead on 8 of the other 13
shapes. So the choice was never "give up speed for safety": it was to buy that one row a cheaper way
and keep the other thirteen. The entry scan then bought it outright.

### The entry scan — the change that removed the last losing shape

One scan in whichever direction the first pair points, stopping at the first pair that breaks the
pattern:

- descending end to end → reverse the range and return
- never descending → the range is already sorted, return

The second branch is what an **all-equal** array is, and that was the one shape *every* quicksort
variant here lost to `std::sort` (0.74–0.83x, because MSVC finishes it in a single three-way
partition while a two-way scheme needs two passes). It is now **1.50x**. Sorted went to 22.08x and
reverse-sorted to 13.20x as a side effect.

**Do not over-read it.** It recognises a monotonic run spanning the *whole* range and nothing
weaker; a mostly-sorted array still takes the ordinary path. The worry was that a near-miss would
waste a full scan — measured, it does not: nearly-sorted is **1.25x** (the best of any variant) and
sorted-plus-random-tail 1.45x. Random input pays two comparisons.

### Sort changes measured individually

| change | effect | verdict |
|---|---|---|
| Lomuto → Dutch-national-flag 3-way | all-equal 0.09x→0.69x, but **sorted 0.82x→0.15x** | rejected |
| DNF self-swap guard `if (lt != i)` | no change (0.88x geomean either way) | rejected |
| DNF out-params → returned struct | no change | rejected |
| Bentley-McIlroy 3-way partition | geomean 0.44x → 0.88x | superseded |
| ninther threshold sweep | n>16 best; **n>128 heapsorted 33% of reverse-sorted input** | KEPT at 16 |
| `median3` selecting vs mutating | organ pipe **1.18x vs 0.85x** | KEPT selecting |
| `partial_insertion_sort` on already-partitioned ranges | sorted 0.77x → **3.81x** | **KEPT** |
| leaf insertion sort instead of a global pass | all-equal 0.67→0.93x, geomean 1.06→**1.17x** | **KEPT** |
| pdq-B two-way partition + `partition_left` | geomean 1.17 → **1.51x** | **KEPT** |
| pdq-A clustered+mutating pivot | in-library 1.56x but organ pipe 0.76x, 2 runs 0.81x | rejected |
| pdq-C spread+mutating pivot | 1.36x, nearly-sorted 0.83x | rejected |
| pdq-D clustered+selecting pivot | 1.22x, reverse-sorted 0.65x | rejected |
| descending-only entry check | reverse 1.40x → 13.27x, geomean 1.60x | superseded |
| bidirectional entry scan | **all-equal 0.75x → 1.50x**, geomean → **1.88x**, zero losing shapes | **KEPT** |

Ninther threshold sweep, comparisons per `n log n`:

| threshold | 16 | 32 | 40 | 64 | 128 |
|---|---|---|---|---|---|
| reverse-sorted | **1.70** | 1.70 | 2.29 | 2.29 | 3.25 |
| organ pipe | **1.53** | 1.55 | 1.57 | 1.60 | 1.67 |
| random | 1.56 | 1.56 | 1.55 | 1.56 | 1.56 |

The cliff between 32 and 40 is the finding: sub-ranges of ~40–128 elements coming out of a
partitioned reversed array defeat three-point sampling completely and split `(n-2, 1, 1)`, burning
the depth budget until introsort heapsorts a third of the array. Bentley and McIlroy's paper uses
40; 16 is correct here.

---

## 4. String

| change | effect | verdict |
|---|---|---|
| `strlen_` byte loop → 8-byte SWAR (aligned, so it cannot fault) | construct len-96 0.64x→0.90x, append 0.67x→1.13x | **KEPT** |
| add `compare` / `operator<` (did not exist at all) | string sort 0.38x → 0.66x | **KEPT** |
| substring find: first+last byte guard, scalar | **no change**, 0.18x either way | rejected |
| substring find: 16-byte SSE two-anchor scan | 0.18x → **2.28x** | **KEPT** |
| trivially-relocatable byte `swap` | string sort 0.66x → 0.71x | **KEPT** |
| min first heap block, unconditional | push_back-64 0.69x→0.92x, but **200k strings 0.97x→0.85x** | rejected |
| min first heap block, char-at-a-time growth only | push_back-64 0.91x, 200k strings **1.08x** | **KEPT** |
| skip zero-length `memcpy_` in `_grow_to` | construct len-96 0.90x → 0.93x, consistent over 2 runs | **KEPT** |
| copy SSO buffer whole (2 words) when growing out of it | no change (0.92x / 0.94x vs 0.93x) | rejected |
| construct via `_init` at exact size, bypassing `_grow_to` | **len-96 0.91x → 1.80x, len-11 1.26x → 2.00x** | **KEPT** |
| `push_back` fast path with an early return | **0.91x → 1.17x** | **KEPT** |

Minimum-heap-block sweep on `push_back 64 chars`: 32 → 0.72x, 48 → 0.78x, **64 → 0.92x**, 96 →
0.92x, 128 → 0.92x. 64 is the knee; larger only wastes memory.

Two of these are the same lesson from opposite ends. `_grow_to` is `__declspec(noinline)` on
purpose — it must not be inlined into `push_back` loops — but every construction from a C string was
routing through it for a length that was already known, paying an out-of-line call and a doubling
calculation it did not need. And `push_back`'s fast path was falling through into the SSO/heap
pointer select instead of returning; giving it its own `return` and letting the cold path assume
large mode was worth 0.91x → 1.17x on its own.

The rejected scalar find guard is worth remembering too: the nested loop's cost was never the inner
comparison, it was touching 4000 bytes one at a time. No amount of early rejection fixes a scalar
scan — only doing sixteen bytes at once does.

---

## 5. Vector

| change | effect | verdict |
|---|---|---|
| `insert` backward element loop → `memmove` for trivially-copyable T | **0.20x → 1.00x** | **KEPT** |

MSVC will not turn a backward element-by-element loop into a vector move the way it does a forward
one. `erase` was already 2.6–3.0x faster than `std::vector`, so it was left alone.

---

## 6. Benchmark bugs found

- `sort 100k strings` refilled the kstl array from C strings inside the timed region while the std
  side used `sv[i] = seed[i]`, which reuses the destination's capacity after the first run. std was
  doing no allocation while kstl did 100k. The row read **0.75x** for a sort that is actually 1.25x,
  and it nearly cost a correct decision. Both sides now construct from a C string.

---

## 7. Correctness gates (no fuzzing)

- `hdrfree_check` — compiles and exercises **every** kstl header; includes a 40k-case brute-force
  cross-check of `find_sub` against a naive search. Added after the `format.hpp` bug.
- `sortcmp` gate — 6000 random arrays per variant across 7 shapes: sorted, identical multiset to
  `std::sort`, and guard words untouched.
- `hashqual`, `iter_check`, `churn_check` — unchanged, still pass.
- `hash_map` re-checked after every `string.hpp` change: 1.63–1.72x vs phmap, no regression.
