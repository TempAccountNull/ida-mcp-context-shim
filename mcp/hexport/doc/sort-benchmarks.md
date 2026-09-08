# kstl benchmark log

Every variant that was built and measured, what it scored, and whether it was kept. Anything not
marked **KEPT** is not in the tree — it was benchmark-only.

Method: median of 11 interleaved runs against MSVC's `std::sort` / `std::string` / `std::vector`,
`/O2 /GL /LTCG`, 300k `unsigned` for sort shapes unless stated. `vs_std` above 1.00x means kstl is
faster. Harnesses: `bench/lib.cpp` (library-wide) and `scratchpad/sortcmp.cpp` (sort bake-off).

Rerunning the same binary moves a row by a few percent, so single-run differences under ~5% are not
treated as real.

---

## 1. Where this started

`vector`, `string`, `algorithm` and `format` had never been benchmarked at all — only `hash_map`
had. The first measurement of them:

**9 win / 1 tie / 12 loss vs std, geomean 0.78x.**

Worst rows: `sort` all-equal **0.09x**, `sort` 3-distinct 0.15x, `find` substring 0.18x,
`vector::insert(0)` 0.20x, `sort` organ pipe 0.44x.

Also found: `format.hpp` contained `inline void append_static_cast<double>(...)`, which is not legal
C++. It was committed and invisible because nothing in the project ever compiled that header.

## 2. Final state

**geomean 1.47x–1.51x over 23 rows**, 15–17 win / 3–4 tie / 3–4 loss.

That is a range and not a single figure on purpose: two back-to-back runs of the *same binary* gave
16/4/3 at 1.49x and 15/4/4 at 1.47x. Rows sitting near the ±3% verdict band change side between
runs, so a single run's tally is worth about ±1 row. Only `sort all-equal`, `construct from char*
(len 96)` and `push_back 64 chars` lose in every run.

| row | before | after |
|---|---|---|
| sort sorted | 0.82x | **5.74x** |
| sort organ pipe | 0.44x | **1.44x** |
| sort reverse-sorted | 0.71x | **1.42x** |
| sort 3 distinct | 0.15x | **1.26x** |
| sort sawtooth 1k | 0.72x | **1.21x** |
| sort random | 1.13x | 1.15x |
| sort 100 distinct | 0.74x | 1.14x |
| sort 100k strings | 0.38x | 1.01x |
| sort all-equal | 0.09x | 0.88x |
| find substring in 4 KB | 0.18x | **2.49x** |
| vector::insert(0) | 0.20x | 1.00x |
| vector::erase(0) | 2.64x | 2.84x |
| construct from char\* (len 96) | 0.64x | 0.90x |
| append char\* (len 96) | 0.67x | 1.13x |
| push_back 64 chars | 0.86x | 0.91x |
| push_back 200k strings | 1.00x | 1.08x |
| format decimal / hex / line | 3.78x / 7.45x / 1.40x | 3.83x / 7.70x / 1.57x |

---

## 3. Sort: the bake-off

Four partition schemes, 14 shapes, all verified before being timed (6000 random arrays each, sorted
+ same multiset as `std::sort` + guard words around the array intact, because the two-way scans have
no bounds test).

| shape | Lomuto (orig) | Bentley-McIlroy | pdq-A (as published) | **pdq-B (KEPT)** | pdq-C |
|---|---|---|---|---|---|
| random | 1.13x | 1.10x | **1.24x** | 1.16x | 1.17x |
| sorted | 0.82x | 9.01x | 14.22x | **14.28x** | 14.23x |
| reverse-sorted | 0.71x | 0.83x | **10.33x** | 1.48x | 1.28x |
| all-equal | 0.09x | **0.83x** | 0.75x | 0.74x | 0.75x |
| 3 distinct | 0.15x | 0.89x | **1.99x** | 1.56x | 1.56x |
| 100 distinct | 0.74x | 1.17x | **1.25x** | 1.18x | 1.16x |
| organ pipe | 0.44x | 1.28x | 0.76x | **1.47x** | 1.00x |
| sawtooth 1k | 0.72x | 1.15x | 1.21x | 1.22x | **1.23x** |
| nearly sorted | — | 1.05x | 1.23x | **1.27x** | 0.89x |
| sorted + rnd tail | — | 1.13x | 1.41x | **1.50x** | 1.32x |
| 2 runs appended | — | 1.37x | 0.84x | **1.52x** | 1.07x |
| many dups rnd | — | 1.14x | **1.20x** | 1.16x | 1.17x |
| pipe of dups | — | 1.15x | 1.18x | **1.25x** | 1.25x |
| 100k strings | 0.38x | 0.97x | 1.26x | 1.25x | **1.26x** |
| **geomean** | — | 1.24x | **1.61x** | 1.51x | 1.37x |
| **rows below 1.0x** | — | 2 | 3 | **1** | 2 |

Variants:

- **Lomuto** — original: two-way, middle-element pivot. Quadratic on duplicates; only the introsort
  depth limit stopped it being a hang, which is why it read as "slow" rather than broken.
- **Bentley-McIlroy** — three-way partition, spread ninther by selection. Fixes duplicates but asks
  **two** comparisons per element; for heap-allocated strings the second is a cache miss.
- **pdq-A** — pdqsort as published: two-way, clustered sampling, mutating `sort3`.
- **pdq-B — KEPT** — two-way, nine samples spread at n/8, chosen by selection.
- **pdq-C** — spread sampling *with* mutating `sort3`. The attempt to combine A's and B's strengths;
  it got neither (nearly-sorted 0.89x, organ pipe 1.00x). Rejected.

**Why pdq-B over pdq-A despite the lower geomean:** A regresses two shapes below what the tree
already shipped (organ pipe 1.28x → 0.76x, two sorted runs appended 1.37x → 0.84x). A's nine samples
sit at the ends and the middle, which is exactly where organ-pipe data hides its peak. Spreading them
costs a little on random input and turns both rows into wins. Beating std on every shape was judged
worth more than the geometric mean.

`all-equal` (0.88x) is the one shape std still wins and it is structural: MSVC finishes an all-equal
array in one three-way partition; a two-way scheme needs two passes. Buying it back means a second
comparison per element everywhere else — the Bentley-McIlroy row, 1.24x against 1.51x. 34µs on 300k
elements was not worth that.

### Sort changes measured individually

| change | effect | verdict |
|---|---|---|
| Lomuto → Dutch-national-flag 3-way | all-equal 0.09x→0.69x, but **sorted 0.82x→0.15x**, reverse 0.71x→0.19x | rejected (replaced by B-M) |
| DNF self-swap guard `if (lt != i)` | no change (0.88x geomean either way) | rejected |
| DNF out-params → returned struct | no change | rejected |
| Bentley-McIlroy 3-way partition | geomean 0.44x → 0.88x | superseded by pdq-B |
| ninther threshold sweep | n>16 best; **n>128 heapsorted 33% of reverse-sorted input** | KEPT at 16 |
| `median3` selecting vs mutating | organ pipe **1.18x vs 0.85x**, reverse 0.87 vs 0.77 | KEPT selecting |
| `partial_insertion_sort` on already-partitioned ranges | sorted 0.77x → **3.81x**, geomean 0.88→1.06 | **KEPT** |
| leaf insertion sort instead of one global pass | all-equal 0.67→0.93x, sorted 3.81→4.90x, geomean 1.06→**1.17x** | **KEPT** |
| pdq-B two-way partition + partition_left | geomean 1.17 → **1.51x** | **KEPT** |

The ninther threshold sweep, in comparisons per `n log n`:

| threshold | 16 | 32 | 40 | 64 | 128 |
|---|---|---|---|---|---|
| reverse-sorted | **1.70** | 1.70 | 2.29 | 2.29 | 3.25 |
| organ pipe | **1.53** | 1.55 | 1.57 | 1.60 | 1.67 |
| random | 1.56 | 1.56 | 1.55 | 1.56 | 1.56 |

The cliff between 32 and 40 is the finding: sub-ranges of ~40–128 elements coming out of a reversed
array defeat three-point sampling completely and split `(n-2, 1, 1)`, burning the depth budget until
introsort heapsorts a third of the array. Bentley and McIlroy's paper uses 40; 16 is correct here.

---

## 4. String

| change | effect | verdict |
|---|---|---|
| `strlen_` byte loop → 8-byte SWAR (aligned, so it cannot fault) | construct len-96 0.64x→0.90x, append 0.67x→**1.13x** | **KEPT** |
| add `compare` / `operator<` (did not exist at all) | string sort 0.38x → 0.66x | **KEPT** |
| substring find: first+last byte guard, scalar | **no change**, 0.18x either way | rejected |
| substring find: 16-byte SSE two-anchor scan | 0.18x → **2.49x** | **KEPT** |
| trivially-relocatable byte `swap` | string sort 0.66x → 0.71x | **KEPT** |
| min first heap block, unconditional | push_back-64 0.69x→0.92x, but **push_back-200k-strings 0.97x→0.85x** | rejected |
| min first heap block, only for char-at-a-time growth | push_back-64 **0.91x**, 200k strings **1.08x** | **KEPT** |
| skip zero-length `memcpy_` in `_grow_to` | construct len-96 0.90x → 0.93x (consistent over 2 runs) | **KEPT** |

Minimum-heap-block sweep on `push_back 64 chars`: 32 → 0.72x, 48 → 0.78x, **64 → 0.92x**, 96 →
0.92x, 128 → 0.92x. 64 is the knee; larger only wastes memory.

The scalar find guard is worth remembering: the nested loop's cost was never the inner comparison,
it was touching 4000 bytes one at a time. No amount of early rejection fixes a scalar scan.

---

## 5. Vector

| change | effect | verdict |
|---|---|---|
| `insert` backward element loop → `memmove` for trivially-copyable T | **0.20x → 1.00x** | **KEPT** |

MSVC will not turn a backward element-by-element loop into a vector move the way it does a forward
one. `erase` was already 2.6–3.1x faster than `std::vector`, so it was left alone.

---

## 6. Benchmark bugs found

- `sort 100k strings` refilled the kstl array from C strings inside the timed region while the std
  side used `sv[i] = seed[i]`, which reuses the destination's capacity after the first run. std was
  doing no allocation while kstl did 100k. The row read **0.75x** when the sort itself is 1.25x.
  Both sides now construct from a C string. A benchmark that is unfair in your favour is a bug too,
  but this one was unfair against us and nearly cost a correct decision.

---

## 7. Correctness gates (no fuzzing)

- `hdrfree_check` — compiles and exercises **every** kstl header; includes a 40k-case brute-force
  cross-check of `find_sub` against a naive search. Added after the `format.hpp` bug.
- `sortcmp` gate — 6000 random arrays per variant across 7 shapes: sorted, identical multiset to
  `std::sort`, and guard words around the array untouched (the two-way scans are unguarded by
  design, so an out-of-bounds *write* had to be testable).
- `hashqual`, `iter_check`, `churn_check` — unchanged, still pass.
- `hash_map` string rows re-checked after every `string.hpp` change: 1.68x vs phmap, no regression.
