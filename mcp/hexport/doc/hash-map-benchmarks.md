# hash_map benchmark log

Lifted out of `src/kstl/hash_map.hpp`, which had grown to 42% comments. The source keeps the
invariants a reader needs at the point of code; the measurements live here.

Method: 170 rows (5 sizes x 8 key distributions x 8 workloads) against `phmap::flat_hash_map`
(parallel-hashmap) and `std::unordered_map`, median of 11 interleaved runs, paired sign test.

## Result

Two back-to-back runs of the same binary, because one run cannot separate a real loss from drift --
the paired test only protects the kstl-vs-phmap comparison *inside* a run:

- **146 win / 10 tie / 14 loss** and **146 win / 9 tie / 15 loss** vs phmap, geomean **1.38x / 1.36x**
- **166 of 170** vs `std::unordered_map`

Rerunning the same binary moves a row by up to 0.14x at the 90th percentile and the tally by about
+/-2 rows, so no single run's tally is a ranking.

## What makes it fast

1. **Fibonacci bucketing** -- hash * 2^64/phi, keep the top bits. The first probed slot needs
   nothing but the hash, so its entry load issues in **parallel** with its state load. This is the
   property a pure group scan gives up: a slot found through a loaded control byte serialises its
   entry load behind that load.
2. **Key and value in one entry array** -- a hit touches one cache line, not two streams.
3. **7-bit fingerprint in the state byte** -- an occupied-but-wrong slot touches the entry array
   with probability 1/128 instead of certainty, so a probe walk stays inside one cache line of the
   dense state array (64 slots per line).
4. **7/8 fill**, matching phmap. Lower spends a whole extra doubling at N=100k and N=200k, and that
   2x memory -- not probe length -- was what lost those rows.
5. **Triangular group probing**, 16 slots per SSE compare, shared by lookup, insert and rehash (they
   must share it, or a key would sit where no lookup probes). Lookup still opens with a direct
   hash-addressed probe of the home slot, keeping property 1.

---------------------------------------------------------------------------------------------
Rejected by measurement, so nobody re-tries them:

* Separate _keys and _vals arrays (the original layout). Three streams per hit; replacing them
with one entry array was worth 1.34x-1.56x at 4M.
* State byte packed into the key array (struct{state,key}[]). The dense state array holds 64
slots per cache line, so a probe walk stays in one line; packing drops that to 8 and it lost
at 100k and 1M, winning only 4M hits.
* SWAR group scanning: fingerprints matched 8-at-a-time in a general-purpose register instead of
with SSE. Slower at every size (10k random lookups 0.36/0.30/0.31x against 0.48/0.35/0.37x for
the design of the day), and it carries borrow/masking hazards SSE does not.
* Prefetching the entry inside find(). See the note in find().
* Dropping the home-slot probe and letting the group scan handle everything (a pure Swiss-table
lookup). It WON every all-miss row -- 100k clustered 0.70x -> 1.36x, 100k random 0.85x -> 1.19x
-- and broke 50%-miss everywhere at the same time: sequential 1.43x -> 0.63x, spread
1.37x -> 0.76x, clustered 1.29x -> 0.73x. The giveaway was that 50%-miss cost more per op
(5.4 ns) than either pure component (hit 2.5 ns, miss 1.5 ns), i.e. the alternating pattern was
mispredicting, which the home probe's early returns avoid. This is why the home probe survived
the move to group probing: it is measurably redundant work on an occupied-home miss and still
the right trade.
* Gating BOTH home-probe tests on table size, not just the empty one. Fixes 10k random misses
the same way the split gate does, but the hit test is what wins every ordered all-hit row and
losing it costs far more: 10k clustered all-hit 1.42x -> 0.97x, sequential 1.08x -> 0.94x, and
141 win / 12 tie / 17 loss at 1.33x against 144 / 13 / 13 at 1.35x with only 2 significant
losses. The lesson is that the two tests have opposite branch behaviour and must be treated
separately: `s0 == fp` predicts (false ~127/128 on a miss, correlated on ordered keys),
`s0 == EMPTY` does not (a 39/61 coin flip at a 0.61 fill).
* A LINEAR probe sequence (what this was until the group-probing rewrite). It is the reason
2/3 fill was needed: at 7/8 a random-key miss walked ~9 slots with a max chain of 125, and the
whole random-key column paid for it. Held together it scored 148 win / 7 tie / 15 loss at
1.36x; triangular scores 153 / 5 / 12 with the entire random-key-miss and 64-byte-miss loss
classes gone. The switch also deleted a whole regime split -- a cache-resident group scan, a
big-table scalar walk, a SIMD miss shortcut and the _small flag choosing between them -- so
lookup, insert and rehash now share one sequence and the class is ~50 lines shorter.
The prediction that group probing must cost the big-table hit rows turned out to be WRONG,
and worth understanding: it costs them only if you also give up the hash-addressed first
probe. Anchoring the first group at the home slot keeps that, and 4M went 13 win / 2 loss to
15 win / 1 loss across the rewrite.

HOW MUCH A ROW IS ALLOWED TO MOVE. Rerunning the SAME binary moves a row's speedup by 0.03x at
the median and up to 0.14x at the 90th percentile -- wider than the 3% verdict band. So a single
run's tally is worth about +/-2 rows, and a row is only "losing" if it loses in every run. The
figures below are the worst and best across four runs, not one run's number.

Still losing to phmap, with the reason, so nobody hunts them blind. Nine rows of 170; sequential
and addresses keys lose nothing that reproduces:
- 10k random all-hit 0.67-0.75x, 10k random 50%-miss 0.82-0.88x, 100k random 50%-miss
0.81-0.86x. All the SAME cost: the `s0 == fp` test in the home probe is a ~70/30 coin flip
when the keys are random and the lookup is a hit, and on an L2-resident table one mispredict
is most of the lookup. A 50%-miss stream mispredicts it by construction. It cannot simply be
removed -- deleting the home probe takes 10k random to ~0.81x/1.21x but costs every ordered
all-hit row far more (see the rejected entry above). These rows are 0.03-1.4 ms end to end,
2.1-7.0 ns/op.
The all-MISS row at 10k random used to be the worst of that group at 0.71x and is now 1.41x,
reproduced across three runs at 11/11 paired, because that one was the `s0 == EMPTY` coin
flip and that test could be gated on size.
- 200k 64-byte iterate, spread 0.83-0.86x and random 0.81-0.95x, and 1M clustered iterate
0.87-0.94x: bound by streaming the value array, not by probing. The for_each prefetch was
aimed at exactly these and did not move them; the note there says why.
- strkeys len=40 insert 0.81-0.89x: bound by hashing 40-byte keys, not by probing. Two-lane
hashing was tried for this row specifically and measured worse; see hash.hpp.
- 4M spread mixed 0.85-0.94x and 1M clustered unreserved insert 0.91-0.94x. An earlier version
of this note claimed both "have landed on the winning side in other runs" -- four runs say
neither ever did, so that claim was wrong and is withdrawn. They are narrow but real.

Straddling the band, sign changes between runs. Listed so nobody optimises for one run's noise:
1M clustered reserved insert 0.87-1.06x, 100k random64 all-hit 0.94-1.41x, 100k addresses
all-miss 0.94-1.02x, 100k random64 50%-miss 0.90-0.98x, 10k spread mixed 0.87-1.01x, 100k random
all-hit 0.88-0.99x.

Losing to std::unordered_map on four rows, stable across every run, and all one artifact rather
than a probing problem: the benchmark reserves for N inserts, but the clustered and len=12 key
generators emit only ~63k and ~2.6k DISTINCT keys, so the table sits at load 0.01-0.03. Insert
then scatters over an 18 MB array and iterate scans 2M state bytes to reach 63k entries, while a
node map touches only what it allocated. phmap loses the same rows to std by the same margin (we
are 0.91-0.94x of phmap there), so this is inherent to open addressing at a 16x over-reserve and
is not worth contorting the map for. Honouring reserve() exactly is the point of reserve().
---------------------------------------------------------------------------------------------

## Caching members in locals: measured, and one place it LOSES

The obvious optimisation in `for_each` is to hoist `_state`, `_ent` and `_cap` into locals before
the loop. The reasoning is sound -- `f` is an arbitrary callable, so the compiler cannot know it
does not touch the map and must reload all three after every call. It was tried and it is **slower**:

| variant | iterate | insert | mixed | erase |
|---|---|---|---|---|
| members read through `this` (**shipped**) | **1.79x** | 1.23x | 1.06x | 1.62x |
| `_state`/`_ent`/`_cap` hoisted into locals | 1.48x | 1.23x | 1.02x | 1.61x |

Keeping three extra values live across an opaque call costs more in register pressure than
rematerialising them from `this`, which is live anyway. Do not re-apply it without re-running the
22 iterate rows.

The same change on the insert path -- binding `entry_t *e = this->_ent + i` once after
`_emplace_slot` in `operator[]`, `insert`, `try_emplace` and `emplace` -- is free (insert 1.23x
either way) and is kept, because there it removes a repeated index computation rather than
lengthening a live range across a call.

Where caching is unambiguously right is a loop with no call in it: `string::rfind(char)` was calling
`data()` per iteration, and `data()` is a branch on the SSO flag that the compiler must redo after
any store through the returned pointer.

