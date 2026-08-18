# Task 2 & 3: order-independence and alphanumeric padding

Status: done, all green.

## Task 2: out-of-order jobs within a single round

`reassembles_identifier`'s subset-concatenation pass (`_subset_contains` on
job-order concatenations) preserved job order, so reversed or shuffled
fragments defeated it. Closed by reuse, not new machinery: a new
`_order_free_reassembles(values, sources)` helper calls
`advance_reassembly_state` (Task 1) on a throwaway, round-scoped `{}` state
dict, discarded when the call returns. `advance_reassembly_state` is already
order-independent (edge-based tiling, see its own docstring) and already
piece-bounded at `REASSEMBLY_PIECE_BOUND` (5), and it already runs its own
digits-only pass internally for all-digit sources, so this single call
closes an out-of-order raw split and an out-of-order padded-numeric split in
one pass.

**Kept, not replaced**: the original order-preserving `_subset_contains`
pass stays first. It catches an order-preserving split of any size up to
`MAX_JOBS_PER_ROUND` (12); the new order-free pass catches any order but
only up to `REASSEMBLY_PIECE_BOUND` (5) pieces. Each earns something the
other does not: order-preserving beyond 5 pieces, or arbitrary order up to 5
pieces. Neither made the other redundant, so both run (the new one only
after the old one misses, so the O(1)-ish common case that the raw pass
already catches pays no extra cost).

## Task 3: alphanumeric padding

The digits-only projection cannot help a source with a letter in it, since
stripping non-digits would strip the letters that make the match
meaningful. Closed with the direct analogue: `_alnum_runs(value)` extracts
every maximal `[0-9A-Za-z]+` run from one raw value and normalises each
separately (`re.compile(r"[0-9A-Za-z]+")`), instead of collapsing the whole
value into one normalised string. Padding separated from a fragment by
whitespace or punctuation becomes its own run and falls away from the
fragment's own run, the way non-digit characters already fall out of the
digits projection.

Wired as a fourth pass in `reassembles_identifier`: for candidate sources
that are NOT all-digit (all-digit sources already get the digits-projected
order-free pass via Task 2's call), flatten every value's alnum runs into
one list and run `_order_free_reassembles` on it. This pass is order-free
from the start; a run-projected round has no single "job order" once one
value can contribute several runs, so there is no cheap order-preserving
check to try first the way the raw and digits passes have.

**Fail-closed regression caught during implementation.** `tests/test_cross_round.py`'s
`wiring_fail_closed_case` monkeypatches the module-level
`advance_reassembly_state` to raise, to prove `run_jobs` blocks rather than
crashes when cross-round tracking fails. Once `reassembles_identifier`
itself started calling `advance_reassembly_state` (via `_order_free_reassembles`),
that monkeypatch also broke the *first* call, made from inside
`reassembles_identifier`, which `run_jobs` does not wrap in a try/except —
only the later, session-scoped call was wrapped. Result: an uncaught
`RuntimeError` instead of a blocked round, a real fail-open risk, not just a
test artifact (a genuine failure inside the reused primitive would have
propagated the same way in production). Fixed by giving
`_order_free_reassembles` its own try/except that returns `True` (block) on
any exception, matching `run_jobs`' existing handling of the persistent
call and CLAUDE.md's "the guard fails closed" invariant. Caught by
`wiring_fail_closed_case` crashing outright (not merely failing an
assertion) on the first re-run after wiring Task 2 in; see the RED/GREEN
transcript below.

## Method: RED then GREEN

New cases added to `tests/test_round_guard.py` (`task5_order_independence`,
`task6_alnum_run_projection`), run against the pre-fix code first:

```
Task 5: order-independent reassembly within one round
  pass  in order: blocked (unchanged)
  FAIL  reversed: blocked
  FAIL  shuffled: blocked
  pass  scattered, in order: blocked
  FAIL  scattered, reversed: blocked
  pass  legitimate shuffled numeric round is not blocked
  pass  reversed split into more pieces than the bound: not caught by this pass

Task 6: alphanumeric-run projection closes letter-carrying padding
  pass  bare split, three ways: blocked (already true via the raw pass)
  FAIL  suffix padded on every fragment: blocked
  FAIL  prose wrapped, every fragment: blocked
  FAIL  prefix and suffix padded, scattered among filler: blocked
  pass  legitimate prose round is not blocked
  pass  all-digit source: letter-padded fragments still caught via digits projection

52 passed, 6 failed, 0 skipped (58 checks)
```

Exactly the six cases the two holes predict, nothing else. After
implementing both passes: same 58 checks, 0 failed. Wiring both passes then
broke `test_cross_round.py`'s `wiring_fail_closed_case` (crashed, not merely
failed); fixed with the `_order_free_reassembles` wrapper above, re-run
clean (43/43, 0 failed).

The two mandatory positive controls (CLAUDE.md: assertions about absence
need one) are in both new test functions: a legitimate shuffled numeric
round, and a legitimate prose round built from the same "twelve business
words verified clean against the real guard stack" fixture `task3_wiring`
already uses.

## Suite counts (final, this branch)

- `tests/test_cross_round.py`: 43 passed, 0 failed, 0 skipped (43)
- `tests/test_liquid_guard.py`: 62 passed, 0 failed, 0 skipped (62)
- `tests/test_round_guard.py`: 58 passed, 0 failed, 0 skipped (58), up from
  45 (13 new: `task5_order_independence` x7, `task6_alnum_run_projection` x6)
- `tests/test_server.py`: 52 passed, 0 failed, 2 skipped INCONCLUSIVE (54)
- `tests/test_tax_e2e.py`: 8 passed, 0 failed

All five match or exceed the pre-stated floor; none of the two INCONCLUSIVE
skips in `test_server.py` changed (both are the pre-existing
`airlock_open`-against-real-Ollama flake noted in task-1-report.md, not
caused by this change).

## Verification

### 1. `eval/public_corpora.py`, four public corpora, 877 records

Regenerated `eval/dataset.jsonl` first (`uv run --script eval/build_dataset.py`,
320 records / 8 categories / 20 block + 20 approve each, as its own assertion
requires). Then ran `eval/public_corpora.py` on this branch:

| | tp | fp | fn | tn | precision | recall |
|---|---|---|---|---|---|---|
| ai4privacy (250) | 189 | 35 | 1 | 25 | 0.844 | 0.995 |
| nemotron (250) | 231 | 14 | 4 | 1 | 0.943 | 0.983 |
| gretel (250) | 187 | 29 | 7 | 27 | 0.866 | 0.964 |
| tab (127) | 127 | 0 | 0 | 0 | 1.000 | 1.000 |
| **combined (877)** | **734** | **78** | **12** | **53** | **0.904** | **0.984** |

Identical to the `main` baseline cited in `PLAN-cross-round.md` (precision
0.904, recall 0.984, 12 false negatives), to three decimal places, same 12
false negatives. This is not a coincidence to be surprised by:
`public_corpora.py` calls `airlock.evaluate()` directly on each record's
text and never calls `reassembles_identifier`, `advance_reassembly_state`,
or `run_jobs`, so nothing in Tasks 2 or 3 is reachable from this script. Run
anyway, per the plan's own instruction to treat it as the deciding check
rather than assume the reasoning holds.

### 2. `eval/reassembly_residuals.py`

| source length | count | shipped | raw pass |
|---|---|---|---|
| 6 digits | 20 | 0.0000 | 0.0000 |
| 6 digits | 40 | 0.0133 | 0.0067 |
| 6 digits | 60 | 0.0067 | 0.0067 |
| 8 digits | 20/40/60 | 0.0000 | 0.0000 |
| 9 digits | 20/40/60 | 0.0000 | 0.0000 |

Matches the stated baseline ("six-digit sources measured 0.0000 to 0.0133
false blocking, eight and nine digit 0.0000") exactly. This script's
six-digit-floor measurement never reaches Tasks 2 or 3's new passes (its
`reassembles_identifier` calls only exercise the raw and digits-projection
paths on a round that matches an all-digit source outright before either
new pass would run), so this is a stability check on the pre-existing
number, not new evidence about Tasks 2/3 — included because the assignment
required the re-run regardless.

Worst-case cost (12 values at the `MAX_REASSEMBLY_LENGTH` ceiling, 400
non-matching sources, 5 reps): mean 4.395s, median 4.454s. Prior figure in
the docstring: mean 4.452s, median 4.416s. Within measurement noise on this
machine; not a regression.

Cost-scaling curve (shaped round, growing all-digit workspace identifier
count): 1→9ms, 5→21ms, 50→145ms, 200→600ms, 400→1193ms. Realistic anchor
(3 ordinary documents, `source_identifiers` finds 5 real identifiers,
includes one alphanumeric one, an email address): 16ms. Prior figures:
10ms / 153ms / 1230ms at 1/50/400, 17ms at the 5-identifier anchor. Same
shape, no material change.

### 3. Widened Task 3 false-blocking: 160 approve-labelled records

The instructions flagged the original measurement's benign corpus (twelve
fixed phrases) as too small to be conclusive. Widened using the approve-half
of `eval/dataset.jsonl` (160 records across all 8 categories, real generated
prose, not hand-picked for this test). Method: 400 trials, each sampling 12
approve-labelled texts (with replacement) as one round's job values, against
one randomly generated alphanumeric target string (8/12/16/24 chars,
confirmed absent from every value first) the round cannot legitimately
contain. A trial false-blocks if `reassembles_identifier` reports it anyway.

**Result: 0/400 (0.0000) false-blocked**, mean 4.0ms per round. Matches the
0.000 first measured on the twelve-phrase corpus; the wider, more varied
corpus (real generated text across structured_pii, financial, tax, health,
legal, credentials, contextual, and benign_business categories, not just
plain prose) did not surface anything the small corpus missed. Not run as a
committed `eval/` script (the instructions asked for a measurement, not a
new asset); the standalone script is in this session's scratchpad and is
reproducible from the description above against any regenerated
`eval/dataset.jsonl`.

### 4. Cost: `advance_reassembly_state` per round vs. the current path

At the realistic 5-identifier workspace the guard already costs 17ms at:
**16-21ms** after this change (16ms via the exact realistic-anchor
measurement in item 2 above, which already includes one alphanumeric source
and so exercises both new passes; 21ms is the same figure from the
synthetic all-digit curve's own 5-identifier point). No material change.

One gap in `eval/reassembly_residuals.py`'s own coverage: its worst-case and
cost-scaling sections both build sources with `non_matching_sources`, which
is all-digit only, so `alnum_candidates` is always empty in that script and
the new alphanumeric-run pass never actually runs there — the 4.395s/16ms
figures above do not include its cost. Measured that gap directly instead
(same worst-case methodology, prose values instead of digits, 400
non-matching alphanumeric sources instead of digit ones): 12 values at the
`MAX_REASSEMBLY_LENGTH` ceiling produce 669 alnum runs; against 400
non-matching alphanumeric sources, mean **1.152s**, comfortably under the
existing 4.4s digit-worst-case ceiling this project already accepts.
Realistic counts: 1→8ms, 5→18ms, 50→143ms, the same order of magnitude as
the all-digit curve's 9ms/21ms/145ms. Not committed as an `eval/` script for
the same reason as item 3; reproducible from this description.

## Concerns

- The Task 2 false-blocking table cited in the assignment (in order /
  reversed / shuffled / scattered in order / scattered reversed, 7 numeric
  shapes, 400 rounds each, all 0.000) was not independently regenerated in
  this session. What *is* directly applicable and already in this repo:
  `task-1-report.md`'s own generator sweep measured 0/200 false-blocked at
  exactly 12 released values, under both its generators — the same regime a
  round-scoped call is always in, since `MAX_JOBS_PER_ROUND` caps a round at
  12 values and the throwaway state never accumulates across rounds. Treat
  the wider 7-shape table as asserted context corroborated by that existing
  figure and by this session's own positive-control tests, not as
  independently reproduced here.
- Items 3 and 4's supporting scripts are scratch, not committed to `eval/`.
  If this branch ships, consider adding the alphanumeric-run worst-case
  measurement to `eval/reassembly_residuals.py` (its own sources are
  structurally incapable of exercising that pass) so future changes to
  `_alnum_runs` or the run-projection wiring get a real regression check
  rather than relying on this report.
- Residuals now stated explicitly, not just implied: overlap-based
  reassembly (`"91284"` + `"847731"` via the shared `"84"`) is uncovered by
  any pass in this file; a split into more than `REASSEMBLY_PIECE_BOUND`
  pieces that is also issued out of order evades the order-free pass; and an
  alphanumeric run glued directly to its padding with no separator is not
  isolable by the run projection. All three are documented in
  `reassembles_identifier`'s docstring, `CLAUDE.md`'s Known weaknesses, and
  `README.md`'s Limitations.
