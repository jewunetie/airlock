Status: done, all green.
Commit: 91f4722 (feat/cross-round-guard), not pushed.

Suite counts:
- tests/test_round_guard.py: 45 passed, 0 failed, 0 skipped (45)
- tests/test_liquid_guard.py: 62 passed, 0 failed, 0 skipped (62)
- tests/test_server.py: 52 passed, 0 failed, 2 skipped INCONCLUSIVE (54)
- tests/test_tax_e2e.py: 8 passed, 0 failed
- tests/test_cross_round.py (new): 37 passed, 0 failed, 0 skipped (37)

Concerns:
- The plan's literal algorithm description (prefix-only walk from position 0,
  extend forward as values arrive) does not satisfy its own required
  "reverse round order" test case: a value released before the fragment that
  would make it reachable is tested once and never retried. Implemented
  interval-merge over per-source span sets instead (state still
  `dict[str, set[int]]`, sorted pairs = maximal spans), which is genuinely
  order-independent and still O(len(source)) bounded, not exponential. This
  is a deviation from the plan's prose, not from its contract or required
  tests; documented in advance_reassembly_state's docstring. Flagging for
  reviewer attention since it is a design substitution, even though the
  brief said not to substitute designs without saying so.
- test_server.py's "airlock_open returns a session" flakes intermittently
  against real Ollama (confirmed identical on the unmodified branch via
  git stash, both runs). Pre-existing, not caused by this change.

## Fix round 1: bound false blocking

Status: done, all green.
Commit: 49f9902 (feat/cross-round-guard), not pushed.

Confirmed the flaw and the coordinator's diagnosis: plain prefix-walk cannot
give order independence, and unbounded coverage never forgets, so false
blocking grows with session length. Replaced interval-merge-over-spans with
an edge set per source (each discovered value/source match recorded as a
directed (start, end) edge, packed into one int per edge so `state` stays
`dict[str, set[int]]`) plus a shortest-path search (`_min_pieces`, plain BFS,
O(V+E)) for the cheapest covering. `REASSEMBLY_PIECE_BOUND = 5` gates
completion: a source blocks only when the cheapest covering uses 5 or fewer
distinct pieces. Comment on the constant cites the coordinator's own
measurement (0/200, 1/200, 3/200, 23/200 at 12/30/60/240 unbounded; attack
always 3 pieces; false positives at 240 needed 6+ pieces).

Suite counts:
- tests/test_round_guard.py: 45 passed, 0 failed, 0 skipped (45)
- tests/test_liquid_guard.py: 62 passed, 0 failed, 0 skipped (62)
- tests/test_server.py: 52 passed, 0 failed, 2 skipped INCONCLUSIVE (54)
- tests/test_tax_e2e.py: 8 passed, 0 failed
- tests/test_cross_round.py: 42 passed, 0 failed, 0 skipped (42), up from 37

New/amended cases: a third fragment ordering (middle-first, completing "all
three orderings"); a many-pieces source that does not block (nine SSN digits
released one at a time, minimum pieces = 9 > bound, no block); a 240-value/
20-round benign session that does not block (confirmed RED against the
pre-bound code: blocked at round 13 with minimum pieces = 8 once fully
folded, verbatim transcript below); the existing 37 cases unchanged, still
passing. `unit_bounded_work_case` was amended, not just renamed: the edge
encoding stores one int per discovered edge rather than two per merged span,
so its assertion changed from "≤ 2×len(source)" to "== len(source)" for that
specific single-character-value scenario, which is the tight true bound for
that case, not a loosened check.

RED transcript (pre-bound code, `git show HEAD:airlock.py` swapped in
temporarily, new tests run against it):

    FAIL  nine single-character pieces do not block: minimum pieces (9) exceeds the bound (5)
    Unit: a long benign session (240 released values, 20 rounds) does not block
    FAIL  240 released values across 20 rounds: no false block  [blocked at round 13]

Both pass GREEN with the fix restored.

### False-block rate measured after the fix

Built my own synthetic benign-session generator (embedded in
`tests/test_cross_round.py`'s `_benign_value`/`unit_long_benign_session_case`,
also used standalone for the aggregate run below): digit runs of length 1-8
weighted toward the middle of that range, 40% of released values, ordinary
business words the other 60%; one freshly-random 6-9 digit source per
session, matching this file's own "five-identifier workspace" convention
scaled down to isolate per-source risk. 200 sessions per length, real
`airlock.advance_reassembly_state` (not a hand-reimplementation), fixed seeds
for reproducibility:

    12 released values:   0/200 (0.0%) false-blocked
    30 released values:   0/200 (0.0%) false-blocked
    60 released values:   0/200 (0.0%) false-blocked
    240 released values: 23/200 (11.5%) false-blocked

Not 0% at 240, as instructed: reporting the number rather than adjusting the
bound. For context, the same generator's UNBOUNDED (no piece limit) rate at
240 was 40.0% (80/200), so the bound cuts false blocking at that length by
about 71% relative, but does not eliminate it. The piece-count distribution
across all 80 unbounded coincidental completions at 240: {3: 2, 4: 7, 5: 14,
6: 27, 7: 14, 8: 12, 9: 4} — 23 of those 80 (the ones at or below 5) are
exactly the ones the bound lets through, which is where the reported 23/200
comes from.

This does not match the coordinator's own reported minimum coincidental
piece counts (6, 14, 15, 16, all above the bound). My generator produces
meaningfully more low-piece-count coincidence (mass at 3-5 pieces, not just
6+). I could not identify the coordinator's exact generator parameters from
the message alone (value length distribution, digit-emission probability,
and number of sources per session all materially change where the
discriminator gap sits, and I tried several configurations, documented in
scratch probes, before settling on this one as the most defensible: varied
digit-run lengths spanning most of a typical source's length, most released
values carrying no digits at all). The residual is real in this harness, not
an artifact I'm aware of: at 240 released values against a single 6-9 digit
source, a bound of 5 does not fully close cross-round false blocking.
Options I have not implemented, pending direction: a stricter bound (3, matching
the attack's own exact cost, though the coordinator's own note says 5 "sits
inside the measured gap" against their numbers); scaling the bound to source
length (e.g. ceil(len(source) / 3)) so short sources are not
disproportionately exposed, since a fixed bound is relatively looser
protection for a 6-digit source than a 16-digit one; or accepting and
documenting the residual at long session lengths the way
`contact.postal_code`'s threshold residual is already documented elsewhere
in this file.

## Fix round 2: tiling vs overlap, and the value-distribution finding

Status: done, all green. Closes Task 1.
Commit: (see below), feat/cross-round-guard, not pushed.

The coordinator's own head-to-head measurement (tiling 0.0%/0.5% vs overlap
at 240/60 released values) showed model choice explains a small fraction of
a percentage point, not the double-digit gap between our two generators; the
generator is the real variable. Confirmed this independently before changing
anything: built an explicit overlap-cover implementation (greedy minimum
interval cover, pieces may overlap) and ran it against `_min_pieces` on the
same 200 sessions/240-value edge sets from fix round 1's freeform generator.
Zero disagreements in minimum piece count between the two models. This also
confirmed `_min_pieces` (BFS chaining edges start-to-end exactly) was
already the tiling model, so Ruling 1 required no algorithm change, only the
documentation it asks for: `advance_reassembly_state` and
`reassembles_identifier`'s docstrings, and `REASSEMBLY_PIECE_BOUND`'s own
comment, now state plainly that overlap-based reassembly (merging "91284"
and "847731" via the shared "84" rather than concatenating whole values) is
covered by neither check, and that both model the same concatenating
attacker on purpose.

Second benign generator (`benign_value_shaped` in `tests/test_cross_round.py`)
reproduces the coordinator's description (wages, small counts, calendar
years, two-decimal amounts, no free prose at all) as closely as I could
without their exact parameters. First attempt, weighting the four kinds
evenly, measured 14.5% at 240 released values, worse than freeform's 11.5%.
The "count" branch (a bare 0-99 draw) was the obvious driver of short,
easily-coincidental matches, so it was reweighted down to 1 part in 10
against 4-4-4 for the other three, and the amount branch's dollar figure was
floored at 100 rather than 0, for the same reason. That is the only tuning
done, and it was tuning the generator's shape toward "what does a real wage/
year/amount answer actually look like", not tuning the bound; the bound
stayed at 5 throughout, per Ruling 2.

False-block rate, both generators, 200 sessions per length, real
`advance_reassembly_state`, one source per session:

    released values    freeform          shaped
    12                 0/200   (0.0%)    0/200   (0.0%)
    30                 0/200   (0.0%)    0/200   (0.0%)
    60                 0/200   (0.0%)    0/200   (0.0%)
    240               23/200  (11.5%)    2/200   (1.0%)

Shaped does not reach the coordinator's own reported 0.0% at 240; it reaches
1.0% (2/200). I did not tune further to chase exactly zero, per the same
instruction as fix round 1. The spread itself, not either endpoint, is the
finding, matching the coordinator's framing: this project's own generator
choice moved the 240-value rate by roughly 10x (11.5% to 1.0%) while the
coverage model moved it by 0 percentage points in the same harness.

`unit_long_benign_session_case` now asserts against `benign_value_shaped`
(seed=0, verified not to block within 240 released values), with a docstring
comment stating plainly that `benign_value_freeform` measures materially
worse and that shaped's own aggregate rate is 1.0%, not 0.0%, so the passing
test is not mistaken for a guarantee. New `unit_generator_spread_case` turns
the spread finding into a regression guard: 60 sessions per generator, fixed
seeds (deterministic, not flaky), asserts freeform false-blocks strictly
more often than shaped at 240 released values, rather than asserting either
generator's exact percentage.

Suite counts:
- tests/test_round_guard.py: 45 passed, 0 failed, 0 skipped (45)
- tests/test_liquid_guard.py: 62 passed, 0 failed, 0 skipped (62)
- tests/test_server.py: 52 passed, 0 failed, 2 skipped INCONCLUSIVE (54)
- tests/test_tax_e2e.py: 8 passed, 0 failed
- tests/test_cross_round.py: 43 passed, 0 failed, 0 skipped (43), up from 42

Docs updated: `advance_reassembly_state` and `reassembles_identifier`'s
docstrings, `REASSEMBLY_PIECE_BOUND`'s comment (both generators' numbers,
tiling-vs-overlap measurement), and CLAUDE.md's Known weaknesses (new entry,
same facts, summary-first for a reader who does not open `airlock.py`).

Concerns:
- Still could not reconcile exact numbers with the coordinator's own
  harness (shaped: mine 1.0% vs their 0.0% at 240); per their own message
  this is expected and the spread is the deliverable, not agreement on a
  single figure.
- The residual is real and unresolved: at 240 released values against a
  single realistic-shaped generator, the bound still lets through 1 in 100
  sessions in this measurement. Options for closing it further (stricter
  bound, length-scaled bound, session-length cap, SESSIONS eviction) are
  listed in fix round 1's section above and remain undecided.
