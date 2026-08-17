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
