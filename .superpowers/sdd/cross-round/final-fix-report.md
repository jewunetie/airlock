Status: done, all green.
Commit: TBD (feat/cross-round-guard), not pushed.

Suite counts:
- tests/test_cross_round.py: 49 passed, 0 failed, 0 skipped (49 checks;
  baseline 43 + 6 new: 5 for wiring_blocked_round_does_not_poison_state_case
  (item 1a) + 1 for unit_whole_value_first_round_not_combined_case (minor,
  airlock.py:2027))
- tests/test_liquid_guard.py: 73 passed, 0 failed, 0 skipped (73)
- tests/test_round_guard.py: 58 passed, 0 failed, 0 skipped (58)
- tests/test_server.py: 85 passed, 0 failed, 0 skipped (85 checks; baseline
  80 + 5 new group_b8 checks, item 5)
- tests/test_tax_e2e.py: 8 passed, 0 failed, 0 skipped (8)

eval/public_corpora.py, re-run myself (877 records, four public corpora):
precision 0.909, recall 0.987, f1 0.946, 10/746 false negatives (was
0.904/0.984/12). Matches .superpowers/sdd/cross-round/item-3-report.md's
own numbers exactly, independently reproduced, not copied. eval/README.md
updated with the full per-corpus table, layer attribution (policy-linter
6 -> 8), the corrected false-negative list, and a new paragraph attributing
the change to item-3 and noting the two recall improvements unrelated to
either fix (flagged in item-3-report.md as likely float non-determinism,
not re-investigated here).

## Item 1: sticky cross-round state (IMPORTANT 1)

(a) `run_jobs` folded a round's `released` values into
`session.reassembly_state` before deciding whether that round itself
blocks. A round that completed a cross-round reassembly and returned
`blocked` still recorded its own never-delivered fragments. Fixed by
snapshotting `session.reassembly_state` before the fold and restoring it
whenever the round blocks or the fold raises, so only actually-released
rounds leave a mark. TDD: RED captured verbatim (47 passed / 1 failed,
"round 4 ... is not blocked by round 3's never-released fragment" failing
with round 4 reading "blocked"), then GREEN after the fix.

(b) Ruling: sessions are NOT sticky-forever after a block, and no separate
flag was added. With fix (a), a session's state after any `ok` round never
has a source at or under `REASSEMBLY_PIECE_BOUND` pieces on its own
(otherwise that round would have blocked and been rolled back), so a later
round can only trip on fragments it contributes itself, never on residue
from an earlier blocked one. Re-submitting the same completing fragment
still blocks every time (fail-closed, not stickiness). Documented in
CLAUDE.md's "Known weaknesses" with the exact repro sequence from the
brief and the reasoning above; the measured 1.0-11.5% coincidental rate is
now per-round again, not per-session-fatal.

Also fixed the same-symptom minor at airlock.py:2027:
`advance_reassembly_state` lacked `reassembles_identifier`'s
`not any(source in v for v in normalised)` exclusion, so a single value
equal to a source on a session's first round (no prior state) read as
"combines with values released earlier", which is impossible on round 1.
Added the same exclusion. TDD: RED (advance_reassembly_state(state, [SSN],
sources) returned True with no prior state), GREEN after the fix.

## Item 2: stale eval numbers (IMPORTANT 2)

Regenerated eval/dataset.jsonl, re-ran eval/public_corpora.py myself
(cached HF weights, ~5 min), numbers above. No docs-only claim taken from
the gitignored/report-only source; eval/README.md now carries my own run's
output.

## Item 3: TTL comment overclaim (IMPORTANT 3)

Corrected rather than added a bound (less code, no new behavioural
surface). The Session-eviction comment block now states plainly: TTL and
cap bound orphaned/idle sessions and total concurrent Session count, not
an actively-used session's accumulation (touch_session refreshes
last_active on every ask/extract, so an active session never idles out).
What actually keeps one session's reassembly_state bounded is geometry
(_fold_source_edges: edge set capped by source length squared, independent
of round count) -- state size is bounded, the false-block *rate* is not.
Docs-only, no RED needed.

## Item 4: "whole session" coverage overstatement (IMPORTANT 4)

Named the airlock_ask gap in both README.md ("Limitations", new bullet)
and CLAUDE.md (appended to the existing cross-round piece-bound
paragraph): advance_reassembly_state is reachable only via run_jobs
(airlock_extract's pipeline), so fragments split across airlock_ask calls,
or mixed between airlock_ask and airlock_extract, are untracked
cross-round. Docs-only.

## Item 5: fail-closed hole (IMPORTANT 5)

`signature = (action, step.get("path"), step.get("query"))` in
`run_worker` was hashed against `seen_actions` outside every try; a dict or
list `path`/`query` raised `TypeError: unhashable type` and escaped
`run_worker` uncaught. Wrapped signature-build + seen_actions lookup/add in
their own try, returning a block envelope (no leaked content) on
TypeError. New tests/test_server.py group_b8, stubbing ollama_chat to
return path={dict} and path=[list]; TDD RED captured verbatim (4 FAIL:
TypeError escaping, twice for each bad type), GREEN after the fix. Includes
a positive control (ordinary string-path step still approves).

## Minors

- airlock.py:2027 -- covered under item 1 above.
- airlock.py ("caught before it burns a step") -- reworded; the repeat
  check still consumes a loop iteration via `continue`, it only skips
  re-running the sandbox call. Docs-only.
- README.md Limitations -- covered under item 4 above.
- .github/workflows/tests.yml -- added `timeout-minutes: 30` at job level
  (reasoned ceiling, not measured; comment says so explicitly), replacing
  GitHub's 360-minute default.

## Concerns

- The item-3-report.md path the brief called "gitignored" is actually
  tracked in this worktree (`git check-ignore` returns not-ignored, `git
  ls-files` lists it); only `.superpowers/sdd/PLAN-cross-round/` (a
  different, plan-staging directory) is gitignored here. Re-ran the eval
  myself regardless, per the instruction, so this does not change what was
  done, only that the brief's specific claim about that file's tracked
  status does not hold in this worktree.
- Positive controls added per the Method section:
  wiring_blocked_round_does_not_poison_state_case (round 4, unrelated
  benign value, not blocked) doubles as the "normal round still releases
  its values" control via round 5 re-tripping; group_b8's final check is
  the "ordinary step still approves" control for item 5.
