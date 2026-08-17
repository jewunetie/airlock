# Plan: close the round guard's three remaining holes

## Context

`reassembles_identifier` blocks a round when a workspace identifier is
reconstructed from the values that round released. Three documented holes remain,
all recorded in its docstring rather than hidden:

1. **Cross-round accumulation is unguarded.** The check bounds one round.
   Nothing bounds a caller issuing three rounds of one fragment each. `Session`
   carries counters, not released-value history. This was flagged before any of
   the round-guard work began and has never been closed. It is the largest
   remaining gap and it is structurally the same attack the round guard exists
   to stop.
2. **Out-of-order jobs** defeat the check, which preserves job order and does
   not permute.
3. **Alphanumeric identifiers padded on every fragment** defeat it, because the
   digits projection that closed numeric padding cannot apply to a value whose
   letters carry the meaning.

## Global Constraints

- **The guard fails closed.** Any error is a block.
- **No unbounded work on the guard path.** The existing bounds
  (`MAX_JOBS_PER_ROUND` on count, `MAX_REASSEMBLY_LENGTH` on total length) exist
  because a 4000-char round against 400 identifiers already costs seconds. Any
  cross-round mechanism must NOT reintroduce exponential cost: 2**(all released
  values across a session) is not an option.
- **No protected plaintext may escape.** Whatever state a session accumulates
  holds fragments of protected values. It must never reach a return value, a
  concern, a receipt, a trace record, or an exception message.
- **The receipt describes what airlock did, never what it found.**
- Deterministic layers keep running first.
- Single file; tests in `tests/`.
- Style per CLAUDE.md.

## Measured baseline that must not regress

`eval/public_corpora.py`, four public corpora, 877 records: precision 0.904,
recall 0.984, 12 false negatives. `eval/reassembly_residuals.py`: six-digit
sources 0.0000 to 0.0133 false blocking, eight and nine digit 0.0000. Cost at a
realistic five-identifier workspace: 17ms per round.

Any change here is measured against those, not against intuition.

## Task 1: cross-round accumulation

**The wrong design, stated so nobody tries it.** Keeping every released value on
the `Session` and re-running subset enumeration over the union is exponential in
session length. `MAX_JOBS_PER_ROUND` bounds one round at 2**12; a session with
sixty released values would be 2**60. Do not do this.

**The design.** Track reachability incrementally, per source identifier, as a set
of reachable prefix positions.

For a source identifier S, maintain the set of positions p such that S[:p] can be
assembled from values released so far. Start at {0}. When a value v is released,
for every reachable p, if S continues with v at p then p + len(v) becomes
reachable. Reaching len(S) means the session has now released enough to
reconstruct S, and the round blocks.

Cost is O(len(S)) per source per released value, with no exponential term. State
is one small set of integers per source identifier.

Because the caller controls the order it issues jobs, cross-round assembly should
NOT assume order: a value released in round 3 may precede one from round 1 in the
caller's reconstruction. Reachability as described is order-independent by
construction, which also closes hole 2 for the cross-round case. Say so in the
docstring rather than leaving it implicit.

**Data model.** `Session` gains a field holding, per normalised source
identifier, the set of reachable positions. Keyed by identifier, so it is
naturally bounded by the workspace's identifier count rather than by session
length.

**API contract:**

```python
def advance_reassembly_state(
    state: dict[str, set[int]], values: list[str], sources: set[str]
) -> bool:
    """Fold newly released values into per-source reachability.

    Mutates state. Returns True when any source has become fully
    reconstructible from everything released this session.
    """
```

Apply both the raw value and its digits-only projection, matching what
`reassembles_identifier` already does, so cross-round numeric padding is covered
the same way single-round padding is.

**Where it runs.** In `run_jobs`, after the existing per-round check passes,
before the round's results are returned. A round that completes the
reconstruction blocks, and the block message must not name the identifier, the
document, or which jobs contributed.

**Tests** (`tests/test_cross_round.py`, new):

| case | expect |
|---|---|
| three rounds of one SSN fragment each | third round blocks |
| the same three fragments in reverse round order | third round blocks (order independence) |
| fragments split across rounds with benign rounds between | blocks |
| three rounds of unrelated benign values | none block |
| a single round containing the whole identifier | blocked by the existing check, not this one |
| state is bounded: N released values do not grow work exponentially | a timing or call-count assertion, not a wall-clock guess |
| session state never appears in any returned payload | assert on `json.dumps` of every round's result |

The fourth is the positive control against blocking everything, and the last is
the containment control. Both are mandatory.

## Task 2: out-of-order within a single round

Hole 2 for the single-round case: `reassembles_identifier` enumerates subsets in
job order only.

Reuse Task 1's reachability primitive rather than adding permutations: applying
it to a single round's values gives order independence at O(len(S)) per value
instead of 12! arrangements.

**Measure before adopting.** Order independence is strictly more permissive, so
it can only increase false blocking. Re-run `eval/reassembly_residuals.py` and
`eval/public_corpora.py`. If false blocking rises materially above the recorded
baseline, report the numbers and stop rather than shipping it; recall is worth
more than order coverage, but not at any price.

## Task 3: alphanumeric padding

Hole 3. The digits projection cannot help an identifier whose letters matter,
such as an API key.

**Investigate before building.** Ask first whether this is reachable in practice:
a shaped job (`as: "digits"` is `^[0-9-]{1,20}$`, `as: "number"` is a JSON
number) cannot carry padding, so the attack needs unshaped free-text jobs, and
the value must survive the per-job guard in fragments.

Options to weigh, with measurement:

- an alphanumeric-run projection, the direct analogue of the digits projection
- restricting it to sources that look like credentials, where `SECRET_PATTERNS`
  already defines the shapes
- declining it and documenting why, if the false-blocking cost exceeds the
  coverage gained

Any of the three is an acceptable outcome. An unmeasured choice is not.

## Task 4: reconcile the docstring and the docs

`reassembles_identifier`'s docstring, `CLAUDE.md`'s known weaknesses and
`README.md`'s limitations all currently list these three holes as open. Update
each to what actually shipped, including anything Task 3 declines and why.

Re-run `eval/public_corpora.py` and record the post-change precision, recall and
false-negative count against the 0.904 / 0.984 / 12 baseline. A change that
improves reassembly coverage while quietly costing recall on real corpora is a
bad trade and must be visible.
