# Plan: close the round-level reassembly hole

## Context

`run_jobs` executes up to `MAX_JOBS_PER_ROUND = 12` independent extraction jobs
and guards each result on its own. Because splitting a protected value across
jobs is a leak that decomposition creates, it then guards the concatenation of
the approved results:

    combined = " ".join(str(r.get("value", "")) for r in results)

The stated justification is that "912", "84" and "7731" each pass and
reassemble into an SSN.

That check was measured on 2026-08-16 (`eval/round_guard.py`,
`eval/round_full_stack.py`, results in `eval/results/`). It does not work.

Detection of a reassembled SSN, fraction of 40 trials, full airlock stack:

| placement | 0 filler | 2 | 4 | 6 | 9 |
|---|---|---|---|---|---|
| fragments adjacent | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| fragments scattered | 1.00 | 0.40 | 0.03 | 0.07 | **0.00** |

Fragment order is preserved in both rows. The only variable is whether benign
job results sit between the fragments. Scattering costs a caller nothing: it
reads each job result separately and never needs the concatenation to be well
formed. Two independent causes were isolated:

1. The encoder layers are bidirectional contextual scorers, so surrounding
   tokens dilute the per-token score. The PII-Detector emitted `identity.ssn`
   in 100% of trials on the fragments alone and 5% with 9 benign jobs present.
2. The deterministic layers do not dilute, but `us_ssn` needs its three groups
   adjacent. `"912 <benign sentence> 84 7731"` does not match.

A second, separate defect surfaced in the same measurement:

    '31-7729104'  -> ['us_ein']
    '31 7729104'  -> NO MATCH

`us_ein` is `\b\d{2}-\d{7}\b`, hyphen only, while `us_ssn` already accepts
`[-\s]`. EIN reassembly was caught in 0 of 40 trials at every placement and
every filler level, including fully adjacent.

## Approach, and the approach that was rejected

The rejected approach was to strip separators from the round output and run the
identifier patterns over the resulting digit stream. It fails on airlock's own
stated grounds, recorded next to `labelled_ssn`: "A bare nine-digit run is a
phone number, an order id, or an SSN, and only the label separates them." Job
answers are frequently numbers (`JOB_SHAPES` has `number` and `digits`), so
concatenating a wage, a count and a year produces nine-digit windows by
accident and blocks rounds that leaked nothing.

The approach taken anchors on the workspace instead. Source documents hold
identifiers intact and delimited, which is the form the existing detectors are
accurate on. Scan them once per round, normalise each identifier to its
separator-free form, and block the round when its normalised concatenation
contains one of those values that no single job result contained on its own.

This matches a known value rather than a shape, so it is unaffected by
dilution, adjacency, ordering and filler, and it cannot fire on a coincidental
digit run because a coincidence must equal a real identifier exactly.

The "no single job result contained it" condition is what keeps the check
targeted at decomposition. If one job released the whole value, that job's own
guard verdict already governed it and the round check has nothing to add.

## Global Constraints

- **The guard fails closed.** Any error reading the workspace during the check
  is a block, never an approve.
- **The identifier set never leaves the process.** It holds raw protected
  values. It must not appear in a return value, a concern, a receipt, a trace
  record, or an exception message. `scan_pii_patterns` deliberately returns
  only `mask(value)`; the new scan must be a separate function, and its output
  must not be routed into findings.
- **The existing whole-round `evaluate_session` check stays.** It catches
  semantic reassembly that has no identifier. The new check is added alongside,
  and both must pass.
- Read documents through `Sandbox.read_text`, which truncates at
  `FILE_SLICE_CHARS`. That is the same slice the worker sees, so the check
  covers exactly what a job could have extracted.
- Single file: all production code goes in `airlock.py`. Tests go in `tests/`.
- No new dependencies.
- Style per CLAUDE.md: least code that works, comments explain why not what.

## Task 1: catch the space-separated EIN by label, not by widening the shape

**Superseded design.** This task originally widened `us_ein` from
`\b\d{2}-\d{7}\b` to `\b\d{2}[-\s]\d{7}\b`, mirroring `us_ssn`. That is wrong,
and the first implementer proved it: the specified regression fixture
`"we shipped 12 3456789 units"` cannot fail to match, because `12 3456789` is
exactly two digits, a space, and seven digits.

The asymmetry is real and was the error in the original reasoning. `us_ssn`
tolerates a space separator because 3-2-4 across *two* separators is a
distinctive shape. An EIN is 2-7 across *one*, which ordinary prose produces
constantly: amounts, counts, quantities, part numbers, order ids. Widening the
shape would trade a rare miss for a frequent false block, and in `run_jobs` a
false block is not a revise cycle, it is a permanently withheld value.

**Change instead:** leave `us_ein` alone. Add a context rule to
`CONTEXT_SECRET_PATTERNS`, alongside `labelled_ssn` and `labelled_account`,
which already exist for precisely this reason: "A bare nine-digit run is a
phone number, an order id, or an SSN, and only the label separates them."

    "labelled_ein": re.compile(
        r"\b(?:ein|employer id(?:entification)?(?:\s+number)?|federal tax id)\b"
        r"[^\n]{0,24}?\b(\d{2}[-\s]\d{7})\b",
        re.I,
    ),

**Location:** `airlock.py`, `CONTEXT_SECRET_PATTERNS`.

**Tests** (`tests/test_round_guard.py`, new file):

| case | input | expect |
|---|---|---|
| intact form still matches | `"EIN 31-7729104"` | a finding for the EIN |
| labelled space form matches | `"EIN 31 7729104"` | a finding for the EIN |
| labelled space form, longer label | `"Employer identification number: 31 7729104"` | a finding for the EIN |
| unlabelled pair does not match | `"we shipped 12 3456789 units"` | no EIN finding |
| label too far away does not match | `"EIN" + " " * 40 + "31 7729104"` | no EIN finding |

The fourth case is the regression guard for the whole point of this task: it
must fail if anyone later widens `us_ein`'s shape instead. The fifth constrains
the `{0,24}` window so the rule cannot be loosened to `[^\n]*`.

Note that the intact-hyphen case is expected to match via the existing `us_ein`
in `PII_PATTERNS`, and the space cases via the new context rule. Assert that an
EIN finding exists, not which rule produced it, so the test does not encode
which layer catches which form.

## Task 2: source-anchored identifier reassembly detection

**Location:** `airlock.py`, beside the other scanners, above `run_jobs`.

**Data model.** No new types. Two module-level helpers and one predicate.

**API contract:**

```python
MIN_REASSEMBLY_LENGTH = 6

def normalise_identifier(value: str) -> str:
    """Lowercase alphanumerics only, for separator-independent comparison.

    "912-84-7731" and "912 84 7731" both normalise to "912847731".
    """

def source_identifiers(sandbox: Sandbox) -> set[str]:
    """Normalised identifiers present in the workspace documents.

    Holds raw protected values. Never returned to a caller, never logged,
    never placed in a concern. Raises SandboxError, which the caller turns
    into a block.
    """

def reassembles_identifier(values: list[str], sources: set[str]) -> bool:
    """True if the values together reconstruct a source identifier that none
    of them contains on its own."""
```

`source_identifiers` scans every non-directory entry from `sandbox.list_dir(".")`
via `sandbox.read_text` and collects the normalised matched values.

**Which patterns, and why not the scanners.** It must NOT call
`scan_pii_patterns` or `scan_secrets`. Those return `mask(value)` by design, and
changing their return shape to expose raw values would put protected plaintext
into the `findings` list that flows toward `concerns` and the receipt. Instead,
iterate the pattern dictionaries directly in a private helper:

    PII_PATTERNS, SECRET_PATTERNS, CONTEXT_SECRET_PATTERNS

For `CONTEXT_SECRET_PATTERNS` take group 1 where the pattern defines one (those
rules match a label plus the value, and only the value is the identifier);
otherwise take group 0.

`detect-secrets` is deliberately excluded. It contributes finds that have no
fixed shape, which is both the class whose raw span is awkward to recover and
the class least likely to be reconstructed from constrained job answers. This is
a coverage limit, so state it in the docstring rather than leaving it implicit.

The Luhn filter that `scan_pii_patterns` applies to `credit_card` must be
applied here too, or every long digit run in a document becomes a source
identifier and the check starts blocking rounds at random.

Identifiers whose normalised form is shorter than `MIN_REASSEMBLY_LENGTH` are
dropped: a value that short collides with ordinary content and would block
rounds that leaked nothing.

`reassembles_identifier` normalises each value, then returns True when some
source identifier is a substring of the concatenation of SOME SUBSET of the
normalised values taken in job order, and is not a substring of any single
normalised value.

**Why a subset and not the whole concatenation.** The original spec here said
"substring of the concatenation", which is impossible: benign job results sit
between the fragments, so `["912", "notes", "84", "more", "7731"]` concatenates
to `912notes84more7731` and no substring test can find `912847731` in it.

The first implementer correctly caught that and substituted a character-level
subsequence test. That is far too loose, and it was measured rather than
argued: on legitimate rounds of twelve numeric answers against five workspace
identifiers, the subsequence test blocks **38.0%** of rounds (190/500). With a
single identifier it is still 13.3%. The arithmetic is unforgiving: a round
normalises to roughly 60 digits, and C(60,9) times 10^-9 puts the expected
number of chance nine-digit subsequence matches above one.

The model that is both correct and tight is what the caller can actually do:
keep some of the job results it received and concatenate them in the order it
received them. Enumerating subsets is exact for that model and bounded, since
`MAX_JOBS_PER_ROUND` is 12 and 2^12 is 4096.

Measured on the same harness:

| | subsequence | subset concatenation |
|---|---|---|
| false blocks on legitimate numeric rounds | 38.0% | **0.0%** |
| catches fragments scattered among prose | yes | yes |
| catches fragments padded with numeric jobs | yes | yes |
| ignores a value one job released whole | yes | yes |
| cost per round | negligible | **4.9ms** |

Build the subset concatenations once per round and test every identifier
against each, rather than rebuilding per identifier.

**Documented residual.** A caller that issues its jobs out of order defeats
this, because the check preserves job order and does not permute. Closing that
would cost 12! arrangements. Say so in the docstring rather than implying the
check is complete. Cross-round accumulation is also out of scope for this plan
and remains open.

**Tests** (`tests/test_round_guard.py`):

| case | values | sources | expect |
|---|---|---|---|
| scattered fragments caught | `["912", "notes", "84", "more", "7731"]` | SSN present | True |
| adjacent fragments caught | `["912", "84", "7731"]` | SSN present | True |
| single job released it, not this check's business | `["912-84-7731"]` | SSN present | False |
| one job holds it among others | `["notes", "912-84-7731", "more"]` | SSN present | False |
| value absent from workspace | `["555", "12", "3456"]` | SSN present | False |
| empty round | `[]` | SSN present | False |
| short identifiers ignored | `["12", "34"]` | source `"1234"` | False |
| normalisation is separator-blind | `["912 84", "7731"]` | SSN present | True |
| `source_identifiers` finds an SSN in a file | workspace with SSN in a `.txt` | set contains `"912847731"` |
| `source_identifiers` returns normalised, never masked | as above | no `"*"` in any member |

The masked-value test is the regression guard for the invariant that this scan
must not be wired through `scan_pii_patterns`' return shape.

Credentials use `fake_credential` from the existing test conventions, never
literals. See CLAUDE.md.

## Task 4: close the padding bypass with a digits projection

Added after the final review, which surfaced the bypass, and after the
measurement cycle the deferral called for (`eval/padding_bypass.py`,
`eval/results/padding_bypass.json`).

**The bypass is broader than previously documented.** The shipped docstring says
padding defeats the check "depending on which side the padding sits", implying a
prefix is tolerated. Measured over 200 trials per cell with six benign prose
jobs interleaved, every padding shape defeats it, because each fragment's own
padding sits between it and the next:

| padding applied to every fragment | shipped | digits | substr |
|---|---|---|---|
| none | 1.00 | 1.00 | 1.00 |
| suffix (`"912 ok"`) | **0.00** | 1.00 | 1.00 |
| prefix (`"value 912"`) | **0.00** | 1.00 | 1.00 |
| both (`"the 912 confirmed"`) | **0.00** | 1.00 | 1.00 |
| prose (`"The figure recorded here is 912"`) | **0.00** | 1.00 | 1.00 |

**Two candidates were measured, and one is disqualified.** `substr`, a dynamic
programme letting each value contribute any contiguous substring, is complete
against padding and is the fastest of the three, but it false-blocks:

| legitimate round | digits per value | shipped | digits | substr |
|---|---|---|---|---|
| numeric | 5 | 0.000 | 0.000 | 0.128 |
| tax-like | 4 | 0.000 | 0.000 | 0.128 |
| long numbers | 8 | 0.000 | 0.000 | 0.745 |
| hyphenated ids | 8 | 0.000 | 0.000 | 0.662 |
| prose with numbers | 7 | 0.000 | 0.000 | 0.580 |
| 16-digit values | 16 | 0.000 | 0.000 | **1.000** |

That is the subsequence failure mode returning under a different name: a model
loose enough to catch every attack is loose enough to block every round.
`substr` is rejected on this evidence.

**Accepted design: `digits`.** Run the existing subset test, and if it does not
fire, run the SAME test again over each value's digits-only projection against
the numeric source identifiers only. Non-digit padding vanishes under the
projection, while prose filler contributes almost nothing. Detection 1.00 on
every padding shape, false blocking 0.000 on all six legitimate shapes above.

Cost, worst case with non-matching sources so no candidate early-exits: 34ms
per round of twelve short values against 10ms for the shipped check, and 101ms
against 54ms at the `MAX_REASSEMBLY_LENGTH` ceiling. Roughly 3x, because the
projection pass is a second full subset enumeration. Acceptable: the guard path
already carries model layers costing far more, and both passes stay bounded by
`MAX_JOBS_PER_ROUND` and `MAX_REASSEMBLY_LENGTH`.

**Location:** `airlock.py`, `reassembles_identifier` and a helper.

**API contract.** No signature changes. Extract the subset-containment logic
into a private helper so it is called twice rather than duplicated:

```python
def _subset_contains(values: list[str], sources: set[str]) -> bool:
    """True if some source is a substring of some subset concatenation."""
```

`reassembles_identifier` keeps its two existing fail-closed bounds, computes
`candidates` as now, returns False when there are none, tries
`_subset_contains(normalised, candidates)`, and only then projects:

```python
numeric = {s for s in candidates if s.isdigit()}
projected = ["".join(c for c in v if c.isdigit()) for v in normalised]
```

returning False early when `numeric` is empty or nothing projects. Alphanumeric
identifiers such as API keys are unaffected by the projection and must keep
relying on the raw pass.

**Tests** (`tests/test_round_guard.py`, new group):

| case | expect |
|---|---|
| suffix-padded fragments among benign jobs | blocked |
| prefix-padded fragments | blocked |
| fragments padded on both sides | blocked |
| fragments wrapped in prose | blocked |
| legitimate numeric round of twelve | not blocked |
| twelve 16-digit values, none reconstructing a source | not blocked |
| a generated API key split across jobs | still blocked, via the raw pass |
| round with only alphanumeric sources and no numeric ones | projection does not run and does not block |

The two "not blocked" rows are the positive controls, and the 16-digit one is
the exact shape that took `substr` to 1.00. Without them a check that blocks
everything passes every containment assertion.

Update the docstring: the padding bypass is CLOSED for numeric identifiers and
remains open for alphanumeric ones padded on every fragment. Do not leave the
superseded "depending on which side the padding sits" wording in place.

## Task 3: wire the check into `run_jobs`

**Location:** `airlock.py`, `run_jobs`, at the existing round-level check.

**Change.** Keep the current `evaluate_session(session, combined)` call. Before
or after it, compute the source-anchored check over the list of released values
(the `value` field of results with status `ok`), and block the round when either
check fails. The `SandboxError` path from `source_identifiers` blocks.

The existing block message stays accurate for both, and must not name the
identifier, the document, or the job indices: per CLAUDE.md the receipt
describes what airlock did, never what it found.

**Driving `run_jobs` without Ollama.** `run_jobs` calls `ollama_chat` twice per
job: once for the worker answer, and once inside `evaluate` for the guard's
model layer. Follow the convention group B2 in `tests/test_server.py` already
uses: save `airlock.ollama_chat`, replace it, restore in a `finally`.

The stub must serve both callers, and the third positional argument
distinguishes them: the guard layer passes `GUARD_SCHEMA`, the worker passes a
member of `JOB_SHAPES` or `None`. So:

    def stub(model, prompt, schema=None):
        if schema is airlock.GUARD_SCHEMA:
            return {"verdict": "approve", "concerns": [], "instruction": ""}
        return next(answers)          # or {"value": next(answers)} when shaped

Construct the `Session` with `use_presidio=False` and `guardian_model=None` so
the only model layer in play is the stubbed one. Note that the deterministic
layers still run and are NOT stubbed, which is what makes these tests
meaningful: a fragment must genuinely pass `scan_pii_patterns` on its own.

**Supersede the existing coverage.** `tests/test_server.py` group B3 is named
"Split-across-jobs reconstruction" and passes today, but it only calls
`scan_pii_patterns` on a space-joined string and never drives `run_jobs`. It
tests the adjacent arrangement, which already worked, and is the source of the
false confidence this plan corrects. Leave that group in place, and add a line
to its docstring pointing at the round-level tests here, so the next reader does
not mistake it for coverage of the scattered case.

**Tests** (`tests/test_round_guard.py`), driving `run_jobs` with a stub worker
so no model is required:

| case | expect |
|---|---|
| three jobs returning SSN fragments, scattered among benign jobs | round blocked, `status` `blocked`, no fragment in the payload |
| the same round with the fragments adjacent | round blocked |
| twelve benign jobs over a workspace containing an SSN none of them touch | round returns `ok` with all twelve results |
| workspace unreadable during the check | round blocked, not approved |

The third case is the positive control for false blocking: without it, a check
that blocks everything passes every containment assertion. Per CLAUDE.md,
assertions about absence need a positive control.

Assert on the serialised payload, not only the status: the point of the round
check is that no fragment reaches the caller.
