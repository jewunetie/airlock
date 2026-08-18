Status: done, all green.
Commit: ab67897 (feat/cross-round-guard), not pushed.

Suite counts:
- tests/test_liquid_guard.py: 73 passed, 0 failed, 0 skipped (73; baseline 62
  + 11 new item-3 checks: rule5_bare_words_case 8, postal_code_letter_gate_case 3)
- tests/test_round_guard.py: 58 passed, 0 failed, 0 skipped (58)
- tests/test_cross_round.py: 43 passed, 0 failed, 0 skipped (43)
- tests/test_server.py: 52 passed, 0 failed, 2 skipped INCONCLUSIVE (54)
- tests/test_tax_e2e.py: 8 passed, 0 failed

eval/public_corpora.py (877 records, four public corpora, deciding regression
gate):
- precision 0.904 -> 0.909
- recall 0.984 -> 0.987 (12 -> 10 false negatives)
- Recall improved, did not fall. Ship criterion met.

eval/reassembly_residuals.py: unchanged, as expected (this path never calls
scan_policy or scan_pii_model). Six-digit floor 0.0000-0.0133, eight/nine
digit 0.0000 across all cells, matching the figures already in airlock.py.

## Fix 1: rule 5 reword

CONTEXTUAL_RULES[5] changed from "Flag confidential business information
such as unannounced acquisitions or a customer leaving." to "Flag disclosure
of non-public company information that has not been announced, such as a
pending acquisition, a major customer ending its contract, or an internal
investigation."

Re-measured directly against the real model (scratch probes, not committed):

    all 6 rules (prior wording)   recall 0.9500  false-block 0.4062
    rule 5 removed                recall 0.8000  false-block 0.4000
    rule 5 reworded (shipped)     recall 0.9500  false-block 0.3438
    bare-word trip rate:          prior 3/8 (shipment, inventory, ledger)
                                   reworded 0/8

Contextual recall over eval/dataset.jsonl's 20 contextual-block records;
false-block over all 160 approve records. Matches the fix brief's reference
numbers closely (0.95/0.41 vs my 0.95/0.4062, 0.95/0.34 vs 0.95/0.3438),
independently derived, not copied.

## Fix 2: postal_code letter gate

`_scan_pii_region` now additionally requires `re.search(r"[A-Za-z]", chunk)`
for any `contact.postal_code` finding, on top of the existing 0.70
threshold. Narrow: this entity only, not a general mechanism.

Re-measured directly against the real model: a fresh 600-string sweep of
bare, tax-extraction-shaped numbers (mixed integer/decimal/comma/negative
shapes, seed 20260817) found 5/600 (0.83%) scoring above 0.70 for
contact.postal_code before the gate, 0/600 after (definitionally, since none
contain a letter). Six constructed real-postal-code-in-address sentences
fired identically before and after the gate (6/6 both times; the gate never
applies to text that already has a letter). One concrete false positive used
as a test literal: the bare number "43044" scores 0.7189, above the shipped
threshold, with no letter.

## Regression found and fixed along the way

tests/test_round_guard.py's twelve-word benign-round fixture ("twelve
benign jobs over an untouched SSN") was verified clean, individually and
joined, against the OLD rule 5 wording. The reworded rule 5 now names "a
customer ending its contract" as an example, and the fixture's old word set
(which included "payroll", "contract" and "vendor" together) tripped rule 5
once joined by run_jobs' own `" ".join(...)`, even though every word in it
still measured clean individually. Swapped "contract" for "spreadsheet";
re-verified clean both individually and joined against the real model, and
against the exact space-join run_jobs uses. This is the same phenomenon the
fixture's own pre-existing comment already described for the old wording
recurring under the new one, not a new failure mode.

pii_entity_threshold_case's "override mechanism: lowering the threshold
reproduces the false positive" check also had to change: its vehicle
(PII_POSTAL_FALSE_POSITIVE_TEXT, "94250.0", a bare number) is now
permanently silent for contact.postal_code regardless of threshold, by
design of fix 2. Replaced with PII_POSTAL_MIDSCORE_ADDRESS_TEXT ("Deliver to
warehouse bay 94105 by Friday.", measured 0.5454, has a letter so the gate
does not apply), which still demonstrates PII_DETECTOR_ENTITY_THRESHOLDS
being read live. No assertion was weakened or deleted; the check's claim is
unchanged, only the input text that must demonstrate it.

## Docs

CLAUDE.md's "Known weaknesses" and README.md's "Limitations" rewritten to
describe what shipped and the residuals that remain: the linter still
false-blocks ~0.34 of approve-class text overall (linter-wide, not rule 5's
alone), and the PII detector's own recall on real postal codes is a
separate, unmeasured-here limit this fix does not touch.

## Concerns

- The two "rejected alternative" rule 5 wordings named in the fix brief
  (abstract harm-framing, event-list framing) were not given verbatim, so I
  reconstructed my own candidates to sanity-check the brief's direction. My
  harm-framing candidate scored 0.00 recall (matches the brief). My
  event-list candidate did NOT reproduce the brief's specific claim that it
  "kept the false positives" at the bare-word level (mine scored 0/8 on bare
  words, and its dataset-level false-block, 0.325, was actually slightly
  better than the shipped wording's 0.3438) - only its recall (0.85, below
  the shipped 0.95) was clearly worse. The comment in airlock.py cites the
  brief's framing (kept the dataset-level false-block rate high) rather than
  a bare-word claim I could not reproduce, to avoid stating something I
  measured to be false. This does not affect which wording shipped; it only
  affects how confidently the rejected-alternative comment can be trusted
  verbatim.
- eval/public_corpora.py's recall improved by 2 false negatives (12 -> 10)
  on records unrelated to postal codes or rule 5 (a nemotron employee_id and
  a gretel name/street_address record). Neither fix should plausibly change
  detector recall on unrelated entities; this is more likely float
  non-determinism in MPS reduction ops between runs than a causal effect of
  either fix, but I have not isolated it, so I'm not claiming it as evidence
  either fix improved unrelated recall.
