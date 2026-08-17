# Plan: replace the model guard layers with two LFM2.5 encoders

## Decision and the evidence behind it

The guard's three upper layers (`presidio`, `guardian`, `model`) are replaced by
two 350M bidirectional encoders:

    LiquidAI/LFM2.5-Encoder-350M-PII-Detector    replaces presidio
    LiquidAI/LFM2.5-Encoder-350M-Policy-Linter   replaces guardian + model

The user chose this scope explicitly after seeing the validation below. Record
what supports it and what does not, because half of it is unsupported and a
later reader must not mistake the whole for measured.

**Supported.** The PII-Detector is benchmarked on six public PII corpora with
partial-F1, best on five of six, beaten only by models trained in-distribution
on that exact corpus: SPY 0.428, Gretel 0.880, TAB 0.867, ai4privacy 0.715,
Nemotron 0.855, MAPA 0.236. It covers 40 PII types across 11 domains and 16
languages, including `healthcare.condition`, `legal.case_number`,
`credential.connection_string` and `identity.tax_id`, none of which Presidio's
taxonomy has.

**Not supported.** The Policy Linter has NO published benchmarks. Liquid's own
release post calls both fine-tunes "proof-of-concept demonstrations running on
CPU-only Hugging Face spaces, not formally evaluated research contributions".
The only evidence for it is `eval/`, on a synthetic 320-record set built for
this project.

**And that eval flatters everything it measured.** The PII-Detector scored 1.00
precision and 0.82 recall on `eval/dataset.jsonl` against 0.428 and 0.236 on the
hardest public corpora. The synthetic set is markedly easier than real PII
benchmarks, so every figure in `eval/` should be read as an upper bound, not as
expected field performance.

**What is being given up.** Granite Guardian 4.1 is a benchmarked guardrail
model (AUC 0.871 guardrail, 0.854 RAG-hallucination) whose 4.1 release improved
custom-criteria handling substantially: IFEval multi-constraint balanced
accuracy 0.458 to 0.844, InfoBench 0.585 to 0.726 GPT-4 annotated. Its trained
taxonomy does NOT include privacy or PII, which is the real argument against it
here. Note also that `eval/bakeoff.py` config C, labelled "the current
architecture", tested granite through its native scoring protocol, while
`airlock.py` actually calls it with `GUARD_PROMPT`. Those are different modes
and granite performs differently in them, so the bake-off's verdict on granite
was never a test of the shipped configuration. That comparison remains unrun.

## Global Constraints

- **The guard fails closed.** Any error, missing dependency, failed model load,
  or unparseable output is a block, never an approve.
- **Deterministic layers run first and must not be reachable only through an
  optional dependency.** `secrets` and `pii-patterns` are untouched by this
  plan and keep running before any model layer. `pii-patterns` deliberately
  duplicates part of what the detector does; that duplication is the reason
  disabling the model layers degrades coverage rather than removing it.
- **Everything outbound passes through `envelope`.** Concerns still go through
  `sanitise_concerns`.
- **The receipt describes what airlock did, never what it found.**
- Concerns may name a detected entity TYPE or a rule, never a matched span.
  Category-level attribution is existing practice ("personal information
  detected: PERSON"); emitting the matched text is not.
- Single file: production code stays in `airlock.py`. Tests in `tests/`.
- Style per CLAUDE.md: least code that works, comments explain why.

## Accepted risk: `trust_remote_code=True`

Both encoders use custom architectures and load through
`trust_remote_code=True`, which executes code from the model repository at load
time. Presidio required nothing of the sort. This is a real supply-chain
tradeoff being taken on inside a privacy tool, and it must be stated in
`README.md` and `CLAUDE.md` rather than buried in a call site. Pin the revision
where the API allows it so a later repo change cannot silently alter what runs.

## Operating point

From `eval/`, and therefore provisional:

    PII_DETECTOR_THRESHOLD        = 0.5
    POLICY_LINTER_THRESHOLD       = 0.70
    POLICY_LINTER_RULE_THRESHOLDS = {1: 0.98, 4: 0.98}

Rule 1 (financial hardship) and rule 4 (immigration) are raised because at a
global 0.70 they produced 40 and 24 false positives respectively; the override
cut total false positives from 96 to 65. Rule 5 (confidential business) stays
low because it is the only rule that catches the hardest contextual cases, and
it is 52% of the remaining false positives. That is a rule-wording problem, not
a threshold problem, and is left open.

F1 is the wrong objective here: a false positive costs a redraft, a false
negative is an unrecoverable leak. The operating point maximises recall subject
to tolerable precision.

## Task 1: the two encoder layers, not yet wired

**Location:** `airlock.py`, replacing the Presidio block.

**Data model.** No new types. Module constants for the model ids, thresholds and
rules; two cached loaders; two scan functions.

**API contract:**

```python
class GuardModelUnavailable(Exception):
    """Raised when a guard encoder cannot be loaded or run."""

CONTEXTUAL_RULES: list[str]          # six free-text rules, order is the rule index

def scan_pii_model(text: str) -> list[dict[str, str]]:
    """Entity types found by the PII detector, above threshold.

    Returns findings shaped like the other scanners: rule, masked, layer.
    Never returns the matched span unmasked.
    """

def scan_policy(text: str) -> list[dict[str, str]]:
    """Rules the policy linter scores above their threshold."""
```

Both raise `GuardModelUnavailable`. Loaders are `@lru_cache`d, because loading
two 350M encoders per call would dominate every guard decision. Device
resolution prefers MPS on Apple Silicon, then CUDA, then CPU.

Port the scoring logic from `eval/bakeoff.py` `PIIDetectorGuard.decide` and
`PolicyLinterGuard.decide`. Read them; do not reinvent the rule-pool
construction, which is fiddly and already measured.

**Tests** (`tests/test_liquid_guard.py`, new): each of these needs the models
present, so gate them and report SKIP when unavailable rather than failing, per
CLAUDE.md's rule that skips are reported.

| case | expect |
|---|---|
| detector finds an SSN | finding with an identity entity type |
| detector finds an email | finding with a contact entity type |
| detector is clean on ordinary prose | no findings |
| detector findings never carry the raw span | no member equals the input substring |
| linter flags a medical disclosure | rule 0 |
| linter flags an unannounced acquisition | rule 5 |
| linter is clean on a benign file description | no findings |
| per-rule threshold override is honoured | rule 1 silent at 0.98, fires at 0.50 |
| a loader failure raises `GuardModelUnavailable` | raises, does not return empty |

The last one is the fail-closed control: an empty finding list and a failed load
are indistinguishable to a caller that does not separate them, and that
confusion is exactly how a guard starts approving.

## Task 2: rewire `evaluate`

**Location:** `airlock.py`, `evaluate`, `GuardVerdict`, `Session`,
`evaluate_session`.

**Change.** Layers become:

    secrets  ->  pii-patterns  ->  pii-detector  ->  policy-linter

`evaluate`'s signature loses `guard_model`, `use_presidio`, `spacy_model` and
`guardian_model`, and gains `linter_threshold: float = POLICY_LINTER_THRESHOLD`.
`Session` loses the same four fields and gains `linter_threshold`.

`GuardModelUnavailable` from either layer returns `decision="block"` with an
instruction naming the install step, mirroring what the Presidio path did.

Delete `get_analyzer`, `scan_pii`, `PresidioUnavailable`, `BLOCKING_ENTITIES`,
`PRESIDIO_THRESHOLD`, `DEFAULT_SPACY_MODEL`, `granite_guardian_verdict`,
`GUARDIAN_CRITERIA`, `GUARDIAN_BLOCK`, `GUARD_PROMPT`, `GUARD_SCHEMA` and
`DEFAULT_GUARD_MODEL`.

**Delete by AST line range, never by text slice.** CLAUDE.md records that
slicing from one `def` to the next swallowed three functions once and a block of
constants once.

**After the edit, import the module and resolve every name.** `py_compile`
proves almost nothing here; a missing name is a runtime error and two refactors
in this repo deleted live functions and still compiled.

**Tests:** extend `tests/test_liquid_guard.py`.

| case | expect |
|---|---|
| a credential still blocks via `secrets` | decision revise, layer `secrets` |
| a bare SSN still blocks via `pii-patterns` | revise, layer `pii-patterns`, before any model layer |
| a contextual disclosure with no identifier blocks | revise, layer `policy-linter` |
| ordinary file description approves | approve, all four layers ran |
| detector unavailable blocks, does not approve | decision block |
| linter unavailable blocks, does not approve | decision block |

The last two are the fail-closed controls and must assert `block`, not merely
"not approve", so a future refactor cannot satisfy them with an exception.

## Task 3: CLI, session and server surface

**Location:** `build_parser`, `CLI_DEFAULTS`, `make_session`, `cmd_guard`,
`cmd_serve`, `build_server`, `cmd_ask`, `cmd_chat`.

Remove `--guard-model`, `--guardian-model`, `--no-presidio`, `--spacy-model`.
Add `--linter-threshold` (float, default `POLICY_LINTER_THRESHOLD`), which is
the operating point and the one dial worth exposing; do not add flags for the
detector threshold or the per-rule overrides, which are constants until measured
otherwise.

`--model` stays: the worker still runs on Ollama. Only the GUARD leaves Ollama.

`/mcp` output at `render_mcp_help` embeds `--guard-model`; update it or the
config it prints will not parse.

**Tests:** parser-level, no models needed, so these must not skip.

| case | expect |
|---|---|
| removed flags are rejected | `SystemExit` on `--no-presidio`, `--guard-model`, `--guardian-model`, `--spacy-model` |
| `--linter-threshold` parses and reaches the session | session carries the value |
| `CLI_DEFAULTS` has no stale keys | none of the four removed names present |
| the printed MCP config contains no removed flag | no `--guard-model` in output |

## Task 4: doctor, banner and the config screen

**Location:** `cmd_doctor`, `banner`, `_config_loop`, `pick_model`, `HELP_TEXT`
if it names removed settings.

`doctor` must check: torch and transformers importable; both encoders loadable;
the device actually selected; and that each encoder returns a usable verdict on
a fixed probe. It currently checks a guard model exists in Ollama, which is no
longer meaningful for the guard.

State the first-run download in `doctor`'s output. Roughly 700MB across the two
encoders is a surprise worth warning about before it happens, not during.

The config screen currently offers `guard`, `guardian` and `presidio` toggles.
Replace with what is now tunable: the linter threshold. Do not leave a toggle
whose backing field no longer exists.

`banner` prints `session_like.guard_model` and a presidio-dependent layer
string; both will raise once those fields are gone.

**Tests:** `doctor`'s check function is pure enough to test its formatting; for
the rest assert that `banner` and the config screen run against a `Session`
built the new way without raising. A smoke test that constructs the real objects
is what catches a stale attribute reference, which is the failure mode here.

## Task 5: dependencies, docs and dead code

`airlock.py` PEP 723 block: remove `presidio-analyzer` and `spacy`, add `torch`
and `transformers`. Bound both sides, per the existing comment.

`README.md`: the guard layer list, the model requirements, the first-run
download, and the `trust_remote_code` risk.

`CLAUDE.md`: update the invariant text that names Presidio and the guardian
model. Add the `trust_remote_code` tradeoff and the fact that the Policy Linter
is unbenchmarked, so a later reader does not assume it was measured externally.
Keep `eval/`'s existing section accurate.

The module docstring at the top of `airlock.py` describes the three-layer guard
and names Presidio explicitly. It is user-facing and will be wrong.

**Final check, not a test:** import the module, then resolve every public name
the CLI and server reference. Run both existing suites. The point is to catch a
name deleted in Task 2 that is still called in a path no test covers.
