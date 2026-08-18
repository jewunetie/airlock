#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "torch>=2.13.0,<2.14.0",
#     "transformers>=5.15.0,<5.16.0",
#     "rich>=13.7",
# ]
# ///
"""Tests for the two encoder guard layers. See task-1-brief.md, and
task-2-brief.md for the cases appended below that exercise evaluate()
rewired onto them (secrets -> pii-patterns -> pii-detector -> policy-linter)
and the CLI surface that configures it.

    uv run --script tests/test_liquid_guard.py

torch and transformers are declared here too, as their own copy, the way
eval/ scripts do, even though airlock.py's own PEP 723 block now declares
them as well (Task 5).

Every case that calls scan_pii_model/scan_policy directly, or evaluate() in a
way that must reach them, needs both LiquidAI encoders loadable from the local
Hugging Face cache. If a real load fails, every such case is SKIPped with the
reason, per CLAUDE.md: a suite that silently collects fewer checks reads like
one that passed. The two fail-closed controls are the exception: they force a
load failure on purpose, so they run unconditionally and need no model at all.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import secrets
import string
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
AIRLOCK = HERE.parent / "airlock.py"

spec = importlib.util.spec_from_file_location("airlock", AIRLOCK)
airlock = importlib.util.module_from_spec(spec)
sys.modules["airlock"] = airlock
spec.loader.exec_module(airlock)

PASS, FAIL, SKIP = [], [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    mark = "  pass" if ok else "  FAIL"
    print(f"{mark}  {name}" + (f"  [{detail}]" if detail else ""))


def skip(name: str, why: str) -> None:
    SKIP.append(name)
    print(f"  skip  {name}  [{why}]")


# Real, empirically-scored examples (see task-1-report.md for the probe that
# picked them). Not fake_credential/CREDENTIAL_SHAPES material: these are
# prose sentences for a contextual model, not vendor-shaped secrets.
SSN_TEXT = "My social security number is 912-84-7731."
EMAIL_TEXT = "Reach me at jane.doe@example.com for details."
CLEAN_PII_TEXT = "The quarterly report was filed on time and everyone was pleased."
MEDICAL_TEXT = (
    "I was recently diagnosed with stage 2 breast cancer and started "
    "chemotherapy last week."
)
ACQUISITION_TEXT = (
    "Just so you know, we are about to be acquired by a larger competitor "
    "but it hasn't been announced yet."
)
CLEAN_POLICY_TEXT = (
    "The README describes how to set up the development environment and "
    "run the test suite."
)
# rule1 (financial hardship) scores 0.946 here: below the 0.98 override,
# above a 0.50 threshold. Picked by direct measurement against the real
# model, not guessed.
BORDERLINE_FINANCIAL_TEXT = "Money has been a bit tight lately with all the bills piling up."

# The exact tax-workflow defect: run_jobs hands the guard
# str(answer).strip() for a "number"-shaped job, i.e. a bare, context-free
# numeric string. Measured against the real model: contact.postal_code =
# 0.545, inside the measured false-positive cluster (0.524-0.565, 8/300
# sampled; see PII_DETECTOR_ENTITY_THRESHOLDS' comment in airlock.py).
# Below the shipped PII_DETECTOR_ENTITY_THRESHOLDS override of 0.70, above
# the flat PII_DETECTOR_THRESHOLD of 0.5 the bug shipped at.
PII_POSTAL_FALSE_POSITIVE_TEXT = "94250.0"
# A real postal code with the surrounding context a genuine disclosure would
# have. Measured: contact.postal_code = 0.911, inside the coordinator's
# measured true-positive cluster (0.845-0.998). Above 0.70, so recall on an
# actual postal-code disclosure must survive the same override that silences
# the bare-number false positive above.
PII_POSTAL_TRUE_POSITIVE_TEXT = (
    "Please mail the refund check to zip code 94250, care of the Franchise "
    "Tax Board."
)

# Fix round 3 (item-3): the 0.70 threshold alone still lets some bare numbers
# through. Measured directly against the real model (scratch probe, not
# committed, 600-string sweep of tax-extraction-shaped bare numbers): "43044"
# scores 0.7189 for contact.postal_code, above the shipped 0.70 threshold,
# with no letter anywhere in the string. This is the RED case for the
# letter-presence gate: without it, this bare number is indistinguishable
# from a real postal code at the threshold alone.
PII_POSTAL_HIGH_SCORING_BARE_NUMBER = "43044"
# The letter gate makes every bare number permanently silent for
# contact.postal_code regardless of threshold, by design (that is the fix).
# That means PII_POSTAL_FALSE_POSITIVE_TEXT ("94250.0", no letter) can no
# longer serve as pii_entity_threshold_case's vehicle for proving
# PII_DETECTOR_ENTITY_THRESHOLDS is read live: lowering the threshold cannot
# reproduce a finding the letter gate excludes unconditionally. This
# address-shaped replacement (has a letter, so the gate does not apply)
# measures 0.5454 for contact.postal_code, real model, directly probed:
# below the shipped 0.70 threshold, above a 0.50 override, so it still
# demonstrates the dict being read live rather than baked in.
PII_POSTAL_MIDSCORE_ADDRESS_TEXT = "Deliver to warehouse bay 94105 by Friday."

# Fix round 3: CONTEXTUAL_RULES[5] reworded (see airlock.py's comment above
# CONTEXTUAL_RULES for the measurements behind the wording and the two
# rejected alternatives). Measured directly against the real model: the
# shipped wording trips on 3 of these 8 ("shipment", "inventory", "ledger")
# with no surrounding context; the reworded rule trips on 0/8.
BARE_BUSINESS_WORDS = [
    "shipment", "inventory", "ledger", "invoice",
    "backlog", "vendor", "forecast", "revenue",
]

# Filler long enough to push a trailing identifier past a single 512-token
# window under the real PII detector tokenizer: measured at 642 tokens for
# this exact filler, comfortably past the model's own truncation limit, so an
# identifier placed after it is invisible to a single untruncated call and
# must be caught by chunking instead. See task-1-report.md fix round 1 for
# the probe that measured this.
PII_OVERFLOW_FILLER = (
    "The quarterly report was filed on time and everyone was pleased with "
    "the outcome. " * 40
)
PII_OVERFLOW_TEXT = PII_OVERFLOW_FILLER + SSN_TEXT

# Filler measured at 2042 tokens under the policy linter tokenizer, past the
# 2048-token budget even before the 92-token rule prefix is added, so a
# disclosure placed after it is invisible to a single untruncated call.
POLICY_OVERFLOW_FILLER = (
    "The README describes how to set up the development environment and "
    "run the test suite. " * 120
)
POLICY_OVERFLOW_TEXT = POLICY_OVERFLOW_FILLER + MEDICAL_TEXT

# Carried finding from Task 1's re-review (see task-2-report.md fix round 1):
# PII_CHUNK_CHARS/POLICY_CHUNK_CHARS rest on a chars/token ratio measured over
# ASCII identifier-shaped text (~1.06 chars/token), not a proven floor. Dense
# non-ASCII text can tokenize well below 1 char/token via BPE byte-fallback,
# so a single PII_CHUNK_CHARS/POLICY_CHUNK_CHARS-sized window of it can still
# overflow the model's token budget on its own, reproducing the original
# fail-open at window granularity instead of document granularity. Rare CJK
# characters (well outside the tokenizer's common vocabulary, forcing heavy
# byte-fallback) measured furthest below 1 char/token of several scripts
# probed; a 500-char slice tokenizes to ~1020 tokens under the PII detector's
# tokenizer (over the 512 budget) and a 1800-char slice plus the policy
# linter's ~92-token rule prefix tokenizes to ~3600+ tokens (over the 2048
# budget). Both fillers below are sized so the trailing value lands inside
# the LAST outer chunk _chunk_text produces (guaranteed to cover the tail),
# not rescued by landing in some other, less-dense overlapping window.
RARE_KANJI_UNIT = "鬱鬱蔥蔥薔薇鑫燚龘齉爨龗蠿豔驫麤龖钃鱻虋鼺齾靐飝饗饕"
DENSE_NON_ASCII_PII_FILLER = (RARE_KANJI_UNIT * (900 // len(RARE_KANJI_UNIT) + 2))[:900]
DENSE_NON_ASCII_PII_TEXT = DENSE_NON_ASCII_PII_FILLER + SSN_TEXT
DENSE_NON_ASCII_POLICY_FILLER = (RARE_KANJI_UNIT * (2500 // len(RARE_KANJI_UNIT) + 2))[:2500]
DENSE_NON_ASCII_POLICY_TEXT = DENSE_NON_ASCII_POLICY_FILLER + MEDICAL_TEXT


def models_available() -> str:
    """Try a real call through both guards. Empty string if both work,
    otherwise the failure reason to skip every case with.
    """
    try:
        airlock.scan_pii_model("probe")
        airlock.scan_policy("probe")
    except airlock.GuardModelUnavailable as exc:
        return str(exc)
    return ""


def pii_detector_cases(unavailable: str) -> None:
    print("\nPII detector: entity types above threshold")
    if unavailable:
        for name in (
            "detector finds an SSN",
            "detector finds an email",
            "detector is clean on ordinary prose",
            "detector findings never carry the raw span",
        ):
            skip(name, unavailable)
        return

    findings = airlock.scan_pii_model(SSN_TEXT)
    rules = {f["rule"] for f in findings}
    check(
        "detector finds an SSN",
        any(r.split(".")[0] == "identity" for r in rules),
        ",".join(sorted(rules)) or "no findings",
    )

    findings = airlock.scan_pii_model(EMAIL_TEXT)
    rules = {f["rule"] for f in findings}
    check(
        "detector finds an email",
        any(r.split(".")[0] == "contact" for r in rules),
        ",".join(sorted(rules)) or "no findings",
    )

    findings = airlock.scan_pii_model(CLEAN_PII_TEXT)
    check("detector is clean on ordinary prose", findings == [], str(findings))

    findings = airlock.scan_pii_model(SSN_TEXT) + airlock.scan_pii_model(EMAIL_TEXT)
    leaked = [
        v for f in findings for v in f.values()
        if v in (SSN_TEXT, EMAIL_TEXT, "912-84-7731", "jane.doe@example.com")
    ]
    check(
        "detector findings never carry the raw span",
        leaked == [],
        ",".join(leaked),
    )


def containment_positive_control_case() -> None:
    """Positive control for "detector findings never carry the raw span"
    (CLAUDE.md: assertions about absence need one). That check cannot fail as
    written, because scan_pii_model's real findings only ever carry the
    literal "masked": "detected" marker, never a captured value. A hand-built
    finding that DOES carry the raw span must trip the identical assertion,
    or the check above proves nothing about the guarantee it claims to test.
    No model needed, so this runs unconditionally rather than being gated
    behind model availability like the checks it backs up.
    """
    print("\nPositive control: the containment check can actually fail")

    poisoned = [{"rule": "identity.ssn", "masked": "912-84-7731", "layer": "pii:model"}]
    poisoned_leaked = [
        v for f in poisoned for v in f.values()
        if v in (SSN_TEXT, EMAIL_TEXT, "912-84-7731", "jane.doe@example.com")
    ]
    check(
        "positive control: a hand-built span-carrying finding is caught by the same check",
        poisoned_leaked != [],
        ",".join(poisoned_leaked) or "not caught",
    )


def policy_linter_cases(unavailable: str) -> None:
    print("\nPolicy linter: contextual rules above threshold")
    if unavailable:
        for name in (
            "linter flags a medical disclosure",
            "linter flags an unannounced acquisition",
            "linter is clean on a benign file description",
            "per-rule threshold override: silent at 0.98",
            "per-rule threshold override: fires at 0.50",
        ):
            skip(name, unavailable)
        return

    findings = airlock.scan_policy(MEDICAL_TEXT)
    rules = {f["rule"] for f in findings}
    check("linter flags a medical disclosure", "rule0" in rules, ",".join(sorted(rules)) or "none")

    findings = airlock.scan_policy(ACQUISITION_TEXT)
    rules = {f["rule"] for f in findings}
    check(
        "linter flags an unannounced acquisition",
        "rule5" in rules,
        ",".join(sorted(rules)) or "none",
    )

    findings = airlock.scan_policy(CLEAN_POLICY_TEXT)
    check("linter is clean on a benign file description", findings == [], str(findings))

    original = dict(airlock.POLICY_LINTER_RULE_THRESHOLDS)
    try:
        airlock.POLICY_LINTER_RULE_THRESHOLDS = {1: 0.98}
        rules = {f["rule"] for f in airlock.scan_policy(BORDERLINE_FINANCIAL_TEXT)}
        check("per-rule threshold override: silent at 0.98", "rule1" not in rules, ",".join(sorted(rules)))

        airlock.POLICY_LINTER_RULE_THRESHOLDS = {1: 0.50}
        rules = {f["rule"] for f in airlock.scan_policy(BORDERLINE_FINANCIAL_TEXT)}
        check("per-rule threshold override: fires at 0.50", "rule1" in rules, ",".join(sorted(rules)))
    finally:
        airlock.POLICY_LINTER_RULE_THRESHOLDS = original


def rule5_bare_words_case(unavailable: str) -> None:
    """Item-3 fix round: CLAUDE.md's "Known weaknesses" measured rule 5
    (confidential business) firing on ordinary business vocabulary alone,
    3/8 of BARE_BUSINESS_WORDS with no surrounding context, 52% of the
    bake-off's false positives. The reworded CONTEXTUAL_RULES[5] (see
    airlock.py) must be silent on all 8. policy_linter_cases above already
    covers the paired positive control (rule5 still fires on
    ACQUISITION_TEXT), so it is not repeated here.
    """
    print("\nPolicy linter: reworded rule 5 does not fire on bare business vocabulary (item-3 fix)")
    if unavailable:
        for word in BARE_BUSINESS_WORDS:
            skip(f"rule5 silent on bare word: {word!r}", unavailable)
        return

    for word in BARE_BUSINESS_WORDS:
        rules = {f["rule"] for f in airlock.scan_policy(word)}
        check(
            f"rule5 silent on bare word: {word!r}",
            "rule5" not in rules,
            ",".join(sorted(rules)) or "none",
        )


def pii_entity_threshold_case(unavailable: str) -> None:
    """PII_DETECTOR_ENTITY_THRESHOLDS exists because the flat
    PII_DETECTOR_THRESHOLD false-flagged 2.7% of
    bare number-shaped job answers (measured 8/300) as contact.postal_code,
    landing on the tax-extraction workflow test_tax_e2e.py exercises. Same
    override-mechanism shape as policy_linter_cases's per-rule test above:
    checks the shipped value, then proves the dict is read live rather than
    the fix happening to work only at the one value committed.

    The "lowering the threshold reproduces a finding" half uses
    PII_POSTAL_MIDSCORE_ADDRESS_TEXT, not PII_POSTAL_FALSE_POSITIVE_TEXT.
    Item-3's letter gate (postal_code_letter_gate_case below) makes every
    bare number permanently silent for this entity regardless of threshold,
    so the original bare-number vehicle can no longer demonstrate the
    threshold dict being live; PII_POSTAL_FALSE_POSITIVE_TEXT still proves
    the "silent at the shipped threshold" half just below.
    """
    print("\nPII detector: per-entity threshold override (fix round 2)")
    if unavailable:
        for name in (
            "bare number false positive: silent at the shipped threshold",
            "postal code in context: still fires at the shipped threshold",
            "override mechanism: raising the threshold silences a real postal code",
            "override mechanism: lowering the threshold reproduces a finding",
        ):
            skip(name, unavailable)
        return

    rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_FALSE_POSITIVE_TEXT)}
    check(
        "bare number false positive: silent at the shipped threshold",
        "contact.postal_code" not in rules,
        ",".join(sorted(rules)) or "none",
    )

    rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_TRUE_POSITIVE_TEXT)}
    check(
        "postal code in context: still fires at the shipped threshold",
        "contact.postal_code" in rules,
        ",".join(sorted(rules)) or "none",
    )

    original = dict(airlock.PII_DETECTOR_ENTITY_THRESHOLDS)
    try:
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = {"contact.postal_code": 0.98}
        rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_TRUE_POSITIVE_TEXT)}
        check(
            "override mechanism: raising the threshold silences a real postal code",
            "contact.postal_code" not in rules,
            ",".join(sorted(rules)),
        )

        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = {"contact.postal_code": 0.50}
        rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_MIDSCORE_ADDRESS_TEXT)}
        check(
            "override mechanism: lowering the threshold reproduces a finding",
            "contact.postal_code" in rules,
            ",".join(sorted(rules)),
        )
    finally:
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = original


def postal_code_letter_gate_case(unavailable: str) -> None:
    """Item-3 fix round: the false-positive and true-positive score
    distributions for contact.postal_code overlap (CLAUDE.md's "Known
    weaknesses"), so no threshold on this entity alone separates them
    cleanly. PII_POSTAL_HIGH_SCORING_BARE_NUMBER ("43044", 0.7189) is a
    directly measured case above the shipped 0.70 threshold that a threshold
    fix cannot touch.

    The mechanism: a contact.postal_code finding only counts when the
    scanned text contains at least one letter, because a real postal code
    always travels with an address, city, or label, and a bare extracted
    number does not. This is a positive control in the CLAUDE.md sense: the
    threshold-override case below proves the letter gate is a real,
    independent filter and not just the 0.70 threshold happening to already
    exclude this case, by lowering the threshold far enough that it
    definitely would not exclude it, and confirming the gate still does.
    """
    print("\nPII detector: contact.postal_code requires a letter in the scanned text (item-3 fix)")
    if unavailable:
        for name in (
            "high-scoring bare number: not blocked as a postal code",
            "real postal code: still blocked in an address",
            "letter gate is independent of the threshold: still silent at a near-zero threshold",
        ):
            skip(name, unavailable)
        return

    rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_HIGH_SCORING_BARE_NUMBER)}
    check(
        "high-scoring bare number: not blocked as a postal code",
        "contact.postal_code" not in rules,
        ",".join(sorted(rules)) or "none",
    )

    rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_TRUE_POSITIVE_TEXT)}
    check(
        "real postal code: still blocked in an address",
        "contact.postal_code" in rules,
        ",".join(sorted(rules)) or "none",
    )

    original = dict(airlock.PII_DETECTOR_ENTITY_THRESHOLDS)
    try:
        # 0.01 is far below 0.7189: if the letter gate were not independent
        # of the threshold, this override alone would let the bare number
        # through. It must not.
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = {"contact.postal_code": 0.01}
        rules = {f["rule"] for f in airlock.scan_pii_model(PII_POSTAL_HIGH_SCORING_BARE_NUMBER)}
        check(
            "letter gate is independent of the threshold: still silent at a near-zero threshold",
            "contact.postal_code" not in rules,
            ",".join(sorted(rules)) or "none",
        )
    finally:
        airlock.PII_DETECTOR_ENTITY_THRESHOLDS = original


def chunking_cases(unavailable: str) -> None:
    print("\nChunking: a value past a single window is still found, not truncated away")
    if unavailable:
        for name in (
            "PII detector: an SSN past a single window is still found",
            "policy linter: a disclosure past a single window is still found",
        ):
            skip(name, unavailable)
        return

    rules = {f["rule"] for f in airlock.scan_pii_model(PII_OVERFLOW_TEXT)}
    check(
        "PII detector: an SSN past a single window is still found",
        any(r.split(".")[0] == "identity" for r in rules),
        ",".join(sorted(rules)) or "no findings, truncated away",
    )

    rules = {f["rule"] for f in airlock.scan_policy(POLICY_OVERFLOW_TEXT)}
    check(
        "policy linter: a disclosure past a single window is still found",
        "rule0" in rules,
        ",".join(sorted(rules)) or "no findings, truncated away",
    )


def prefix_derivation_case() -> None:
    """Minor fix: _load_policy_linter must not cache a prefix string baked
    from CONTEXTUAL_RULES at first load. scan_policy's pool construction
    already reads CONTEXTUAL_RULES live on every call; a prefix frozen at
    load time would drift from that the moment CONTEXTUAL_RULES changes,
    misaligning the offsets with no error. _policy_prefix() must be the one
    place both read, computed fresh, so there is nothing to cache and nothing
    that can go stale. No model needed: this is a pure string check.
    """
    print("\nMinor: the rule prefix is derived fresh, never a stale cached copy")

    original = list(airlock.CONTEXTUAL_RULES)
    try:
        first = airlock._policy_prefix()
        check(
            "prefix reflects the current CONTEXTUAL_RULES",
            "medical condition" in first,
            first[:60],
        )

        airlock.CONTEXTUAL_RULES = ["Flag disclosure of a favourite colour."]
        second = airlock._policy_prefix()
        check(
            "prefix rebuilds immediately after CONTEXTUAL_RULES changes",
            "favourite colour" in second and "medical condition" not in second,
            second[:60],
        )
    finally:
        airlock.CONTEXTUAL_RULES = original


def fail_closed_case() -> None:
    print("\nFail closed: a loader failure raises, never returns empty")

    original_model = airlock.PII_DETECTOR_MODEL
    airlock.PII_DETECTOR_MODEL = "LiquidAI/does-not-exist-airlock-test-xyz"
    airlock._load_pii_detector.cache_clear()
    try:
        raised = None
        try:
            airlock.scan_pii_model("anything")
        except airlock.GuardModelUnavailable as exc:
            raised = exc
        check(
            "a loader failure raises GuardModelUnavailable, not an empty list",
            raised is not None,
            str(raised) if raised else "no exception raised",
        )
    finally:
        airlock.PII_DETECTOR_MODEL = original_model
        airlock._load_pii_detector.cache_clear()


# --------------------------------------------------------------------------
# evaluate() rewired onto secrets -> pii-patterns -> pii-detector ->
# policy-linter, and the CLI/session/server surface that configures it.
# --------------------------------------------------------------------------

CRED_ALPHABET = string.ascii_letters + string.digits


def rewired_evaluate_cases(unavailable: str) -> None:
    """The four layers in order, each catching what the ones before it must
    not. A generated credential (never a hand-picked literal, per CLAUDE.md)
    for the secrets case; ACQUISITION_TEXT and CLEAN_POLICY_TEXT for the two
    model-backed cases below, chosen and verified (see task-2-report.md) to
    carry no secret, no structured identifier, and no PII-detector entity,
    so they actually reach the policy-linter rather than being caught earlier.
    """
    print("\nevaluate(): the rewired four-layer stack")

    credential = "sk-" + "".join(secrets.choice(CRED_ALPHABET) for _ in range(24))
    verdict = airlock.evaluate(f"here is a key: {credential}")
    check(
        "a credential still blocks via secrets",
        verdict.decision == "revise" and verdict.layers_run == ["secrets"],
        f"{verdict.decision} via {verdict.layers_run}",
    )

    verdict = airlock.evaluate(SSN_TEXT)
    check(
        "a bare SSN blocks via pii-patterns before any model layer",
        verdict.decision == "revise"
        and "pii-patterns" in verdict.layers_run
        and "pii-detector" not in verdict.layers_run
        and "policy-linter" not in verdict.layers_run,
        f"{verdict.decision} via {verdict.layers_run}",
    )

    if unavailable:
        skip("a contextual disclosure with no identifier blocks via policy-linter", unavailable)
        skip("ordinary file description approves, all four layers ran", unavailable)
        return

    verdict = airlock.evaluate(ACQUISITION_TEXT)
    check(
        "a contextual disclosure with no identifier blocks via policy-linter",
        verdict.decision == "revise" and "policy-linter" in verdict.layers_run,
        f"{verdict.decision} via {verdict.layers_run}",
    )

    verdict = airlock.evaluate(CLEAN_POLICY_TEXT)
    check(
        "ordinary file description approves, all four layers ran",
        verdict.decision == "approve"
        and verdict.layers_run
        == ["secrets", "pii-patterns", "pii-detector", "policy-linter"],
        f"{verdict.decision} via {verdict.layers_run}",
    )


def evaluate_fail_closed_cases() -> None:
    """The two fail-closed controls task-2-brief.md calls the most important
    tests in this task. Both force a load failure the same way
    fail_closed_case above does, by pointing a model id at a repo that does
    not exist, so both run unconditionally and need no real model download.
    Asserted as decision == "block" explicitly, not merely "not approve", so
    a future refactor that turns the failure into an uncaught exception
    cannot silently satisfy this check.
    """
    print("\nevaluate(): the two fail-closed controls")

    original_pii_model = airlock.PII_DETECTOR_MODEL
    airlock.PII_DETECTOR_MODEL = "LiquidAI/does-not-exist-airlock-test-xyz"
    airlock._load_pii_detector.cache_clear()
    try:
        verdict = airlock.evaluate(CLEAN_PII_TEXT)
        check(
            "detector unavailable blocks",
            verdict.decision == "block",
            f"{verdict.decision}: {'; '.join(verdict.concerns)}",
        )
    finally:
        airlock.PII_DETECTOR_MODEL = original_pii_model
        airlock._load_pii_detector.cache_clear()

    # The detector must succeed and find nothing for evaluate() to reach the
    # linter at all, so it is stubbed clean here rather than requiring the
    # real detector model just to get past it.
    original_scan_pii_model = airlock.scan_pii_model
    original_linter_model = airlock.POLICY_LINTER_MODEL
    airlock.scan_pii_model = lambda text: []
    airlock.POLICY_LINTER_MODEL = "LiquidAI/does-not-exist-airlock-test-xyz"
    airlock._load_policy_linter.cache_clear()
    try:
        verdict = airlock.evaluate(CLEAN_POLICY_TEXT)
        check(
            "linter unavailable blocks",
            verdict.decision == "block",
            f"{verdict.decision}: {'; '.join(verdict.concerns)}",
        )
    finally:
        airlock.scan_pii_model = original_scan_pii_model
        airlock.POLICY_LINTER_MODEL = original_linter_model
        airlock._load_policy_linter.cache_clear()


def evaluate_default_threshold_case() -> None:
    """A bare evaluate(text) call must read POLICY_LINTER_THRESHOLD at call
    time, not at import time.

    `def evaluate(..., linter_threshold: float = POLICY_LINTER_THRESHOLD)`
    binds the default when airlock.py is first imported, so a later change to
    the module global (as evaluate_fail_closed_cases above and eval/'s
    harness both make) would be invisible to any caller that omits the
    argument. scan_pii_model and scan_policy are stubbed so this is a pure
    call-boundary check: no real model load, runs unconditionally.
    """
    print("\nevaluate(): linter_threshold default reads the current global, not the import-time one")

    original_scan_pii_model = airlock.scan_pii_model
    original_scan_policy = airlock.scan_policy
    original_threshold = airlock.POLICY_LINTER_THRESHOLD
    seen: dict[str, object] = {}
    airlock.scan_pii_model = lambda text: []
    airlock.scan_policy = lambda text, threshold=None: (seen.__setitem__("threshold", threshold), [])[1]
    # A value nothing in this codebase would pick by coincidence, so the
    # assertion cannot pass by accident.
    airlock.POLICY_LINTER_THRESHOLD = 0.13579
    try:
        airlock.evaluate(CLEAN_POLICY_TEXT)
        check(
            "bare call passes the threshold current at call time",
            seen.get("threshold") == 0.13579,
            f"scan_policy received {seen.get('threshold')!r}",
        )
    finally:
        airlock.scan_pii_model = original_scan_pii_model
        airlock.scan_policy = original_scan_policy
        airlock.POLICY_LINTER_THRESHOLD = original_threshold


def cli_parser_cases() -> None:
    """Task 3 section of the plan: the removed flags, --linter-threshold
    (wired through, and range-validated per the final fix wave), and what
    gets printed for a client to paste. Parser-level only, no model or
    Ollama needed, so none of these may skip.
    """
    print("\nCLI: removed flags rejected, --linter-threshold wired through and range-checked")

    parser = airlock.build_parser()
    for flag, value in (
        ("--no-presidio", None),
        ("--guard-model", "x"),
        ("--guardian-model", "x"),
        ("--spacy-model", "x"),
    ):
        argv = [flag] if value is None else [flag, value]
        raised = False
        with contextlib.redirect_stderr(sys.stdout):  # argparse writes usage to stderr on error
            try:
                parser.parse_args(argv)
            except SystemExit:
                raised = True
        check(f"removed flag rejected: {flag}", raised)

    args = parser.parse_args(["--linter-threshold", "0.42"])
    check(
        "--linter-threshold parses",
        getattr(args, "linter_threshold", None) == 0.42,
        str(getattr(args, "linter_threshold", None)),
    )

    session = airlock.Session(
        session_id="cli-test",
        objective="x",
        sandbox=airlock.Sandbox(root=HERE.parent),
        worker_model="stub",
        linter_threshold=args.linter_threshold,
    )
    check(
        "--linter-threshold reaches the session",
        session.linter_threshold == 0.42,
        str(session.linter_threshold),
    )

    # Fix wave: the config screen already rejects a threshold outside
    # 0.0-1.0 (_config_loop's "linter threshold" branch), but the CLI flag
    # had no equivalent check and applied whatever float() parsed. A
    # threshold above 1.0 makes every rule without its own
    # POLICY_LINTER_RULE_THRESHOLDS override unreachable, since sigmoid
    # output never exceeds 1.0, so this must be rejected at the parser, not
    # silently accepted.
    for bad in ("2", "-0.1", "1.0001", "not-a-number"):
        raised = False
        with contextlib.redirect_stderr(sys.stdout):
            try:
                parser.parse_args(["--linter-threshold", bad])
            except SystemExit:
                raised = True
        check(f"--linter-threshold rejects out-of-range/non-numeric: {bad}", raised)

    for edge in ("0.0", "1.0"):
        args_edge = parser.parse_args(["--linter-threshold", edge])
        check(
            f"--linter-threshold accepts boundary value: {edge}",
            args_edge.linter_threshold == float(edge),
            str(args_edge.linter_threshold),
        )

    stale = {"guard_model", "use_presidio", "spacy_model", "guardian_model"}
    present = stale & set(airlock.CLI_DEFAULTS)
    check("CLI_DEFAULTS has no stale keys", not present, ",".join(sorted(present)) or "clean")

    mcp_args = argparse.Namespace(root=HERE.parent, model=airlock.DEFAULT_MODEL)
    with airlock.console.capture() as capture:
        airlock.render_mcp_help(mcp_args)
    printed = capture.get()
    check(
        "printed MCP config contains no removed flag",
        "--guard-model" not in printed,
        "found --guard-model in output" if "--guard-model" in printed else "clean",
    )


def chunk_text_step_guard_case() -> None:
    """The one-line guard the re-reviewer flagged (fix round 1): _chunk_text
    never asserted step > 0. Current constants (500-200, 1800-400) are safe,
    but a future edit setting overlap >= window would make pos stop
    advancing (overlap == window) or walk backward (overlap > window),
    hanging or looping forever rather than raising. No model needed.
    """
    print("\n_chunk_text: overlap >= window is refused, not a silent hang")

    raised = False
    try:
        airlock._chunk_text("x" * 10, window=5, overlap=5)
    except AssertionError:
        raised = True
    check("overlap == window raises, does not hang", raised)

    raised = False
    try:
        airlock._chunk_text("x" * 10, window=5, overlap=8)
    except AssertionError:
        raised = True
    check("overlap > window raises, does not hang", raised)


def dense_non_ascii_truncation_case(unavailable: str) -> None:
    """Carried finding from Task 1's re-review: truncation can still fire
    INSIDE a single chunk on dense non-ASCII text, reproducing the original
    fail-open at window granularity. See the fixture comments above
    DENSE_NON_ASCII_PII_TEXT/DENSE_NON_ASCII_POLICY_TEXT for the measurement
    behind these two texts. Confirmed RED against the pre-fix code (fix
    round 1, git-stashed and re-run): both returned [] silently. The fix is
    _scan_pii_region/_scan_policy_region asking the tokenizer directly
    whether a chunk overflows, rather than trusting PII_CHUNK_CHARS/
    POLICY_CHUNK_CHARS' char ratio, and bisecting until each piece fits.
    """
    print("\nDense non-ASCII text: truncation inside one window is caught, not silent")
    if unavailable:
        skip("PII detector: a value past a single dense-CJK window is still found", unavailable)
        skip("policy linter: a disclosure past a single dense-CJK window is still found", unavailable)
        return

    rules = {f["rule"] for f in airlock.scan_pii_model(DENSE_NON_ASCII_PII_TEXT)}
    check(
        "PII detector: a value past a single dense-CJK window is still found",
        any(r.split(".")[0] == "identity" for r in rules),
        ",".join(sorted(rules)) or "no findings, truncated away",
    )

    rules = {f["rule"] for f in airlock.scan_policy(DENSE_NON_ASCII_POLICY_TEXT)}
    check(
        "policy linter: a disclosure past a single dense-CJK window is still found",
        "rule0" in rules,
        ",".join(sorted(rules)) or "no findings, truncated away",
    )


def worker_step_exhaustion_case() -> None:
    """Fix round 2 defect: run_worker's step-exhaustion path used to set a
    fixed diagnostic string ("I could not finish...") as `draft` and fall
    through to the guard, one line above a check that already blocks an
    explicit empty answer. The guard correctly approves that string, since
    it is harmless prose, and the caller then reads status=="approved" for a
    run in which the worker never produced an answer at all: the guard doing
    its job got conflated with the operation having succeeded. Pinned
    directly against run_worker here rather than depending on
    tests/test_server.py's stub arrangement (that suite's version of this
    check depended on an accidental coupling: the exhausted stub also fed
    worker-shaped output to the guard's own call, which failed to parse as a
    verdict and blocked for the wrong reason). No model needed: with the fix,
    this path returns before evaluate_session is ever called, which this
    case also demonstrates by never installing a real guard.
    """
    print("\nrun_worker: step-exhaustion is blocked, not approved as harmless prose")

    session = airlock.Session(
        session_id="exhaustion-test",
        objective="x",
        sandbox=airlock.Sandbox(root=HERE.parent, allow_writes=False),
        worker_model="stub-worker",
    )
    # Always a valid, schema-compliant action that never sets draft, so the
    # loop runs out MAX_WORKER_STEPS times without ever breaking.
    original = airlock.ollama_chat
    airlock.ollama_chat = lambda model, prompt, schema=None: {"action": "list", "path": "."}
    try:
        result = airlock.run_worker(session, "what is here?")
    finally:
        airlock.ollama_chat = original

    check(
        "step exhaustion is reported blocked, not approved",
        result.get("status") == "blocked",
        str(result.get("status")),
    )
    check(
        "step exhaustion carries no message content",
        not result.get("message"),
        repr(result.get("message")),
    )
    check(
        "step exhaustion names the cause, distinct from the empty-answer path",
        any("step" in c.lower() for c in result.get("guard_concerns", [])),
        ",".join(result.get("guard_concerns", [])) or "no concerns",
    )


def jobs_empty_answer_case() -> None:
    """Fix round 3: the same fail-open worker_step_exhaustion_case pins for
    run_worker, found in run_jobs and reported (not fixed) in fix round 2,
    now closed here per the coordinator's explicit instruction. An unshaped
    extraction job whose worker answer is an empty string used to be handed
    to the guard anyway; evaluate("") approves, since an empty string trips
    none of the four layers, so the job was recorded status=="ok" with an
    empty value, the same status a genuine extraction gets. The fix matches
    the vocabulary the fill-mode branch a few lines above already uses for
    exactly this case (empty or "NOT PRESENT"): not_found, not ok. No model
    needed: with the fix, this path returns before evaluate_session is ever
    called, which this case also demonstrates by never installing a real
    guard.
    """
    print("\nrun_jobs: an empty extraction answer is not_found, never a guarded ok")

    tmp = Path(tempfile.mkdtemp(prefix="jobs-empty-answer-"))
    (tmp / "doc0.txt").write_text("irrelevant content\n")
    session = airlock.Session(
        session_id="jobs-empty",
        objective="x",
        sandbox=airlock.Sandbox(root=tmp, allow_writes=False),
        worker_model="stub-worker",
    )
    original = airlock.ollama_chat
    airlock.ollama_chat = lambda model, prompt, schema=None: ""
    try:
        result = airlock.run_jobs(session, [{"document": 0, "extract": "the value in box 1"}])
    finally:
        airlock.ollama_chat = original

    results = result.get("results") or []
    job = results[0] if results else {}
    check(
        "an empty answer is reported not_found, not ok",
        job.get("status") == "not_found",
        str(job),
    )
    check(
        "an empty answer never carries a released value",
        "value" not in job,
        str(job),
    )


# --------------------------------------------------------------------------
# Task 4: doctor, banner and the config screen, made correct rather than
# merely non-crashing. See task-4-brief.md.
# --------------------------------------------------------------------------


def check_function_formatting_case() -> None:
    """check() renders through Text.assemble, which does NOT parse rich
    markup (CLAUDE.md's own documented trap for this file: a tag in a check
    detail prints literally). A detail string containing bracket text has to
    survive unprocessed, or a future switch to console.print-style rendering
    would silently start eating operator-facing detail text that happens to
    look like a tag. No model or Ollama needed: check() is pure.
    """
    print("\ncheck(): formatting is pure, and does not parse markup in detail text")

    with airlock.console.capture() as capture:
        airlock.check("probe", True, "note [with] brackets")
    printed = capture.get()
    check("check() reports the label and an ok mark", "probe" in printed and "ok" in printed, printed.strip())
    check(
        "check() detail text is literal, not parsed as markup",
        "[with]" in printed,
        printed.strip(),
    )


def banner_and_config_screen_case() -> None:
    """banner() and the config screen against a REAL Session built the new
    way (worker_model + linter_threshold; no guard_model, guardian_model or
    use_presidio). A stale attribute reference is the failure mode this
    guards against, per the brief's own method note, and only a real
    construction and a real render catches it. Also exercises the config
    screen's new linter-threshold row end to end (select it, enter a value,
    confirm the Session field actually changes), since that is the one
    control this task adds rather than merely un-breaks.
    """
    print("\nbanner() and the config screen: real Session, real render, editable threshold")

    tmp = Path(tempfile.mkdtemp(prefix="banner-config-smoke-"))
    (tmp / "note.txt").write_text("hello\n")
    session = airlock.Session(
        session_id="banner-config-test",
        objective="x",
        sandbox=airlock.Sandbox(root=tmp, allow_writes=False),
        worker_model="stub-worker",
        linter_threshold=0.42,
    )

    with airlock.console.capture() as capture:
        airlock.banner(session)
    printed = capture.get()
    check("banner runs against a Session with no guard_model field", "stub-worker" in printed, printed[:200])
    check(
        "banner describes the real four-layer guard",
        all(name in printed for name in ("secrets", "pii-patterns", "pii-detector", "policy-linter")),
        printed[:200],
    )

    args = argparse.Namespace(**{**airlock.CLI_DEFAULTS, "root": tmp, "model": "stub-worker"})
    notices: list[str] = []
    # choose()'s non-tty fallback reads one line per prompt via Prompt.ask;
    # there is no contextlib.redirect_stdin (that only exists for
    # stdout/stderr), so sys.stdin is swapped by hand. "5" selects the fifth
    # settings row (linter threshold, once worker/writes/trace/objective
    # precede it), "0.55" is the new value, the trailing blank line exits.
    original_stdin = sys.stdin
    sys.stdin = io.StringIO("5\n0.55\n\n")
    try:
        airlock._config_loop(session, args, notices)
    finally:
        sys.stdin = original_stdin

    check(
        "config screen's linter-threshold row changes the real Session field",
        session.linter_threshold == 0.55,
        str(session.linter_threshold),
    )
    check(
        "config screen records a notice for the change",
        any("linter threshold" in n for n in notices),
        "; ".join(notices) or "no notices",
    )


def cmd_doctor_encoder_checks_case(unavailable: str) -> None:
    """cmd_doctor must check what now actually matters for the guard: torch/
    transformers importability, both encoders loadable, the selected device,
    and a real verdict from each on a fixed probe (previously it checked an
    Ollama-hosted guard model tag, meaningless now the guard is two local
    encoders). Needs both encoders AND a reachable Ollama with the worker
    model installed, since cmd_doctor also runs the pre-existing worker
    checks; skipped with a reason rather than failing when either is
    missing, matching this file's own convention for model-gated cases.
    """
    print("\ncmd_doctor: checks the two real encoders, not a vestigial Ollama guard tag")

    try:
        airlock.ollama_models()
        ollama_unavailable = ""
    except RuntimeError as exc:
        ollama_unavailable = str(exc)
    reason = unavailable or ollama_unavailable
    labels = (
        "torch/transformers importable",
        "device",
        "PII detector loadable",
        "policy linter loadable",
        "PII detector probe",
        "policy linter probe",
    )
    if reason:
        skip("cmd_doctor returns 0 with the real worker and encoders available", reason)
        for label in labels:
            skip(f"cmd_doctor prints '{label}'", reason)
        return

    tmp = Path(tempfile.mkdtemp(prefix="doctor-smoke-"))
    (tmp / "note.txt").write_text("hello\n")
    args = argparse.Namespace(**{**airlock.CLI_DEFAULTS, "root": tmp})
    with airlock.console.capture() as capture:
        code = airlock.cmd_doctor(args)
    printed = capture.get()
    check("cmd_doctor returns 0 with the real worker and encoders available", code == 0, str(code))
    for label in labels:
        check(f"cmd_doctor prints '{label}'", label in printed, "missing" if label not in printed else "present")


def main() -> int:
    print(f"airlock: {AIRLOCK}")

    def run(name: str, fn, *args) -> None:
        try:
            fn(*args)
        except BaseException as exc:  # noqa: BLE001 - report, never abort
            FAIL.append(f"{name} crashed")
            print(f"  FAIL  {name} crashed  [{type(exc).__name__}: {str(exc)[:200]}]")

    unavailable = models_available()
    if unavailable:
        print(f"\nmodels unavailable, skipping model-dependent cases: {unavailable}")

    run("pii_detector_cases", pii_detector_cases, unavailable)
    run("containment_positive_control_case", containment_positive_control_case)
    run("policy_linter_cases", policy_linter_cases, unavailable)
    run("rule5_bare_words_case", rule5_bare_words_case, unavailable)
    run("pii_entity_threshold_case", pii_entity_threshold_case, unavailable)
    run("postal_code_letter_gate_case", postal_code_letter_gate_case, unavailable)
    run("chunking_cases", chunking_cases, unavailable)
    run("prefix_derivation_case", prefix_derivation_case)
    run("fail_closed_case", fail_closed_case)
    run("rewired_evaluate_cases", rewired_evaluate_cases, unavailable)
    run("evaluate_fail_closed_cases", evaluate_fail_closed_cases)
    run("evaluate_default_threshold_case", evaluate_default_threshold_case)
    run("cli_parser_cases", cli_parser_cases)
    run("chunk_text_step_guard_case", chunk_text_step_guard_case)
    run("dense_non_ascii_truncation_case", dense_non_ascii_truncation_case, unavailable)
    run("worker_step_exhaustion_case", worker_step_exhaustion_case)
    run("jobs_empty_answer_case", jobs_empty_answer_case)
    run("check_function_formatting_case", check_function_formatting_case)
    run("banner_and_config_screen_case", banner_and_config_screen_case)
    run("cmd_doctor_encoder_checks_case", cmd_doctor_encoder_checks_case, unavailable)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    # Per CLAUDE.md, a suite that silently collects fewer checks reads like
    # one that passed.
    if total < 73:
        print(f"\nWARNING: only {total} checks ran. Expected at least 73.")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    # Skips are reported, not failed, per CLAUDE.md. But a run where every
    # model-backed case skipped has verified nothing about either guard, and
    # that must not read like a quiet pass in a log a human is skimming.
    if unavailable:
        print(
            "\n" + "!" * 70
            + "\nNO MODEL-BACKED CHECK RAN. Every PII/policy-linter case was "
            "skipped.\nThis run verified nothing about either guard's actual "
            f"behaviour.\nReason: {unavailable}\n" + "!" * 70
        )
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
