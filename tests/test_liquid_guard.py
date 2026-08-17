#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "torch>=2.2",
#     "transformers>=4.57",
#     "rich>=13.7",
# ]
# ///
"""Tests for the two encoder guard layers. See task-1-brief.md.

    uv run --script tests/test_liquid_guard.py

torch and transformers are declared here, not in airlock.py's PEP 723 block
(that is Task 5's job); this file gets its own copy the way eval/ scripts do.

Every case needs both LiquidAI encoders loadable from the local Hugging Face
cache. If a real load fails, every case that depends on it is SKIPped with the
reason, per CLAUDE.md: a suite that silently collects fewer checks reads like
one that passed.
"""

from __future__ import annotations

import importlib.util
import sys
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
# rule1 (financial hardship) scores 0.946 here: below the PLAN's 0.98
# override, above a 0.50 threshold. Picked by direct measurement against the
# real model, not guessed.
BORDERLINE_FINANCIAL_TEXT = "Money has been a bit tight lately with all the bills piling up."

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
    run("chunking_cases", chunking_cases, unavailable)
    run("prefix_derivation_case", prefix_derivation_case)
    run("fail_closed_case", fail_closed_case)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 15:
        print(f"\nWARNING: only {total} checks ran. Expected at least 15.")
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
