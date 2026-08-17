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


def policy_linter_cases(unavailable: str) -> None:
    print("\nPolicy linter: contextual rules above threshold")
    if unavailable:
        for name in (
            "linter flags a medical disclosure",
            "linter flags an unannounced acquisition",
            "linter is clean on a benign file description",
            "per-rule threshold override is honoured",
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
    run("policy_linter_cases", policy_linter_cases, unavailable)
    run("fail_closed_case", fail_closed_case)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 9:
        print(f"\nWARNING: only {total} checks ran. Expected at least 9.")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
