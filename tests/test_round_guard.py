#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "rich>=13.7",
# ]
# ///
"""Tests for the round-reassembly guard. See PLAN-round-reassembly.md.

    uv run --script tests/test_round_guard.py

Task 1: catch a space-separated EIN by label, not by widening `us_ein`'s
shape. `us_ein` stays hyphen-only; a new `labelled_ein` context rule catches
the space form only when a label word is nearby. See task-1-brief.md for why
widening `us_ein` itself was rejected.
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


def ein_rules(text: str) -> set[str]:
    """Every rule name, across both scanners, whose name mentions an EIN.

    Deliberately not "which rule matched": the intact hyphen form is expected
    to match via `us_ein` in PII_PATTERNS, the labelled space forms via the
    new `labelled_ein` context rule in CONTEXT_SECRET_PATTERNS, and the test
    should not encode which layer catches which form.
    """
    findings = airlock.scan_pii_patterns(text) + airlock.scan_secrets(text)
    return {f["rule"] for f in findings if "ein" in f["rule"]}


def task1_labelled_ein() -> None:
    print("\nTask 1: space-separated EIN caught by label, not by widened shape")

    rules = ein_rules("EIN 31 7729104")
    check("labelled space form matches", bool(rules), ",".join(sorted(rules)) or "no match")

    rules = ein_rules("Employer identification number: 31 7729104")
    check(
        "labelled space form, longer label, matches",
        bool(rules),
        ",".join(sorted(rules)) or "no match",
    )

    rules = ein_rules("EIN 31-7729104")
    check("intact hyphen form still matches", bool(rules), ",".join(sorted(rules)) or "no match")

    # Regression guard for the whole point of this task: fails if anyone
    # later widens us_ein's shape instead of gating the space form by label.
    rules = ein_rules("we shipped 12 3456789 units")
    check(
        "unlabelled pair does not match",
        not rules,
        ",".join(sorted(rules)) or "no match",
    )

    # Constrains the {0,24} window: fails if it is ever loosened to [^\n]*.
    rules = ein_rules("EIN" + " " * 40 + "31 7729104")
    check(
        "label too far from the digits does not match",
        not rules,
        ",".join(sorted(rules)) or "no match",
    )


def main() -> int:
    print(f"airlock: {AIRLOCK}")

    def run(name: str, fn: object) -> None:
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - report, never abort
            FAIL.append(f"{name} crashed")
            print(f"  FAIL  {name} crashed  [{type(exc).__name__}: {str(exc)[:120]}]")

    run("task1_labelled_ein", task1_labelled_ein)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 5:
        print(f"\nWARNING: only {total} checks ran. Expected at least 5.")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
