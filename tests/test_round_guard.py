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

Task 2: source-anchored identifier reassembly detection. `reassembles_identifier`
catches a protected value split across job results even when benign job
results sit between the fragments, by matching against identifiers actually
present in the workspace rather than a shape. See task-2-brief.md.
"""

from __future__ import annotations

import importlib.util
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


def task2_reassembly() -> None:
    print("\nTask 2: source-anchored identifier reassembly detection")

    # Matches PLAN-round-reassembly.md's own illustrative example. Not a real
    # person's identifier; an SSN carries no vendor shape for secret scanning
    # to trip on, unlike the credential prefixes fake_credential exists for.
    ssn_sources = {airlock.normalise_identifier("912-84-7731")}

    check(
        "adjacent fragments caught",
        airlock.reassembles_identifier(["912", "84", "7731"], ssn_sources),
    )
    check(
        "single job released it, not this check's business",
        not airlock.reassembles_identifier(["912-84-7731"], ssn_sources),
    )
    check(
        "one job holds it among others",
        not airlock.reassembles_identifier(["notes", "912-84-7731", "more"], ssn_sources),
    )
    check(
        "value absent from workspace",
        not airlock.reassembles_identifier(["555", "12", "3456"], ssn_sources),
    )
    check(
        "empty round",
        not airlock.reassembles_identifier([], ssn_sources),
    )
    check(
        "short identifiers ignored",
        not airlock.reassembles_identifier(["12", "34"], {"1234"}),
    )
    check(
        "normalisation is separator-blind",
        airlock.reassembles_identifier(["912 84", "7731"], ssn_sources),
    )
    check(
        "scattered fragments caught",
        airlock.reassembles_identifier(
            ["912", "notes", "84", "more", "7731"], ssn_sources
        ),
    )

    tmp = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test-"))
    (tmp / "notes.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    sandbox = airlock.Sandbox(root=tmp, allow_writes=False)
    sources = airlock.source_identifiers(sandbox)

    check(
        "source_identifiers finds an SSN in a file",
        "912847731" in sources,
        ",".join(sorted(sources)) or "empty",
    )
    check(
        "source_identifiers returns normalised, never masked",
        not any("*" in s for s in sources),
        ",".join(sorted(sources)),
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
    run("task2_reassembly", task2_reassembly)

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
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
