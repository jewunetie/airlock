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

Task 3: wires the Task 2 check into `run_jobs`, driving it end to end with a
stubbed `ollama_chat` so no local model is required. See task-3-brief.md.
"""

from __future__ import annotations

import importlib.util
import json
import os
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
    check(
        "fragments padded with numeric job answers still caught",
        airlock.reassembles_identifier(
            ["912", "500", "84", "700", "7731"], ssn_sources
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

    # Positive control against false blocking (CLAUDE.md: assertions about
    # absence need one). Twelve plausible numeric answers, none of them a
    # fragment of the SSN: each carrier sandwiches one of the SSN's digits
    # between two unrelated '5's, so no whole job value ever places two of
    # the SSN's digits adjacent to each other, and no subset of whole values
    # concatenated can ever reproduce the SSN contiguously. The rejected
    # subsequence design does not honour that distinction (it drops the
    # sandwich digits and reads the target straight through), which is why
    # it blocked 38.0% of legitimate rounds like this one in the plan
    # owner's measurement.
    legitimate_round = [f"5{d}5" for d in sorted(ssn_sources)[0]] + ["203", "410", "999"]
    check(
        "legitimate round of twelve numeric answers is not blocked",
        not airlock.reassembles_identifier(legitimate_round, ssn_sources),
    )

    # Defensive bound: _subset_concatenations is 2**len(values). Today only
    # run_jobs enforces MAX_JOBS_PER_ROUND, and that enforcement is not wired
    # to this function (that is Task 3), so reassembles_identifier must not
    # trust its caller. Empty sources is the case that would otherwise
    # trivially return False, so this proves the bound fires ahead of the
    # normal candidate-filtering path rather than coinciding with it.
    oversized_round = ["x"] * (airlock.MAX_JOBS_PER_ROUND + 1)
    check(
        "more than MAX_JOBS_PER_ROUND values blocks even with no sources",
        airlock.reassembles_identifier(oversized_round, set()),
    )


def task3_wiring() -> None:
    print("\nTask 3: wiring the source-anchored check into run_jobs")

    def stub_ollama(answers):
        """Serves both callers run_jobs drives per round: the worker (unshaped
        here, since these jobs set no "as") and the guard's model layer
        (GUARD_SCHEMA). The guard always approves, so only the deterministic
        scanners and the new source-anchored check can block a round below.
        """
        it = iter(answers)

        def stub(model, prompt, schema=None):
            if schema is airlock.GUARD_SCHEMA:
                return {"verdict": "approve", "concerns": [], "instruction": ""}
            return next(it)

        return stub

    def run_with_stub(session, jobs, answers):
        real = airlock.ollama_chat
        try:
            airlock.ollama_chat = stub_ollama(answers)
            return airlock.run_jobs(session, jobs)
        finally:
            airlock.ollama_chat = real

    def session_over(root, allow_writes=False):
        # use_presidio=False and guardian_model=None per task-3-brief.md, so
        # the stubbed model layer is the only model layer in play; the
        # deterministic scanners are not stubbed and still run for real.
        return airlock.Session(
            session_id="t3", objective="x",
            sandbox=airlock.Sandbox(root=root, allow_writes=allow_writes),
            worker_model="stub-worker", guard_model="stub-guard",
            use_presidio=False, guardian_model=None,
        )

    # Scattered fragments: three job results carry the SSN's groups, with
    # benign job results between them. This is the arrangement the plan's own
    # measurement shows the pre-existing evaluate_session(combined) check
    # misses (PLAN-round-reassembly.md's placement table: 0.00 detection at
    # 9 filler jobs).
    tmp = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test3-"))
    (tmp / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    session = session_over(tmp)
    jobs = [{"document": 0, "extract": f"question {i}"} for i in range(5)]
    answers = ["912", "some notes about the weather", "84", "another line of text", "7731"]
    result = run_with_stub(session, jobs, answers)
    payload = json.dumps(result)
    check(
        "scattered SSN fragments: round is blocked",
        result.get("status") == "blocked",
        str(result.get("status")),
    )
    check(
        "scattered SSN fragments: no fragment reaches the serialised payload",
        not any(fragment in payload for fragment in ("912", "84", "7731")),
    )

    # Workspace unreadable during the check: one document the job would read,
    # and a second it never touches but source_identifiers must still scan
    # (it walks every entry, not just the ones jobs referenced). Made
    # unreadable after writing: list_dir needs no read permission on the file
    # itself, only read_text does, so listing still succeeds. source_identifiers
    # is now snapshotted before the job loop runs at all (see the mid-round
    # write case below for why), so this failure surfaces before the one job
    # here ever executes, not "during" round-level scoring as the name might
    # suggest; the round is still blocked either way, which is what matters.
    tmp2 = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test3-"))
    (tmp2 / "doc0.txt").write_text("Just a benign note about scheduling.\n")
    secret_path = tmp2 / "doc1_secret.txt"
    secret_path.write_text("irrelevant content\n")
    os.chmod(secret_path, 0o000)
    try:
        session = session_over(tmp2)
        jobs = [{"document": 0, "extract": "what does the note say"}]
        answers = ["A benign one-line answer."]
        result = run_with_stub(session, jobs, answers)
        check(
            "workspace unreadable during the check: round is blocked, not approved",
            result.get("status") == "blocked",
            str(result.get("status")),
        )
    finally:
        os.chmod(secret_path, 0o644)

    # Mid-round write cannot erase the evidence. Reachable only with
    # allow_writes=True: a job can fill_field over the very document a
    # fragment came from, later in the same round. The identifiers present
    # when the round BEGAN are what this must check against, since those are
    # exactly what the round's jobs could have extracted from; scanning the
    # workspace only after the loop would find the field already overwritten
    # and see nothing to match the earlier fragments against.
    tmp5 = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test3-"))
    (tmp5 / "record.txt").write_text("Notes\nssn: 912-84-7731\nFiled Monday.\n")
    session = session_over(tmp5, allow_writes=True)
    jobs = [
        {"document": 0, "extract": "first three digits of the ssn field"},
        {"document": 0, "extract": "an unrelated note"},
        {"value": "redacted", "into": 0, "field": "ssn"},
        {"document": 0, "extract": "next two digits of the ssn field"},
        {"document": 0, "extract": "last four digits of the ssn field"},
    ]
    # Four worker calls: the third job is a literal fill (has "value" and an
    # int "into"), which run_jobs services from the literal itself and never
    # calls ollama_chat for.
    answers = ["912", "some unrelated note", "84", "7731"]
    result = run_with_stub(session, jobs, answers)
    check(
        "mid-round write cannot erase the evidence: round is still blocked",
        result.get("status") == "blocked",
        str(result.get("status")),
    )

    # Same fragments, adjacent this time. The pre-existing
    # evaluate_session(combined) check already catches this arrangement
    # (shape scanners work fine when the groups sit next to each other, per
    # the plan's own measurement); this confirms the new check does not
    # regress it.
    tmp3 = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test3-"))
    (tmp3 / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    session = session_over(tmp3)
    jobs = [{"document": 0, "extract": f"question {i}"} for i in range(5)]
    answers = ["912", "84", "7731", "some notes", "another line"]
    result = run_with_stub(session, jobs, answers)
    check(
        "adjacent SSN fragments: round is blocked",
        result.get("status") == "blocked",
        str(result.get("status")),
    )

    # Positive control (CLAUDE.md: assertions about absence need one). Twelve
    # benign, non-numeric jobs over a workspace containing an SSN none of
    # them touches must not be blocked, or the check would be blocking every
    # round rather than reassembly specifically.
    tmp4 = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test3-"))
    (tmp4 / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    session = session_over(tmp4)
    jobs = [{"document": 0, "extract": f"question {i}"} for i in range(12)]
    answers = ["apple", "banana", "cherry", "date", "fig", "grape",
               "honey", "kiwi", "lemon", "mango", "nectarine", "olive"]
    result = run_with_stub(session, jobs, answers)
    check(
        "twelve benign jobs over an untouched SSN: round is ok",
        result.get("status") == "ok",
        str(result.get("status")),
    )
    check(
        "twelve benign jobs over an untouched SSN: all twelve results present",
        len(result.get("results", [])) == 12,
        str(len(result.get("results", []))),
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
    run("task3_wiring", task3_wiring)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 25:
        print(f"\nWARNING: only {total} checks ran. Expected at least 25.")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
