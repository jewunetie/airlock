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

Fix wave (final whole-branch review, see final-fix-report.md):

CRITICAL 1: a workspace over MAX_LISTING_ENTRIES blocked every round, because
source_identifiers passed list_dir's truncation sentinel to read_text.

CRITICAL 2: run_jobs' snapshot failure path interpolated the raw SandboxError,
including document filenames and absolute host paths, into an outbound
concern the caller never asked about.

IMPORTANT 3: reassembles_identifier had no bound on total value length, only
on value count, so an unshaped job with a long answer could make
_subset_concatenations expensive enough to be a denial of service on the
guard path itself.

MINOR 4: generic_secret_assignment stored "label+value" as one identifier
instead of the value alone, so a caller splitting only the value across jobs
was not caught.
"""

from __future__ import annotations

import importlib.util
import json
import os
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


def ein_rules(text: str) -> set[str]:
    """Every rule name, across both scanners, whose name mentions an EIN.

    Deliberately not "which rule matched": the intact hyphen form is expected
    to match via `us_ein` in PII_PATTERNS, the labelled space forms via the
    new `labelled_ein` context rule in CONTEXT_SECRET_PATTERNS, and the test
    should not encode which layer catches which form.
    """
    findings = airlock.scan_pii_patterns(text) + airlock.scan_secrets(text)
    return {f["rule"] for f in findings if "ein" in f["rule"]}


def fake_secret_value(length: int = 16) -> str:
    """A synthetic secret value, generated rather than a hand-picked literal.

    In the spirit of fake_credential in tests/test_server.py: no vendor shape
    to preserve here (generic_secret_assignment matches any 8+ non-whitespace
    run after a label), so a plain alphanumeric run is enough. See CLAUDE.md
    for why a literal that looks like a live credential is never written down.
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def stub_ollama(answers):
    """Serves both callers run_jobs drives per round: the worker (unshaped
    here, since these jobs set no "as") and the guard's model layer
    (GUARD_SCHEMA). The guard always approves, so only the deterministic
    scanners and the source-anchored check can block a round in these tests.
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
    # use_presidio=False and guardian_model=None per task-3-brief.md, so the
    # stubbed model layer is the only model layer in play; the deterministic
    # scanners are not stubbed and still run for real.
    return airlock.Session(
        session_id="t3", objective="x",
        sandbox=airlock.Sandbox(root=root, allow_writes=allow_writes),
        worker_model="stub-worker", guard_model="stub-guard",
        use_presidio=False, guardian_model=None,
    )


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


def critical1_large_workspace() -> None:
    """CRITICAL 1: a workspace over MAX_LISTING_ENTRIES must not block every
    round. list_dir appends a literal "... truncated at 200" sentinel once a
    listing hits the cap; that string is not a file, and source_identifiers
    used to hand it straight to read_text, turning any large workspace's
    first round into an automatic block.
    """
    print("\nCRITICAL 1: a large workspace does not block every round")

    tmp = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test-c1-"))
    for i in range(airlock.MAX_LISTING_ENTRIES + 5):
        (tmp / f"doc{i}.txt").write_text(f"benign note number {i}\n")
    sandbox = airlock.Sandbox(root=tmp, allow_writes=False)

    try:
        sources = airlock.source_identifiers(sandbox)
        raised = None
    except Exception as exc:  # noqa: BLE001 - captured for the check below
        sources, raised = None, exc
    check(
        "source_identifiers returns normally over a >200-entry workspace",
        raised is None,
        f"{type(raised).__name__}: {raised}" if raised else "",
    )

    session = session_over(tmp)
    jobs = [{"document": 0, "extract": "what does the note say"}]
    result = run_with_stub(session, jobs, ["a benign one-line answer"])
    check(
        "a round over the same large workspace is not blocked",
        result.get("status") == "ok",
        str(result.get("status")),
    )


def critical2_no_filename_leak() -> None:
    """CRITICAL 2: run_jobs' snapshot failure path must not leak a filename
    or an absolute host path the caller never referenced. The SandboxError
    from an unreadable file carries both, e.g. "Cannot read
    medical_records_2026.txt: [Errno 13] ... '/private/var/.../
    medical_records_2026.txt'", and the pre-fix concern interpolated it
    verbatim into the outbound payload. CLAUDE.md names this exact failure by
    example. Distinctive filename generated, not hardcoded, per the plan.
    """
    print("\nCRITICAL 2: an unreadable workspace file leaks no filename or path")

    tmp = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test-c2-"))
    (tmp / "doc0.txt").write_text("a benign note\n")
    distinctive = "unreadable_" + fake_secret_value(12) + ".txt"
    secret_path = tmp / distinctive
    secret_path.write_text("irrelevant content\n")
    os.chmod(secret_path, 0o000)
    try:
        session = session_over(tmp)
        jobs = [{"document": 0, "extract": "what does the note say"}]
        result = run_with_stub(session, jobs, ["a benign one-line answer"])
        payload = json.dumps(result)
        check(
            "unreadable file: round is blocked, not approved",
            result.get("status") == "blocked",
            str(result.get("status")),
        )
        check(
            "unreadable file: serialised payload names no filename",
            distinctive not in payload,
        )
        check(
            "unreadable file: serialised payload carries no absolute path",
            str(tmp) not in payload,
        )
    finally:
        os.chmod(secret_path, 0o644)


def important3_length_bound() -> None:
    """IMPORTANT 3: reassembles_identifier must bound total normalised value
    length, not only value count, or an unshaped job's long answer makes
    _subset_concatenations expensive enough to be a denial of service on the
    guard path. Empty sources is the case that would otherwise trivially
    return False, proving the length bound fires ahead of the normal
    candidate-filtering path rather than coinciding with it.
    """
    print("\nIMPORTANT 3: total value length is bounded, defensively")

    oversized = ["x" * (airlock.MAX_REASSEMBLY_LENGTH + 1)]
    check(
        "total length over the bound blocks even with no sources",
        airlock.reassembles_identifier(oversized, set()),
    )

    # Positive control: twelve "line"-shaped answers (JOB_SHAPES maxLength 80)
    # sum to at most 960 characters, well under the bound, so a realistic
    # round is not affected by this check.
    legitimate_round = [f"line-shaped answer {i}" for i in range(12)]
    check(
        "a realistic round of twelve short answers stays under the bound",
        sum(len(airlock.normalise_identifier(v)) for v in legitimate_round)
        <= airlock.MAX_REASSEMBLY_LENGTH,
    )
    check(
        "that realistic round is not blocked by the length bound",
        not airlock.reassembles_identifier(legitimate_round, set()),
    )


def minor4_generic_secret_value_only() -> None:
    """MINOR 4: generic_secret_assignment must store the secret VALUE alone,
    not "label+value", so a caller splitting only the value across jobs is
    still caught. Credential generated with fake_secret_value, never a
    literal that looks like a live key; see CLAUDE.md.
    """
    print("\nMINOR 4: generic_secret_assignment identifies the value, not the label")

    value = fake_secret_value(16)
    tmp = Path(tempfile.mkdtemp(prefix="airlock-round-guard-test-m4-"))
    (tmp / "creds.txt").write_text(f"password: {value}\n")
    sandbox = airlock.Sandbox(root=tmp, allow_writes=False)
    sources = airlock.source_identifiers(sandbox)
    normalised_value = airlock.normalise_identifier(value)

    check(
        "the value alone is a source identifier",
        normalised_value in sources,
        ",".join(sorted(sources)) or "empty",
    )

    half = len(value) // 2
    fragments = [value[:half], value[half:]]
    check(
        "a round splitting the value across jobs is caught",
        airlock.reassembles_identifier(fragments, sources),
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
    run("critical1_large_workspace", critical1_large_workspace)
    run("critical2_no_filename_leak", critical2_no_filename_leak)
    run("important3_length_bound", important3_length_bound)
    run("minor4_generic_secret_value_only", minor4_generic_secret_value_only)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 35:
        print(f"\nWARNING: only {total} checks ran. Expected at least 35.")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
