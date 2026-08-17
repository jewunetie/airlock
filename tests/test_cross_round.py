#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "rich>=13.7",
#     "torch>=2.13.0,<2.14.0",
#     "transformers>=5.15.0,<5.16.0",
# ]
# ///
"""Tests for cross-round reassembly. See PLAN-cross-round.md Task 1.

    uv run --script tests/test_cross_round.py

reassembles_identifier bounds one round: a caller issuing three rounds of one
fragment each defeats it, because Session carried counters, not released
values, between rounds. advance_reassembly_state closes that by tracking, per
source identifier, which contiguous spans of it are reachable from values
released so far in the session, folding in each newly released value as it
arrives. run_jobs runs it after the existing per-round check, so a round that
completes a cross-session reconstruction blocks even though every round on
its own, and every job in it, was individually clean.
"""

from __future__ import annotations

import importlib.util
import json
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


# Same illustrative SSN used throughout tests/test_round_guard.py: not a real
# person's identifier, PLAN-round-reassembly.md's own example, and carries no
# vendor shape for secret scanning to trip on (see fake_credential/
# CREDENTIAL_SHAPES in tests/test_server.py for why a real secret would need
# to be generated instead).
SSN = "912-84-7731"


def stub_ollama(answers):
    it = iter(answers)

    def stub(model, prompt, schema=None):
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
    return airlock.Session(
        session_id="cross-round-test", objective="x",
        sandbox=airlock.Sandbox(root=root, allow_writes=allow_writes),
        worker_model="stub-worker",
    )


def ssn_workspace() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="airlock-cross-round-test-"))
    (tmp / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")
    return tmp


def one_job(i: int) -> list[dict]:
    return [{"document": 0, "extract": f"question {i}"}]


# --------------------------------------------------------------------------
# Unit level: advance_reassembly_state directly, no Ollama or sandbox needed.
# --------------------------------------------------------------------------


def unit_natural_order_case() -> None:
    print("\nUnit: three rounds of one SSN fragment each, natural order")

    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}

    r1 = airlock.advance_reassembly_state(state, ["912"], sources)
    r2 = airlock.advance_reassembly_state(state, ["84"], sources)
    r3 = airlock.advance_reassembly_state(state, ["7731"], sources)

    check("first round alone does not complete it", not r1)
    check("second round still does not complete it", not r2)
    check("third round completes the reconstruction", r3)


def unit_reverse_order_case() -> None:
    print("\nUnit: same three fragments, reverse round order")

    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}

    r1 = airlock.advance_reassembly_state(state, ["7731"], sources)
    r2 = airlock.advance_reassembly_state(state, ["84"], sources)
    r3 = airlock.advance_reassembly_state(state, ["912"], sources)

    check("first round (last fragment) alone does not complete it", not r1)
    check("second round still does not complete it", not r2)
    check(
        "third round completes it: order independence, per the docstring",
        r3,
    )


def unit_interleaved_benign_rounds_case() -> None:
    print("\nUnit: fragments split across rounds with benign rounds between")

    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}

    r1 = airlock.advance_reassembly_state(state, ["912"], sources)
    r2 = airlock.advance_reassembly_state(state, ["forecast", "quarterly"], sources)
    r3 = airlock.advance_reassembly_state(state, ["84"], sources)
    r4 = airlock.advance_reassembly_state(state, ["invoice", "headcount"], sources)
    r5 = airlock.advance_reassembly_state(state, ["7731"], sources)

    check(
        "no round before the final fragment completes it",
        not any([r1, r2, r3, r4]),
        str([r1, r2, r3, r4]),
    )
    check("the round with the final fragment completes it", r5)


def unit_unrelated_benign_values_case() -> None:
    """Positive control (CLAUDE.md: an absence claim needs one). Many rounds
    of ordinary words over a workspace containing an untouched SSN must
    never complete a reconstruction, or this check is blocking everything
    rather than reassembly specifically.
    """
    print("\nUnit: many rounds of unrelated benign values, positive control")

    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}
    rounds = [
        ["forecast", "quarterly"], ["template", "summary"], ["agenda", "payroll"],
        ["contract", "vendor"], ["documentation", "kitchen"], ["invoice", "headcount"],
    ]
    results = [airlock.advance_reassembly_state(state, r, sources) for r in rounds]

    check(
        "none of the unrelated rounds ever complete a reconstruction",
        not any(results),
        str(results),
    )


def unit_bounded_work_case() -> None:
    """N released values must not grow work exponentially. Two distinct
    assertions, neither a wall-clock guess:

    1. Call-count: advance_reassembly_state's own folding primitive is
       invoked exactly once per (round, source) pair, proven by counting
       calls across n rounds. 2**n would be astronomically larger than n for
       even a modest n; observing exactly n rules out any exponential term
       structurally, not by timing it.
    2. State-size: the span set for one source cannot grow past roughly
       twice its length, since every insertion either extends or merges an
       existing span or is discarded, so flooding many more rounds than the
       source has characters must not grow the stored state past that bound.
    """
    print("\nUnit: N released values do not grow work exponentially")

    original = airlock._fold_source_spans
    calls = {"n": 0}

    def counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    airlock._fold_source_spans = counting
    try:
        state: dict[str, set[int]] = {}
        sources = {airlock.normalise_identifier(SSN)}
        n = 60
        for i in range(n):
            airlock.advance_reassembly_state(state, [f"filler-{i}-noise"], sources)
    finally:
        airlock._fold_source_spans = original

    # Two calls per round, not one: the lone source is all-digit, so both
    # advance_reassembly_state passes (raw, then digits-only) run every
    # round. Still exactly linear in n; 2**n would already be
    # 1152921504606846976 at n=60, nowhere near 120.
    check(
        "folding primitive is called a fixed number of times per round (linear, not exponential)",
        calls["n"] == 2 * n,
        f"{calls['n']} calls for {n} rounds",
    )

    source = next(iter(sources))
    state2: dict[str, set[int]] = {}
    # Many overlapping single-character "matches" (every digit of the source
    # appears somewhere in isolation), the shape most likely to inflate the
    # span set if merging were not actually collapsing it.
    for ch in source * 20:
        airlock.advance_reassembly_state(state2, [ch], sources)
    stored = state2.get(source, set())
    check(
        "span set for one source stays bounded by its own length, not round count",
        len(stored) <= 2 * len(source),
        f"{len(stored)} ints stored for a {len(source)}-char source after 180 rounds",
    )


def unit_digits_projection_case() -> None:
    """Mirrors reassembles_identifier's own digits-only projection: a
    numeric source padded on every cross-round fragment must still be
    caught, the same way single-round padding already is (task-4-brief.md
    in tests/test_round_guard.py). Not one of the plan's seven required
    rows, but explicitly required by the Task 1 brief ("Apply both the raw
    value and its digits-only projection... so cross-round numeric padding
    is covered exactly as single-round padding is"), so it needs its own
    regression guard.
    """
    print("\nUnit: cross-round padding on a numeric source is still caught")

    state: dict[str, set[int]] = {}
    sources = {airlock.normalise_identifier(SSN)}

    r1 = airlock.advance_reassembly_state(state, ["value is 912 confirmed"], sources)
    r2 = airlock.advance_reassembly_state(state, ["the 84 recorded"], sources)
    r3 = airlock.advance_reassembly_state(state, ["figure 7731 noted"], sources)

    check("padded fragments across rounds: not complete after two", not r1 and not r2)
    check("padded fragments across rounds: digits projection catches the third", r3)


# --------------------------------------------------------------------------
# Integration level: wired into run_jobs, real Session, real guard models.
# --------------------------------------------------------------------------


def wiring_natural_order_case() -> None:
    print("\nWiring: run_jobs blocks on the round that completes cross-round reassembly")

    tmp = ssn_workspace()
    session = session_over(tmp)

    r1 = run_with_stub(session, one_job(1), ["912"])
    r2 = run_with_stub(session, one_job(2), ["84"])
    r3 = run_with_stub(session, one_job(3), ["7731"])

    check("round 1 of 3 is ok", r1.get("status") == "ok", str(r1.get("status")))
    check("round 2 of 3 is ok", r2.get("status") == "ok", str(r2.get("status")))
    check(
        "round 3 of 3 blocks: completes a reassembly begun in earlier rounds",
        r3.get("status") == "blocked",
        str(r3.get("status")),
    )

    # Mandatory containment control (CLAUDE.md: no protected plaintext may
    # escape, and this state holds fragments of real identifiers). Checked
    # against json.dumps of every round's result, per the plan. Rounds 1 and
    # 2 legitimately carry their own small released value ("912", "84") in
    # their own payload, since that release is each round's normal, correct
    # output and neither fragment completes anything on its own; what must
    # never appear in ANY round, blocked or not, is the internal
    # reassembly_state itself. The blocking round (round 3) is held to the
    # stronger bar: not only must it not leak the state, its withheld
    # payload must carry none of the SSN's fragments or the full value
    # either, since that is the payload the block message actually ships.
    for label, result in (("round 1", r1), ("round 2", r2), ("round 3", r3)):
        payload = json.dumps(result)
        check(
            f"{label}: serialised payload never carries the raw session reassembly state",
            "reassembly_state" not in payload,
            payload[:200],
        )
    payload3 = json.dumps(r3)
    check(
        "round 3 (blocked): payload carries no SSN fragment or the full value",
        not any(fragment in payload3 for fragment in ("912", "84", "7731", "912-84-7731")),
        payload3[:200],
    )
    check(
        "the blocking round's message names no identifier, document, or job",
        "record.txt" not in payload3 and "912-84-7731" not in payload3,
        payload3[:200],
    )


def wiring_reverse_order_case() -> None:
    print("\nWiring: reverse round order still blocks on the third round")

    tmp = ssn_workspace()
    session = session_over(tmp)

    r1 = run_with_stub(session, one_job(1), ["7731"])
    r2 = run_with_stub(session, one_job(2), ["84"])
    r3 = run_with_stub(session, one_job(3), ["912"])

    check("round 1 of 3 (reverse) is ok", r1.get("status") == "ok", str(r1.get("status")))
    check("round 2 of 3 (reverse) is ok", r2.get("status") == "ok", str(r2.get("status")))
    check(
        "round 3 of 3 (reverse) blocks: order independence",
        r3.get("status") == "blocked",
        str(r3.get("status")),
    )

    # Same distinction as the natural-order case above: rounds 1 and 2
    # legitimately carry their own released fragment; only the blocking
    # round (round 3) is held to the no-fragment bar, and no round, blocked
    # or not, may leak the raw reassembly state.
    for label, result in (("round 1", r1), ("round 2", r2), ("round 3", r3)):
        payload = json.dumps(result)
        check(
            f"reverse order {label}: serialised payload never carries the raw session reassembly state",
            "reassembly_state" not in payload,
            payload[:200],
        )
    payload3 = json.dumps(r3)
    check(
        "reverse order round 3 (blocked): payload carries no SSN fragment or the full value",
        not any(fragment in payload3 for fragment in ("912", "84", "7731", "912-84-7731")),
        payload3[:200],
    )


def wiring_interleaved_benign_rounds_case() -> None:
    print("\nWiring: fragments split across rounds with benign rounds between")

    tmp = ssn_workspace()
    session = session_over(tmp)

    r1 = run_with_stub(session, one_job(1), ["912"])
    r2 = run_with_stub(session, one_job(2), ["forecast"])
    r3 = run_with_stub(session, one_job(3), ["84"])
    r4 = run_with_stub(session, one_job(4), ["quarterly"])
    r5 = run_with_stub(session, one_job(5), ["7731"])

    check(
        "no round before the final fragment blocks",
        all(r.get("status") == "ok" for r in (r1, r2, r3, r4)),
        str([r.get("status") for r in (r1, r2, r3, r4)]),
    )
    check(
        "the round with the final fragment blocks",
        r5.get("status") == "blocked",
        str(r5.get("status")),
    )


def wiring_unrelated_benign_session_case() -> None:
    """Positive control at the wiring level (CLAUDE.md). Twelve separate
    rounds of ordinary single-word answers, one round per word, over an
    untouched SSN: none may block, or cross-round tracking is blocking every
    long-running session rather than reassembly specifically. Same word list
    as tests/test_round_guard.py's task3 positive control, verified there
    clean against the real PII detector and policy linter both individually
    and combined.
    """
    print("\nWiring: twelve unrelated benign rounds over an untouched SSN, positive control")

    tmp = ssn_workspace()
    session = session_over(tmp)
    words = [
        "forecast", "quarterly", "template", "summary", "agenda", "payroll",
        "contract", "vendor", "documentation", "kitchen", "invoice", "headcount",
    ]
    results = [run_with_stub(session, one_job(i), [w]) for i, w in enumerate(words)]

    check(
        "none of the twelve unrelated rounds block",
        all(r.get("status") == "ok" for r in results),
        str([r.get("status") for r in results]),
    )


def wiring_whole_identifier_one_round_case() -> None:
    """A single job releasing the intact identifier is the existing per-job
    guard's business (evaluate_session's pii-patterns layer, unconditionally
    reachable per CLAUDE.md), not advance_reassembly_state's:
    reassembles_identifier itself already treats a single whole-value
    release as out of scope (tests/test_round_guard.py, "single job released
    it, not this check's business"). Verified directly against evaluate()
    first, so the expectation below is measured, not assumed: evaluate(SSN)
    returns decision "revise" via ["secrets", "pii-patterns"], which
    GuardVerdict.approved reports as False, so the job is withheld before
    reassembles_identifier or advance_reassembly_state ever run. The round
    as a whole stays "ok" with one withheld result, since nothing else in
    the round is affected; this confirms Task 1 has not disturbed that
    existing per-job path.
    """
    print("\nWiring: a single job with the intact identifier is withheld via the existing check")

    verdict = airlock.evaluate(SSN)
    check(
        "evaluate() itself rejects the intact SSN (establishes the premise)",
        not verdict.approved,
        f"{verdict.decision} via {verdict.layers_run}",
    )

    tmp = ssn_workspace()
    session = session_over(tmp)
    result = run_with_stub(session, one_job(1), [SSN])
    results = result.get("results") or []
    job = results[0] if results else {}

    check(
        "the round is not blocked outright",
        result.get("status") == "ok",
        str(result.get("status")),
    )
    check(
        "the one job in it is withheld, not released",
        job.get("status") == "withheld",
        str(job),
    )
    check(
        "the withheld job carries no value",
        "value" not in job,
        str(job),
    )


def wiring_fail_closed_case() -> None:
    """CLAUDE.md invariant: the guard fails closed. If
    advance_reassembly_state itself raises, run_jobs must block, not approve
    or crash the caller with an uncaught exception.
    """
    print("\nWiring: an error inside cross-round tracking blocks, not approves")

    tmp = ssn_workspace()
    session = session_over(tmp)

    original = airlock.advance_reassembly_state
    airlock.advance_reassembly_state = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        result = run_with_stub(session, one_job(1), ["a benign one-line answer"])
    finally:
        airlock.advance_reassembly_state = original

    check(
        "round is blocked when cross-round tracking errors",
        result.get("status") == "blocked",
        str(result.get("status")),
    )
    check(
        "the failure carries no exception detail outbound",
        "boom" not in json.dumps(result),
        json.dumps(result)[:200],
    )


def main() -> int:
    print(f"airlock: {AIRLOCK}")

    def run(name: str, fn) -> None:
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - report, never abort
            FAIL.append(f"{name} crashed")
            print(f"  FAIL  {name} crashed  [{type(exc).__name__}: {str(exc)[:200]}]")

    run("unit_natural_order_case", unit_natural_order_case)
    run("unit_reverse_order_case", unit_reverse_order_case)
    run("unit_interleaved_benign_rounds_case", unit_interleaved_benign_rounds_case)
    run("unit_unrelated_benign_values_case", unit_unrelated_benign_values_case)
    run("unit_bounded_work_case", unit_bounded_work_case)
    run("unit_digits_projection_case", unit_digits_projection_case)
    run("wiring_natural_order_case", wiring_natural_order_case)
    run("wiring_reverse_order_case", wiring_reverse_order_case)
    run("wiring_interleaved_benign_rounds_case", wiring_interleaved_benign_rounds_case)
    run("wiring_unrelated_benign_session_case", wiring_unrelated_benign_session_case)
    run("wiring_whole_identifier_one_round_case", wiring_whole_identifier_one_round_case)
    run("wiring_fail_closed_case", wiring_fail_closed_case)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 37:
        print(f"\nWARNING: only {total} checks ran. Expected at least 37.")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
