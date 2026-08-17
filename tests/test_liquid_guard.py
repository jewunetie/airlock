#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "torch>=2.2",
#     "transformers>=4.57",
#     "rich>=13.7",
# ]
# ///
"""Tests for the two encoder guard layers. See task-1-brief.md, and
task-2-brief.md for the cases appended below that exercise evaluate()
rewired onto them (secrets -> pii-patterns -> pii-detector -> policy-linter)
and the CLI surface that configures it.

    uv run --script tests/test_liquid_guard.py

torch and transformers are declared here, not in airlock.py's PEP 723 block
(that is Task 5's job); this file gets its own copy the way eval/ scripts do.

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
import secrets
import string
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
# Task 2: evaluate() rewired onto secrets -> pii-patterns -> pii-detector ->
# policy-linter, and the CLI/session/server surface that configures it. See
# task-2-brief.md and the Task 3 section of PLAN-liquid-guard.md; the two
# were merged into one implementation task because evaluate()'s signature and
# its call sites cannot be verified independently (see the merge ruling in
# progress.md).
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


def cli_parser_cases() -> None:
    """Task 3 section of the plan: the removed flags, --linter-threshold, and
    what gets printed for a client to paste. Parser-level only, no model or
    Ollama needed, so none of these may skip.
    """
    print("\nCLI: removed flags rejected, --linter-threshold wired through")

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
    run("rewired_evaluate_cases", rewired_evaluate_cases, unavailable)
    run("evaluate_fail_closed_cases", evaluate_fail_closed_cases)
    run("cli_parser_cases", cli_parser_cases)
    run("chunk_text_step_guard_case", chunk_text_step_guard_case)
    run("dense_non_ascii_truncation_case", dense_non_ascii_truncation_case, unavailable)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    # Raised from 29 to 33: fix round 1 adds 2 _chunk_text step-guard cases
    # and 2 dense-non-ASCII truncation cases, all of which run (or are
    # explicitly SKIPped and still counted) every time, per CLAUDE.md: a
    # suite that silently collects fewer checks reads like one that passed.
    if total < 33:
        print(f"\nWARNING: only {total} checks ran. Expected at least 33.")
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
