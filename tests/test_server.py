#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp[cli]>=2.0.0,<2.1.0",
#     "rich>=13.7",
#     "presidio-analyzer>=2.2",
#     "spacy>=3.7",
#     "detect-secrets>=1.5",
#     "torch>=2.2",
#     "transformers>=4.57",
# ]
# ///
"""End to end tests for airlock, run against the installed MCP SDK.

    uv run --script tests/test_server.py

Group A needs the SDK, B and B2 need nothing, C needs Ollama. Testing
conventions and why they are what they are: see CLAUDE.md.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import secrets
import shutil
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


def make_args(root: Path, **over: object) -> argparse.Namespace:
    values = dict(airlock.CLI_DEFAULTS)
    values.update(root=root, no_presidio=True, approve="none")
    values.update(over)
    return argparse.Namespace(**values)


ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "/+"


def fake_credential(prefix: str, length: int, alphabet: str = ALNUM) -> str:
    """A syntactically valid, entirely fake credential. See CLAUDE.md."""
    return prefix + "".join(secrets.choice(alphabet) for _ in range(length))


# Every prefix variant each vendor issues, so a detector covering one member of
# a shape but not another fails here.
CREDENTIAL_SHAPES: list[tuple[str, str, int, str]] = [
    ("stripe", "sk_live_", 24, ALNUM),
    ("stripe", "sk_test_", 24, ALNUM),
    ("stripe", "rk_live_", 24, ALNUM),
    ("stripe", "pk_test_", 24, ALNUM),
    ("github", "ghp_", 36, ALNUM),
    ("github", "gho_", 36, ALNUM),
    ("github", "ghs_", 36, ALNUM),
    ("gitlab", "glpat-", 20, ALNUM),
    ("aws key id", "AKIA", 16, string.ascii_uppercase + string.digits),
    ("aws key id", "ASIA", 16, string.ascii_uppercase + string.digits),
    ("google", "AIza", 35, ALNUM + "_-"),
    ("slack", "xoxb-", 24, string.digits + string.ascii_letters + "-"),
    ("npm", "npm_", 36, ALNUM),
    ("digitalocean", "dop_v1_", 64, string.hexdigits[:16].lower()),
    ("twilio", "SK", 32, string.hexdigits[:16].lower()),
]


def worker_failed(payload: dict) -> bool:
    """True when the local model never produced a usable answer.

    Distinguishes "the guard withheld something" (the behaviour under test)
    from "the worker could not run at all" (an environment problem). Both
    return no content, so a containment check cannot tell them apart, and the
    second one makes every leak assertion pass for the wrong reason.
    """
    concerns = payload.get("guard", {}).get("concerns", []) or payload.get("guard_concerns", [])
    return any("local model" in str(c) or "no answer" in str(c) for c in concerns)


def workspace() -> Path:
    """A throwaway workspace with a decoy secret outside it."""
    tmp = Path(tempfile.mkdtemp(prefix="airlock-test-"))
    root = tmp / "vault"
    (root / "notes").mkdir(parents=True)
    (root / "notes" / "plan.md").write_text(
        "# Plan\nTwelve planning documents about budget forecasting.\n"
    )
    (root / "notes" / "people.txt").write_text(
        "Contact jane.doe@example-corp.com or 555-555-0100. SSN 123-45-6789.\n"
    )
    outside = tmp / "outside_secret.txt"
    outside.write_text("SHOULD-NEVER-BE-READABLE\n")
    (root / "notes" / "link.txt").symlink_to(outside)
    return root


async def group_a(root: Path) -> None:
    print("\nA. MCP surface, against the real SDK")
    try:
        from mcp import Client
    except ImportError as exc:
        check("import Client from mcp", False, str(exc))
        return
    check("import Client from mcp", True)

    try:
        server = airlock.build_server(make_args(root))
    except Exception as exc:  # noqa: BLE001
        check("build_server constructs", False, f"{type(exc).__name__}: {exc}")
        return
    check("build_server constructs", True, "MCPServer + mcp_types import OK")

    async with Client(server) as client:
        listed = await client.list_tools()
        # list_tools returns a ListToolsResult, not a bare list. Iterating the
        # result directly yields pydantic (field, value) tuples, which is what
        # the first run of this suite tripped over.
        tools = {t.name: t for t in listed.tools}
        expected = {"airlock_open", "airlock_ask", "airlock_close",
                    "airlock_extract", "airlock_guard_check"}
        check("five tools registered", set(tools) == expected, ",".join(sorted(tools)))

        ask = tools.get("airlock_ask")
        if ask is None:
            check("airlock_ask present", False)
            return

        ann = getattr(ask, "annotations", None)
        check("airlock_ask carries annotations", ann is not None)
        if ann is not None:
            ro = getattr(ann, "read_only_hint", None)
            check("read_only_hint true when writes are off", ro is True, f"{ro!r}")
            # model_dump is pydantic's. Guarded rather than assumed, so a
            # changed base class reports a failure instead of raising here and
            # taking the rest of the group down with it.
            if hasattr(ann, "model_dump"):
                dumped = ann.model_dump(by_alias=True, exclude_none=True)
                check(
                    "serialises to camelCase wire names",
                    "readOnlyHint" in dumped,
                    ",".join(sorted(dumped)),
                )
            else:
                check("annotations are a pydantic model", False, type(ann).__name__)

        required = set(ask.input_schema.get("required", []))
        check(
            "disclosure_request is optional",
            required == {"session", "question"},
            ",".join(sorted(required)),
        )
        check(
            "disclosure_request is in the schema",
            "disclosure_request" in ask.input_schema.get("properties", {}),
        )

    # The annotation must follow the flag, or it is a lie in the one
    # configuration where the lie matters.
    server_w = airlock.build_server(make_args(root, allow_writes=True, approve="none"))
    async with Client(server_w) as client:
        ask = {t.name: t for t in (await client.list_tools()).tools}["airlock_ask"]
        ann = getattr(ask, "annotations", None)
        check(
            "read_only_hint flips to false with --allow-writes",
            getattr(ann, "read_only_hint", None) is False,
        )
        check(
            "destructive_hint flips to true with --allow-writes",
            getattr(ann, "destructive_hint", None) is True,
        )


def group_b(root: Path) -> None:
    print("\nB. Sandbox and deterministic guard layers")
    sb = airlock.Sandbox(root=root, allow_writes=False)

    for attack in [
        "../outside_secret.txt",
        "../../etc/passwd",
        "/etc/passwd",
        "notes/../../outside_secret.txt",
        "notes/link.txt",
    ]:
        blocked = False
        try:
            sb.read_text(attack)
        except airlock.SandboxError:
            blocked = True
        except Exception:  # noqa: BLE001
            blocked = True
        check(f"blocked: {attack}", blocked)

    body = sb.read_text("notes/plan.md")
    check("legitimate read still works", "budget forecasting" in body)

    wrote = True
    try:
        sb.write_text("notes/x.md", "x")
    except airlock.SandboxError:
        wrote = False
    check("writes refused by default", not wrote)

    # Each case below is one that actually failed at some point. The "key ..."
    # lines are adversarial against the detector's own trigger word.
    aws = fake_credential("", 40, B64)
    for label, text, want in [
        ("aws secret in prose", f"the AWS secret key is {aws}", True),
        ("aws secret in env form", f"AWS_SECRET_ACCESS_KEY={aws}", True),
        ("aws secret in yaml", f"  aws_secret_access_key: {aws}", True),
        ("aws secret after bare 'key'", f"key is {aws}", True),
        ("clean prose", "Twelve planning documents about budget forecasting.", False),
        ("key findings", "Key findings: revenue rose, headcount fell.", False),
        ("the key to", "The key to good documentation is worked examples that run.", False),
        ("key considerations", "key considerations: responsibilities and governance", False),
        ("laws and flaws", "The laws and flaws of the proposal were discussed.", False),
        ("secret to good writing", "The secret to good writing is revision.", False),
        ("access credentials prose", "Access credentials are issued by reception.", False),
        ("a url", "See https://example.com/documentation/getting-started", False),
    ]:
        got = bool(airlock.scan_secrets(text))
        check(f"secrets, {label}", got == want, f"detected={got}")

    # Generated credentials, several per shape. A regex that covers one member
    # of a vendor's prefix set but not another fails here rather than in
    # production, which is exactly how the Stripe underscore bug escaped.
    missed = []
    for vendor, prefix, length, alphabet in CREDENTIAL_SHAPES:
        for _ in range(8):
            sample = fake_credential(prefix, length, alphabet)
            if not airlock.scan_secrets(sample):
                missed.append(f"{vendor} {prefix}")
                break
    check(
        f"detects all {len(CREDENTIAL_SHAPES)} credential shapes, 8 samples each",
        not missed,
        ", ".join(sorted(set(missed))) or "all caught",
    )

    for label, text, want in [
        ("email", "write to jane.doe@example-corp.com", True),
        ("ssn", "ssn 123-45-6789", True),
        ("ordinary sentence", "The team meets on Tuesday to review scope.", False),
    ]:
        got = bool(airlock.scan_pii_patterns(text))
        check(f"pii, {label}", got == want, f"detected={got}")

    # The guard's own explanation is an outbound path too. A model that says
    # "the message reveals alice@example.com" leaks what it just blocked.
    for label, leaky in [
        ("email", "the message reveals the email jane.doe@example-corp.com"),
        ("credential", f"found {fake_credential('sk_live_', 24)} in the draft"),
        ("ssn", "contains the SSN 123-45-6789"),
    ]:
        cleaned = airlock.sanitise_concerns([leaky])
        check(f"guard explanation cannot quote a blocked {label}", cleaned != [leaky])
    safe = ["personal identifier detected: email", "described health circumstances"]
    check("safe explanations survive sanitising", airlock.sanitise_concerns(safe) == safe)


def group_b3() -> None:
    """Decomposition must not become a way to smuggle a value out in pieces.

    This only exercises fragments joined adjacent, via scan_pii_patterns
    directly, never run_jobs itself. It does not cover fragments scattered
    among benign job results, which is the arrangement that actually defeats
    the shape-based scanners; see the round-level tests driving run_jobs in
    tests/test_round_guard.py (PLAN-round-reassembly.md) for that coverage.
    """
    print("\nB3. Split-across-jobs reconstruction")
    fragments = ["912", "84", "7731"]
    for f in fragments:
        check(f"fragment {f!r} is harmless alone", not airlock.scan_pii_patterns(f))
    joined = " ".join(fragments)
    check("but the round reassembles into an identifier",
          bool(airlock.scan_pii_patterns(joined)),
          ",".join(sorted({x["rule"] for x in airlock.scan_pii_patterns(joined)})))
    check("MAX_JOBS_PER_ROUND caps fishing", airlock.MAX_JOBS_PER_ROUND <= 20,
          str(airlock.MAX_JOBS_PER_ROUND))


def group_b2() -> None:
    """Worker-loop recovery, with the model stubbed so no Ollama is needed."""
    print("\nB2. Worker loop recovery")
    session = airlock.Session(
        session_id="test", objective="x",
        sandbox=airlock.Sandbox(root=Path("."), allow_writes=False),
        worker_model="stub",
    )
    real = airlock.ollama_chat
    try:
        # A model that answers with an empty field, then recovers. Only
        # "action" is required by the schema, so this is schema-valid output
        # and it used to end the run with "produced no answer".
        replies = [
            {"action": "answer"},
            {"action": "answer", "answer": "Two planning files, no personal data."},
            {"verdict": "approve", "concerns": [], "instruction": ""},
        ]
        def scripted(*_a, **_k):
            return replies.pop(0) if replies else {"action": "answer", "answer": "x"}

        airlock.ollama_chat = scripted
        out = airlock.run_worker(session, "what is here?")
        check(
            "empty answer is retried, not fatal",
            out.get("status") == "approved",
            f"{out.get('status')}: {out.get('guard_concerns')}",
        )

        def always_empty(*_a, **_k):
            return {"action": "answer"}

        airlock.ollama_chat = always_empty
        out = airlock.run_worker(session, "what is here?")
        check(
            "a permanently empty worker still fails closed",
            out.get("status") in ("blocked",) and not out.get("message"),
            f"{out.get('status')}",
        )
    finally:
        airlock.ollama_chat = real


async def group_c(root: Path) -> None:
    print("\nC. Whole loop through the MCP client (needs Ollama)")
    # Skip, not crash, on either missing prerequisite. Group A already reports
    # an absent SDK as a failure; a second traceback for the same cause is
    # noise, and a crash here loses the summary for everything else.
    try:
        from mcp import Client
    except ImportError as exc:
        skip("receipt withholds content", f"no MCP SDK: {exc}"[:60])
        skip("disclosure_request returns content", "same")
        return

    try:
        airlock.ollama_models()
    except RuntimeError as exc:
        skip("receipt withholds content", str(exc)[:60])
        skip("disclosure_request returns content", "same")
        return

    server = airlock.build_server(make_args(root))
    async with Client(server) as client:
        opened = (await client.call_tool("airlock_open", {"objective": "Describe this folder."}))
        session = (opened.structured_content or {}).get("session")
        check("airlock_open returns a session", bool(session))
        if not session:
            return

        res = await client.call_tool(
            "airlock_ask",
            {"session": session, "question": "What personal details are in the notes?"},
        )
        payload = res.structured_content or {}

        # A containment assertion is vacuous when there was nothing to
        # contain, so report inconclusive rather than pass. Every check this
        # early return bypasses gets its own skip(): CLAUDE.md's low-total
        # guard exists because a suite that silently collects fewer checks
        # reads exactly like one that passed, and a `return` here skips not
        # just the three checks right below but the entire second ask() call
        # too.
        if worker_failed(payload):
            why = "; ".join(payload.get("guard", {}).get("concerns", []))[:80]
            reason = f"INCONCLUSIVE, worker never ran: {why}"
            skip("receipt withholds content", reason)
            skip("receipt says work was performed", reason)
            skip("receipt has no message field", reason)
            skip("disclosure_request returns an envelope", reason)
            skip("guard still blocks identifiers on disclosure", reason)
            skip("an approved reply actually carried content", reason)
            return

        blob = json.dumps(payload)
        leaks = [s for s in ("jane.doe", "123-45-6789", "555-555-0100", "people.txt") if s in blob]
        check("receipt withholds content", not leaks, ",".join(leaks) or "clean")
        check("receipt says work was performed", payload.get("performed") is True)
        check("receipt has no message field", "message" not in payload)

        res2 = await client.call_tool(
            "airlock_ask",
            {
                "session": session,
                "question": "How many files are here, roughly?",
                "disclosure_request": "a one line summary, to decide whether to read more",
            },
        )
        payload2 = res2.structured_content or {}
        check("disclosure_request returns an envelope", "status" in payload2)
        if worker_failed(payload2):
            # Two checks follow below, not one: both need a skip(), or this
            # path silently collects one fewer check than a successful run
            # does, the exact undercount the low-total guard exists to catch.
            skip("guard still blocks identifiers on disclosure", "INCONCLUSIVE, worker never ran")
            skip("an approved reply actually carried content", "INCONCLUSIVE, worker never ran")
            return
        blob2 = json.dumps(payload2)
        hard_leaks = [s for s in ("123-45-6789", "jane.doe@example-corp.com") if s in blob2]
        check("guard still blocks identifiers on disclosure", not hard_leaks,
              ",".join(hard_leaks) or "clean")
        check(
            "an approved reply actually carried content",
            bool(str(payload2.get("message", "")).strip()),
            f"{len(str(payload2.get('message','')))} chars",
        )


def main() -> int:
    root = workspace()
    print(f"workspace: {root}")
    print(f"airlock:   {AIRLOCK}")
    print(f"mcp sdk:   {airlock.installed_version('mcp') or 'not installed'}")

    # Groups are isolated: a crash is recorded as a failure and the run
    # continues, so one surprise does not cost the whole summary.
    def run_group(name: str, fn: object, is_async: bool) -> None:
        try:
            asyncio.run(fn(root)) if is_async else fn(root)
        except BaseException as exc:  # noqa: BLE001 - report, never abort
            # BaseException because anyio raises ExceptionGroup, which is not
            # an Exception subclass on every version in play here.
            FAIL.append(f"{name} crashed")
            print(f"  FAIL  {name} crashed  [{type(exc).__name__}: {str(exc)[:120]}]")

    try:
        run_group("group A", group_a, True)
        run_group("group B", group_b, False)
        run_group("group B2", lambda _root: group_b2(), False)
        run_group("group B3", lambda _root: group_b3(), False)
        run_group("group C", group_c, True)
    finally:
        # The workspace holds a symlink to a decoy secret outside it.
        shutil.rmtree(root.parent, ignore_errors=True)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 40:
        print(f"\nWARNING: only {total} checks ran. Expected around 50.")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
