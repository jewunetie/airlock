#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp[cli]>=2.0.0,<2.1.0",
#     "rich>=13.7",
#     "detect-secrets>=1.5",
#     "torch>=2.13.0,<2.14.0",
#     "transformers>=5.15.0,<5.16.0",
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
import contextlib
import importlib.util
import io
import json
import secrets
import shutil
import string
import sys
import tempfile
from datetime import datetime, timedelta
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
    values.update(root=root, approve="none")
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

        # Item-3: the server identifies itself with airlock's own version,
        # not the empty default MCPServer("airlock") would otherwise carry.
        server_version = getattr(client.server_info, "version", None)
        check(
            "MCP server identifies itself with airlock's own version",
            server_version == airlock.__version__,
            server_version,
        )

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

    # Item-1, end to end: through the real airlock_open/airlock_ask tool
    # closures rather than evict_stale_sessions directly (group_b5 covers
    # that level). A small SESSION_CAP forces eviction without opening 200
    # real sessions; needs the SDK but not Ollama, since airlock_ask on an
    # unknown/evicted id returns before the worker ever runs.
    real_cap = airlock.SESSION_CAP
    airlock.SESSION_CAP = 2
    airlock.SESSIONS.clear()
    try:
        server_evict = airlock.build_server(make_args(root))
        async with Client(server_evict) as client:
            opened_ids = []
            for _ in range(3):
                opened = await client.call_tool("airlock_open", {"objective": "x"})
                opened_ids.append((opened.structured_content or {}).get("session"))
                await asyncio.sleep(0.01)  # keep last_active strictly ordered
            check("all three opens returned a session", all(opened_ids), str(opened_ids))
            check(
                "the cap is enforced: at most SESSION_CAP sessions live",
                len(airlock.SESSIONS) <= airlock.SESSION_CAP,
                f"{len(airlock.SESSIONS)} live",
            )

            oldest, newest = opened_ids[0], opened_ids[-1]
            res = await client.call_tool("airlock_ask", {"session": oldest, "question": "x"})
            payload = res.structured_content or {}
            check(
                "an evicted session id fails closed: a clear refusal, not a "
                "silent new session or a crash",
                payload.get("status") == "error",
                str(payload),
            )
            check(
                "positive control: the newest session, under the cap, is not evicted",
                newest in airlock.SESSIONS,
                sorted(airlock.SESSIONS),
            )
    finally:
        airlock.SESSION_CAP = real_cap
        airlock.SESSIONS.clear()


def _stub_answers(values: list[str]):
    """A stub ollama_chat that returns each value in order, then repeats the
    last one if over-called. Same convention as tests/test_cross_round.py's
    stub_ollama, adapted for reassignment mid-test since this test switches
    the stubbed sequence between phases.
    """
    it = iter(values)
    last = values[-1] if values else ""

    def stub(*_args: object, **_kwargs: object) -> str:
        return next(it, last)

    return stub


async def group_a2_cross_round_via_tool(root: Path) -> None:
    """Item 4 (acceptance fix): drives airlock_extract through the real MCP
    tool boundary -- SESSIONS, touch_session, the tool closure's argument and
    result (de)serialisation -- across three rounds on one session id.

    tests/test_cross_round.py's wiring_* cases already exercise run_jobs
    directly against a hand-built Session object, extensively. What none of
    them touch is the tool surface itself: a real cloud assistant addresses
    a session by its string id through airlock_extract, not by holding a
    Session object, and nothing before this test called airlock_extract
    through the SDK's Client even once (group_a's tool-registration check
    only confirms the name is registered). ollama_chat is stubbed --
    deterministic on purpose, since a clean-context tester found the real
    worker unreliable at this exact task (it returned "123" for both "first
    three digits" and "last four digits" of an SSN), and this test is about
    the guard and the session plumbing, not the worker's arithmetic.

    Uses its own temporary root (a bare file directly under it, addressable
    as document 0) rather than the shared workspace() fixture, which nests
    its files under notes/ and so has no top-level document for a job to
    address.
    """
    print("\nA2. airlock_extract through the real tool, across rounds, one session")
    try:
        from mcp import Client
    except ImportError as exc:
        check("A2: import Client from mcp", False, str(exc))
        return

    tmp = Path(tempfile.mkdtemp(prefix="airlock-crossround-tool-test-"))
    (tmp / "record.txt").write_text("Client SSN is 912-84-7731, filed Monday.\n")

    real_ollama = airlock.ollama_chat
    try:
        server = airlock.build_server(make_args(tmp))
        async with Client(server) as client:
            opened = await client.call_tool("airlock_open", {"objective": "x"})
            session = (opened.structured_content or {}).get("session")
            check(
                "A2: airlock_open returns a session",
                bool(session),
                str(opened.structured_content),
            )
            if not session:
                return

            def one_job(i: int) -> dict:
                return {"session": session, "jobs": [{"document": 0, "extract": f"q{i}"}]}

            airlock.ollama_chat = _stub_answers(["912", "84", "7731"])
            round_results = []
            for i in range(3):
                res = await client.call_tool("airlock_extract", one_job(i))
                round_results.append(res.structured_content or {})

            check(
                "A2: round 1 of 3 is ok, through the real tool",
                round_results[0].get("status") == "ok",
                str(round_results[0]),
            )
            check(
                "A2: round 2 of 3 is ok, through the real tool",
                round_results[1].get("status") == "ok",
                str(round_results[1]),
            )
            check(
                "A2: round 3 blocks through the real tool: completes cross-round reassembly",
                round_results[2].get("status") == "blocked",
                str(round_results[2]),
            )

            payload3 = json.dumps(round_results[2])
            check(
                "A2: the blocked round's payload carries no SSN fragment or the full value",
                not any(f in payload3 for f in ("912", "84", "7731", "912-84-7731")),
                payload3[:200],
            )

            # Mandatory positive control: continuing the SAME session with
            # ordinary, unrelated answers afterward stays ok through the real
            # tool -- a block is per-round, not a permanent trip of the
            # session once it goes through SESSIONS and the tool closure.
            # Same word list as test_round_guard.py's task3 positive control
            # and test_cross_round.py's wiring_unrelated_benign_session_case,
            # verified there clean against the real guard.
            words = ["forecast", "quarterly", "template", "summary", "agenda"]
            airlock.ollama_chat = _stub_answers(words)
            benign_results = []
            for i, _word in enumerate(words, start=10):
                res = await client.call_tool("airlock_extract", one_job(i))
                benign_results.append((res.structured_content or {}).get("status"))

            check(
                "A2: a benign multi-round session over the same session id stays "
                "ok, through the real tool (positive control)",
                all(status == "ok" for status in benign_results),
                str(benign_results),
            )
    finally:
        airlock.ollama_chat = real_ollama
        shutil.rmtree(tmp, ignore_errors=True)


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


def group_b4() -> None:
    """Item-5: a looping worker gets nudged, and futile revision stops early.

    Measured against the real model (see PLAN item-5): "How many files are
    here, roughly?" looped on `list` for all 8 steps and never answered.
    "Which file mentions a vendor contract?" answered, got rejected by the
    guard for naming content, and burned all three revisions restating the
    same unrevisable answer. Both are reproduced here with a scripted
    ollama_chat, deterministically and without needing Ollama.
    """
    print("\nB4. Worker loop and revision-budget fixes")

    def make_session() -> airlock.Session:
        return airlock.Session(
            session_id="test-b4", objective="x",
            sandbox=airlock.Sandbox(root=Path("."), allow_writes=False),
            worker_model="stub",
        )

    real = airlock.ollama_chat
    try:
        # Case 1: a worker that repeats the same action gets a nudge fed back
        # as input (same pattern as sandbox refusals), and reaches an answer
        # well inside the step budget instead of being run to exhaustion.
        prompts: list[str] = []
        loop_replies = [
            {"action": "list", "path": "."},
            {"action": "list", "path": "."},
            {"action": "answer", "answer": "Two planning files, no personal data."},
        ]

        def scripted_loop(_model: str, prompt: str, _schema: dict) -> dict:
            prompts.append(prompt)
            return loop_replies.pop(0) if loop_replies else {"action": "list", "path": "."}

        airlock.ollama_chat = scripted_loop
        out = airlock.run_worker(make_session(), "how many files are here, roughly?")
        check(
            "a repeated action still reaches an answer, not step exhaustion",
            out.get("status") == "approved",
            f"{out.get('status')}: {out.get('guard_concerns')}",
        )
        check(
            "the repeat is fed back to the model before its next turn",
            len(prompts) >= 3 and any(
                w in prompts[2].lower() for w in ("already", "repeat")
            ),
            prompts[2][-300:] if len(prompts) >= 3 else f"only {len(prompts)} prompts",
        )

        # Positive control: a worker that answers on its very first turn is
        # unaffected by the repeat check (no repeat ever occurs).
        def scripted_immediate(_model: str, _prompt: str, _schema: dict) -> dict:
            return {"action": "answer", "answer": "Two planning files, no personal data."}

        airlock.ollama_chat = scripted_immediate
        out = airlock.run_worker(make_session(), "what is here?")
        check(
            "a worker that answers immediately is unaffected",
            out.get("status") == "approved",
            f"{out.get('status')}: {out.get('guard_concerns')}",
        )

        # Case 2: a worker whose answer keeps getting rejected for the same
        # reason stops revising early instead of burning every revision on an
        # answer it cannot fix. The secret is generated per CLAUDE.md's
        # testing conventions, never a literal.
        secret = fake_credential("sk_live_", 24)

        def scripted_unrevisable(_model: str, _prompt: str, _schema: dict) -> dict:
            return {"action": "answer", "answer": secret}

        airlock.ollama_chat = scripted_unrevisable
        session = make_session()
        out = airlock.run_worker(session, "what is the vendor key?")
        check(
            "identical repeated guard rejections stop before all revisions are spent",
            out.get("status") == "blocked" and session.revisions < airlock.MAX_REVISIONS,
            f"status={out.get('status')} revisions={session.revisions}",
        )
        blob = json.dumps(out)
        check(
            "the stop-early concern names neither the file, path, nor the "
            "withheld content",
            secret not in blob and str(Path(".").resolve()) not in blob,
            blob[:200],
        )
        check(
            "no concern text contains a path separator",
            not any("/" in c for c in out.get("guard_concerns", [])),
            str(out.get("guard_concerns")),
        )

        # Positive control: a rejection that IS successfully revised still
        # works, i.e. the early-stop only fires on a repeated identical
        # reason, not on every rejection.
        revise_replies = [
            {"action": "answer", "answer": secret},
            {"action": "answer", "answer": "It is a general business document."},
        ]

        def scripted_revisable(_model: str, _prompt: str, _schema: dict) -> dict:
            return revise_replies.pop(0) if revise_replies else {
                "action": "answer", "answer": "It is a general business document."
            }

        airlock.ollama_chat = scripted_revisable
        session = make_session()
        out = airlock.run_worker(session, "what is the vendor key?")
        check(
            "a rejection that is then successfully revised still approves",
            out.get("status") == "approved" and session.revisions == 1,
            f"status={out.get('status')} revisions={session.revisions}",
        )
    finally:
        airlock.ollama_chat = real


def group_b5() -> None:
    """Item-1: session eviction bounds SESSIONS, a process-global dict.

    Direct against evict_stale_sessions and the module-global SESSIONS
    dict, no SDK or Ollama needed, at the same level group_b2 already tests
    run_worker recovery. The end-to-end version, through the real
    airlock_open/airlock_ask tool closures, is in group A (needs the SDK,
    not Ollama).
    """
    print("\nB5. Session eviction")

    def fresh_session(sid: str, idle_seconds: float) -> airlock.Session:
        s = airlock.Session(
            session_id=sid, objective="x",
            sandbox=airlock.Sandbox(root=Path("."), allow_writes=False),
            worker_model="stub",
        )
        s.last_active = (datetime.now() - timedelta(seconds=idle_seconds)).isoformat()
        return s

    real_cap, real_ttl = airlock.SESSION_CAP, airlock.SESSION_IDLE_SECONDS
    airlock.SESSIONS.clear()
    try:
        # Cap: oldest-idle evicted first once at the cap; a session under
        # the cap is a positive control and survives.
        airlock.SESSION_CAP = 3
        airlock.SESSION_IDLE_SECONDS = 99999  # TTL not under test here
        airlock.SESSIONS["old"] = fresh_session("old", 30)
        airlock.SESSIONS["mid"] = fresh_session("mid", 20)
        airlock.SESSIONS["new"] = fresh_session("new", 10)
        airlock.evict_stale_sessions()
        check(
            "positive control: three sessions under the cap are not evicted",
            set(airlock.SESSIONS) == {"old", "mid", "new"},
            sorted(airlock.SESSIONS),
        )

        airlock.SESSIONS["newer"] = fresh_session("newer", 0)
        airlock.evict_stale_sessions()
        check(
            "cap enforced once a fourth session arrives",
            len(airlock.SESSIONS) <= airlock.SESSION_CAP,
            f"{len(airlock.SESSIONS)} live: {sorted(airlock.SESSIONS)}",
        )
        check("oldest-idle session evicted first", "old" not in airlock.SESSIONS,
              sorted(airlock.SESSIONS))
        check(
            "positive control: the newest session is not evicted",
            "newer" in airlock.SESSIONS,
            sorted(airlock.SESSIONS),
        )

        # TTL: idle past SESSION_IDLE_SECONDS is evicted even while under
        # the cap; a session well within the TTL is a positive control.
        airlock.SESSIONS.clear()
        airlock.SESSION_CAP = 200
        airlock.SESSION_IDLE_SECONDS = 60
        airlock.SESSIONS["stale"] = fresh_session("stale", 120)
        airlock.SESSIONS["active"] = fresh_session("active", 5)
        airlock.evict_stale_sessions()
        check("a session idle past the TTL is evicted", "stale" not in airlock.SESSIONS)
        check(
            "positive control: a session under the TTL is not evicted",
            "active" in airlock.SESSIONS,
        )

        # Fail closed: an evicted id must refuse, not silently open a new
        # session or crash. Eviction is the same dict.pop primitive
        # airlock_close already uses, so SESSIONS.get on an evicted id
        # returns None exactly like it does on a closed one, which is what
        # airlock_ask/airlock_extract key their "Unknown session." refusal
        # on (see group A's end-to-end version of this same check).
        check(
            "an evicted id looks exactly like an unknown one to the caller",
            airlock.SESSIONS.get("stale") is None,
        )
    finally:
        airlock.SESSION_CAP, airlock.SESSION_IDLE_SECONDS = real_cap, real_ttl
        airlock.SESSIONS.clear()


def group_b6() -> None:
    """Item-2: serve warm-up. Both encoders must load, in order, before
    mcp.run() starts the transport and readiness is announced; a load
    failure must be a startup failure, never a server that starts and then
    fails closed on every request instead. build_server and both loaders
    are stubbed so this needs neither the real ~700MB download nor Ollama;
    a real end-to-end run was also driven manually against the live
    encoders for this fix (see item-4-report.md), which this cannot
    reproduce as a repeatable check.
    """
    print("\nB6. serve warm-up")
    real_build = airlock.build_server
    real_pii, real_policy = airlock._load_pii_detector, airlock._load_policy_linter
    calls: list[str] = []

    class StubServer:
        def run(self) -> None:
            calls.append("mcp.run")

    def stub_build(_args: object) -> StubServer:
        calls.append("build_server")
        return StubServer()

    def stub_pii(*_a: object, **_k: object) -> None:
        calls.append("load_pii")

    def stub_policy(*_a: object, **_k: object) -> None:
        calls.append("load_policy")

    airlock.build_server = stub_build
    airlock._load_pii_detector = stub_pii
    airlock._load_policy_linter = stub_policy
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = airlock.cmd_serve(make_args(Path(".")))
        check("serve reaches readiness and runs the transport", rc == 0, str(rc))
        check(
            "both encoders load, in order, before mcp.run",
            calls == ["build_server", "load_pii", "load_policy", "mcp.run"],
            str(calls),
        )
        check(
            "serve prints nothing to stdout during warm-up (CLAUDE.md: stdout "
            "is the JSON-RPC channel)",
            buf.getvalue() == "",
            repr(buf.getvalue()[:120]),
        )
    finally:
        airlock.build_server = real_build
        airlock._load_pii_detector = real_pii
        airlock._load_policy_linter = real_policy

    # A load failure is a startup failure: mcp.run must never be reached,
    # and the process must fail closed (non-zero exit), not start a server
    # that would then fail closed on every later request instead.
    calls.clear()
    airlock.build_server = stub_build

    def failing_pii(*_a: object, **_k: object) -> None:
        calls.append("load_pii")
        raise airlock.GuardModelUnavailable("stub load failure")

    airlock._load_pii_detector = failing_pii
    airlock._load_policy_linter = stub_policy
    try:
        rc = airlock.cmd_serve(make_args(Path(".")))
        check("a warm-up load failure is a startup failure, not success", rc != 0, str(rc))
        check("mcp.run is never reached when warm-up fails", "mcp.run" not in calls, str(calls))
    finally:
        airlock.build_server = real_build
        airlock._load_pii_detector = real_pii
        airlock._load_policy_linter = real_policy


def group_b7() -> None:
    """Item-3: __version__ surfaces in cmd_doctor's output.

    cmd_doctor prints the version before anything encoder- or
    Ollama-dependent runs, so both are stubbed to fail fast here
    (GuardModelUnavailable, RuntimeError) and the assertion is on the
    captured text alone. No real model load, no Ollama needed, unlike
    tests/test_liquid_guard.py's cmd_doctor_encoder_checks_case, which
    exercises the real thing and skips when either is unavailable.
    """
    print("\nB7. cmd_doctor prints the version")
    real_pii = airlock._load_pii_detector
    real_policy = airlock._load_policy_linter
    real_ollama = airlock.ollama_models

    def fail_load(*_a: object, **_k: object) -> None:
        raise airlock.GuardModelUnavailable("stub: no real model load in this test")

    def fail_ollama() -> list[str]:
        raise RuntimeError("stub: no ollama in this test")

    airlock._load_pii_detector = fail_load
    airlock._load_policy_linter = fail_load
    airlock.ollama_models = fail_ollama
    try:
        with airlock.console.capture() as capture:
            code = airlock.cmd_doctor(make_args(Path(".")))
        printed = capture.get()
        check("cmd_doctor prints the version", airlock.__version__ in printed, printed[:80])
        check("cmd_doctor still fails closed when its stubs are unavailable", code == 1, str(code))
    finally:
        airlock._load_pii_detector = real_pii
        airlock._load_policy_linter = real_policy
        airlock.ollama_models = real_ollama


def group_b8() -> None:
    """Item 5 (fix wave): a worker step whose path/query is not a string
    must block run_worker, not crash it with an uncaught TypeError.

    signature = (action, step.get("path"), step.get("query")) is hashed
    against seen_actions two lines later; if the model returns a dict or a
    list for "path", building that hash raises TypeError: unhashable type,
    outside every try in the loop, so it used to escape run_worker entirely
    instead of returning a block envelope. Reachable, not theoretical:
    CLAUDE.md records that installed worker models do ignore JSON schema
    constraints (`doctor` probes for exactly this), so a schema-violating
    step is ordinary input from this guard's point of view, not an edge
    case that cannot occur.
    """
    print("\nB8. Item 5: a step with an unhashable path/query fails closed")

    def make_session() -> airlock.Session:
        return airlock.Session(
            session_id="test-b8", objective="x",
            sandbox=airlock.Sandbox(root=Path("."), allow_writes=False),
            worker_model="stub",
        )

    real = airlock.ollama_chat
    try:
        for bad in ({"nested": "dict"}, ["a", "list"]):
            def scripted_bad(_model: str, _prompt: str, _schema: dict, _bad: object = bad) -> dict:
                return {"action": "list", "path": _bad}

            airlock.ollama_chat = scripted_bad
            raised: Exception | None = None
            out: dict | None = None
            try:
                out = airlock.run_worker(make_session(), "what is here?")
            except Exception as exc:  # noqa: BLE001 - this is exactly what must not happen
                raised = exc

            check(
                f"path={type(bad).__name__} does not escape run_worker as an exception",
                raised is None,
                f"{type(raised).__name__}: {raised}" if raised else "no exception",
            )
            check(
                f"path={type(bad).__name__} blocks rather than approving",
                out is not None and out.get("status") == "blocked",
                str(out),
            )
    finally:
        airlock.ollama_chat = real

    # Positive control: a step shaped exactly like the malformed one but
    # with an ordinary string path must not be affected by whatever fixes
    # the unhashable case, i.e. the fix must not start blocking valid steps.
    try:
        def scripted_ok(_model: str, _prompt: str, _schema: dict) -> dict:
            return {"action": "answer", "answer": "Two planning files, no personal data."}

        airlock.ollama_chat = scripted_ok
        out = airlock.run_worker(make_session(), "what is here?")
        check(
            "a normal string-path/answer step still approves (positive control)",
            out.get("status") == "approved",
            f"{out.get('status')}: {out.get('guard_concerns')}",
        )
    finally:
        airlock.ollama_chat = real


def group_b9(root: Path) -> None:
    """Grounded-ness: a caller cannot tell a correct answer from a fabricated
    one, since the guard checks disclosure, not correctness (a clean-context
    tester's finding). run_worker now tracks whether any "read" step actually
    succeeded before the worker answered, and envelope/receipt surface that as
    a plain operation fact: not a paths, not a count of files, only whether
    the worker grounded its answer in something it actually read. This is
    allowed under CLAUDE.md's receipt invariant for the same reason step
    counts are: it describes what airlock did, not what it found.

    Uses the real workspace() fixture (root, with a real notes/plan.md) so
    the "successful read" case is a genuine sandbox read, not a stub.
    """
    print("\nB9. Grounded-ness: fabricated answers are distinguishable from real reads")

    def make_session() -> airlock.Session:
        return airlock.Session(
            session_id="test-b9", objective="x",
            sandbox=airlock.Sandbox(root=root, allow_writes=False),
            worker_model="stub",
        )

    real = airlock.ollama_chat
    try:
        # Case 1: the worker reads a real file, then answers. Grounded.
        grounded_replies = [
            {"action": "read", "path": "notes/plan.md"},
            {"action": "answer", "answer": "Two planning files, no personal data."},
        ]

        def scripted_grounded(*_a, **_k):
            return grounded_replies.pop(0) if grounded_replies else {
                "action": "answer", "answer": "x"
            }

        airlock.ollama_chat = scripted_grounded
        out = airlock.run_worker(make_session(), "what is here?")
        check(
            "a worker that reads successfully before answering is grounded",
            out.get("status") == "approved" and out.get("grounded") is True,
            f"status={out.get('status')} grounded={out.get('grounded')!r}",
        )

        # Case 2: the worker answers with no read at all. Not grounded.
        def scripted_no_read(_model: str, _prompt: str, _schema: dict) -> dict:
            return {"action": "answer", "answer": "Two planning files, no personal data."}

        airlock.ollama_chat = scripted_no_read
        out = airlock.run_worker(make_session(), "what is here?")
        check(
            "a worker that answers with zero reads is not grounded",
            out.get("status") == "approved" and out.get("grounded") is False,
            f"status={out.get('status')} grounded={out.get('grounded')!r}",
        )

        # Case 3: the tester's actual scenario. A read fails (the path does
        # not exist in the sandbox, standing in for the permission error the
        # tester hit), and the worker then fabricates an answer anyway
        # instead of reporting the real failure. Still not grounded, and
        # this must be true regardless of the guard's status verdict: a
        # generic fabricated sentence like this one is expected to pass the
        # privacy guard, which is exactly why grounded-ness cannot be
        # inferred from status alone.
        fabricated_replies = [
            {"action": "read", "path": "does-not-exist.txt"},
            {"action": "answer", "answer": "the file does not exist"},
        ]

        def scripted_fabricated(*_a, **_k):
            return fabricated_replies.pop(0) if fabricated_replies else {
                "action": "answer", "answer": "x"
            }

        airlock.ollama_chat = scripted_fabricated
        out = airlock.run_worker(make_session(), "what does the file say?")
        check(
            "a failed read followed by a fabricated answer is not grounded",
            out.get("grounded") is False,
            f"status={out.get('status')} grounded={out.get('grounded')!r}",
        )
    finally:
        airlock.ollama_chat = real

    # The guarantee statement (fix part a): envelope's note must say plainly
    # that passing the guard is not a correctness guarantee, not just a
    # privacy one, on both the approved and blocked paths.
    session = make_session()
    approved = airlock.envelope(session, "approved", "fine", [])
    note = approved.get("note", "").lower()
    check(
        "envelope's note states passing the guard is not an accuracy guarantee",
        "accura" in note or "correct" in note,
        approved.get("note", ""),
    )

    # receipt() surfaces grounded as a plain operation fact, alongside step
    # counts, and carries nothing content-derived (CLAUDE.md's receipt
    # invariant): the workspace's real file name must not leak into it.
    result_grounded = {"session": "x", "status": "approved", "grounded": True,
                        "withheld": False, "guard_concerns": []}
    rcpt = airlock.receipt(result_grounded, ["read", "approved"])
    check(
        "receipt reports grounded as a top-level operation fact",
        rcpt.get("grounded") is True,
        str(rcpt),
    )
    check(
        "receipt carries no file name even though grounded is reported",
        "plan.md" not in json.dumps(rcpt) and "notes" not in json.dumps(rcpt),
        str(rcpt),
    )
    result_ungrounded = {"session": "x", "status": "approved", "grounded": False,
                         "withheld": False, "guard_concerns": []}
    rcpt2 = airlock.receipt(result_ungrounded, ["answer"])
    check(
        "receipt reports grounded=False when nothing was successfully read (positive control)",
        rcpt2.get("grounded") is False,
        str(rcpt2),
    )


# Every check group_c performs on a run that completes, in order. Each early
# return below must skip() everything in this list not already recorded via
# check(), so a suite that exits early collects exactly as many checks as one
# that runs to completion. CLAUDE.md: a suite that silently collects fewer
# checks reads exactly like one that passed.
GROUP_C_CHECKS = [
    "airlock_open returns a session",
    "receipt withholds content",
    "receipt says work was performed",
    "receipt has no message field",
    "disclosure_request returns an envelope",
    "guard still blocks identifiers on disclosure",
    "an approved reply actually carried content",
]


def skip_remaining_group_c(done: int, reason: str) -> None:
    """skip() every GROUP_C_CHECKS entry from index `done` onward."""
    for name in GROUP_C_CHECKS[done:]:
        skip(name, reason)


async def group_c(root: Path) -> None:
    print("\nC. Whole loop through the MCP client (needs Ollama)")
    # Skip, not crash, on either missing prerequisite. Group A already reports
    # an absent SDK as a failure; a second traceback for the same cause is
    # noise, and a crash here loses the summary for everything else.
    try:
        from mcp import Client
    except ImportError as exc:
        skip_remaining_group_c(0, f"no MCP SDK: {exc}"[:60])
        return

    try:
        airlock.ollama_models()
    except RuntimeError as exc:
        skip_remaining_group_c(0, str(exc)[:60])
        return

    server = airlock.build_server(make_args(root))
    async with Client(server) as client:
        opened = (await client.call_tool("airlock_open", {"objective": "Describe this folder."}))
        session = (opened.structured_content or {}).get("session")
        check(GROUP_C_CHECKS[0], bool(session))
        if not session:
            skip_remaining_group_c(1, "airlock_open returned no session")
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
            skip_remaining_group_c(1, reason)
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
        check(GROUP_C_CHECKS[4], "status" in payload2)
        if worker_failed(payload2):
            # Two checks follow below, not one: both need a skip(), or this
            # path silently collects one fewer check than a successful run
            # does, the exact undercount the low-total guard exists to catch.
            skip_remaining_group_c(5, "INCONCLUSIVE, worker never ran")
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


async def group_c_prereq_counts(root: Path) -> None:
    """Every group_c prerequisite guard must skip exactly what a completed
    run would have checked, not fewer. Drives group_c three times under
    synthetic failures (SDK missing, Ollama unreachable, session absent) so
    the invariant is asserted behaviourally, not just read off the source.
    """
    print("\nC-prereqs. group_c early returns account for every check")

    async def run_and_count() -> int:
        # These drives of group_c are synthetic probes of its early-return
        # accounting, not real results, so pop what they add back out of the
        # global lists after counting. Otherwise the absent-session probe's
        # deliberately-induced "no session" would show up as a real suite
        # failure, and the other two would double the real group C's tally.
        before = (len(PASS), len(FAIL), len(SKIP))
        await group_c(root)
        after = (len(PASS), len(FAIL), len(SKIP))
        total = sum(a - b for a, b in zip(after, before))
        del PASS[before[0]:]
        del FAIL[before[1]:]
        del SKIP[before[2]:]
        return total

    # Missing SDK: sys.modules[name] = None is the documented way to make
    # `from mcp import Client` raise ImportError without needing mcp absent
    # from the environment (it is a declared dependency of this script).
    had_mcp = "mcp" in sys.modules
    real_mcp = sys.modules.get("mcp")
    sys.modules["mcp"] = None
    try:
        n = await run_and_count()
        check("missing-SDK path accounts for every check", n == len(GROUP_C_CHECKS),
              f"{n} of {len(GROUP_C_CHECKS)}")
    finally:
        if had_mcp:
            sys.modules["mcp"] = real_mcp
        else:
            del sys.modules["mcp"]

    # Unreachable Ollama: same prerequisite-guard shape, different exception.
    real_ollama_models = airlock.ollama_models
    airlock.ollama_models = lambda: (_ for _ in ()).throw(RuntimeError("no ollama"))
    try:
        n = await run_and_count()
        check("unreachable-Ollama path accounts for every check", n == len(GROUP_C_CHECKS),
              f"{n} of {len(GROUP_C_CHECKS)}")
    finally:
        airlock.ollama_models = real_ollama_models

    # Absent session: let the SDK import and the Ollama check succeed, but
    # replace Client with a stub whose call_tool returns no "session" key, so
    # `if not session: return` fires. Needs the real mcp package importable
    # (it is, per the dependency block above), so restore it first.
    try:
        from mcp import Client as _RealClient  # noqa: F401 - proves it imports
    except ImportError:
        skip("absent-session path accounts for every check", "no MCP SDK to drive this with")
        return

    class _FakeResult:
        structured_content = {}  # no "session" key -> falsy session

    class _NoSessionClient:
        def __init__(self, _server: object) -> None:
            pass

        async def __aenter__(self) -> "_NoSessionClient":
            return self

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        async def call_tool(self, _name: str, _args: dict) -> _FakeResult:
            return _FakeResult()

    real_client = sys.modules["mcp"].Client
    real_ollama_models = airlock.ollama_models
    airlock.ollama_models = lambda: ["stub-model"]
    sys.modules["mcp"].Client = _NoSessionClient
    try:
        n = await run_and_count()
        check("absent-session path accounts for every check", n == len(GROUP_C_CHECKS),
              f"{n} of {len(GROUP_C_CHECKS)}")
    finally:
        sys.modules["mcp"].Client = real_client
        airlock.ollama_models = real_ollama_models


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
        run_group("group A2", group_a2_cross_round_via_tool, True)
        run_group("group B", group_b, False)
        run_group("group B2", lambda _root: group_b2(), False)
        run_group("group B3", lambda _root: group_b3(), False)
        run_group("group B4", lambda _root: group_b4(), False)
        run_group("group B5", lambda _root: group_b5(), False)
        run_group("group B6", lambda _root: group_b6(), False)
        run_group("group B7", lambda _root: group_b7(), False)
        run_group("group B8", lambda _root: group_b8(), False)
        run_group("group B9", group_b9, False)
        run_group("group C", group_c, True)
        run_group("group C prereqs", group_c_prereq_counts, True)
    finally:
        # The workspace holds a symlink to a decoy secret outside it.
        shutil.rmtree(root.parent, ignore_errors=True)

    total = len(PASS) + len(FAIL) + len(SKIP)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed, {len(SKIP)} skipped ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 73:
        # 98 with the SDK and Ollama both available (92 plus group A2's 6
        # cross-round-through-the-real-tool checks); ~79 with the SDK
        # genuinely unavailable (group A and group A2 each degrade to a
        # single check, but B/B2..B9 and group_c_prereq_counts are
        # unaffected). 73 sits under that floor with margin.
        print(f"\nWARNING: only {total} checks ran. Expected around 98 (79 without the SDK).")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
