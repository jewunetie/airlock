Status: done, all green.
Commit: 51a8bee (feat/cross-round-guard), not pushed.

Suite counts:
- tests/test_cross_round.py: 43 passed, 0 failed, 0 skipped (43 checks) - unchanged
- tests/test_liquid_guard.py: 73 passed, 0 failed, 0 skipped (73 checks) - unchanged
- tests/test_round_guard.py: 58 passed, 0 failed, 0 skipped (58 checks) - unchanged
- tests/test_server.py: 80 passed, 0 failed, 0 skipped (80 checks) - baseline 61 +
  19 new checks (item-1: 4 in group A + 7 in new group B5; item-2: 5 in new
  group B6; item-3: 1 in group A + 2 in new group B7). Floor raised 45 -> 60
  (measured worst case with mcp SDK genuinely unavailable: 66 collected).
- tests/test_tax_e2e.py: 8 passed, 0 failed - unchanged

All five re-run with OLLAMA_HOST pointed at a closed port (127.0.0.1:1) to
confirm the four Ollama-tolerant suites stay green without it: cross_round
43/0/0, liquid_guard 66/0/7 skipped, round_guard 58/0/0, server 73/0/7
skipped, all exit 0. test_tax_e2e.py is NOT included in that set (see item 4
below); run separately under the same condition it produced 6 real failures,
as expected.

## Item 1: session eviction

SESSION_CAP = 200 (concurrent sessions), SESSION_IDLE_SECONDS = 3600 (1
hour idle). Chose both, not one: a cap alone still lets a single session
that nothing else ever interrupts accumulate past the false-blocking
residual advance_reassembly_state's own comment measures (up to 11.5% at
240 released values); a TTL alone still lets concurrent-session count grow
without bound if sessions open faster than the TTL retires them. Neither
number is measured; both are reasoned as generous-but-bounded for one local
process serving one cloud assistant.

`evict_stale_sessions()` drops idle-past-TTL sessions first, then
oldest-idle while still over the cap; called from `airlock_open` right
after the new session is registered, so its own last_active is always
newest and never the one evicted. Eviction is the same `dict.pop` primitive
`airlock_close` already uses, so an evicted id fails exactly like a closed
one: `SESSIONS.get(...)` is None, `airlock_ask`/`airlock_extract` return
`{"status": "error", "message": "Unknown session."}`. No new refusal path
was needed; this "falls out" of the existing pop-based check, verified by
opening 3 sessions against a monkeypatched SESSION_CAP=2 through the real
tool closures and confirming the oldest id refuses while the newest
survives (group A, SDK-driven, no Ollama needed since the refusal returns
before the worker runs). `touch_session` is called from both
`airlock_ask` and `airlock_extract`.

TDD: group_b5 (unit, no SDK/Ollama) exercises the cap, oldest-idle-first
eviction, the TTL, and includes both mandatory positive controls (a session
under the cap is not evicted; a session under the TTL is not evicted).
First cut of the cap check used `>=` and evicted a session sitting exactly
at the cap when called directly (RED, caught before committing); fixed by
making the cap check a strict postcondition (`> SESSION_CAP`) and moving
the `airlock_open` call site to after registration instead of before.

## Item 2: warm-up

`cmd_serve` now calls `_load_pii_detector()`/`_load_policy_linter()`
(existing `@lru_cache(maxsize=1)` loaders, unchanged) right after
`build_server` succeeds and before `mcp.run()`. A `GuardModelUnavailable`
there is a startup failure (return 1, clear err_console message), never a
server that starts and fails closed on every later request instead. All
new output goes through `err_console` only; verified stdout is empty with
a stubbed `mcp.run` (group_b6) and manually against the real encoders (`uv
run --script airlock.py serve --root .`, 8s capture): stdout was byte-for-byte
empty, stderr showed loading -> "guard encoders ready" -> "serving ... over
MCP" in order, confirming both the ordering and the CLAUDE.md stdout
invariant on a real run, not just the stub.

TDD: group_b6 stubs `build_server`/both loaders/`mcp.run`, asserting call
order, non-stdout output, a success return, and (inverted) that a load
failure short-circuits before `mcp.run` and returns non-zero. The full
encoder download and a real `serve` startup were not made into repeatable
checks (network- and multi-GB-dependent); covered instead by the manual
run above, described in this report rather than automated.

## Item 3: version

`__version__ = "0.1.0"`. Pre-1.0: no prior release, no compatibility
guarantee yet, so nothing 1.0 would mean anything against. Surfaced in
`cmd_doctor` (first check, unconditional), `MCPServer("airlock",
version=__version__)` (SDK's own `version` parameter, confirmed via
`inspect.signature` against the installed mcp package rather than assumed),
and `render_mcp_help`'s panel.

TDD: group_a asserts `client.server_info.version == airlock.__version__`
through the real SDK Client. group_b7 stubs both encoders and Ollama to
fail fast and asserts the version string appears in `cmd_doctor`'s
captured output before either dependency is reached, and that doctor still
returns 1 (fails closed) when its stubs are unavailable.

## Item 4: CI

`.github/workflows/tests.yml`: `actions/checkout`, `astral-sh/setup-uv`
(python-version pinned to "3.11", the floor every PEP 723 block declares),
`actions/cache` on `~/.cache/huggingface` (key on `hashFiles('airlock.py')`,
`restore-keys: hf-models-` fallback so an unrelated code change still
restores already-downloaded model blobs), then one step per suite.

Action versions are pinned by commit SHA with a version comment
(`actions/checkout@3d3c...  # v7.0.1`, `astral-sh/setup-uv@c771a7...  #
v9.0.0`, `actions/cache@55cc83...  # v6.1.0`), fetched from
https://docs.astral.sh/uv/guides/integration/github/ and
https://github.com/actions/cache directly rather than written from memory,
per CLAUDE.md.

test_liquid_guard.py, test_round_guard.py, test_cross_round.py,
test_server.py run as normal steps (no continue-on-error): each already
reports Ollama-unavailability as INCONCLUSIVE/skip rather than failure, and
each already enforces its own low-total floor internally, so a green step
here means both "no real failure" and "nothing silently failed to
collect," verified above by re-running all four with OLLAMA_HOST pointed
at a closed port.

test_tax_e2e.py has no such fallback: it is a straight end-to-end
demonstration, not a suite designed to run degraded, and 6 of its 8 checks
genuinely assert on-disk form content that a stubless run never produces
without a live worker. Confirmed by running it locally with OLLAMA_HOST
unreachable: 1 pass, 6 real fails (not skips), fails closed, no crash, exit
1. Rather than defeat that suite's own real assertions to force a fake
green, or silently drop it from CI, it runs as its own step marked
`continue-on-error: true` with a comment stating plainly that its failure
on a hosted runner is expected, not a regression, until a self-hosted
runner with Ollama exists.

## What is unverified

I did not push and cannot run this workflow on GitHub's own infrastructure.
Verified locally: the YAML parses (PyYAML), every `uv run --script
tests/X.py` command in it runs and exits as described above (on this
machine, with the real dependencies these PEP 723 blocks declare), and
`~/.cache/huggingface` is confirmed as the real default Hugging Face cache
directory in this environment (31G present, `hub/` subdirectory holds the
model snapshots `_load_pii_detector`/`_load_policy_linter` write to).

NOT verified, because it requires pushing: whether `actions/cache` actually
round-trips a save/restore across two separate workflow runs on GitHub's
infrastructure; whether a fresh ubuntu-latest runner's Python/torch/CPU
combination behaves identically to this Apple Silicon/MPS development
machine (device selection already falls back to CPU generically and is
unchanged by this work, but was not exercised on Linux/CPU here); whether
`astral-sh/setup-uv`'s `python-version: "3.11"` resolves and installs
cleanly on a fresh hosted runner with no local Python at all; and whether
GitHub Actions' own YAML parser accepts this file identically to PyYAML's
local parse (PyYAML resolves the bare `on:` key as the boolean `True`
internally, a known YAML 1.1 quirk that GitHub's parser handles as the
literal trigger key in every real workflow that uses this exact form; not
independently confirmed against GitHub's parser here).
