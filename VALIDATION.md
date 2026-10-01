# Current Airlock validation

This records the completed root promotion and authorized hardening, not production acceptance. The original `new_design/TEST_REPORT.md` references artifacts and tests absent from this repository; its reported counts are not reproducible here.

## Executed checks

On 2026-10-01, the approved information-flow clarification completed with **50 passed, zero skipped, zero failures**. The locked environment was already complete; `UV_CACHE_DIR=/private/tmp/airlock-uv-cache uv sync --locked --offline` made no dependency changes, and the same cache location was used for `uv run --locked --offline python -B -m pytest -q test.py`. The full passing run had permission to bind localhost. A prior restricted run passed 49 checks and failed only the existing HTTP test at `socket.bind`; that restriction was not counted as a pass or removed from the suite.

The two added sequence checks exercise actual supervisor authorization and SQLite. A synthetic document claiming approval cannot produce a tool grant; an exact local vote permits the call once, replay is denied, and unknown tools fail. A scripted fixture worker reads and copies synthetic confidential text into a differently named file with permitted operations. Its first task returns only a receipt; a later task's attempted disclosure is withheld by a content-sensitive fixture scanner despite an omitted source hint, and an unrelated benign response succeeds. This copy test is not live Coder/model/scanner/SRT acceptance. Existing real Coder and MCP checks, restart/idempotency checks, and approval/policy mutation checks remain in the full suite.

`ARCHITECTURE.md` now states confidentiality separately from authority and records the existing tool/model/scanner/cloud boundary contracts. No new policy engine, per-file label store, public API, or production code was needed for these three changes. Fresh review checked the added rules against `run_coder`, `worker_message`, `Egress`, and the existing retry/recovery behavior; no additional concrete defect was found in that scope. `git diff --check` passes.

On 2026-09-28, the redesigned root suite completed with **48 passed, zero skipped, zero failures** in the resolved project environment. It imports root `airlock.py`; it does not extract selected definitions or replace Pydantic/SQLite/OpenTelemetry with stubs.

```sh
uv sync --locked
uv run --locked python -B -m pytest -q test.py
uv build
```

Local HTTP tests need permission to bind localhost. An earlier restricted run failed at `socket.bind` with `PermissionError`; the permitted run passed. An initial test-client configuration used an unsupported mode name; it was corrected to the installed SDK's actual protocol version before the passing run.

| Area | Evidence and limits |
|---|---|
| Fragment search | 600 seeded small graphs match an independent exhaustive interval-placement reference. Original short-fragment sensitivity and search bounds remain. Three ordinary prose fixtures complete; reverse/overlap/decoded/single-character/repeated-occurrence reconstruction withholds the completing release, and an unrelated later release succeeds. This is synthetic usability/algorithm evidence. |
| Human review | Original question/purpose/workspace/policy/candidate shown; one vote; request immutability; candidate mutation during a wait; canonical findings order/deduplication; changed evidence and changed policy invalidate approval. |
| Release state | Cancellation during final scanning records no release. Two workspaces sharing a ledger cannot jointly release a complete identifier. Fixed no-disclosure receipts contain no candidate; required-scanner failure withholds output. Scanners are fixtures. |
| Persistence | Actual SQLite full condition retains the original error and rolls back. A failed final commit publishes no candidate or ledger change and marks the runtime unavailable. An injected admission-audit failure queues no work. |
| Storage/deletion | A configured 256 KiB main-database cap forces actual exhaustion without removing committed records or queueing refused work. Lowering below usage is refused. Reopen reapplies the cap. Confirmed local deletion preserves active tasks, other workspaces, audit/configuration rows, retry fingerprints, and the disclosure ledger. Freed pages accept new work after reopen; deleted IDs reject replay/conflicting content. The startup command carries the configured cap before recovery. |
| Retry identity | Twenty competing coroutine submissions bind to one queued task. Changed request/purpose and conflicting identity pairs fail. Missing IDs and different workspaces remain independent. One synthetic worker write executes once despite retries. Reopened databases replay completed/interrupted results without queueing. The write test uses a fixture worker, not Coder/SRT. |
| Migration | An actual schema-2 database created by the unchanged original redesign migrates native task identity and disclosure geometry to schema 3. |
| Real MCP | Installed FastMCP client/server execute legacy and `2026-07-28` task-capable calls. Three-tool schemas expose `request_id`; retry/conflict/status behavior and native identity bindings are asserted. A real localhost HTTP server accepts the token and rejects missing tokens, browser origins, and unexpected Host headers. |
| Coder/framework | Actual Pydantic AI/Harness constructs the six native tools, reads a synthetic file, and exercises direct and deferred manual approval hooks. Model replies and supervisor-channel decisions are scripted; this is framework compatibility evidence, not Ollama or OS isolation evidence. |
| Authority/policy | Authority fields are rejected. Policy intersections do not broaden clean/unsafe permissions across the tested modes. Enforce startup requires explicit calibration. An omitted source followed by a declared source demonstrates the tracking limitation with a clean fixture scanner. |
| Packaging/CLI | Inline/project dependencies agree; all lazy import names resolve. Source help and fixed invalid-command behavior pass. Source and wheel distributions build; archive inspection confirms one shipped production module and excludes the historical implementation. The wheel installs/imports from a separate environment and its entry point exits zero for help. |

The production source also imports successfully and `python -I -B airlock.py --help` exits zero. Import and help alone establish no isolation or scanner accuracy.

The project environment was managed through `uv`, and the generated `uv.lock` is committed. Relevant tested versions: Python 3.13.14; Pydantic 2.13.4; pydantic-settings 2.15.0; SQLite from this Python build; OpenTelemetry SDK 1.45.0; Pydantic AI 2.46.0; Harness 0.36.0; FastMCP, fastmcp-slim and fastmcp-tasks 4.0.10; MCP 2.2.0; uvicorn 0.52.4; pytest 9.1.1; pytest-asyncio 1.4.0. Scanner packages resolve/import, but no scanner weights or accepted calibration were exercised.

CI now installs the lockfile, runs these contracts, builds both distributions, checks archive contents, and verifies the installed wheel entry point. The workflow YAML parses locally. No remote Actions run is claimed; these changes have not been pushed.

Fresh review found and corrected a history-deletion reference to the removed `native_tasks` table and a build pattern that included `new_design/airlock.py`. It also checked retry lookup before cached-result reuse, cap application before startup/recovery writes, transaction rollback after SQLite's automatic rollback, and retention of disclosure/retry evidence. No further concrete defect was found in the reviewed hardening paths. This is a code review of those paths, not an independent security audit.

## Still required

- Exercise real Coder/SRT/Ollama/scanners together with reviewed assets and calibration on the target platform. No real privacy detection accuracy, worker isolation, image-model behavior, process escape resistance, or combined memory use was measured.
- Exercise interactive Textual approval/history flows and native disconnect/cancellation recovery. The HTTP and in-process MCP results do not establish all client-recovery behavior.

The referenced preparation/calibration tools and corpus are absent; no accepted live profile is supplied. Source tracking remains fallible and reconnects old evidence only when sources are declared again after restart. The hardening is complete within the approved contracts, while live acceptance remains outstanding.
