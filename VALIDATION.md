# Current Airlock validation

This is evidence for the root promotion in progress, not a production acceptance report. The original `new_design/TEST_REPORT.md` references artifacts and tests absent from this repository; its reported counts are not reproducible here.

## Executed checks

On 2026-09-28, the direct production-module harness completed with **32 passed, zero skipped, zero failures**. It imports root `airlock.py`; it does not extract selected definitions or replace Pydantic/SQLite/OpenTelemetry with stubs.

```sh
/private/tmp/airlock-hardening-venv/bin/python -B -m pytest -q \
  /private/tmp/airlock_hardening_test.py
```

Local HTTP tests need permission to bind localhost. An earlier restricted run failed at `socket.bind` with `PermissionError`; the permitted run passed. An initial test-client configuration used an unsupported mode name; it was corrected to the installed SDK's actual protocol version before the passing run.

| Area | Evidence and limits |
|---|---|
| Fragment search | 600 seeded small graphs match an independent exhaustive interval-placement reference. Original short-fragment sensitivity and search bounds remain. Three ordinary prose fixtures complete; short-fragment reconstruction withholds the completing release, and an unrelated later release succeeds. This is synthetic usability/algorithm evidence. |
| Human review | Original question/purpose/workspace/policy/candidate shown; one vote; request immutability; candidate mutation during a wait; canonical findings order/deduplication; changed evidence and changed policy invalidate approval. |
| Release state | Cancellation during final scanning records no release. Two workspaces sharing a ledger cannot jointly release a complete identifier. Fixed no-disclosure receipts contain no candidate; required-scanner failure withholds output. Scanners are fixtures. |
| Persistence | Actual SQLite full condition retains the original error and rolls back. A failed final commit publishes no candidate or ledger change and marks the runtime unavailable. An injected admission-audit failure queues no work. |
| Retry identity | Twenty competing coroutine submissions bind to one queued task. Changed request/purpose and conflicting identity pairs fail. Missing IDs and different workspaces remain independent. One synthetic worker write executes once despite retries. Reopened databases replay completed/interrupted results without queueing. The write test uses a fixture worker, not Coder/SRT. |
| Migration | An actual schema-2 database created by the unchanged original redesign migrates native task identity and disclosure geometry to schema 3. |
| Real MCP | Installed FastMCP client/server execute legacy and `2026-07-28` task-capable calls. Three-tool schemas expose `request_id`; retry/conflict/status behavior and native identity bindings are asserted. A real localhost HTTP server accepts the token and rejects missing tokens, browser origins, and unexpected Host headers. |

The production source also imports successfully and `python -I -B airlock.py --help` exits zero. Import and help alone establish no isolation or scanner accuracy.

The temporary environment was managed through `uv`. Relevant tested versions: Python 3.13.14; Pydantic 2.13.4; pydantic-settings 2.15.0; SQLite from this Python build; OpenTelemetry SDK 1.45.0; FastMCP, fastmcp-slim and fastmcp-tasks 4.0.10; MCP 2.2.0; uvicorn 0.54.0; pytest 9.1.1; pytest-asyncio 1.4.0. These are temporary integration versions, not a claim that the repository lockfile resolves the new runtime.

## Still required

- Choose the storage-cap default and retry-record semantics after explicit transcript deletion; complete their implementation and tests.
- Resolve the test/build migration choice. Root `test.py`, packaging, and CI still describe the retired API. The regression harness currently resides in `/private/tmp` under the approved temporary test scope.
- Exercise real Coder/SRT/Ollama/scanners and reviewed calibration on the target platform. No real privacy detection accuracy, worker isolation, image-model behavior, process escape resistance, or combined memory use was measured.
- Exercise interactive Textual approval/history flows and native disconnect/cancellation recovery. The HTTP and in-process MCP results do not establish all client-recovery behavior.

The migration's history-deletion handler still needs integration with the chosen retry policy. The promotion is incomplete and must not be deployed as an accepted privacy boundary.
