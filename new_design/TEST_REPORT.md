# Airlock 0.4 Test Report

## Executed result

**113 passed, 13 skipped, 0 failures/errors; 126 collected.**

Environment: Linux x86_64, Python 3.13.5. The final test command was:

```sh
python -m pytest -q -ra --junitxml=validation/pytest.xml
```

`validation/pytest.txt` and `validation/pytest.xml` contain the captured results. `validation/environment.json` records installed versions. Test count is not a security-certification metric.

## What passed

| Area | Executed evidence |
|---|---|
| Typed contract and governance | Exact request/disclosure schemas, rejected authority fields, uncategorized protected sources, contextual AUTO intersection, hidden tools, monotonic policy updates, and one-use manual approvals. |
| Persistence and egress | Real SQLite, exact request/final logging, no rejected candidate/source sidecar in the database, immutable final results, transactional failure rollback, interrupted tasks, and explicit transcript deletion without ledger deletion. |
| Global reassembly | Cross-workspace cumulative evidence, concurrent release serialization, varying fragment sizes/order/overlap, standalone characters, finite repeated-substring accounting, restart reconnect without unresolved-history blocking, and bounded encodings. |
| Independent algorithm check | 150 deterministic-seeded small graph cases compared with a separate exhaustive interval-placement reference. Policy intersection is checked across 640 mode/flag/risk combinations in both orders. These are cases inside tests, not additional pytest test items. |
| Human review | Full local finding payload, canonical order/deduplication, changed spans invalidating approval, cancellation/configuration races, and first valid vote semantics. |
| Process lifecycle | Real Python children and framed IPC; library output separated from protocol; cancellation cleanup; cancelled waiter isolation; worker recreation without replay; cancelled judge reply draining before stream reuse; registered orphan cleanup. These children were **not SRT-confined**. |
| Supervisor/control | An actual isolated daemon, singleton file lock, owner-only Unix socket, competing starter, process listing, clean stop-all, bounded response timeout, and synthetic transport-recovery state tests. |
| Files/media | Real Pillow PNG/JPEG/WebP input validation; real pypdf extraction; input/page/output/no-text errors; a synthetic PDF larger than 16 MiB transferred through the production parser protocol in an unconfined Python child with resource limits. PDF line-window continuation and long-line bounds are tested. |
| Scanner adapters | Synthetic detector outputs, decoded-view provenance, serial Liquid scheduling contract, unhealthy-generation disposal/reprobe, correct recognizer/entity canary matching, and a fake executable exercising Betterleaks JSON/decoded-capture handling. **No real learned-detector accuracy was measured.** |
| Resource policy/telemetry | Mock local HTTP responses exercise positive preload ownership and non-ownership cases. Real private OpenTelemetry records are filtered to fixed labels/numbers. No real Ollama residency or combined model RAM measurement was performed. |
| Evaluation tooling | Corpus split validation, real-parser graph predictions, metric calculations, accepted-profile bindings, manifest authority rejection, and detection of a single erroneous resubmission of an existing task. |

## Additional actual checks

The deterministic graph smoke corpus contains 12 scenarios and 26 output decisions. At an explicitly selected smoke threshold of 1.0, both splits had 13 decisions, zero observed false positives, and zero observed false negatives. This small synthetic result is **not learned-scanner calibration or proof of general accuracy**. See `validation/graph-smoke.json`.

An editable build/install succeeded in the pre-existing tool environment using `--no-deps --no-build-isolation --offline`. A preceding fresh virtual environment attempt failed because that environment did not have the build backend. The successful check did not resolve or install the application's dependency set. Both attempts are retained in `validation/editable-install.txt`.

Actual installed `airlock --help`, `airlock ps`, and `uv run --no-sync --active airlock` help/process-list commands exited 0. An unprovisioned startup exited 2 rather than bypassing missing components. See `validation/cli-smoke.json`. Source/tests/tools compiled; provisioning and evaluation `--help` paths also ran.

With `AIRLOCK_STRICT_ACCEPTANCE=1`, a selected missing-library integration failed with exit 1 instead of skipping. This expected negative control is saved separately in `validation/strict-acceptance-negative-control.txt`; it is not counted as a failure of the normal suite.

## Skipped integrations

Thirteen tests require unavailable packages or live assets:

- Ten library cases: actual Pydantic shared limiter, binary serialization, four native Coder/read/hook cases, real Presidio canary, FastMCP schema/legacy behavior, native Tasks cancellation, and Textual mounting.
- Three live-stack cases: complete startup with real SRT/model/scanner checks, real decoded semantic scanning, and full legacy ask/status with a durable no-disclosure receipt.

The skip report groups nine tests under the first missing `pydantic_ai` prerequisite, one under Presidio, two under FastMCP, and one under Textual. Satisfying that first import alone is not sufficient to run a live test; it also needs the configured assets and services.

Package registry resolution failed with DNS errors. A full `uv.lock` could not be produced, and a direct wheel-download attempt did not succeed. PydanticAI/Harness, FastMCP/Tasks, Textual, Presidio, Transformers/Liquid, Betterleaks, SRT, and Ollama integration behavior remains unverified here. The existing `pypdf` test version was **5.9.0**, not the intended **6.19.0** candidate. The existing uvicorn version was **0.48.0**, not the **0.53.0** candidate; native MCP HTTP serving was not executed.

## Acceptance still required

Run the full strict suite with actual pinned packages and local assets on the target Mac. Add representative adversarial/privacy calibration and inspect errors, rather than treating the bundled 24 scanner examples as representative. Execute multi-client disconnect/reconnect/server-recovery cases, multiple interactive TUIs, native background shell/judge cancellation, native image-model behavior, resource measurements, and model ownership/unload behavior on the real deployment.

No target-Mac isolation, zero-error privacy guarantee, full transitive reproducibility, plugin model-selection quality, or production certification is claimed by this report.
