# Airlock

Historical candidate saved at commit `1bd2999`. The active implementation and current validation are now at the repository root. This original document references provisioning tools and test artifacts that were not supplied in this directory; consult root `README.md`, `ARCHITECTURE.md`, and `VALIDATION.md` for the current state.

A local workspace agent with an explicit disclosure boundary. Cloud assistants use `ask`, `status`, and `stop`; a private Pydantic Coder worker operates inside SRT. Privacy checks run only on candidate disclosures, never on ordinary local reads.

**Status: development candidate.** Core regression tests execute, but the complete Pydantic Coder/SRT/Ollama/scanner/FastMCP stack has not been run in the implementation environment. Do not use a passing core suite as evidence of target-Mac isolation or calibrated scanner accuracy. See [TEST_REPORT.md](TEST_REPORT.md) and [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

[ARCHITECTURE.md](ARCHITECTURE.md) defines the current system. [THREAT_MODEL.md](THREAT_MODEL.md) states its security boundaries. Application logic is in `airlock.py`; tests and provisioning/evaluation tools are separate.

## What it does

`ask(request, disclosure_request=None)` submits local work. Without a disclosure request, only a fixed completion receipt can return. With one, the model's candidate answer passes local scanning, cumulative reassembly, and release authorization. `status(task_id)` reports fixed labels/counters and any committed final result. `stop(task_id)` cancels work without claiming to undo completed writes.

The native Coder tools are `read_file`, `write_file`, `edit_file`, `list_files`, `grep`, and `shell`. Delegation is disabled. Text reads use the library reader; a small same-name adapter provides local image input and bounded PDF text extraction. A text-only model cannot see images. Image-only PDFs do not become readable through hidden OCR.

Protected values/facts are supplied separately by the local model as uncategorized strings. They are fallible hints, not a complete trusted inventory. Raw values remain in memory; one per-user ledger keeps HMAC identifiers and finite disclosure geometry. Restart does not block the workspace waiting for old source strings to reappear.

## Provision before running

Use Python 3.12 or 3.13 on macOS/Linux. `pyproject.toml` lists direct dependency candidates. There is **no supplied resolved `uv.lock`**: package resolution failed because registry DNS was unavailable. Resolve and review the complete dependency set on the target machine rather than assuming all direct candidates are compatible.

```sh
uv sync --extra test --extra evals
```

Provision the following independently, before starting Airlock:

1. A pinned Anthropic Sandbox Runtime and its platform prerequisites. Pin the full SRT package tree, runtime, and executable; do not use an auto-downloading `npx` command as the runtime executable.
2. A pinned Betterleaks executable and explicit local rules. The rules must match the production startup canary shown by `SCANNER_CANARIES` in the source. Online credential validation is not used.
3. Exact local revisions of LiquidAI's LFM2.5 Encoder 350M PII Detector and Policy Linter, with tokenizer/model files and reviewed custom Python helpers. The PII adapter expects `pii_hybrid_decode.py` and `context_cued.py`. The policy adapter expects the rule-pooling model interface. Materialize regular files rather than cache symlink trees.
4. The reviewed local Transformers dynamic-module cache for those assets, prepared during provisioning. Runtime loading is offline; it must not download missing modules or assets.
5. A local-only Ollama service with the selected model already installed. Airlock checks its exact name/digest and tool capability; native image reads additionally require a vision-capable model. Set Ollama's own local-only/single-inference configuration before launching it. Airlock does not certify an independently started service's environment.

Copy `provision.example.toml` **outside the workspace**, replace every placeholder, and restrict it to the owning user. The example does not contain pretend verified hashes.

```sh
chmod 600 /absolute/provision.toml
uv run --no-sync python tools/prepare.py \
  --config /absolute/provision.toml --inventory-only
```

This records local asset/package/source pins in `runtime.manifest.json` next to `airlock.py`. It does not download assets or alter workspace governance. It queries local Ollama metadata, but does not preload a model.

### Calibrate and review

Operational canaries establish basic scanner function; they are not accuracy calibration. Use a labeled adversarial corpus with **separate calibration and held-out cases**, representative private-content classes, benign cases, fragments, and encodings. The included `tests/corpus/calibration.json` is a small synthetic smoke corpus, not enough to certify deployment accuracy.

```sh
uv run --no-sync python tools/calibrate.py \
  --manifest runtime.manifest.json \
  --corpus /absolute/reviewed-corpus.json \
  --output /absolute/calibration.json
```

The utility executes each scanner threshold candidate through the real SRT/scanner adapters. It selects using the calibration split, evaluates held-out cases afterward, and records measured false positives/negatives. It does not infer accuracy from test doubles or apply the policy encoder's scores as if they were another detector's scores. `pii_threshold` is the structured Presidio threshold; Liquid PII uses its vendor hybrid decoder, whose output is not assigned an invented confidence score.

Inspect the profile and `.report.json`, revise inadequate corpus coverage, and explicitly set `reviewed` to `true` only after accepting the results. Preparation pins the reviewed bytes:

```sh
uv run --no-sync python tools/prepare.py \
  --config /absolute/provision.toml --calibration /absolute/calibration.json
```

Enforce/warn startup rejects missing, changed, or unreviewed calibration. No measured profile is included because the real learned scanners could not be executed here. Updating source/model/scanner assets invalidates the binding and requires re-evaluation and preparation; this conservative development workflow is intentional.

An optional user `config.toml` controls governance and limits. Find its path using:

```sh
uv run --no-sync python -c 'from platformdirs import user_config_path; print(user_config_path("airlock") / "config.toml")'
```

Use `config.example.toml`, owner-only permissions, and explicit `--config` when appropriate. Airlock does not read workspace `.env` or `.airlock.toml` as policy. Manifest settings cannot contain a preset or governance override.

## Run and connect

```sh
uv run --no-sync airlock /absolute/workspace
uv run --no-sync airlock /absolute/workspace --headless
uv run --no-sync airlock ps
uv run --no-sync airlock status /absolute/workspace
uv run --no-sync airlock stop /absolute/workspace
uv run --no-sync airlock stop --all
```

From an already prepared project, plain `uv run airlock` is also the intended developer entrypoint. An omitted workspace means `.`. Stopping all runtimes also shuts down the supervisor; a later invocation starts a fresh one. Stop the old supervisor before running changed code.

Configure a stdio-only MCP client to execute the prepared environment's Python directly:

```text
command: /absolute/checkout/.venv/bin/python
args: ["-I", "-B", "/absolute/checkout/airlock.py", "_bridge", "/absolute/workspace"]
```

Start the workspace locally first. The bridge never silently creates a runtime. It retrieves a transient token through owner-only local control and attaches to the authenticated loopback endpoint. No publicly reachable server or persistent bearer-token file is needed.

Clients with negotiated MCP Tasks receive native task handling. Legacy clients use a quick `ask` receipt and later `status`. Never repeatedly submit `ask` merely because approval or work is pending. `disclosure_request` asks for information; it cannot weaken privacy or authorize filesystem access.

The Textual UI lists approvals and local state, permits exact approval/denial, edits runtime governance, stops tasks, and views/deletes interaction history. A headless manual approval waits for the local user. It is never delegated to the cloud caller.

## Storage and resource behavior

On macOS the usual private state directory is `~/Library/Application Support/airlock/`; use `platformdirs.user_state_path("airlock")` to determine the configured location. `airlock.sqlite` intentionally retains exact accepted ask/disclosure fields and committed final responses indefinitely. This is sensitive local history, not content-free telemetry. The UI requires `DELETE HISTORY` to remove terminal transcripts; deletion does not reset disclosure protection.

Raw rejected candidates, raw `protected_sources`, internal messages, tool output, and judge explanations are not added to that log. Files intentionally written by tools are ordinary workspace files. Native Coder shell jobs need temporary output/status files: private memory-backed scratch is preferred on Linux; on macOS scratch may be disk-backed until cleanup. No guarantee of secure erasure from swap, snapshots, SSD blocks, or backups is made.

Pydantic's filesystem checks are not a shell sandbox. The complete worker runs under SRT. Airlock enables the library's unrestricted-filesystem mode **inside that sandbox** so native tools can read task scratch as well as the workspace. This removes the library's protected-file patterns; SRT and Airlock tool policy are the operative boundaries. In particular, an approved write-capable shell can edit `.git` or `.env` inside its permitted workspace. Keep workspace OS writes disabled unless needed.

Task-owned subprocesses are tracked and stopped before release. A portable process tracker is not a proof against malicious daemonization/environment scrubbing. Registered scratch/jobs are also cleaned after supervisor restart. Completed file changes are not rolled back.

The local judge uses the same model and shared inference limiter as the worker, not a remote evaluator. Both Liquid encoders remain resident while the shared scanner is active, but their forward passes are serialized. Closing the last runtime tears down shared scanner/model clients. Ollama unloading requires `ollama_exclusive=true`, a genuinely dedicated endpoint, and a model that Airlock itself preloaded after observing it absent. Preexisting/shared residency is not treated as owned.

## Validate

```sh
uv run --no-sync python -m pytest
AIRLOCK_LIVE_CONFIG=/absolute/config-with-assets.toml \
AIRLOCK_STRICT_ACCEPTANCE=1 \
  uv run --no-sync python -m pytest
```

The first command reports unavailable integrations as skips. The strict command fails when dependencies/live assets are missing. Live tests use temporary synthetic workspaces but run actual local services. Ensure the prepared manifest is present or include the complete pinned settings in `AIRLOCK_LIVE_CONFIG`.

For cloud tool-selection checks against a chosen model:

```sh
uv run --no-sync python tools/evaluate_plugin.py \
  --model <provider:model> --output /absolute/plugin-evaluation.json
```

The evaluation exposes synthetic tool stubs, not a real workspace. External providers, if deliberately chosen for that developer evaluation, receive only the synthetic cases. Evaluate actual target models and inspect their mistakes before declaring the plugin calibrated. No provider credentials, workspace content, or hidden transcript is bundled here.
