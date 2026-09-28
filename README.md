# Airlock

A private local workspace agent with a separate disclosure boundary. Cloud assistants submit work through `ask`, inspect it through `status`, and cancel it through `stop`. Production behavior lives in one file, `airlock.py`.

**Development work in progress.** The redesign has been promoted to the root. Storage-cap defaults, history-deletion retry semantics, and migration of the old test/build configuration await the user's decisions. The existing `test.py`, dependency metadata, and CI still target the previous implementation. Do not treat the old installation instructions or the supplied redesign test report as validation of this checkout. Current executed evidence is recorded in [VALIDATION.md](VALIDATION.md).

[ARCHITECTURE.md](ARCHITECTURE.md) defines the design. [HOW.md](HOW.md) defines the authorized hardening contracts. The original implementation and tests are saved in commit `26d93ec`; the original redesign and review are saved in `1bd2999`. `new_design` is a historical reference, not a second active implementation.

## Interface

| Tool | Behavior |
|---|---|
| `ask(request, disclosure_request=None, request_id=None)` | Submit private local work. Without a disclosure request, return a fixed receipt. Requested information must pass scanning, cumulative fragment checks, and separate release authorization. |
| `status(task_id)` | Return fixed status labels, bounded counters, and any committed final response. |
| `stop(task_id)` | Cancel the task and its tracked processes. Completed writes remain in place. |

Use a stable `request_id` when retrying a submission. It must be nonblank UTF-8 text of at most 256 characters. The same ID and exact request/disclosure text return the same task; changed text returns `task_identity_conflict`. IDs are scoped to the connected workspace. Without an ID, identical submissions are separate tasks. Poll with `status` while work or local approval is pending.

A supervisor restart marks unfinished work interrupted and preserves completed results. Retrying an interrupted task does not rerun it. A deliberately new attempt needs a new ID. Task idempotency prevents duplicate execution; it does not make arbitrary filesystem changes transactional.

## Local controls

The worker uses the native Coder tools `read_file`, `write_file`, `edit_file`, `list_files`, `grep`, and `shell`, inside the Sandbox Runtime. OS capabilities and local governance control access; a caller's request cannot grant permissions. Privacy scanning runs on candidate disclosures, with enforce, warn, and off modes. In enforce mode, scanner failure or a privacy finding withholds the answer.

A manual release review shows the original request, disclosure purpose, workspace, effective policy/version, exact proposed answer, and full findings. A vote applies to that proposal once. Changed decision context invalidates the vote. Approval is a local operation; the cloud caller cannot answer it.

Release checks serialize across workspaces. SQLite commits the disclosure evidence and final response before the response is published. A failed commit publishes no candidate and makes the runtime unavailable.

## Preparation and limits

The complete runtime needs compatible Pydantic AI/Harness, FastMCP/Tasks, Textual, scanner/media dependencies, a pinned Sandbox Runtime, a pinned Betterleaks executable/rules, reviewed local encoder assets/helpers, and a local Ollama model with tools. Enforce/warn startup also requires an explicitly reviewed calibration profile bound to the actual source and assets. The supplied design references provisioning tools and a test corpus that are absent from this repository. No accepted live profile is supplied.

Once those prerequisites and dependency metadata are prepared, the source CLI accepts a workspace, `--headless`, `ps`, `status WORKSPACE`, and `stop WORKSPACE` or `stop --all`. The local bridge attaches to an already running workspace; it does not silently start one. A stdio MCP client uses the prepared environment's absolute Python executable with `-I -B /absolute/airlock.py _bridge /absolute/workspace`.

Protected sources are fallible model-supplied hints. An omitted or late declaration can miss a cumulative disclosure. Raw sources live in memory; after restart, old fragment evidence reconnects only when the source is declared again. Semantic answers, timing, refusal patterns, and arbitrary covert encodings are not comprehensively detected. Scanner accuracy and actual platform confinement require live evidence.

SQLite deliberately stores exact requests, disclosure purposes, and committed final responses in owner-only local history. Rejected candidates, raw source hints, tool output, and model reasoning are excluded. History is kept until explicit local deletion; automatic pruning is not authorized. Disclosure evidence must survive transcript deletion. A storage cap is authorized, with its default still pending.

Encoder custom code is a supply-chain trust decision even when pinned, reviewed, loaded offline, and sandboxed. A passing synthetic suite is not measured field privacy performance or an independent security audit.

MIT. See [LICENSE](LICENSE).
