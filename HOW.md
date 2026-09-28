# Airlock promotion and hardening HOW-spec

This specification defines the authorized promotion of `new_design` to the repository root. Production behavior stays in `airlock.py`. `ARCHITECTURE.md` remains the authority for capability isolation, outbound-only scanning, fallible model-supplied sources, and explicit release governance. The existing implementation and its tests are recoverable from checkpoint `26d93ec`; the original redesign is checkpoint `1bd2999`.

## Data model

- Preserve the redesign's typed governance, settings, worker output, findings, task states, boundary history, and finite-occurrence fragment graphs.
- `AskRequest` contains immutable UTF-8 `request: str`, `disclosure_request: str | None`, and optional `request_id: str | None`. IDs are nonblank and at most 256 characters, matching the existing native identity bound. IDs grant no authority. Request/disclosure fields retain their existing bounds.
- A release review contains the exact request, disclosure purpose, candidate text, local workspace ID/path, effective governance, configuration version, canonical findings, and fixed scanner failures. This is private review data, never public status or content-free audit data.
- Durable retry identity is scoped to workspace and identity kind (`request` or `native`). Store HMAC identity/payload fingerprints and the original task ID. Payload comparison covers exact request and disclosure text. A task may have both identity kinds.
- Fragment geometry retains its existing normalized offsets, occurrence capacities, ordering/overlap behavior, and bounds. Optimization may remove capacity counters that cannot bind and forget counters only after their last possible placement; it must preserve exact maximum coverage.
- `Settings.max_state_bytes: int` is a positive, strict integer byte limit, defaulting to 1 GiB (1,073,741,824 bytes). One supervisor shares this limit across all workspaces. SQLite enforces the main database limit in whole pages, rounded down; rollback journals and model/scratch files are outside this database cap. No automatic pruning is authorized.
- Explicit history deletion removes completed boundary interactions in the selected workspace. Active interactions, audit/configuration records, opaque task identity/payload fingerprints, and the disclosure ledger/key remain. Deleted retry identities become durable tombstones; no raw request, purpose, or final response remains in those records.

## API contract

- `ask(request, disclosure_request=None, request_id=None)` admits one logical task. With no identity, intentional duplicate requests remain separate tasks. A repeated identity with identical payload returns the original task/committed result; changed payload returns a fixed identity-conflict error. A new native delivery can attach to an existing client-identified task. Identity lookup and new task creation occur in one transaction before queueing; failures schedule no work.
- Supervisor restart retains committed results and marks unfinished tasks interrupted without rerunning writes. A replay attaches to that terminal result. Storage migration preserves existing native identities and disclosure geometry.
- Freeze accepted request fields. Snapshot candidate text before awaiting approval or scanners. A manual release binds all decision-relevant review data and its configuration; a changed final review is withheld. Canonical reordering/duplication alone is immaterial.
- `graph_coverage(graph, length, max_states)` returns the exact maximum covered characters, retaining `reassembly_complexity_limit` on an exhausted search. It cannot over-count a fragment occurrence or silently approve on a bound/error.
- Existing `status` and `stop` retain their documented fixed metadata and committed-result behavior. Error responses contain fixed codes/messages, never exception text or private paths.
- Persistence failure publishes no candidate and makes the runtime unavailable for further work rather than leaving queue consumers silently dead. Transaction rollback must preserve the original failure even if SQLite already rolled back automatically.
- `StateStore(directory, max_bytes=1_073_741_824)` applies the SQLite page limit before schema/recovery writes. `set_storage_limit(max_bytes)` refuses invalid limits or limits below allocated database size with fixed `storage_limit_invalid` / `storage_limit_below_usage` errors; it never shrinks or deletes existing data. The local CLI passes the configured limit into supervisor startup, including restart/recovery. Runtime settings must agree across simultaneously active workspaces.
- At capacity, admission persistence failure schedules no work. Final persistence failure publishes no candidate. Explicit local deletion frees database pages for reuse; restarting the affected runtime is required after a persistence failure. A retained ID whose transcript was deleted returns `task_history_deleted`, including after restart, rather than re-executing work. A changed payload still conflicts.

## Location

- Active production module: root `airlock.py`, promoted from the saved candidate.
- Public architecture and usage: root `ARCHITECTURE.md` and `README.md`, updated for accepted contracts.
- Dependency/build metadata and CI: root `pyproject.toml`, generated `uv.lock`, `.gitignore`, the PEP 723 source header, and `.github/workflows/tests.yml`, migrated to the redesigned contracts. One source version drives build metadata. Dependency changes and lock generation use `uv`.
- Regression suite: root `test.py`, promoted from the authorized synthetic harness. Tests use synthetic workspaces, real SQLite, and the installed MCP transport; no live private documents or model calls are needed for core tests. Retired tests remain in the checkpoint history.
- Historical design/review files in `new_design` remain a saved reference and must identify which root files are authoritative.

## Tests and assertions

- Release review exposes the original question, disclosure purpose, workspace, policy/version, exact candidate, and canonical findings. One vote is consumed once. Changed request/candidate/policy/findings cannot reuse an earlier approval; reordered identical findings can.
- Repeated client/native submissions return one task and one queue entry, including competing asynchronous callers, completed tasks, and reopened databases. Changed request or disclosure conflicts; another workspace or a new ID is independent. Invalid IDs fail before persistence/execution. A real synthetic write occurs once under a retried task.
- Compare fragment coverage against an independent exhaustive interval-placement reference on seeded small graphs. Preserve repeated-character, reverse-order, overlapping, standalone-character, and decoded-fragment cases. Ordinary protected-prose fixtures must run under the unchanged minimum length and bounds; unresolved complexity still fails closed.
- Exercise actual SQLite rollback, interruption recovery, migration from the saved schema, immutable committed results, and injected persistence failure. A refused/cancelled release contributes no disclosure state; an unrelated subsequent release remains possible when storage is healthy.
- Existing architecture controls remain covered: rejected authority fields, no-disclosure fixed receipts, scanner failure, monotonic governance, cancellation during final scanning, and cross-workspace concurrent release.
- Storage tests use small configured caps to force real SQLite exhaustion. Assert bounded main database growth, transactional failure, refusal to lower below usage, enforcement after reopen, and page reuse following explicit deletion. History deletion requires its existing local confirmation, preserves other workspaces/active tasks/ledger/opaque identities, and rejects replays after deletion and reopen.
- Packaging tests assert PEP 723/project dependency agreement, source/build version agreement, successful import/name resolution, and CLI parsing/error behavior. Build a single-module wheel and verify the installed entry point. CI runs the redesigned synthetic suite and package build; it must not count absent real models/scanners/confinement as passed integrations.
- Core tests import the production module directly when its required imports are installed. Process confinement, actual scanners, model behavior, native transport, and interactive UI require separate real integration evidence; unavailable integrations cannot count as passes.
