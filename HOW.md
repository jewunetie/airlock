# Airlock promotion and hardening HOW-spec

This specification defines the authorized promotion of `new_design` to the repository root. Production behavior stays in `airlock.py`. `ARCHITECTURE.md` remains the authority for capability isolation, outbound-only scanning, fallible model-supplied sources, and explicit release governance. The existing implementation and its tests are recoverable from checkpoint `26d93ec`; the original redesign is checkpoint `1bd2999`.

## Data model

- Startup review uses `Settings`, `Governance`, and the existing `CalibrationProfile`. `Settings.calibration_acceptance: str | None` is the exact selected profile SHA-256 accepted by the local user for this workspace startup; it grants nothing when the source/assets binding or file digest changes. Existing owner-only SQLite configuration rows retain the chosen governance and calibration reference; load the latest governance for the same canonical path/device/inode, never from workspace files. No new database table or dependency is needed.

- Remove the public background-startup boolean from `CLI`. Preserve the existing workspace target, trusted configuration, presets, governance, and all attach/control models. No replacement background-startup switch is introduced.

- Approved Codex plugin: reuse `AskRequest`, task/final responses, local runtime selection, and all existing governance. The local connection is a JSON `mcpServers.airlock` stdio entry with absolute Python/source/workspace paths and `-I -B`; no token is written into it. Repository plugin metadata and skill instructions contain no private folder or credentials. Prepared dependencies use the existing `AssetSpec`, `PreparedRuntime`, and `CalibrationProfile`; calibration records measured calibration/held-out cases and remains unreviewed until local acceptance.

- Preserve the redesign's typed governance, settings, worker output, findings, task states, boundary history, and finite-occurrence fragment graphs.
- `AskRequest` contains immutable UTF-8 `request: str`, `disclosure_request: str | None`, and optional `request_id: str | None`. IDs are nonblank and at most 256 characters, matching the existing native identity bound. IDs grant no authority. Request/disclosure fields retain their existing bounds.
- A release review contains the exact request, disclosure purpose, candidate text, local workspace ID/path, effective governance, configuration version, canonical findings, and fixed scanner failures. This is private review data, never public status or content-free audit data.
- Durable retry identity is scoped to workspace and identity kind (`request` or `native`). Store HMAC identity/payload fingerprints and the original task ID. Payload comparison covers exact request and disclosure text. A task may have both identity kinds.
- Fragment geometry retains its existing normalized offsets, occurrence capacities, ordering/overlap behavior, and bounds. Optimization may remove capacity counters that cannot bind and forget counters only after their last possible placement; it must preserve exact maximum coverage.
- `Settings.max_state_bytes: int` is a positive, strict integer byte limit, defaulting to 1 GiB (1,073,741,824 bytes). One supervisor shares this limit across all workspaces. SQLite enforces the main database limit in whole pages, rounded down; rollback journals and model/scratch files are outside this database cap. No automatic pruning is authorized.
- Explicit history deletion removes completed boundary interactions in the selected workspace. Active interactions, audit/configuration records, opaque task identity/payload fingerprints, and the disclosure ledger/key remain. Deleted retry identities become durable tombstones; no raw request, purpose, or final response remains in those records.

## API contract

- Before starting a new workspace runtime, the public CLI opens a local settings screen with saved governance or current defaults, editable approval/privacy/visibility modes, and read-only scanner thresholds/held-out results. Accept validates and returns the exact `Settings`; cancel returns `None` and starts no runtime. Unreviewed measured profiles can be accepted here, independently of their global `reviewed` flag. `calibrated_settings` still verifies the exact profile digest, code/assets binding, permitted thresholds, and either existing explicit review or the workspace's exact acceptance. Missing/incompatible profiles cannot be accepted for scanning modes. Scanner sensitivity changes require a compatible measured profile and restart.
- Local `preferences(target)` returns the last saved governance for the current workspace identity, or an already-running runtime snapshot. It reads only local metadata. Explicit CLI governance overrides apply after saved workspace governance; an explicit preset starts from its configured preset instead. An existing runtime opens its current control screen. Valid new-runtime settings are recorded before readiness probes; runtime governance edits continue to persist through existing configuration versioning. Failed validation/cancellation cannot replace saved choices. Pending tasks retain policy intersection and approvals are invalidated by edits.

- Public workspace startup always opens the local Textual interface; the retired startup flag is rejected by CLI parsing before creating a supervisor. Existing `plugin`, `ps`, `status`, and `stop` remain noninteractive control operations. Internal supervisor/worker/bridge processes retain their current IPC behavior; a background supervisor is still necessary for a runtime to survive closing its screen.

- Pinned SRT invocation preserves the existing profile/role/command data and uses its explicit `-c COMMAND` CLI contract for the shell-quoted command string. Location: `SRTLauncher.spawn` in `airlock.py`; assertions in `test.py` check exact argv and unchanged deny-all networking, with the real scanner/worker probes checking execution and confinement. Startup failure remains fail-closed.
- Private scratch uses its canonical filesystem path in the profile and child environment, preserving the same directory and capabilities when the host temporary directory has a symlink alias. The SRT regression asserts the `TMPDIR` grant is canonical; live scanner probes verify temporary-cache use without allowing shared temp access.
- SRT's `CLAUDE_CODE_TMPDIR` is set to the same private scratch directory because SRT otherwise replaces `TMPDIR`. Its implicit shared `/tmp/claude` write grants are explicitly denied in both alias spellings; scratch overlapping that shared location fails with `scratch_overlap`. Existing data models/API remain unchanged. Profile/env assertions and an existing shared-temp synthetic canary test that denial with real SRT.

- Local-only `airlock plugin [PATH]` emits the stdio MCP connection JSON for an existing canonical folder (current directory when omitted). It does not start a runtime, change policy, read document contents, install dependencies, or grant cloud folder selection. `codex_mcp_config(target: Path) -> dict` validates the folder and uses the current prepared Python executable and production source. Invalid folders use the existing fixed workspace error; invalid CLI shapes use `invalid_command`. The bridge remains attach-only and fails when its selected runtime is absent. Rebinding requires regenerating the local connection and reinstalling/reloading the plugin; an existing bridge remains bound to its original runtime.

- `ask(request, disclosure_request=None, request_id=None)` admits one logical task. With no identity, intentional duplicate requests remain separate tasks. A repeated identity with identical payload returns the original task/committed result; changed payload returns a fixed identity-conflict error. A new native delivery can attach to an existing client-identified task. Identity lookup and new task creation occur in one transaction before queueing; failures schedule no work.
- Supervisor restart retains committed results and marks unfinished tasks interrupted without rerunning writes. A replay attaches to that terminal result. Storage migration preserves existing native identities and disclosure geometry.
- Freeze accepted request fields. Snapshot candidate text before awaiting approval or scanners. A manual release binds all decision-relevant review data and its configuration; a changed final review is withheld. Canonical reordering/duplication alone is immaterial.
- `graph_coverage(graph, length, max_states)` returns the exact maximum covered characters, retaining `reassembly_complexity_limit` on an exhausted search. It cannot over-count a fragment occurrence or silently approve on a bound/error.
- Existing `status` and `stop` retain their documented fixed metadata and committed-result behavior. Error responses contain fixed codes/messages, never exception text or private paths.
- Persistence failure publishes no candidate and makes the runtime unavailable for further work rather than leaving queue consumers silently dead. Transaction rollback must preserve the original failure even if SQLite already rolled back automatically.
- `StateStore(directory, max_bytes=1_073_741_824)` applies the SQLite page limit before schema/recovery writes. `set_storage_limit(max_bytes)` refuses invalid limits or limits below allocated database size with fixed `storage_limit_invalid` / `storage_limit_below_usage` errors; it never shrinks or deletes existing data. The local CLI passes the configured limit into supervisor startup, including restart/recovery. Runtime settings must agree across simultaneously active workspaces.
- At capacity, admission persistence failure schedules no work. Final persistence failure publishes no candidate. Explicit local deletion frees database pages for reuse; restarting the affected runtime is required after a persistence failure. A retained ID whose transcript was deleted returns `task_history_deleted`, including after restart, rather than re-executing work. A changed payload still conflicts.

## Location

- Startup review and calibration acceptance stay in root `airlock.py`; actual Textual startup/cancel/edit, acceptance-binding, saved-governance, runtime-edit, and CLI regressions stay in `test.py`. Root `ARCHITECTURE.md`, `README.md`, and `VALIDATION.md` describe the contract and executed limits. No private acceptance is committed in a runtime manifest or global calibration file.

- Startup cleanup: root `airlock.py`, regression assertions in `test.py`, and active command documentation in `README.md` / `ARCHITECTURE.md`. Remove the retired option from any checked-in historical design reference as well, preserving the originals in Git.

- Codex plugin metadata/skill: `plugins/airlock/.codex-plugin/plugin.json`, `plugins/airlock/skills/airlock/SKILL.md`; local marketplace: `plugins/.agents/plugins/marketplace.json`. Machine-specific `plugins/airlock/.mcp.json` is generated locally and ignored by Git. Connection generation stays in `airlock.py`; regressions remain in `test.py`; usage/evidence in `README.md`/`VALIDATION.md`. Provisioning scripts, downloaded assets, manifests, dummy files, and calibration results stay outside committed source and outside the dummy workspace. No second production Python module is introduced.

- Active production module: root `airlock.py`, promoted from the saved candidate.
- Public architecture and usage: root `ARCHITECTURE.md` and `README.md`, updated for accepted contracts.
- Dependency/build metadata and CI: root `pyproject.toml`, generated `uv.lock`, `.gitignore`, the PEP 723 source header, and `.github/workflows/tests.yml`, migrated to the redesigned contracts. One source version drives build metadata. Dependency changes and lock generation use `uv`.
- Regression suite: root `test.py`, promoted from the authorized synthetic harness. Tests use synthetic workspaces, real SQLite, and the installed MCP transport; no live private documents or model calls are needed for core tests. Retired tests remain in the checkpoint history.
- Historical design/review files in `new_design` remain a saved reference and must identify which root files are authoritative.

## Tests and assertions

- Deferred approval arguments: `run_coder` retains the validated argument dictionary keyed by tool-call ID when `tool_check` requires manual approval. `approve_tool` receives that same dictionary, including schema defaults, rather than unvalidated model JSON. Missing pending arguments fail closed with a fixed local error. Location: root `airlock.py` and actual Coder/supervisor approval assertions in `test.py`. Assert defaulted arguments are identical at approval and resumption, one-use fingerprint consumption, and a real synthetic read after approval. Existing governance, budgets, and public schemas remain unchanged.

- Authorized dummy-only live acceptance: reuse the real prepared `Settings`, pinned `CalibrationProfile`, `AskRequest`, private approval records, and final responses. A temporary `/private/tmp` Python harness presses Accept in the actual startup screen after this explicit operator authorization, starts only `/private/tmp/airlock-dummy-workspace` through the owner-only local control API, and uses the installed plugin's exact stdio connection. Test the strict manual and trusted automatic presets with read-only OS access and enforced privacy; inspect and approve only exact benign synthetic request/read/release proposals. Assert a real file read and correct disclosed answer as a positive control, one-use local decisions, idempotent replay, no-disclosure receipts, denial/withheld behavior, unchanged global profile review flag, and retained saved workspace choices. Store detailed results privately outside source; record honest live evidence and failures in `VALIDATION.md`. Do not use real private documents, relax thresholds, download weights, or stop another runtime/model service.

- Verify startup acceptance and cancellation through Textual, invalid profile/binding rejection, exact profile acceptance without altering its global review flag, per-workspace identity isolation, reload after SQLite reopen, explicit CLI precedence, and persistent runtime governance edits. Manual release remains unable to override an enforce-mode finding; warn/off require deliberate local selection. Retain actual local-socket approve/deny and full contract checks. Synthetic UI/calibration artifacts do not establish live model or scanner accuracy.
- For local review, a temporary preview harness in `/private/tmp` may load the prepared `Settings` and measured `CalibrationProfile` and export the real Textual startup screen as SVG. It must press no acceptance button, start no runtime, and leave `reviewed` false; assert matching calibration binding and no returned acceptance. The preview uses only synthetic dummy-workspace paths and operational settings. A conflicting competing start must fail explicitly rather than use different accepted rules.

- Assert CLI rejection of the retired startup flag and startup routing through Textual. Preserve and run the existing local control, manual approval UI, plugin bridge, and full contract suite. Record exact executed evidence in `VALIDATION.md`.

- Manual UI verification reuses `Governance`, exact `Approval` records, `FinalResponse`, and synthetic candidates. The existing local `review` / `decide` control API is exercised through `make_tui` with the real owner-only Unix socket and Textual test pilot, not by replacing the UI handlers. Location: assertions in `test.py`; executed evidence in `VALIDATION.md`. Check request/purpose/candidate review, approve and deny outcomes, one-use votes, and that enforce-mode findings cannot reach a manual override. No live private documents are used.

- Validate plugin metadata and selected-folder connection generation, including spaces, symlink canonicalization, nonexistent folders, strict three-tool schemas, attach-only failure, and actual stdio-to-authenticated-HTTP bridge operation against a synthetic dummy runtime. Check that the bridge cannot select another workspace through tool arguments, that no private output appears in receipts/errors, and that legitimate work succeeds. Exercise the installed plugin's connection settings. Provision pinned sandbox/scanners without re-downloading cached weights; test real confinement and scanner canaries before starting a live worker. Measure calibration and held-out cases separately, report false positives/negatives, and seek local acceptance of the concrete profile before enforced runtime startup. Never set privacy off or label fixture results as live acceptance.

The approved information-flow clarification uses the existing data model and APIs above: workspace content and derived results stay private by default, untrusted text grants no authority, and `protected_sources` is detection evidence rather than permission. Location: `ARCHITECTURE.md` for the explicit rules and boundary table; `test.py` for missing sequence checks; `VALIDATION.md` for executed evidence. No new per-file labels, runtime dependency, or public API is introduced.

Sequence checks must cover a forged approval in document text, copied private content submitted in a later task, and an unexpected worker tool. Include a legitimate read/release or properly approved action as a positive control. Existing approval-replay, policy-tightening, and restart/idempotency checks remain mandatory; do not duplicate or weaken them. Use synthetic files, scripted model responses, fixture detectors, and actual Coder/SQLite/MCP where available. These checks establish policy behavior, not real detector accuracy or OS confinement.

- Release review exposes the original question, disclosure purpose, workspace, policy/version, exact candidate, and canonical findings. One vote is consumed once. Changed request/candidate/policy/findings cannot reuse an earlier approval; reordered identical findings can.
- Repeated client/native submissions return one task and one queue entry, including competing asynchronous callers, completed tasks, and reopened databases. Changed request or disclosure conflicts; another workspace or a new ID is independent. Invalid IDs fail before persistence/execution. A real synthetic write occurs once under a retried task.
- Compare fragment coverage against an independent exhaustive interval-placement reference on seeded small graphs. Preserve repeated-character, reverse-order, overlapping, standalone-character, and decoded-fragment cases. Ordinary protected-prose fixtures must run under the unchanged minimum length and bounds; unresolved complexity still fails closed.
- Exercise actual SQLite rollback, interruption recovery, migration from the saved schema, immutable committed results, and injected persistence failure. A refused/cancelled release contributes no disclosure state; an unrelated subsequent release remains possible when storage is healthy.
- Existing architecture controls remain covered: rejected authority fields, no-disclosure fixed receipts, scanner failure, monotonic governance, cancellation during final scanning, and cross-workspace concurrent release.
- Storage tests use small configured caps to force real SQLite exhaustion. Assert bounded main database growth, transactional failure, refusal to lower below usage, enforcement after reopen, and page reuse following explicit deletion. History deletion requires its existing local confirmation, preserves other workspaces/active tasks/ledger/opaque identities, and rejects replays after deletion and reopen.
- Packaging tests assert PEP 723/project dependency agreement, source/build version agreement, successful import/name resolution, and CLI parsing/error behavior. Build a single-module wheel and verify the installed entry point. CI runs the redesigned synthetic suite and package build; it must not count absent real models/scanners/confinement as passed integrations.
- Core tests import the production module directly when its required imports are installed. Process confinement, actual scanners, model behavior, native transport, and interactive UI require separate real integration evidence; unavailable integrations cannot count as passes.

## Bounded synthetic financial protocol evaluation

Data model: `financial_golden_cases()` in `test.py` returns 16 plain dictionaries
with `id: str`, `split: str` (`regression` or `heldout`), `raw_document: str`,
`request: str`, `disclosure_request: str | None`, `expected_fields: dict[str,str]`
(decimal strings), `forbidden_values: tuple[str,...]`, `candidate: str`, and
`protected_sources: tuple[str,...]`. Additional fixture fields describe labeled
signed rows, local artifact bytes, scanner/vote controls, desired local/release
usefulness and expected current policy outcome. Raw synthetic statements retain
private identity/account values, two labeled income/expense rows, public text,
and missing/ambiguous or revision semantics. Decimal arithmetic uses stdlib
`Decimal`, with explicit cent rounding; it is bookkeeping, not tax-law arithmetic.
Predetermined desired usefulness is separate from observed enforcement.

API/errors: reuse `AskRequest`, `LocalOutput`, actual native `run_coder`,
`WorkspaceRuntime`/`Egress`, `StateStore`, and local approval records. Test data
and scripted model replies grant no permission. Correct local artifacts require
real synthetic Coder reads/writes and an independent exact byte oracle; without
disclosure the cloud receives the fixed receipt. Selected disclosure requires
the exact candidate, clean enforced privacy/reassembly and a valid one-use local
vote. Findings/failures, deny, missing votes and wrong versions withhold; exact
retry returns one execution and changed payload conflicts. Scanner fixtures and
scripted models check protocol wiring, never live scanner/model accuracy.

Location: append this specification before adding code to root `test.py`. Keep
all evaluation cases and focused assertions there; no production changes,
dependencies, live runner, runtime manifest/profile rebinding or threshold tuning.
Private execution/report evidence stays in `.superpowers/sdd`; `VALIDATION.md`
updates await actual live results in the next task.

Tests: cover public facts, selected amounts without identifiers, protected-amount
false withholding, exact decimal/signed/revised totals, missing and ambiguous
fields without invention, identifier/full-document withholding, forged document
permission, scanner failure, deny/no-vote/wrong-version, exact approval once,
retry identity and related reassembly completion. Explicit blue/green false
source declarations must withhold under a clean fixture scanner while an
undeclared public answer releases only after local consent. Financial fixture
scanning must be named separately from actual production guard execution. Run
focused assertions and one full locked suite, retain existing tests, inspect the
exact diff, and report unmet usability independently of privacy success. Heldout
cases are evaluation-only and cannot tune enforcement.

Authorized sequence extension: use the same plain financial case dictionaries
for `false-source` and `protected-amount`, the same mixed statement and runtime.
A local-only task feeds typed scripted output through the production worker
guard and Egress, registering either public blue/green hints or the financial
amount before the fixed receipt. A later selected-field task in that runtime
must withhold under a clean fixture scanner because the existing reassembly
registry retains those hints; no manual vote can override enforce. An unrelated
later answer must still release after exact manual consent. Add one parameterized
check in `test.py`, separate utility failure from privacy success, and rerun
focused checks after the already executed full suite. No production change.

## Actual synthetic financial workflow evaluation

Data model: owner-only live records contain case ID/split, workflow, production
digest, model/profile identifiers, raw synthetic document/name, original request
and disclosure purpose, exact local approval content/kind/decision, available raw
local artifact/candidate, fixed public final response, model/tool usage, expected
and extracted fields/provenance, correct/wrong/missing, released/withheld and
privacy failures separately. Reuse `financial_golden_cases()` without changing
its frozen expectations. Derive one signed/revised source with printed total
removed, preserving explicit original/revised rows and a separate Decimal oracle.
No real tax data, year, jurisdiction or tax-law arithmetic.

API/errors: existing `load_settings`, `make_startup_tui` and Textual Accept,
`control_request`, generated unchanged `codex_mcp_config` through real
`StdioTransport`/`Client` ask/status/stop, and `make_tui` approve/deny. Preserve
the compatible profile, global reviewed false, unchanged scanner thresholds and
privacy enforce. For these synthetic artifact tasks only, accept visible workspace
writes, manual request/read/write/release, hidden shell. Exact local validation
precedes each vote; deny unexpected shell, outside-workspace writes, identifiers
and full-document release. Invalid versions and approval replay reject. Same
request ID returns the same task/result without execution. Timeouts cancel owned
tasks and count as failures. Assert no existing runtime before starting and stop
only owned runtime IDs; never interrupt shared Ollama or unrelated runtimes.

Location: tracked live changes are `HOW.md` and `VALIDATION.md`; full report in
`.superpowers/sdd/tax-task-2-report.md`. Private runner is
`/private/tmp/airlock-tax-live.py`, with unique owner-only workspaces/evidence.
Use unchanged connection generator for the synthetic folder and label it generated
bridge transport, not the exact installed dummy-folder binding. Existing pinned
assets and locked dependencies only; no production, dependency, profile/manifest
rewrite, download, commit or push.

Tests: inspect processes, memory, model residency and default supervisor ps before
inference. Bounded real cases cover a natural tax-preparation request yielding a
local extraction/calculation/source-reference artifact, signed/revised or missing
field work, selected amount/derived total without identifiers, public fact,
identifier/full-document and local denial. Evaluate at least one local-only task
followed by selected-field request from the same mixed document/runtime, retaining
all source hints. Independently compare actual artifact values/provenance to raw
source and Decimal oracle; copying a stated total is insufficient. Useful artifact
and safe release are desired positive controls, never satisfied by withholding or
usage counts. Independently request 2+2 with no document access and return only its
answer. Record refused release before any local vote explicitly. Validate one-use
approvals/retry through the local UI, deny admission with zero work, and separately
classify wrong answer, withholding and privacy failure. If safe operationally,
scan predetermined golden candidates through the actual prepared ScannerService
under SRT with unchanged settings after owned runtimes stop; never load an extra
scanner concurrently or bypass egress for release. These are heldout measurements,
not tuning. Review exact changes and results; failed usability means
DONE_WITH_CONCERNS. Scripted regression reproduction remains:
`uv run --locked python -B -m pytest -q test.py -k financial`.

Authorized live PDF extension: data adds one synthetic one-page text financial
PDF from the same revised statement and one encrypted copy. Preserve raw source,
PDF bytes/digests, independent Decimal expectations, actual local artifacts and
missing/unreadable outcomes separately. API uses the installed `pypdf.PdfWriter`
and generic text/font stream objects plus stdlib to prepare synthetic input; the
evaluated agent uses current `read_file` and its PDF adapter through the unchanged
bridge and UI. Encrypted input must produce the current `pdf_encrypted` error
and no invented amount. No OCR, image model, dependency or production change.
Location: only private owner-only files in the unique live workspace and private
supplemental runner/evidence under `/private/tmp`; document executed evidence in
`VALIDATION.md` and the Task 2 report. Tests verify generated text matches the raw
statement through the current parser, encrypted input rejects through that parser,
and natural entrypoint requests actually read PDF, produce correct useful local
arithmetic/source references for text, and explicitly mark encrypted data
unavailable without invented values. These are bounded format checks and do not
establish scanned-image readiness. Do not clear prior same-runtime source state
to manufacture a release.

PDF reproduction extension: root `test.py` adds one small parametrized
`test_financial_pdf_parser` using existing golden revised raw text and installed
`pypdf`/stdlib to generate bytes in memory, never a committed binary. Data is
the original raw statement or a blank one-page PDF. API calls the unchanged
`extract_pdf_bytes(data, max_pages, max_text_bytes)`: each original text line
must survive with a page marker; blank input must raise exact `pdf_no_text`.
These two parser assertions are distinct from live sandboxed `read_file`/model
format workflows and do not prove OCR. Run focused checks before the controller's
final full suite; retain every prior test.

If the primary arithmetic-based release-denial control fails before review,
include one bounded ordinary public-fact denial in the separate format runtime.
It uses the same exact UI/vote APIs and private record fields; deny the exact
candidate if review is reached and verify local-decision withholding. A failure
to reach review remains an explicit gap, never a successful denial check.

Bounded component-failure diagnostic: data is one synthetic `Compute 2+2.`
request, exact local model payload/response or exception/traceback, usage and
source/profile digest. API calls existing `run_coder` and `ModelService.request`
once using unchanged loaded settings, recording model frames privately; deny
all proposed tools and use a local-only typed-output capture instead of cloud
egress. This diagnostic runs without SRT and cannot count as confinement or
successful guarded release evidence. Location is one owner-only private runner,
empty synthetic workspace and results under `/private/tmp`; no production or
manifest/profile changes. Tests assert no existing runtime, cached/resident model,
unchanged thresholds/global reviewed false, no accepted tool, no cloud release,
bounded completion or exact exception, and close only its owned client. A
different outcome is variation, not proof that the earlier failure is fixed.

PDF confound resolution: use a fresh owned format workspace containing only
the financial text PDF and encrypted copy, with no plaintext financial sidecar.
The natural local-output requests and independent raw-source/Decimal oracle
remain unchanged. During encrypted-input work, locally deny reads of the
unencrypted PDF or unrelated files; permit the requested encrypted PDF and its
own summary. This is exact request-scope validation, not a scanner override.
Use the same existing APIs/profile/governance, one bounded rerun, private
`/private/tmp/airlock-tax-pdf-only.py` and unique evidence. Record any immediately
committed failed admission through public status rather than assuming a queued
task appears in the runtime list. Cleanup errors remain recorded with a separate
ps check; never hide a failed task behind an artifact that happened to be written.

Cleanup diagnostic data is one owned sleeping Python child, its `ProcessTree`
watcher state and exact private exception/traceback. API uses current
`ProcessTree(pid, marker)`, watcher inspection and `terminate`; fallback cleanup
targets only that exact child. Location is owner-only `/private/tmp` diagnostic
code/results. Test waits for one bounded discovery cycle, records any watcher
or terminate exception, and verifies the owned child exits; no unrelated process
termination or production edit. A clean probe does not explain prior failures.

Bounded SRT PDF adapter diagnostic: data is the existing generated text/encrypted
PDF and exact adapter output/error plus owned tree watcher/close status. API uses
`SRTLauncher` and original `worker_child`, with an owner-only copied module and
private wrapper replacing only its local `run_coder` entry with calls to current
`read_media_bytes`/`read_pdf_in_worker`; no model or egress. The wrapper/digest are
diagnostic-specific, not the installed bridge or scanner profile. Location is
owner-only `/private/tmp/airlock-tax-pdf-adapter-diagnostic.py` and private source,
state/results, with the existing PDF-only synthetic workspace read-only. Tests
run real SRT probes, preserve PDF limits, verify text or record exact fixed error,
reject encrypted input, capture owned watcher/close exceptions and close only
that child. This isolates adapter success from the model's optional grep fallback
without editing production or claiming cloud release.

## Actual SRT arithmetic and cleanup diagnosis

Data model: private records preserve the original `Compute 2+2.` request and
`Return only the answer.` purpose, production/model/profile/settings identifiers,
incoming/outgoing IPC operation names, exact local parent-model and child-Coder
exception types/stacks, raw synthetic LocalOutput, startup/completion flags,
owned ProcessTree watcher state/exception and PID/create-time/status snapshots,
and close result. No real tax files or unrelated-process environments are read.

API/errors: reuse run_coder, ModelService, SRTLauncher/SandboxProcess, ChildChannel
and ProcessTree for one bounded actual SRT run after real startup probes. A
private entry/module copy adds exception tracing only; installed code/supervisor
remain unchanged and normal outward errors stay fixed. Deny all proposed tools
for this arithmetic request. A local-only guard observer captures typed output;
this is not successful guarded release. Snapshot watcher state before close and
capture the exact terminate/close exception without suppressing failure. Stop
only owned child/jobs/clients; retain shared Ollama. If it succeeds, inspect the
original runtime/control lifecycle rather than assigning an unproven cause.

Location: HOW.md precedes owner-only
`/private/tmp/airlock-tax-srt-diagnostic.py` and unique private artifacts. Record
evidence in VALIDATION.md and `.superpowers/sdd/tax-task-3-report.md`. No production
or test edit until a concrete defect, controller review and defect-specific
four-part HOW. Preserve all earlier task edits and evidence.

Tests: assert actual SRT startup probes; require response `4` whenever output is
produced; separately count model/tool requests, worker/model/guard/close faults.
Record private watcher state before close and exact known process identities;
verify owned processes gone, default supervisor empty and shared model retained.
Absence alone never proves cause. Diagnostic trace remains local, never cloud
release. No resource/policy weakening or dependency/profile change.

## Pending macOS PDF monitored-memory proposal (not approved)

Data model: existing settings.pdf_memory_mb remains the configured memory cap;
Linux retains hard RLIMIT_AS enforcement. On macOS proposed monitoring measures
owned PDF child's resident memory and can briefly overshoot between samples.
Private records would retain only exact synthetic errors and known process IDs.

API/errors: proposed owned PDF-child RSS monitor terminates that child on excess,
returns fixed pdf_memory_limit and stops monitor/child on completion, unreadable,
encrypted, blank, parser failure and cancellation. Exact private format-error
tracing requires approval; normal public errors stay fixed. This semantic change
requires human choice before implementation; no resource enforcement is removed.

Location: if approved, minimum changes stay in airlock.py and test.py, with HOW.md
and VALIDATION.md recording contract and evidence; no dependency/module addition.
Source changes invalidate current calibration bindings; no silent acceptance or
profile rewrite. This section is preparation only.

Tests: actual SRT text PDF must extract original source, unreadable/encrypted
must invent no amounts, cap overage/cancel/failure must leave no owned PDF process
or monitor, Linux limits remain unchanged. Existing direct-parser checks are not
substitutes for actual child integration; cap sampling overshoot remains explicit.

Native macOS limit probe (read-only diagnosis): data is each fresh owned Python
child's PID, current RSS/VMS, existing limit tuple and exact exception or success
from unchanged 512 MiB RLIMIT_AS or RLIMIT_DATA assignments. API starts separate
short-lived children, each tries one limit without allocations, settings changes,
or inference; controller records fixed/private evidence and verifies child exit.
Location is one owner-only `/private/tmp/airlock-tax-native-limit-probe.py` and
private diagnostic evidence, with this HOW preceding code. Tests assert both
children execute and exit, preserve exception type/message rather than treating
unsupported hard limits as success, and make no new enforcement claim. Kernel
main-branch source is supporting evidence, not proof of the installed version.

## Authorized PDF hard-limit error clarity (Task 4)

Data model: retain existing Settings.pdf_memory_mb/pdf_timeout and all hard
resource limits. Add only fixed private error code pdf_resource_limit_unavailable
for inability to install a required PDF child resource limit; no exception text,
host paths, limit values or resource measurements enter normal IPC/tool output.
No new stored entity, user setting, dependency or PDF acceptance mode.

API/errors: proposed pdf_child narrowly catches ValueError/OSError from required
setrlimit assignments, sends one negative framed initialization reply with the
fixed code, and returns before acknowledgement, PDF chunks or parser execution.
All existing hard caps stay required. read_pdf_in_worker preserves this exact
allowlisted code rather than collapsing it to pdf_unavailable; unknown codes
remain pdf_unavailable and MemoryError remains pdf_memory_limit. run_coder's
PDF read hook converts only this code to fixed ToolFailed text stating required
PDF resource limits could not be applied and the file was not parsed. All other
format failures retain existing fixed wording. Close/kill/wait/cancellation
behavior remains unchanged; private failures cannot become a successful result.

Location: authorized minimum edits are root airlock.py pdf_child,
read_pdf_in_worker exchange and run_coder execute_tool; regressions in test.py,
contract/evidence in HOW.md/VALIDATION.md. README.md's existing Preparation and
limits section records the required-hard-limit refusal and exact fixed local
model error in one sentence. This documentation alignment is authorized for
Task 4; no source/test change or blanket platform/readiness claim.
No source/calibration acceptance rewrite.
Any production source change invalidates existing live calibration bindings.

Tests: real owned PDF child with a test-only injected setrlimit ValueError must
send the exact negative framed reply and exit; a parser sentinel must prove no
PDF parsing occurred, and no chunk exchange follows failed init. Successful
limit setup retains a positive actual framed acknowledgement/text extraction
control on supported platforms, while this macOS host's real unchanged cap must
report unavailable rather than count as parse success. Assert allowlisted error
propagation, unknown error fallback, exact safe ToolFailed wording, unchanged
memory/format errors, and owned-child cleanup on failure/cancellation. Preserve
existing Linux hard-limit assertions. Focused boundary tests precede one final
full locked suite; actual SRT resource failure remains an explicit integration
limit, not PDF readiness. Controller authorized this exact bounded contract
for Task 4 under the human's architecture-aligned hardening request. The
separate monitored-memory proposal remains unapproved.

## Authorized process cleanup edge cases (Task 4)

Data model: retain ProcessTree's existing PID/create-time process objects,
owned marker, known ancestry and watcher. psutil as_dict may supply uids=None
after AccessDenied or ZombieProcess. Tracked identities may disappear between
is_running and status; neither condition proves an original live failure cause.

API/errors: discover skips unavailable UID metadata and never reads another
process environment without same-user UID evidence. Existing ancestry tracking
and denied-access handling remain. terminate treats only NoSuchProcess in final
survivor verification as gone; zombies retain existing handling, and running
non-zombie survivors still raise process_cleanup_failed. AccessDenied/other
uncertain survivor errors and watcher faults remain failures. Keep terminate,
wait, kill and final verification; never publish before successful cleanup.

Location: minimum inline changes in root airlock.py ProcessTree.discover and
terminate; focused regressions in root test.py and executed evidence in
VALIDATION.md and .superpowers/sdd/tax-task-4-report.md. Preserve prior work.

Tests: reproduce nullable UID through actual psutil as_dict AccessDenied;
prove unknown-user environment is not read and genuine marked owned-child
discovery/termination succeeds. Assert already-gone status race succeeds while
live non-zombie and AccessDenied survivors fail; watcher faults stay visible.
Run focused locked checks, record failing-before/passing-after evidence and
fresh review. Controller runs the final full locked suite. Do not rewrite
source/profile bindings or claim original live cleanup/arithmetic is fixed.

## Authorized Task 4 test portability and provisioning isolation corrections

Data model: one owned fresh Python child's fixed limit-capability result after
the same production imports, one-thread executor, ChildChannel initialization
and Settings as pdf_child. Existing synthetic PDF bytes remain the positive
extraction control. Storage test owns a temporary prepared root containing a
current-source copy and valid PreparedRuntime manifest; active ignored manifest
and calibration/profile bytes are retained unchanged.

API/errors: independently attempt every required RLIMIT_AS/CPU/FSIZE assignment
in that child, record installed or exact fixed resource-limit-unavailable only
for ValueError/OSError. Other failures fail the test. Require actual reader
extraction when the probe installs caps, otherwise exact resource failure;
never accept either outcome without probe evidence or infer from platform name.
Storage test calls the original prepared_settings against its owned root through
a test-only wrapper, preserving real validation/package/source checks. Tampering
with only the owned source must make load_settings raise asset_hash_mismatch.
No production bypass, live rebinding, acceptance or dependency change.

Location: root test.py actual-platform PDF check and existing storage-limit
configuration/reopen check; HOW.md precedes edits; VALIDATION.md and
.superpowers/sdd/tax-task-4-report.md retain controller full-suite failure and
corrected targeted evidence. Production source stays unchanged.

Tests: retain all boundary failure/positive controls and storage cap/reopen
assertions. Probe is owned, bounded and reaped; active manifest/profile digest
comparison must prove byte identity. Run only 23 boundary cases plus the storage
configuration check; record controller's 127 passed/1 failed full-suite result
as an actual prior failure. Fresh review and git diff --check precede handoff;
controller/reviewer performs subsequent full verification.

## Measured preparation candidate only (Task 5)

Data model: reuse PreparedRuntime, Settings and CalibrationProfile, with the
current actual source digest, pinned assets/packages/model, original synthetic
calibration and heldout corpus, and separately measured findings/errors. Fix
pii_threshold=0.3, policy_threshold=0.5, policy_overrides={}, and
reassembly_fraction=1.0 after verifying the approved old profile. Preserve raw
corpus/provenance. Candidate reviewed=false, calibration_acceptance=None, with
unchanged governance. Private before/after active manifest/profile/settings
digests and candidate source/profile identifiers prove no activation. All
candidate artifacts are owner-only in one unique /private/tmp directory.

API/errors: validate existing trusted prepared Settings directly for low-level
measurement without claiming the stale binding is current. Use actual
SRTLauncher/ScannerService startup positive/negative canaries, then one scan of
each original calibration/heldout case with fixed thresholds. No grid/tuning or
live admission. Compute false positives/negatives against independent labels.
Build a fresh measured CalibrationProfile via calibration_binding of final
source, measured time and corpus digest, reviewed=false. Build candidate
PreparedRuntime with that profile, unchanged assets/packages, and an exact
current airlock.py private copy so prepared_settings(candidate_root) verifies
it. Candidate Settings must pass load_calibration and fail calibrated_settings
without explicit acceptance. Render/cancel actual make_startup_tui with Textual
test pilot; never Accept. Scanner/probe failures prevent a valid candidate.
Close only owned scanner; preserve empty shared supervisor and shared Ollama.

Location: HOW.md/VALIDATION.md documentation, private
/private/tmp/airlock-tax-refresh-candidate.py, unique candidate root/state/profile/
corpus/results/source copy/optional preview, and
.superpowers/sdd/tax-task-5-report.md. No installed manifest, Application Support
assets/profile/settings, plugin, SQLite acceptance, production/test or dependency
changes; no second shipped module, commit or push.

Tests: assert active files byte-identical, existing runtimes empty, shared model
unchanged with no generative inference, actual scanner startup healthy and every
case free of failed detectors. Preserve independent split totals/errors, disjoint
splits distinct from canaries, exact source/profile/asset/package binding verified
by existing APIs, unreviewed refusal, and actual startup cancellation returns
None/starts no runtime. Verify owned scanner/job processes gone and shared model/
supervisor retained. Record failed measurements honestly, fresh review and
diffcheck. No broad suite repetition for documentation-only work. Explicit
operator acceptance/activation remains required.
