# Airlock Architecture

## 1. Purpose

Airlock lets a cloud assistant delegate work to a private local workspace without receiving direct filesystem access. A local model performs the work through governed tools inside an operating-system sandbox. Only an explicitly requested, locally authorized response may return to the cloud.

Authorization determines which operations are permitted. The sandbox determines what a process can reach. Privacy checks and release governance determine what information may leave.

Airlock runs on one user's macOS or Linux computer. Production supervision lives in `airlock.py`; local tools and explicit extension registration live in `airlock_tools.py`. Dependencies, model assets, configuration, tests, documentation, and development tools are separate.

## 2. Components

| Component | Responsibility |
|---|---|
| Pydantic Settings | One typed configuration shared by startup, CLI, runtime, and UI |
| Textual | Local runtime status, approvals, settings, and interaction history |
| Supervisor | Runtime registry, local control, task queues, shared resources, and release coordination |
| filelock | One supervisor per operating-system user |
| FastMCP and its Tasks extension | Authenticated local MCP transport and protocol task lifecycle |
| Pydantic AI Harness Coder | Native file, edit, discovery, search, and shell tools |
| PydanticAI | Agent execution, tool schemas, approvals, bounded retries, usage limits, cancellation, and instrumentation |
| Anthropic Sandbox Runtime (SRT) | Operating-system filesystem and network restrictions for workers and their children |
| Ollama | Local model serving, model residency, inference, and transient model caches |
| Optional fixed Linux PDF parser | Supervisor-owned bounded byte parsing through an explicitly pinned local Docker daemon/image; one job at a time |
| Betterleaks, Presidio, Liquid PII, Liquid Policy Linter | Independent offline disclosure checks |
| Reassembly controller | Cumulative, source-relative fragment matching |
| SQLite | Boundary interaction logs, opaque disclosure state, and safe operating metadata |

## 3. Process topology

```text
Local CLI / Textual
         |
         | owner-only Unix socket
         v
Airlock supervisor <------ authenticated loopback MCP ------ Cloud assistant
         |
         +-- Workspace runtime A -- SRT Coder worker A -- Workspace A
         +-- Workspace runtime B -- SRT Coder worker B -- Workspace B
         |
         +-- Shared model service -- local Ollama
         |      one Pydantic inference limiter for worker and judge calls
         |
         +-- Shared SRT scanner process
         |      Betterleaks / Presidio / Liquid PII / Liquid Policy
         |
         +-- Global disclosure ledger and release lock
         +-- Optional fixed PDF slot -- owned short-lived Linux parser
         +-- Local SQLite interaction history
```

Worker and scanner processes communicate with the supervisor through inherited, bounded, framed pipes. They do not need network access, including access to loopback services. Only the supervisor communicates with Ollama and serves the authenticated MCP endpoint.

There is no custom filesystem broker. The complete Coder worker and its subprocess tree run inside SRT. Trusted runtime code and libraries, the selected workspace, and private task scratch are explicit read grants. Writes are limited to task scratch and, when locally enabled, the workspace. State, keys, logs, and unrelated user data are outside worker grants.

## 4. Trust and security limits

The local operator, host operating system, installed Airlock code, pinned dependencies, scanner implementations, and local model-serving service are trusted components.

An explicitly configured `pdf_parser` additionally trusts the pinned local Docker daemon, immutable Linux image, generated helper/package bundle and fixed syscall policy. This parser runs outside the worker's inherited SRT boundary. The worker retains its original SRT grants and receives no Docker socket or lifecycle authority. The supervisor parses only bounded already-read bytes associated with an exact authorized Coder read; bytes do not prove their filesystem origin against a malicious worker with existing read capabilities. Docker VM/daemon buffers, swap and crash dumps can retain transient data; container removal is not secure erasure.

Cloud requests, workspace documents, model decisions, tool proposals, candidate responses, and model-supplied protected sources are untrusted inputs. A model cannot authorize its own actions or override a release decision.

Confidentiality and authority are separate. Workspace content and results derived from it are private by default, including summaries and copies written back to disk. Renaming a file, starting another task, or obtaining a clean scan does not itself authorize disclosure. Only the configured release policy can authorize a specific candidate; privacy checks still apply in enforce mode.

A document can be both private and untrusted. Statements inside documents, tool output, requests, or model responses that claim approval are data, not local approval records. `protected_sources` helps detect cumulative disclosures; adding or omitting a source never grants permission. These rules do not require an input inventory or a per-file classification database.

The local model may make mistakes or follow prompt injections. Scanners and reassembly provide best-effort disclosure prevention for defined, tested classes. They do not prove that arbitrary natural-language output reveals no private information. Paraphrases, omitted source declarations, inference, unknown encodings, timing, and other covert channels remain limitations. A human release decision is explicit authorization, not an infallible disclosure detector.

SRT is the process capability boundary. Tool approval does not create a separate per-system-call boundary inside an already authorized process. In particular, approving a shell command authorizes that command to use its SRT-granted capabilities; hiding `write_file` alone cannot make a write-capable shell read-only. Changes to OS write capability require worker/runtime restart.

A malicious same-user process outside SRT, a compromised kernel, physical compromise, and replacement of trusted installed code are outside the threat model. Owner-only permissions do not defend against the owning user or a process with equivalent privileges.

## 5. Workspace and runtime lifecycle

A workspace is identified by its canonical real path, with device/inode checks during a runtime's lifetime. Duplicate starts attach to the existing runtime.

Overlapping roots are rejected only while their runtimes are active. Stopping a child workspace does not permanently prohibit a parent workspace. Disclosure history is global to the local user, so changing workspace scope does not create an independent history for a source already known to the ledger.

```text
ABSENT -> STARTING -> READY <-> ACTIVE -> DRAINING -> STOPPED
               |                 |
               v                 v
             FAILED          UNAVAILABLE
```

Startup validates configuration, pinned assets, accepted calibration, model availability, required scanner health, SRT probes, state access, and MCP startup before reporting readiness. A replaced, removed, or inaccessible workspace becomes unavailable.

Starting a new runtime first opens a local settings screen. The operator sees the workspace, saved rules or configured defaults, editable approval/privacy/visibility modes, and the measured scanner profile. Accepting starts with those exact rules; cancelling starts no runtime. Valid choices are retained in owner-only configuration history before readiness probes. A running workspace opens its current control screen, where explicit governance edits are saved. Scanner findings cannot override the chosen rules or accept their own configuration.

Each workspace executes one task at a time and queues additional tasks. Workspace runtimes share expensive model and scanner resources rather than loading a copy per workspace.

The public commands are:

```text
airlock [PATH]
airlock ps
airlock status [PATH|ID]
airlock stop [PATH|ID]
airlock stop --all
airlock plugin [PATH]
```

An omitted target means the current directory. The developer workflow is `uv run airlock` from a prepared local repository. Closing a TUI does not stop its runtime. A cloud bridge never silently creates a runtime.

`plugin` emits local Codex connection settings for the chosen folder. It does not start a runtime or alter policy. The repository's plugin carries the existing three-tool bridge and usage instructions. Machine-specific connection paths stay out of Git. A changed folder requires a regenerated connection and plugin reload; an already running bridge keeps its original binding.

## 6. Cloud interface

### `ask(request, disclosure_request=None, request_id=None)`

`request` describes the private work to perform. `disclosure_request` describes what information should return to the cloud and why. Neither grants a capability or changes policy.

Without a disclosure request, permitted local work may still run, but only a fixed receipt is returned. Model-generated wording, source material, and private error details are not substituted for that receipt.

With a disclosure request, the candidate response must pass privacy/reassembly checks and separate release governance. A stable task ID identifies the work. Native MCP Tasks are used when supported. Legacy clients receive a receipt and retrieve the committed result through `status`.

Task-capable transport identities map to the same logical Airlock task; retrying a framework delivery must not execute the work twice. Transport disconnection does not itself cancel work. Supervisor restart does not replay an unfinished request.

An optional caller-provided `request_id` is nonblank UTF-8 text of at most 256 characters, scoped to the selected workspace. Reusing it with exactly the same request and disclosure purpose returns the original task or committed result. Changed text returns `task_identity_conflict`. With no identity, two identical submissions remain distinct work. Request and native transport identities occupy separate namespaces and are compared through HMAC fingerprints. Lookup, identity binding, and task creation are transactional and precede execution. An interrupted task stays interrupted on retry; a new ID is required for a deliberately new attempt. This prevents duplicate task execution; it does not make arbitrary filesystem writes transactional.

### `status(task_id)`

Returns task state, phase, fixed status text, bounded usage counters, activity age, remaining request budget, a fixed advisory trajectory label, and a suggested polling interval. When finished, it can return the already-committed final response.

It never returns raw model reasoning, private tool output, filenames, raw detector findings, or a judge's explanation. Time since activity is an observation, not proof of a stall. Waiting for a local approval is not an error and does not authorize the caller to answer that approval.

### `stop(task_id)`

Cancels the task and terminates its tracked processes. It does not stop unrelated tasks or erase history. Completed filesystem changes are not undone. A response already committed for release cannot be retracted by a later cancellation.

All three tools are scoped to a locally selected runtime. Cloud arguments cannot select a filesystem root, model endpoint, privacy mode, release mode, or permission policy.

## 7. Local agent

Coder supplies the six model-facing tools:

```text
read_file  write_file  edit_file  list_files  grep  shell
```

Delegation is disabled. Repository instructions are not automatically promoted into trusted system instructions. Coder supplies its normal bounded output, argument repair, and context-management machinery. Airlock uses Pydantic hooks for local approval and exact-call validation rather than duplicating the native filesystem tools.

Airlock additionally registers a native `calculate` tool for exact plain-decimal addition, subtraction and multiplication. `Settings.enabled_tools` selects among these seven built-ins; worker preparation and owner model/tool boundaries reject disabled names. Startup selections apply to that start; trusted TOML supplies defaults across starts. Calculation uses admitted-task authorization without filesystem or shell grants, retaining tool budgets, deduplication, audit and cancellation. Its eventual response still passes disclosure checks and release governance.

Tools execute sequentially. Exact approvals bind the tool name, validated arguments, task, and configuration version, and cannot be replayed. Read, write, and shell policies are independent. Native shell work remains confined by SRT even when a command launches another program.

Trusted local configuration may explicitly register additional Python tools by
unique name, read/write/shell boundary, absolute module path, SHA256, exported
async handler, description and bounded plain argument schema. Built-in replacement
and schema references/regex/composition are refused. The supervisor validates
metadata and arguments without importing user code. Only an approved worker call
loads exact pinned bytes outside workspace/state; disabled/denied/pending tools
execute no import code. Installed dependencies remain accessible under existing
SRT grants; there is no automatic install, download or expanded read grant.
Registered code is operator-trusted executable code, with the worker's existing
OS capabilities; category declarations do not create narrower syscall isolation.
Only the built-in calculator has admitted-task authorization. Imports and handlers
retain owner process deadlines/cancellation, accounting and final release checks.
Both shipped modules bind preparation/calibration/restart identity; extension
metadata binds configuration/calibration. A changed tool module is rejected before
execution through the root's embedded pin, including under Python -I.

### Boundary contracts

All filesystem access below uses the worker's SRT grants. Read results and tool errors stay in the local model context; they are not cloud responses. This table describes the existing boundaries, not additional permissions.

| Boundary | Access and effects | Authorization and failure behavior |
|---|---|---|
| `read_file` | Bounded text, PDF text, or supported image input from granted paths | Read policy; unsupported media and read failures remain local tool errors |
| `list_files` | Names and metadata from granted paths | Read policy; listings remain private |
| `grep` | Matching text and paths from granted paths | Read policy; matches remain private |
| `write_file` / `edit_file` | Change granted writable files; derived content remains private | Write visibility and policy; exact validated call approval when manual; completed changes are not rolled back on later failure |
| `shell` | Programs may use all filesystem capabilities granted by SRT; no network | Shell visibility and policy; exact call approval when manual; denying a named write tool does not remove shell write capability |
| `calculate` | Exact bounded decimal addition, subtraction and multiplication; no files, commands or monetary rounding | Admitted task and enabled tool; fixed local argument errors, existing accounting and eventual disclosure checks |
| Worker/judge model requests | Supervisor forwards bounded private context to the configured local model | Literal loopback endpoint only; worker has no direct network; limits/errors cannot authorize release |
| Scanner requests/results | Candidate text and bounded decoded views; private findings returned to supervisor | Required scanner health and limits; enforce mode withholds on findings or failures |
| Cloud `ask` | Admit one request into the locally selected workspace | Request policy; request text cannot set workspace or governance; retry identity binds the original payload |
| Cloud `status` | Fixed metadata and an already committed final response | Workspace-scoped task identity; no new release or raw findings, paths, or tool errors |
| Cloud `stop` | Cancel the selected task and tracked processes | Workspace-scoped task identity; no rollback of completed writes or committed responses |
| Final cloud response | Exact candidate, or a fixed content-free receipt/error | Disclosure purpose, privacy checks, release policy, final recheck, and durable commit; no candidate on denial or failed commit |

Unknown worker tools and unknown IPC operations are rejected. Configuration changes cannot silently extend these contracts. Tests must exercise denied operations as well as legitimate successful work; a worker that never runs is not containment evidence.

Coder's persistent shell implementation uses private task scratch for output/status files. Airlock tracks task-owned children and ends them before accepting a final result. Scratch is removed at task cleanup. An owner-only job registry supports orphan cleanup after supervisor restart. This cleanup is not a claim that a portable process tracker can catch every deliberately daemonized process.

On systems without a memory-backed scratch location, temporary shell artifacts may contain private text on disk until cleanup. Sensitive working data is not added to persistent agent transcripts. Files intentionally written into the workspace remain ordinary workspace files.

### Media through `read_file`

Text uses Coder's native reader. A small same-name adapter supports bounded PDF text extraction and native image input; no separate image or PDF tool is exposed.

PNG, JPEG, and WebP inputs require an image-capable configured local model. Image bytes travel to that model, not to the cloud. Unsupported models or formats produce a bounded tool error rather than fabricated image understanding.

By default PDFs are parsed in a short-lived, resource-limited subprocess that inherits SRT and refuses unavailable hard limits. An explicitly prepared `pdf_parser` selects the fixed supervisor-owned Linux byte route, with no native fallback or automatic Docker start/install/pull. Its exact CLI/daemon/image/helper/package/policy pins, effective settings and positive/negative parser canaries must pass before readiness. Every job retains hard AS up to512MiB, CPU up to15seconds, FSIZE0, finite cgroup/PID/CPU/swap and pipe bounds, no networking, non-root identity and a read-only narrow bundle. Smaller configured limits remain binding.

Input is chunked over private read-bound pipes under the existing channel lock. Exact grants, sequence/size/configuration checks and matching completion prevent replay or replacement. No text returns before input EOF, full bounded terminal stdout EOF, successful exit and verified exact owned container removal/independent absence. Owner-only `pdf-jobs` records retain original pins/IDs/complete image-plus-owner labels for recovery; uncertain creation or cleanup withholds text and disables the configured route. Recovery never enumerates unrelated daemon objects.

Extracted page text and exact qualified AcroForm text-field labels/raw string or null values use the same zero-based line offset/limit interface, with bounded windows and continuation. The complete UTF-8 representation, including page/form markers and separators, obeys the text cap. Duplicate/malformed/unrepresentable forms and XFA are refused. Byte, page, extracted-text, time, and memory limits are separate. Text extraction is not visual document understanding; scanned/image-only or encrypted PDFs can be rejected. No hidden OCR service, remote parser, or external media URL fetch is used.

## 8. Agent health and shared inference

Pydantic supplies the primary execution controls:

- `UsageLimits` for request, tool-call, and token budgets.
- Coder's `WarnNearLimits` for approaching limits.
- `SystemReminders` for retaining task and policy instructions.
- A local `TrajectoryJudge` for advisory steering.
- Cancellation and bounded tool/output retries.

Worker and judge model requests share a supervisor-side Pydantic concurrency limiter. A judge does not create an additional concurrent expensive model slot. Human approvals and model-queue waits do not hold that slot.

Airlock enforces model response, stream-idle, tool execution, and active-work deadlines. Native shell foreground return is not evidence that a background command completed. Task cleanup applies to its remaining tracked children.

The trajectory judge's assessment is advisory. Only fixed verdict labels may be included in status. There is no custom semantic doom-loop detector and no remote judge inspecting private traces.

## 9. Privacy boundary

Private workspace data can be read by the private local agent without running the disclosure scanners over those reads. There is no whole-workspace privacy inventory, scan-before-expose requirement, or input-source indexing step.

The local model produces a typed internal result:

```text
response: string
protected_sources: list[string]
```

Protected sources are minimal, preferably verbatim private values or facts whose cumulative reconstruction matters. They can include identifiers, credentials, private financial amounts, and sensitive contextual facts without a category field. They remain local. Model omission or inconsistent wording can reduce coverage; this side channel is not a trusted completeness assertion.

Only candidate disclosure text is evaluated by the outbound scanner pipeline:

```text
candidate response
    -> original and bounded decoded views
    -> independent privacy detectors
    -> cumulative reassembly
    -> release authorization
    -> serialized final recheck and durable commit
    -> cloud response
```

Betterleaks runs offline with explicit pinned rules. Presidio supplies configured structured/rule-based recognition. Liquid PII and Policy Linter supply learned recognition. The two Liquid forward passes are serialized; deterministic scans may overlap. Both encoder weights can remain resident while scanners are active.

The default context backend is Liquid. An explicit `context_backend = "gemma"`
uses the already pinned local Gemma worker model instead of Liquid Policy. The
supervisor makes stateless, bounded, tool-free classifications through the same
inference limiter used by workers and judges; SRT scanners gain no network access.
Betterleaks, Presidio, Liquid PII, reassembly and release authorization still apply.
Gemma returns the same six rule meanings as clear/match/uncertain with exact local
evidence quotes, not probability scores. Uncertainty and errors fail closed;
failed generation or health latches context unavailability until explicit restart.
Queued classification rechecks availability before generation, and maintenance
does not reload a scanner behind a permanently failed context service.
Six anchored positives and a clean negative precede readiness. Calibration binds
the selected backend, model digest and complete classifier contract; accepting a
Liquid profile or changing its sensitivity cannot accept the Gemma backend.

Semantic detectors inspect the original and bounded decoded views. Betterleaks performs its own decoding. Findings preserve detector-specific metadata and decoded-view provenance; unmappable decoded spans do not receive invented original-text offsets.

Each scanner generation must pass fixed positive rule/entity/span probes and a negative probe. A clean-looking empty result from a nonfunctional scanner is not healthy. Probes check basic operation; they do not establish representative accuracy.

## 10. Reassembly and global disclosure state

One per-user ledger combines releases from all workspaces and MCP peers. Each source is assigned an HMAC-SHA-256 identifier using an installation-local key. Matching normalization is fixed and versioned. The database stores the identifier, source length, finite fragment-placement geometry, and algorithm version—not the source text.

While a source is in memory, candidate literal, normalized, and bounded decoded forms are compared with it. A finite-occurrence fragment graph accounts for different fragment sizes, ordering, overlaps, and alternative placements. Repeated characters do not let one observed fragment count as unlimited copies. Single-character standalone fragments count; arbitrary letters embedded in prose are not a universal covert-channel detector.

Checks are bounded in source count, candidate length, decoding work, and graph search. Exceeding an enforcement bound fails closed instead of claiming a clean result. Cost depends on the in-memory sources and graph states being checked; the HMAC database lookup is not the entire reassembly computation.

HMAC identifies the same normalized text, not semantically equivalent wording. There is no fuzzy semantic similarity inside reassembly. Meaning-based privacy checks remain separate and are also fallible.

After restart, raw source strings are absent from memory. When a source is supplied again, its stable HMAC reconnects it to existing history. Unknown historical sources do not block the workspace while waiting to be supplied again. This is an explicit limit on cross-restart detection, not recovery of source text from a hash.

## 11. Governance and release transaction

Request admission, read/write/shell execution, and final release use `deny / manual / auto / allow`. Tool visibility uses `hidden / visible`. Privacy uses `enforce / warn / off`.

`auto` is a configured local predicate, not an ordinal between manual and allow. Automatic release also requires a clean candidate. A pending task retains the intersection of the policies encountered during its lifetime: tightening applies at the next boundary, and loosening never grants a pending capability retroactively.

In enforce mode, required scanner failure or an ordinary unsafe finding blocks release; a human vote cannot override it. The exact selected financial path below permits only explicitly verified source-relative reassembly findings. Warn mode allows explicitly authorized overrides. Off mode deliberately bypasses privacy/reassembly checks but not release authorization; neither mode creates selected financial consent.

The ENFORCE-only selected financial path retains independent task/workspace/raw-spelling source occurrences and immutable raw decimal/flat-JSON proposals. A supported candidate blocked exclusively by reassembly has a private Coder guard handoff, then successful worker close before local selection. The operator explicitly selects occurrences and plain field/value/source/artifact/context controls, reviews the full raw and canonical-publication findings and evidence, and invokes Verify-and-Approve. A generic vote, document or model proposal cannot create this credential. One field may reference separately proved same-runtime A/B occurrences only when their physical input identity/digest, exact context, label and signed value agree. Unknown, unrelated, normalized-spelling, different-context/file, cross-workspace and legacy collisions deny. Release deny and ordinary scanner findings/failures always dominate.

Proof hashing uses one bounded descriptor-anchored nofollow reader for explicitly selected owned regular files inside the exact owned workspace. It rejects symlinks, nonregular/hard-linked files, unsafe paths, ownership/identity/change errors and aggregate unique sizes above max_pdf_bytes before reads; every descriptor closes. Both immutable raw and sorted compact ASCII JSON publication candidates pass full original scanner/reassembly checks before review and again under the release lock. After final scanner awaits, synchronous proof/evidence/geometry/configuration/cancellation checks must match the complete consent fingerprint, with no await before the SQLite transaction. Original rendered-byte geometry, all contribution associations, exact response, safe audit and one-use consumption commit together; no raw candidate geometry is recorded as released. Filesystem mutation after commit cannot retract committed bytes.

Raw JSON keys/values must contain literal ASCII label/decimal tokens; lexical escapes are unsupported even when decoding would produce a valid value. Structural JSON whitespace remains allowed. Complete selection/verification SQLite-read boundaries restore the previous pending state on error, create no origin/vote, mark the runtime UNAVAILABLE and return fixed storage_unavailable. Local retries and final selected publication refuse that state. Ordinary/guard scans, guard evidence snapshots and final reassembly recomputation classify SQLite lookup failures the same way.

Only trusted selected publication can atomically record an opaque shared_financial marker with fresh consumed consent, original geometry/contributions, exact response and audit. The marker binds the complete sorted six-column verified registration HMAC and exact contribution set. Reassembly still builds and bounds every original graph and records its changes; only the repeat finding is omitted when the previous committed graph already covers the full source and this complete baseline still matches. Partial geometry, ordinary releases, unknown/legacy/unattributed occurrences and other protected sources gain no exemption. New registrations invalidate the baseline until independently verified in a fresh selected publication, including when counters are saturated and graph changes are empty. Current governance and scanner findings/failures still govern every answer. Markers/geometry/consumption survive history deletion; restart cannot upgrade irrecoverable old occurrences.

Full findings are available only to the trusted local reviewer. Audit records use a separate opaque representation. A manual vote binds the original request, disclosure purpose, workspace, effective governance/configuration version, exact candidate, scanner failures, and canonical decision-relevant findings. Reordering or duplicate findings do not invalidate it; materially changed context, spans, rules, scores, or other decision metadata do. Accepted request fields are immutable and the candidate text is captured before any approval wait.

Preview scans and human waits occur outside the global release lock. Inside that lock Airlock revalidates the workspace, cancellation, current policy, approval version, and privacy/reassembly result. One SQLite transaction commits disclosure state and the exact final response before publication.

A crash after commit may count content the client did not receive. Airlock prefers over-counting to publishing bytes that were not recorded. Delivery acknowledgement and SQLite cannot be made one cross-process atomic transaction.

## 12. Storage and logging

The state directory is owner-only and outside the workspace. On macOS its normal location is:

```text
~/Library/Application Support/airlock/
    airlock.sqlite
    ledger.key
    supervisor.lock
    supervisor.json
    control.sock
    jobs/
```

SQLite contains workspace/configuration metadata, task identity mappings, safe audit events, the global opaque disclosure ledger, and the intentional boundary interaction log.

Additive source_registration/source_contribution/financial_consumption tables retain only constrained opaque HMAC references under the existing database cap; no raw proof/context/path/digest is stored in them. Source batches persist atomically before transient registration acceptance, including local-only work. Indexed association queries are bounded by max_sources. Current-session verified origins apply only to their exact recoverable registrations; siblings never inherit authority. Existing geometry without complete attribution gains a permanent opaque legacy marker. These associations and consumed consent survive history deletion. Restart interrupts uncommitted selections, and a matching amount cannot upgrade irrecoverable old occurrences; conservative ambiguity can continue to withhold selected release.

The interaction log retains the exact accepted `request`, `disclosure_request`, and committed final cloud response, including fixed denied/withheld/cancelled/failed outcomes. It is kept indefinitely until explicit local deletion. Rejected candidates, internal tool results, raw source declarations, and judge explanations are not added to this log.

Boundary history is potentially sensitive even though the disclosure ledger is opaque. It has owner-only permissions and no extra application-level encryption. Host disk encryption protects it only when actually enabled. HMAC does not protect against an attacker who obtains both the key and the database.

Deleting interaction history requires an explicit local confirmation. It removes committed interactions for the selected workspace and preserves unfinished interactions, other workspaces, audit/configuration records, the disclosure ledger/key, and opaque retry identity/payload fingerprints. An old ID whose transcript was deleted returns `task_history_deleted`; changed content still conflicts. A deliberately new attempt needs a new ID. Secure physical erasure from SSDs, swap, snapshots, or backups is not promised.

`max_state_bytes` defaults to 1 GiB (1,073,741,824 bytes), configurable in local TOML. SQLite enforces a shared main-database page limit across all workspaces, rounded down to whole pages. This includes history, audit, configuration, retry records, and disclosure evidence; rollback journals, model assets, and job scratch are outside that database cap. There is no automatic pruning. A limit below the allocated database size is refused without deleting data.

Capacity or other persistence failure stops admission/publication rather than bypassing logging. Explicit history deletion makes freed pages reusable, though the database file need not shrink. Stop and restart an unavailable runtime after freeing space or raising the limit; stop all runtimes before changing the shared limit. If retained evidence/metadata fills the cap, raising it is required to continue without discarding protection. A final persistence failure can follow already completed local writes; those writes are not rolled back.

## 13. Recovery

| Failure | Behavior |
|---|---|
| Scanner crashes or fails a probe | Discard generation, back off, recreate, and rerun health checks; enforce mode blocks while unhealthy |
| Worker exits, hangs, or is cancelled | Terminate tracked children; record a terminal result; create a fresh worker for later work without replay |
| Tool or model exceeds limits | End the attempt/task through bounded framework and runtime controls |
| MCP transport fails | Recreate transport with bounded backoff while preserving logical task and committed result state |
| CLI/TUI connection fails | Reattach through the supervisor; no implicit approval or duplicate task |
| Supervisor restarts | Clean registered orphan jobs; mark unfinished interactions interrupted; retain committed logs and disclosure state |
| Persistence fails | Do not publish an uncommitted response; surface runtime failure rather than bypass storage |
| Workspace identity changes | Mark unavailable and reject work until revalidated through local lifecycle control |

Control operations have finite connection, write, response, and close deadlines. A timed-out mutation has an uncertain outcome and is not automatically retried. Local approvals remain independent long-lived task state, not an indefinitely blocked control request.

When the last runtime stops, shared scanner/model clients are closed and the shared configuration is reset. Ollama unloading is limited to an explicitly dedicated endpoint and a model Airlock positively preloaded after confirming it was not resident. A preexisting or ambiguously shared model is not treated as owned. Airlock never shuts down an unrelated Ollama service.

Unverified teardown retains the exact unresolved component handles, runtime
registration and shared configuration/geometry. Scanner health is invalidated
before close and replacements wait for verified cleanup of the original owner.
A failed local stop leaves the runtime unavailable and closing for status and
same-owner stop retry; it cannot release overlap ownership. Shared cleanup attempts
each component independently and preserves its first error. Incomplete stop-all
returns stopped:false with fixed warnings and does not request orderly shutdown.
Startup unwind retains ownership and preserves the primary startup failure.
Failed owned-model unload retains the exact service/client/ownership and blocks
new work for that service/supervisor lifetime; no automatic unload retry or
replacement client is authorized. Independent client cleanup still runs on the
first failure without masking it. A failed HTTPX client close followed by its
CLOSED no-op cannot establish transport cleanup. Only an exact still-open client
may retry client cleanup. This hold promises no durable restart reconciliation.
Ordinary disclosure checks the unavailable-storage latch after every scanner or
approval wait and before committing; later SQL success cannot restore authority.

## 14. Configuration, provisioning, and calibration

Configuration precedence is defaults, preset, trusted user configuration, saved workspace governance, explicit CLI overrides, and temporary runtime settings. An explicit CLI preset bypasses saved workspace governance. Saved rules are bound to the workspace's canonical path/device/inode and still shown for acceptance before a new runtime starts. Workspace files and ambient environment variables cannot broaden governance.

All runtime assets are local and pinned: application source, Python package versions, SRT, Betterleaks/rules, model/tokenizer/custom code assets, and the selected Ollama model digest. A preparation utility builds the local manifest. Provisioning may install dependencies; the running application does not download them.

PII, policy, and reassembly thresholds come from a labeled adversarial benchmark. Calibration and held-out cases are distinct. Profiles bind the evaluated code, assets, model, and relevant configuration, report false positives and false negatives, and require local review. Missing or incompatible calibration does not silently become an arbitrary enforced default.

The startup screen can accept the exact measured profile for that workspace without changing its global review flag. Acceptance is tied to its SHA-256 digest and current code/assets binding. Scanner sensitivity stays read-only in the screen; changing it requires a compatible measured profile and restart. Runtime privacy/approval modes can be edited explicitly. Pending tasks retain policy intersections, and edits invalidate pending votes. Enabling scanners after an off-mode start requires restart; changing workspace write capabilities also requires restart.

Cloud tool descriptions and behavior are evaluated on synthetic use/no-use, disclosure intent, status polling, cancellation, permission-bypass, and withheld-output cases. Actual target models must be evaluated; schema validity alone is not evidence of correct tool selection.

## 15. Observability and validation

Pydantic/OpenTelemetry instrumentation disables message, tool, and binary content capture. A private exporter-free SDK retains only a bounded allowlist of local operational records. Raw judge explanations and model-generated diagnostics are not public status messages. No hosted tracing or Logfire export is enabled automatically.

Failed-task diagnostics share the existing bounded256 in-memory local records.
Only the generated task ID and fixed integer stage/exception-type/pinned-source
line metadata are retained, before private error conversions and separately for
cleanup. No message, path, name, local variable, traceback object or model content
is recorded. Strict numeric child metadata is correlated and validated by the
parent. Owner-only local diagnostics(target,task_id) reads matching current-task
records before stop; missing/evicted records are unavailable. Diagnostics are
absent from MCP, public status, history and exporters, and cannot change failure,
cleanup or cancellation behavior. They cannot reconstruct previously lost causes.

Unit, property-style, adversarial, subprocess, and integration tests cover distinct claims. Real SRT isolation, model/scanner accuracy, native MCP task behavior, Coder tool execution, and multiple interactive TUIs require their actual dependencies and target-platform checks. Skipped tests are not acceptance evidence.

## 16. Non-goals

Airlock does not provide remote or multi-user hosting, autonomous installation, hosted telemetry, persistent model conversations, automatic task replay, write rollback, general-purpose workflow orchestration, model/KV-cache scheduling, or a custom filesystem/tool framework. It does not claim perfect detection of private information or arbitrary covert disclosure.
