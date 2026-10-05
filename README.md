# Airlock

A private local workspace agent with a separate disclosure boundary. Cloud assistants submit work through `ask`, inspect it through `status`, and cancel it through `stop`. Supervision lives in `airlock.py`; local tools live in `airlock_tools.py`.

**Development release.** The root redesign has durable retry identity, contextual release approvals, a configurable storage cap, and its own tests, packaging, and CI. Current executed evidence is recorded in [VALIDATION.md](VALIDATION.md). Real scanner accuracy and OS confinement still require acceptance with reviewed local assets and calibration.

[ARCHITECTURE.md](ARCHITECTURE.md) defines the design. [HOW.md](HOW.md) defines the authorized hardening contracts. The original implementation and tests are saved in commit `26d93ec`; the original redesign and review are saved in `1bd2999`. `new_design` is a historical reference, not a second active implementation.

## Interface

| Tool | Behavior |
|---|---|
| `ask(request, disclosure_request=None, request_id=None)` | Submit private local work. Without a disclosure request, return a fixed receipt. Requested information must pass scanning, cumulative fragment checks, and separate release authorization. |
| `status(task_id)` | Return fixed status labels, bounded counters, and any committed final response. |
| `stop(task_id)` | Cancel the task and its tracked processes. Completed writes remain in place. |

Use a stable `request_id` when retrying a submission. It must be nonblank UTF-8 text of at most 256 characters. The same ID and exact request/disclosure text return the same task; changed text returns `task_identity_conflict`. IDs are scoped to the connected workspace. Without an ID, identical submissions are separate tasks. Poll with `status` while work or local approval is pending.

A supervisor restart marks unfinished work interrupted and preserves completed results. Retrying an interrupted task does not rerun it. A deliberately new attempt needs a new ID. Task idempotency prevents duplicate execution; it does not make arbitrary filesystem changes transactional.

After explicit history deletion, opaque ID/payload fingerprints remain. Replaying that ID returns `task_history_deleted`. For example, deleting an old append task's history must not let a delayed retry append the same entry again. Those records contain no raw request or answer.

## Local controls

The worker uses the native Coder tools `read_file`, `write_file`, `edit_file`, `list_files`, `grep`, and `shell`, inside the Sandbox Runtime. OS capabilities and local governance control access; a caller's request cannot grant permissions. Privacy scanning runs on candidate disclosures, with enforce, warn, and off modes. In enforce mode, scanner failure or an ordinary privacy finding withholds the answer. Exact selected financial fields have the additional local verification flow below.

The native `calculate` tool performs exact decimal addition, subtraction and multiplication without monetary rounding. It takes plain decimal strings and needs no file or command approval; task admission and disclosure checks still apply. The governed `read_csv` tool preserves CSV strings and source rows. All eight tools are enabled by default. Select enabled tools on the startup screen for this start, or save defaults across starts in trusted TOML configuration, for example `enabled_tools = ["read_file", "calculate"]`. An empty list disables all worker tools. Disabling a named tool does not remove filesystem capabilities available through another enabled tool such as `shell`.

You can register your own tools in trusted local TOML, outside the workspace.
Keep their owned Python files outside workspace/state, without symlinks, hard
links or group/other write permissions. For example, an operator file can export:

```python
async def echo(context: str) -> str:
    return context
```

Register its absolute path and actual SHA256 (`shasum -a 256 /absolute/operator-tools.py`):

```toml
enabled_tools = ["read_file", "calculate", "custom_echo"]

[[extensions]]
name = "custom_echo"
boundary = "read"
module = "/absolute/operator-tools.py"
sha256 = "REPLACE_WITH_ACTUAL_64_CHARACTER_SHA256"
handler = "echo"
description = "Return the full supplied context locally."
parameters = { type = "object", properties = { context = { type = "string" } }, required = ["context"], additionalProperties = false }
```

Handlers receive validated keyword arguments and return a bounded string to the
private local model. Names cannot replace built-ins. Declare read, write or shell;
the corresponding existing policy governs every call, including manual review.
Import code runs only after approval. Only the built-in calculator is exempt from
operation approval. Extensions are trusted operator code inside the worker's
existing sandbox, and must use already prepared dependencies. Airlock does not
install/download their dependencies or add runtime grants. Plain schemas support types,
properties/items, required/enum, length and numeric bounds; references, regex and
branching schemas are refused. Changed code needs a new explicit hash and restart;
configuration changes also require a matching calibration profile. Shipped-module
changes invalidate prepared manifests and profiles rather than accepting old ones.

A manual release review shows the original request, disclosure purpose, workspace, effective policy/version, exact proposed answer, and full findings. A vote applies to that proposal once. Changed decision context invalidates the vote. Approval is a local operation; the cloud caller cannot answer it.

For exact financial fields in enforce mode, the local worker can propose a decimal string or a flat JSON object of decimal strings while retaining truthful private source hints. If only cumulative reconstruction blocks it, the worker finishes and closes before the local screen asks you to select supporting occurrences. Enter each selected field, exact signed value, workspace source/artifact files, and the raw financial context you checked locally. Review the exact canonical JSON, all findings, and file identities/digests, then select **Verify and Approve** or **Deny**. Displaying a proposal, adding an occurrence, or ordinary Approve grants no financial consent. Release deny, ordinary privacy findings and scanner failures still withhold it; allow/auto still require this exact local action. Local-only work returns its fixed receipt without this disclosure wait.

Two tasks in the same running workspace can support one field only when you independently verify both occurrences against the same physical source and exact context/value. Unknown, unrelated, different-file/context, cross-workspace or legacy occurrences sharing the normalized value keep it withheld. Selected files must be owned regular files inside the exact workspace, without symlinks or hard links, and fit the aggregate proof byte cap. Source/artifact changes invalidate consent. Checking a PDF digest does not verify its financial meaning; that remains your local judgment.

Financial proposal labels and decimal strings must be literal ASCII tokens. Structural JSON whitespace is allowed; escaped or encoded keys/values are refused. A storage read failure makes the runtime unavailable, and retrying a local selection or verification cannot restore release authority in that runtime.

Once an exact selected financial value has been fully shared, its retained complete verified occurrence baseline permits later answers that touch that same value without another reconstruction block. Original history stays intact, and current sharing rules still apply to every answer. A new or unknown occurrence invalidates this baseline; it gains no origin or consent from matching the old amount. A different private field still needs its own exact local verification and fresh consent.

After restart, retained opaque registrations and contributions cannot gain verified origins from a newly matching amount. If the exact old occurrence/context is no longer recoverable, it remains ambiguous and selected release can stay withheld. Deleting interaction history cannot reset this evidence or consumed consent. Same-runtime fixture success does not establish cross-restart usefulness or live tax-document accuracy.

Starting a workspace first shows its rules. Accept your saved choices or configured defaults, or change the approval, privacy, and tool access modes before starting. Cancel leaves the workspace stopped. Valid choices are saved locally for that exact workspace. An explicit `--preset` starts from that preset instead; explicit permission flags override saved choices.

The screen also shows scanner sensitivity and measured evaluation errors. Accepting a compatible profile applies it to this workspace without approving it globally. Sensitivity changes require a new tested profile and restart. In the running screen, edit the governance settings and select Apply governance to save changes. Pending work keeps the stricter rules it has encountered; changes invalidate pending approvals. Enabling scanners after an off-mode start or changing workspace write access requires stop/start.

The default context scanner remains Liquid. Trusted configuration can explicitly
select `context_backend = "gemma"` using the same pinned local Gemma worker model.
This replaces only Liquid's context check; the other privacy checks remain.
Gemma uses clear/match/uncertain decisions with exact local evidence, rather than
Liquid probability thresholds. Uncertain answers or failed health checks block
release. A failed generation or health check requires an explicit restart, and
this backend needs its own measured, accepted profile. Adding this option does
not activate it or establish real-document accuracy.

Release checks serialize across workspaces. SQLite commits the disclosure evidence and final response before the response is published. A failed commit publishes no candidate and makes the runtime unavailable.

Storage failure also prevents an answer already awaiting scanning or local approval
from publishing. Stop/restart is required to restore that runtime's authority.
If cleanup fails, local status retains the unavailable runtime and its ownership;
retry the same local stop after resolving the failure. New workspace admission
waits for verified cleanup. An incomplete `stop --all` reports `stopped:false`
with fixed warnings and leaves the supervisor available for local reconciliation.
Failed owned-model unload blocks new work for that service/supervisor lifetime.
Airlock retains ownership and does not automatically retry unload or replace the
model client. This does not guarantee reconciliation across supervisor restart.

The owner-only local control operation `diagnostics(target, task_id)` can inspect
retained content-free failure stage, exception-type and source-line numbers for
that runtime's exact task. Read it before stopping the runtime; missing or evicted
records are unavailable. It retains no exception text or document/model content
and is absent from cloud tools, status and history.

The retained `ui/index.html` and `tools/sync_console.py` are unsupported historical
web-console artifacts. The current interface is native Textual.

## Preparation and limits

The complete runtime needs compatible Pydantic AI/Harness, FastMCP/Tasks, Textual, scanner/media dependencies, a pinned Sandbox Runtime, a pinned Betterleaks executable/rules, reviewed local encoder assets/helpers, and a local Ollama model with tools. Enforce/warn startup also requires an explicitly reviewed calibration profile bound to the actual source and assets. The supplied design references provisioning tools and a test corpus that are absent from this repository. No accepted live profile is supplied.

Native `list_files` and `grep` also need `rg` on the worker's clean PATH. Grant the executable, its required libraries, and loader symlinks through local `extra_runtime_reads`; do not grant unrelated user folders. On macOS, a Homebrew library's `opt` symlink may require its own read permission even when the resolved library is allowed.

PDF reading refuses to parse the file when required hard process limits cannot be applied, and the local model receives the fixed error "Required PDF resource limits could not be applied; the file was not parsed."

An optional explicitly prepared `pdf_parser` uses a fixed local Linux byte parser through an already-running pinned Docker daemon. The startup screen shows this component and its availability/storage limits. Airlock does not discover, start or install Docker, pull images, or fall back silently. This adds the daemon/image/syscall policy to the trusted boundary; document bytes traverse VM and daemon buffers, and removal does not securely erase swap, crash dumps or physical storage. The worker keeps its existing sandbox/read approval, and disclosure policy is unchanged.

Preparation must pin the local Unix endpoint and daemon ID/version/kernel, absolute Docker CLI/hash, existing immutable Linux ARM64 image and Python executable/hash, exact locked pypdf version/source files, and the reviewed syscall policy. Explicitly generate `helper.py` with `pdf_parser_source()` from current root code, copy only locked pypdf `.py` files into the narrow read-only bundle, and hash its complete file set into `AssetSpec`. Keep bundle/policy outside source, workspace and runtime state. Store the resulting `PdfParserSpec` only in trusted local preparation/configuration; regenerate compatible measured calibration and obtain exact startup acceptance before activating it. Existing source-bound profiles cannot authorize a changed helper. No new dependency or maintained second parser module is needed.

PDF reads include ordinary page text and a distinct JSON section for exact qualified AcroForm text fields, including empty/missing values. Field-only nonempty text is readable; blank forms, encrypted/image-only documents, duplicate/malformed fields and XFA can be refused. OCR and visual document understanding are not provided. Input/page/text/deadline/hard memory limits stay separate, and cleanup uncertainty withholds parser text.

`read_csv` reads comma-delimited UTF8 files as string-valued rows, with the original
row text and physical line ranges. It preserves quoted commas/newlines, empty
cells, leading zeros and decimal signs; it does not interpret headers, amounts
or formulas. A UTF8 BOM is retained in original text and excluded from the first
cell. Zero-based offset/limit pages logical rows. Existing read approval and
release rules apply; invalid, oversized or unreadable rows give a fixed local
error. PDF/image OCR and table adapters are still in development.

Form JSON puts each ordinary field on its own line for bounded offset/limit reads. A single escaped field entry larger than the existing 60000-character read window remains explicitly unreadable through that reader; the full extraction still retains it within the complete byte cap.

Install the locked development dependencies and run the synthetic contract suite:

```sh
uv sync --locked
uv run --locked python -B -m pytest -q test.py
uv build
uv run --locked airlock --help
```

Python 3.11 or newer on macOS/Linux is required. Package installation and `uv run --script airlock.py --help` use the same bounded direct dependencies as the project. The lockfile fixes the complete development/CI resolution; installing the wheel or script can resolve newer versions within those bounds. Package installation does not provision reviewed executables, model assets, or calibration.

After local preparation, starting a workspace opens the local Textual screen. The CLI accepts a workspace, `--config PATH`, `ps`, `status WORKSPACE`, and `stop WORKSPACE` or `stop --all`. The local bridge attaches to an already running workspace; it does not silently start one. A stdio MCP client uses the prepared environment's absolute Python executable with `-I -B /absolute/airlock.py _bridge /absolute/workspace`.

## Codex plugin

The local plugin lives in `plugins/airlock`. Choose an existing folder locally,
then generate its connection from this checkout's prepared environment:

```sh
uv run --locked airlock plugin "/absolute/chosen folder" > plugins/airlock/.mcp.json
codex plugin marketplace add "$PWD/plugins" --json
codex plugin add airlock@airlock-local --json
```

These commands require a Codex CLI with `plugin` support. On this Mac, the app's
bundled CLI is `/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex`;
the separately installed CLI is older. The generated connection is ignored by
Git and contains no token. It uses absolute paths to this checkout and Python
environment, which must remain available.

Start that same folder locally with `uv run --locked airlock "/absolute/chosen folder"`.
The default policy asks for local admission/read/release approval and keeps privacy
enforced. In Codex, enable/reload the plugin and ask it to use Airlock for the work.
It exposes only `ask`, `status`, and `stop`; the cloud cannot choose another folder
or approve its own operations. A missing runtime returns an unavailable connection.
The skill guides usage; the supervisor and sandbox enforce the boundary.

To choose a different folder, regenerate the connection, reinstall/reload the
plugin, and start the new folder locally. Existing bridges retain their original
binding. Installation does not provision scanners or accept a calibration profile.
Check `VALIDATION.md` for the distinction between synthetic bridge checks and live
scanner/worker evidence before using private documents.

Protected sources are fallible model-supplied hints. An omitted or late declaration can miss a cumulative disclosure. Raw sources live in memory; after restart, old fragment evidence reconnects only when the source is declared again. Semantic answers, timing, refusal patterns, and arbitrary covert encodings are not comprehensively detected. Scanner accuracy and actual platform confinement require live evidence.

SQLite deliberately stores exact requests, disclosure purposes, and committed final responses in owner-only local history. Rejected candidates, raw source hints, tool output, and model reasoning are excluded. History is kept until explicit local deletion, which removes completed transcripts for the selected workspace. Active tasks, audit/configuration records, opaque retry records, source registration/contribution associations, consumed financial consent, and disclosure evidence remain.

The shared state database defaults to a **1 GiB cap**. Set `max_state_bytes` in the local TOML configuration, for example:

```toml
max_state_bytes = 1073741824
```

The cap covers the main SQLite database, rounded down to database pages. Journals, model assets, and worker scratch are separate. At capacity, new work stops and uncommitted answers stay withheld; no records are automatically purged. Delete completed history through the local UI, or raise the limit, then restart an affected runtime. Stop all runtimes before changing the shared limit. Deletion frees pages for reuse without necessarily shrinking the file. A limit below its allocated size is refused. Local writes made before a storage failure remain in place.

Encoder custom code is a supply-chain trust decision even when pinned, reviewed, loaded offline, and sandboxed. A passing synthetic suite is not measured field privacy performance or an independent security audit.

MIT. See [LICENSE](LICENSE).
