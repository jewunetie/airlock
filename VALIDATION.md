# Current Airlock validation

This records the completed root promotion and authorized hardening, not production acceptance. The original `new_design/TEST_REPORT.md` references artifacts and tests absent from this repository; its reported counts are not reproducible here.

## Executed checks

Task 5 prepared a private measured candidate for the current source, without
activation or acceptance. Actual SRTLauncher/ScannerService required startup
probes passed; one scanner generation measured every original calibration and
held-out case at unchanged sensitivity `0.3` / `0.5`, no overrides and reassembly
fraction `1.0`. Both splits contain 12 benign and 12 private examples, are
disjoint and exclude startup canaries. Calibration: **4/12 benign false blocks,
0/12 private misses**. Held-out: **6/12 benign false blocks, 0/12 private misses**.
No detector failed; all false blocks came from the policy linter. These are
fresh measurements of a small synthetic corpus, not field accuracy or a reason
to recommend the profile for real documents. No threshold selection occurred.

Candidate root: `/private/tmp/airlock-tax-refresh-9tp83mfy`; profile SHA-256:
`223d90c8c74a24876267e5789803ce86221938399526fbace00c878d237b22ee`.
It retains raw corpus/provenance/findings and an exact current-source copy.
Original prepared_settings verifies its source/packages; load_calibration
verifies its new binding. A separate fresh process importing the candidate copy
independently recomputed errors and verified bindings and permissions. The
profile remains `reviewed: false`, workspace acceptance remains null, and
calibrated_settings refuses `calibration_not_accepted`. The actual Textual
startup displayed the measured summary and Cancel returned None. No runtime
started. Active manifest/profile/settings and all existing top-level preparation
artifacts remain byte-identical. Owned scanner processes/jobs are gone; the
existing empty old-source supervisor and shared resident model are retained.
Detailed commands/evidence are in `.superpowers/sdd/tax-task-5-report.md`.
Activation and exact per-workspace local acceptance require separate approval;
the old installed bindings and supervisor remain stale by design.

Task 4's authorized bounded cleanup/PDF changes passed **23 focused locked
checks, zero skips/failures, 105 deselected**. Corrected regressions against the
unchanged `f981b60` source snapshot first produced **9 failed, 13 passed**,
including the nullable-UID dereference, already-gone final-status race and lost
PDF resource-error identity. Positive controls discover/terminate an actual
owned marked child and extract actual PDF text through framed child IPC with
test-only successful limits. Those injected limits prove wiring, not resource
enforcement. Memory/unknown/parser errors, uncertain/live survivors, watcher
faults, exact safe Coder ToolFailed text and cancellation cleanup are asserted.

The controller's subsequent full locked suite recorded **127 passed, 1 failed**:
the existing storage-configuration fixture consulted the active ignored runtime
manifest, whose source binding correctly became stale. This full-suite failure
is preserved, not counted as a pass. Reviewer also found the actual-hard-cap
test incorrectly inferred capability from platform name. Authorized test-only
corrections now probe actual required limit installation in an owned fresh child
with production imports/executor/settings, requiring real extraction when limits
install or exact resource refusal when the probe proves failure. Storage uses an
owned current-source PreparedRuntime fixture through original prepared_settings;
all cap/reopen assertions remain and actual source tampering must reject
load_settings with asset_hash_mismatch. Targeted corrected run: **24 passed,
104 deselected, zero skips/failures**. Active manifest/profile and production
source bytes are independently verified unchanged. Independent rereview approved
the corrected bounded changes. The controller's final full locked suite passed
**128 tests, zero skips/failures, exit 0**. Offline source/wheel builds and actual
archive listings under `/private/tmp/airlock-tax-reviewed-build-c639` verify one
root production module, packaging metadata/docs and no historical/private
configuration. The earlier 127/1 failure remains recorded above; final core
success does not establish financial workflow or PDF readiness.

The new-source actual SRT PDF diagnostic passed confinement startup probes;
both synthetic text/encrypted PDFs returned exact
`pdf_resource_limit_unavailable` without extracted text. The watcher remained
running before close, close succeeded and no private job records remained.
Actual unmodified macOS hard-limit installation also refuses parsing. All
required limits remain; PDF readiness, original cleanup failure causation and
original arithmetic failures are not claimed resolved. No RSS monitor or model
changes were introduced. Detailed evidence is in
`.superpowers/sdd/tax-task-4-report.md`.

Production source changed from SHA-256
`fe055275b0deb74d9dd3f1da7dcafb57879ecdcc7668b1a0a94237c384b3b145` to
`c639cd39d2ad63411ccf3120fc81b8efe909770092a08f41ccf113c4d96b761a`.
Existing runtime manifest/calibration bindings remain untouched and stale:
current `prepared_settings()` correctly refuses `asset_hash_mismatch`. The SRT
diagnostic used previously captured trusted settings privately, never a rebound
live profile or acceptance. New enforced live startup requires honest preparation,
compatible measurement and explicit local acceptance. The unaccepted private
candidate above satisfies measurement preparation only. Final controller core
verification is recorded separately from the actual SRT refusal evidence.

Task 3's bounded actual SRT arithmetic diagnostic passed startup probes but
failed useful completion: two successful model requests returned malformed
`4` plus a protected_sources line; strict LocalOutput JSON validation exhausted
the existing retry. No output guard or release was reached. Installed backend
preparation of the exact recorded parameters requires final_result tool output;
the malformed reply violated that contract. This differs from the original
single-call component failures and does not assign their cause. Owned watcher
was running before close; original terminate/close succeeded, no owned process
or job record remained, default supervisor was empty and shared model remained.
The diagnostic runner's final binding check separately exited 1 due its local
wrapper digest; a fresh independent process verified unchanged production/profile,
reviewed false and thresholds 0.3/0.5. No inference rerun or production/test edit.

Two separate fresh owned macOS Python children recorded RSS around 20 MiB and
VMS around 500.5 billion bytes; both unchanged 512 MiB RLIMIT_AS and RLIMIT_DATA
assignments raised ValueError: current limit exceeds maximum limit. Both children
exited and were verified absent. These native probes support the existing PDF
initialization failure, not a working alternative limit. RSS-monitor semantics
remain pending human choice and unimplemented. Detailed evidence and limits are
in `.superpowers/sdd/tax-task-3-report.md`; no earlier failure is recast as a pass.

On 2026-10-02, bounded actual synthetic financial workflows exercised natural
requests through the unchanged generated bridge, real stdio/authenticated MCP,
local Textual votes, Coder, SRT, existing Ollama `gemma4:12b-mlx` and scanners.
These used unique owner-only temporary workspaces, not the installed plugin's
exact dummy-folder binding. The global profile remained `reviewed: false`, privacy
enforce and thresholds `0.3` / `0.5` remained unchanged. Synthetic-only visible
workspace writes were accepted locally with manual request/read/write/release and
hidden shell. No production, dependency, manifest/profile binding or model changes.

The ten primary cases had mixed outcomes. Local-only revised financial preparation
and missing-field work produced actual correct artifacts and fixed null-response
receipts. The revised source omitted all printed totals: independent Decimal and
source-line checks confirm final wages, supplies and derived net. In that same
runtime without source clearing, selected wages were withheld for privacy before
review; selected net later released the exact correct amount through a real local
Approve vote. The public-fact case also released its exact correct answer. Identifier
and full-document requests were withheld; local admission Deny performed zero model
or tool work. `2+2` and the arithmetic-based release-denial control failed with
`component_unavailable`, rather than reaching review. All ten exact request retries
returned the original task/result. Every reached primary vote rejected wrong
versions and replay. No tested private identifier was released; this is bounded
synthetic evidence, not field privacy accuracy.

PDF evaluation preserved a failed, confounded first attempt: it wrote correct
fields but also read a duplicate plaintext statement and later failed. Its next
public-fact denial request was immediately committed as failed; a private harness
assumption about queued tasks raised an error. That final result was recovered from
its exact read-only SQLite record, and the private harness assumption was corrected.
The bounded rerun had no plaintext financial sidecar. Both encrypted-input and
text-PDF local tasks completed with fixed receipts. Independent Decimal/source
checks confirm the actual PDF-only artifact; encrypted-input output marked wages
unavailable without invented numbers, although its explanation incorrectly claimed
PDF format was unsupported. The text case used `read_file` and native `grep` on
the PDF. A separate actual SRT diagnostic isolates an unresolved adapter failure:
both PDFs return `pdf_unavailable` at initialization, before any PDF bytes are sent.
Direct parsing succeeds for text and rejects encrypted input. The useful
PDF-only artifact is consistent with its observed grep fallback, not working sandboxed PDF
`read_file` acceptance. Scanned-image/OCR readiness remains unmeasured.

The controller independently reproduced the matching macOS platform failure:
setting `resource.RLIMIT_AS` to the existing 512 MiB cap raises
`ValueError: current limit exceeds maximum limit`. `pdf_child` does this before
its first acknowledgement. This is direct platform-API evidence consistent with
the observed initialization failure; the actual parser child's exception stack
was not exposed. Production remains unchanged pending a separately approved fix.

An owned actual prepared ScannerService under SRT measured six predetermined
candidates with unchanged thresholds, separately from model/reassembly. Arithmetic,
selected wages, selected net and public fact had zero findings/failures; synthetic
identifier and full statement had findings and zero failures. The actual withheld
wages candidate and raw hints are not available, so its live cause cannot be assigned
to scanner versus reassembly/model behavior. A bounded local-only non-SRT Coder
diagnostic returned the correct arithmetic answer, unlike the bridge failures; it
does not reproduce or resolve their cause and is not release evidence.

Two earlier runtime stops reported `process_cleanup_failed`; subsequent checks
confirmed no active runtimes, scanner or worker processes, with shared Ollama
intact. The final PDF-only runtime stopped cleanly. An owned-child ProcessTree
probe and the owned SRT adapter diagnostic also closed cleanly; the intermittent
cleanup cause remains unresolved. Actual release Deny was not reached and remains
a live acceptance gap. Full private evidence and exact outcomes are listed in
`.superpowers/sdd/tax-task-2-report.md`. No real financial data, tax year/law,
calibration tuning, downloads, commit or push were used.

The repository retains 16 synthetic golden cases and two generated text/blank PDF
parser checks in `test.py`. Reproduce the focused checks with
`uv run --locked python -B -m pytest -q test.py -k financial`.
The authorized PDF parser addition passed its focused locked run: **2 passed,
103 deselected**. The preceding controller full core run passed **103 tests**;
the controller's final suite after the PDF addition is recorded separately.

On 2026-10-01, the operator explicitly authorized accepting the measured profile for `/private/tmp/airlock-dummy-workspace` and running manual/automatic live workflows. The actual Textual startup screen accepted the exact profile for each tested workspace configuration; privacy stayed enforced, OS workspace access stayed read-only, and the global profile remained `reviewed: false`. The installed plugin's exact cached connection exercised real stdio, owner-only control, authenticated HTTP, Coder, SRT, Ollama `gemma4:12b-mlx`, and the real scanners together. No real private documents or new model downloads were used.

The final five-scenario run **did not pass**. Manual and automatic benign requests both read the synthetic public file (two actual tool executions each) but returned `withheld`; no manual release approval was reached. Manual admission denial passed with zero model/tool calls. A no-disclosure task completed with a fixed receipt and no response text. The synthetic SSN request was withheld with no sensitive value in the result. Repeated exact request IDs returned the same committed results. All test runtimes were stopped afterward; the empty supervisor and shared Ollama service were left intact. Detailed synthetic evidence is local at `/private/tmp/airlock-live-workflow-results.json`.

Live testing found a deferred-approval bug: initial tool validation fills default arguments, while the original approval hook sent raw model arguments without those defaults. The supervisor correctly rejected the resulting grant fingerprint mismatch. `run_coder` now retains and approves the exact validated arguments. The existing actual-Coder regression now uses real supervisor fingerprint checks and SQLite instead of scripted approval decisions. **All 67 locked core tests pass**, and final source/wheel builds, archive inspection, and `git diff --check` pass. Fresh review found no additional concrete defect in this fix; the false benign withholding remains unresolved.

Local provisioning also needed the installed `rg` executable and PCRE2 library, including Homebrew's loader symlink. A private diagnostic confirmed native file discovery/read and the correct answer after those grants. That diagnostic bypassed egress for local inspection and is **not** evidence of successful release. It showed the model incorrectly listing public colour words as protected sources. This is a concrete instance of the documented false-source problem; the precise contributions of model hints and individual scanners to each live withholding have not been isolated. An earlier diagnostic showed a denied search-library load; the final live run used the corrected grants. Unexpected shell proposals were denied, not approved as a workaround. A temporary UI test snapshot race and reuse of a bridge bound to a stopped runtime were corrected in the harness, without weakening the success assertions.

Scanner calibration was remeasured against the final production source and retained the same thresholds and errors: `0.3` / `0.5`, calibration 4/12 benign false blocks, held-out 6/12, and zero private examples missed in either small split. Acceptance does not establish field accuracy. Successful live benign release and live manual release approval remain outstanding; the following entries describe earlier checkpoints.

On 2026-10-01, startup settings and the removal of unattended public startup completed with **67 passed, zero skipped, zero failures** in the full locked suite. The real Textual startup screen exercises acceptance, edits, cancellation, invalid binding, malformed profiles, and visible calibration results. Acceptance applies the exact pinned profile without changing its global review flag. Actual SQLite and local-socket UI checks cover persisted governance edits, reopen, workspace identity isolation, approve/deny, and enforced privacy blocks. CLI checks cover saved-policy precedence, cancellation, and attaching to an existing runtime. A competing startup with different accepted settings fails explicitly; a provisioning manifest cannot accept settings.

Fresh review corrected a calibration summary below the initial viewport and malformed-profile errors, added explicit competing-startup rejection, and prevented provisioning from supplying acceptance. No further concrete defect was found in the changed paths. The final full suite and `git diff --check` pass; source/wheel builds and archive inspection still confirm one shipped module with no historical implementation or machine-specific configuration. No dependency or lockfile changes were made. The retired startup option and references were removed from active and historical tracked files; originals remain in Git.

The existing real sandboxed scanner calibration was rerun for the final source: the same `0.3` / `0.5` thresholds, **4/12 benign false blocks in calibration and 6/12 in held-out**, and zero private examples missed in either small split. The exact measured profile remains unreviewed. A private temporary harness rendered the actual startup screen using the prepared assets/profile and dummy-workspace path without pressing Accept or starting a runtime. This verifies rendering and compatible profile loading, not live model acceptance. Live Ollama work still requires the local operator to accept the displayed dummy-workspace settings. No workspace or global calibration acceptance was fabricated.

On 2026-10-01, the manual approval screen checks completed with **56 passed, zero skipped, zero failures** in the full locked suite. Textual's actual test pilot selected a pending approval, displayed the original request, disclosure purpose, and exact candidate, and pressed Approve or Deny through the real owner-only Unix control socket. Approval released the exact candidate once; denial withheld it. An enforce-mode fixture finding withheld output without presenting an override vote. Candidates and scanners are synthetic; these checks exercise the interactive handlers and local transport, not live Ollama/scanner accuracy. Fresh review found no additional concrete defect in these additions; `git diff --check` passed. The startup settings prompt remains pending its new contract.

The prior implementation checkpoint `7a15243` was pushed to `origin/feat/web-ui` on 2026-10-01, and the remote branch hash was verified. Earlier statements about unpushed work below describe their historical checkpoints.

On 2026-10-01, the Codex plugin and SRT compatibility checks completed with **53 passed, zero skipped, zero failures**. The plugin was installed and listed as enabled under `airlock@airlock-local`, version `0.4.0-dev.0`, bound to `/private/tmp/airlock-dummy-workspace`. Its installed connection matches the locally generated settings. The real stdio bridge test uses a synthetic runtime with actual owner-only Unix control, authenticated loopback MCP, and SQLite. It checks the three-tool schema, rejects caller folder selection, preserves retry identity, returns no candidate in a no-disclosure receipt, and refuses an absent runtime. This bridge test does not use a live model.

Live preparation reused the cached Liquid encoder weights through hard links, without downloading model weights. Private assets pin Liquid PII revision `b8c9cf3d2d6ae52501b35a27ba46f271449c9ce2`, Liquid Policy revision `2a56cb94a7083a90263ea5270523ccc10e7ce8af`, Sandbox Runtime `0.0.78`, and Betterleaks `1.9.0` with its tagged rules. Downloaded executable archives matched their published integrity/digest metadata. Model/helper files and the prepopulated offline code cache have complete local SHA-256 manifests. Pinning and inspection do not constitute an independent supply-chain audit.

Actual sandboxed initialization and all four scanner positive canaries passed; the neutral canary had zero findings/failures. A real read-only worker initialized against the dummy folder and passed direct/child outside-file denial, state denial, loopback/public-network denial, and a synthetic canary under SRT's shared temporary directory. This verifies these probes, not all possible escapes. No Ollama task or interactive approval acceptance is claimed yet.

Those live checks found and fixed SRT command-string invocation (`-c`), canonical private scratch paths, and SRT's replacement of `TMPDIR`. The child now receives `CLAUDE_CODE_TMPDIR` pointing to private scratch; implicit `/tmp/claude` write grants are explicitly denied. The prepared local settings include the exact uv interpreter alias needed by this machine, without granting other user folders. Production logic remains in `airlock.py`.

A separate 24-case synthetic calibration split and 24-case held-out split were measured through the real sandboxed scanners, each containing 12 private and 12 benign cases. A fixed threshold grid minimized calibration false negatives, then false positives; ties selected the lower thresholds. An initial `0.7` policy threshold failed the specific bipolar-disorder startup canary and was rejected. Selection now requires the positive/negative startup canaries to pass. Selected Presidio threshold: `0.3`; policy threshold: `0.5`; no rule overrides; reassembly fraction unchanged at `1.0`. Calibration: **0/12 private cases missed, 4/12 benign cases blocked**. Held-out: **0/12 private cases missed, 6/12 benign cases blocked**. The policy linter caused all these false blocks. The held-out set was not used to choose thresholds. The corrected thresholds pass all real startup canaries and worker confinement probes. This small, easy synthetic corpus is a smoke test, not field accuracy; its false-block rate does not justify recommending the profile for real documents. The concrete local profile remains unreviewed pending operator acceptance for a dummy-only test.

The installed plugin's exact cached `.mcp.json` was also exercised against the dummy folder using a synthetic runtime. Actual stdio/control/authenticated HTTP calls completed and returned only the no-disclosure receipt. Its worker/scanner were fixtures; the real scanner/confinement probes above are separate evidence.

The single-module source/wheel distributions build successfully. Offline isolated builds initially failed because cache cleanup had removed the build backend; the normal `uv build` fetched the declared small backend into the temporary cache. No runtime dependency or lockfile changes were needed. Fresh review checked the complete change set and corrected a macOS-only temporary path in the new core test. The final full suite passed 53 tests after that correction; source/wheel archives exclude historical code and machine-specific manifests/connections. No further concrete defect was found in the modified paths; scanner false blocks and pending live model/UI acceptance remain material limitations.

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
| Coder/framework | Actual Pydantic AI/Harness constructs the six native tools, reads a synthetic file, and exercises direct and deferred manual approval hooks with actual supervisor fingerprint checks and SQLite. Core model replies remain scripted; the separate combined live evidence and unresolved withholding are recorded above. |
| Authority/policy | Authority fields are rejected. Policy intersections do not broaden clean/unsafe permissions across the tested modes. Enforce startup requires explicit calibration. An omitted source followed by a declared source demonstrates the tracking limitation with a clean fixture scanner. |
| Packaging/CLI | Inline/project dependencies agree; all lazy import names resolve. Source help and fixed invalid-command behavior pass. Source and wheel distributions build; archive inspection confirms one shipped production module and excludes the historical implementation. The wheel installs/imports from a separate environment and its entry point exits zero for help. |

The production source also imports successfully and `python -I -B airlock.py --help` exits zero. Import and help alone establish no isolation or scanner accuracy.

The project environment was managed through `uv`, and the generated `uv.lock` is committed. Relevant tested versions: Python 3.13.14; Pydantic 2.13.4; pydantic-settings 2.15.0; SQLite from this Python build; OpenTelemetry SDK 1.45.0; Pydantic AI 2.46.0; Harness 0.36.0; FastMCP, fastmcp-slim and fastmcp-tasks 4.0.10; MCP 2.2.0; uvicorn 0.52.4; pytest 9.1.1; pytest-asyncio 1.4.0. Scanner packages resolve/import, but no scanner weights or accepted calibration were exercised.

CI now installs the lockfile, runs these contracts, builds both distributions, checks archive contents, and verifies the installed wheel entry point. The workflow YAML parses locally. No remote Actions run is claimed; these changes have not been pushed.

Fresh review found and corrected a history-deletion reference to the removed `native_tasks` table and a build pattern that included `new_design/airlock.py`. It also checked retry lookup before cached-result reuse, cap application before startup/recovery writes, transaction rollback after SQLite's automatic rollback, and retention of disclosure/retry evidence. No further concrete defect was found in the reviewed hardening paths. This is a code review of those paths, not an independent security audit.

## Still required

- Diagnose selected-wages withholding, arithmetic component failures and original intermittent cleanup failures; complete actual release Deny. Correct live net and public-fact manual releases have actual synthetic workflow evidence. Task 4 identifies PDF initialization refusal at required hard-limit installation and returns its exact safe error; usable sandboxed PDF parsing remains unavailable on this host. Field privacy accuracy, image/scanned-PDF behavior, general process escape resistance and combined memory use remain unmeasured.
- Exercise interactive history flows and native disconnect/cancellation recovery. Actual startup, manual admission/read/denial and net/public-fact release Approve handlers were exercised; actual release Deny and complete client-recovery behavior remain open.

The referenced preparation/calibration tools and corpus are absent from committed source; temporary local preparation and an explicitly accepted dummy-only profile were used above. Source tracking remains fallible and reconnects old evidence only when sources are declared again after restart. Current core hardening checks pass. Selected-wages/arithmetic usability, original cleanup causation, actual release Deny and usable sandboxed PDF parsing remain open. The newly measured private candidate requires separate activation approval and exact local workspace acceptance; it grants no new approval evidence.
