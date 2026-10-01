# Airlock

A private local workspace agent with a separate disclosure boundary. Cloud assistants submit work through `ask`, inspect it through `status`, and cancel it through `stop`. Production behavior lives in one file, `airlock.py`.

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

The worker uses the native Coder tools `read_file`, `write_file`, `edit_file`, `list_files`, `grep`, and `shell`, inside the Sandbox Runtime. OS capabilities and local governance control access; a caller's request cannot grant permissions. Privacy scanning runs on candidate disclosures, with enforce, warn, and off modes. In enforce mode, scanner failure or a privacy finding withholds the answer.

A manual release review shows the original request, disclosure purpose, workspace, effective policy/version, exact proposed answer, and full findings. A vote applies to that proposal once. Changed decision context invalidates the vote. Approval is a local operation; the cloud caller cannot answer it.

Release checks serialize across workspaces. SQLite commits the disclosure evidence and final response before the response is published. A failed commit publishes no candidate and makes the runtime unavailable.

## Preparation and limits

The complete runtime needs compatible Pydantic AI/Harness, FastMCP/Tasks, Textual, scanner/media dependencies, a pinned Sandbox Runtime, a pinned Betterleaks executable/rules, reviewed local encoder assets/helpers, and a local Ollama model with tools. Enforce/warn startup also requires an explicitly reviewed calibration profile bound to the actual source and assets. The supplied design references provisioning tools and a test corpus that are absent from this repository. No accepted live profile is supplied.

Install the locked development dependencies and run the synthetic contract suite:

```sh
uv sync --locked
uv run --locked python -B -m pytest -q test.py
uv build
uv run --locked airlock --help
```

Python 3.11 or newer on macOS/Linux is required. Package installation and `uv run --script airlock.py --help` use the same bounded direct dependencies as the project. The lockfile fixes the complete development/CI resolution; installing the wheel or script can resolve newer versions within those bounds. Package installation does not provision reviewed executables, model assets, or calibration.

After local preparation, the CLI accepts a workspace, `--headless`, `--config PATH`, `ps`, `status WORKSPACE`, and `stop WORKSPACE` or `stop --all`. The local bridge attaches to an already running workspace; it does not silently start one. A stdio MCP client uses the prepared environment's absolute Python executable with `-I -B /absolute/airlock.py _bridge /absolute/workspace`.

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

SQLite deliberately stores exact requests, disclosure purposes, and committed final responses in owner-only local history. Rejected candidates, raw source hints, tool output, and model reasoning are excluded. History is kept until explicit local deletion, which removes completed transcripts for the selected workspace. Active tasks, audit/configuration records, opaque retry records, and disclosure evidence remain.

The shared state database defaults to a **1 GiB cap**. Set `max_state_bytes` in the local TOML configuration, for example:

```toml
max_state_bytes = 1073741824
```

The cap covers the main SQLite database, rounded down to database pages. Journals, model assets, and worker scratch are separate. At capacity, new work stops and uncommitted answers stay withheld; no records are automatically purged. Delete completed history through the local UI, or raise the limit, then restart an affected runtime. Stop all runtimes before changing the shared limit. Deletion frees pages for reuse without necessarily shrinking the file. A limit below its allocated size is refused. Local writes made before a storage failure remain in place.

Encoder custom code is a supply-chain trust decision even when pinned, reviewed, loaded offline, and sandboxed. A passing synthetic suite is not measured field privacy performance or an independent security audit.

MIT. See [LICENSE](LICENSE).
