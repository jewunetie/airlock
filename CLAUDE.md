# Working on airlock

Notes for anyone, human or agent, changing this code. Everything here was
learned by something breaking. The reasoning lives here so `airlock.py` can
stay readable; the file states what the code does, this states why.

User-facing behaviour belongs in README.md. Do not repeat it here.

## Shape

One file, `airlock.py`, with PEP 723 inline dependencies. Tests live in
`tests/`, never in the shipped file. Keep it that way: new helpers go in the
same file unless they are test-only.

**Why a single file, and why that claim changed.** The single-file structure
used to be justified as "no install needed": `uv run --script` resolves the
PEP 723 header on first run, so there was nothing to set up beforehand. That
claim has expired and this file said something false until it was corrected
here. airlock now pulls `torch`, `transformers`, `mcp[cli]`,
`detect-secrets`, and `pypdf`, plus roughly 2.6GB of encoder model weights,
and needs Ollama installed separately for the worker model. None of that is
"nothing," and pretending otherwise in the file that exists to record why
things are true would defeat the point of this file.

The real reason the file stays single is **auditability**, not install
cost: a privacy tool that reads a directory and decides what may leave it is
exactly the kind of thing a user should be able to read end to end before
trusting it with their documents, and a single file is what makes "read it
end to end" a realistic thing to ask of someone. Splitting `airlock.py` into
a package would not remove any dependency; it would only spread the same
trust surface across files a reader has to reassemble themselves. `uv run
--script airlock.py` still works, unchanged, for exactly that reading and
hacking use case.

`pyproject.toml` enables `uv tool install .` alongside the single file:
it builds from the same `airlock.py` (see `[tool.hatch.build.targets.wheel]`
in `pyproject.toml`), never a restructured package. This exists because
registering airlock as an MCP server previously meant writing an absolute
path to `airlock.py` into a client config; move the checkout and every
registration breaks, silently, and several clients only surface that after a
full restart. A name on `PATH` survives a move or an upgrade; a filesystem
path does not. `render_mcp_help` detects whether `airlock` resolves on
`PATH` (via `shutil.which`) and prints whichever config is actually correct,
falling back to the absolute-path `uv run --script` form when it is not
installed, rather than assuming one or the other.

**A bare `"airlock"` on PATH is not enough; GUI-launched clients need the
resolved absolute path instead, and that is not the same fix as "found on
PATH".** An earlier version of this fix emitted `"command": "airlock"`
whenever `shutil.which` found it, which works for Claude Code, Codex, and
Gemini CLI, since each starts as a child of the user's interactive shell
and inherits its `PATH`. It does not work for Claude Desktop, Cursor,
VS Code, or Zed: those are started by the window manager or `launchd`, not
a shell, and on this machine `launchctl getenv PATH` is empty, so a
Dock-launched app gets the system default `/usr/bin:/bin:/usr/sbin:/sbin`,
which contains neither `~/.local/bin` (`uv tool install`) nor
`/opt/homebrew/bin` (Homebrew). A bare name in a GUI client's config is a
silent command-not-found there, and shipping it was a regression: the
pre-packaging version emitted the `uv run --script` absolute-path form
unconditionally, which did work for Desktop. `_airlock_launch_forms` now
returns one form per launch kind, keyed off `MCP_CLIENTS[client]["launch"]`
(`"shell"` or `"gui"`), not one shared form.

**`shutil.which` can resolve to a path that will not exist once the
process exits, and emitting that into a client's config registers a
command that breaks on the next launch.** Hit directly while testing this
fix: running from inside an ephemeral `uv run --script` venv (a git
worktree's own `.venv`), `shutil.which("airlock")` resolved to
`<worktree>/.venv/bin/airlock`, a path that disappears with the worktree.
`_looks_ephemeral` checks the found path, and what it points to if it is a
symlink, for path components that mark a venv, temp dir, or build cache,
and treats a match the same as "not found": both launch forms fall back to
`uv run --script <absolute path to airlock.py>`. The emitted GUI path is
deliberately the symlink `shutil.which` reports (`~/.local/bin/airlock`,
`/opt/homebrew/bin/airlock`), not its fully resolved target: both
`uv tool install` and Homebrew put a stable symlink at that documented
location pointing into an internal per-tool venv, and dereferencing it
would print an unrecognisable implementation path instead, even though
both forms happen to work.

**`/mcp` is a slash command, reachable only inside an interactive chat
session; a setup script has no session to run it in.** `airlock mcp
[--client NAME] [--json]` is the non-interactive equivalent:
`--client` picks one of `MCP_CLIENTS`' seven supported clients and emits
its own schema (`mcpServers` for claude-code/claude-desktop/cursor/
gemini-cli, TOML `mcp_servers` for codex, `servers` with `"type": "stdio"`
for vscode, `context_servers` with `"source": "custom"` for zed);
`--json` strips it to parseable output only, so a script can pipe it
straight into a client's config file. Extend `MCP_CLIENTS` only after
checking a client's real schema, never by assuming it matches one already
there; the four that share `mcpServers` were confirmed to, not guessed.

The PEP 723 header and `pyproject.toml`'s `[project.dependencies]` now both
declare the same dependency list, and nothing keeps them in sync
automatically: no native mechanism ties a PEP 723 inline block to a sibling
pyproject.toml's dependencies, and a custom hatchling metadata hook that
derived one from the other was considered and rejected, because it would
make `pyproject.toml`'s dependency list dynamic and unreadable at a glance,
the same auditability cost splitting the module would carry.
`tests/test_packaging.py` is the safety net instead: it parses both and
fails if they disagree, on names or version bounds, needs neither models nor
Ollama, and runs in CI alongside the other suites. The version number does
not have this problem: `[tool.hatch.version]` reads `__version__` directly
out of `airlock.py`, so there is exactly one version number in the
repository, not two that can drift the way the dependency lists could.

`eval/` is a third thing: the measurement harness behind the numbers cited in
`airlock.py`'s docstrings (padding-shape detection, round-shape false
blocking, the guard-architecture bake-off). It is not part of the shipped
tool and `airlock.py` does not depend on it. `eval/dataset.jsonl` is
generated by `eval/build_dataset.py`, never committed: its credentials
category needs values that look like real keys, and a fixed literal one is
exactly the kind of thing that already got a push rejected by secret
scanning once (see Testing conventions below). Regenerate it before running
anything in `eval/`. See `eval/README.md` for which claims each script
reproduces and which ones it cannot.

## Rules that came from failures

**Never write a checkable fact from memory.** Model tags, API names, version
numbers, library behaviour. Read the file, query the machine, or fetch the
docs. This project has been wrong about a model tag, an SDK import path, a
memory requirement, and a PyPI version, every time from a confident guess.

**A stale fetch is not evidence.** PyPI once returned a cached page listing an
old version as latest, and a GitHub README described a shipped release as
pre-release. Both contradicted what the maintainer could see. If a page
disagrees with a primary source, check again rather than concluding.

**`py_compile` proves almost nothing.** A missing name is a runtime error. Two
refactors here deleted live functions and still compiled. After any structural
edit, import the module and resolve the names.

**Delete top-level definitions by AST line range, never by text slice.**
Slicing from one `def` to the next swallows everything defined in between.
That deleted three functions once and a block of constants once.

**Know what green looks like before trusting it.** The test suite once passed
every containment check because the worker had failed and produced nothing to
contain. Assertions about absence need a positive control.

**A step outside every try still needs to fail closed.** `run_worker`
builds `signature = (action, step.get("path"), step.get("query"))` from the
worker model's own step, then hashes it to check `seen_actions`, outside
any try/except. Hashing raises `TypeError: unhashable type` if the model
returns a dict or list for "path" or "query" instead of a string, which
escaped `run_worker` as an uncaught exception rather than the block
envelope every other malformed-step path in that loop returns. Reachable,
not hypothetical: "Things that look like bugs and are not" below already
records that installed worker models ignore JSON schema constraints, so a
schema-violating step is ordinary input from this guard's point of view.
Fixed by wrapping the signature build and the `seen_actions` lookup/add in
their own try, returning a block envelope on `TypeError`. The general
lesson: fail-closed has to be checked at every point user- or
model-controlled data gets hashed, indexed, or otherwise used in a way
that can raise on an unexpected shape, not just at the call sites that
obviously look risky.

## Invariants

**The guard fails closed.** Any error, timeout, or unparseable payload is
`block`, never `approve`. A guard that approves on error manufactures
confidence.

**Deterministic layers run before model layers,** and must not be reachable
only through an optional dependency. `pii-patterns` duplicates part of
`pii-detector` on purpose: an earlier version delegated all PII detection to
Presidio, and `--no-presidio` then approved an email and a phone number.
`--no-presidio` no longer exists (Presidio was replaced by the two Liquid
encoders), but the lesson still applies to `pii-detector`: it must stay
reachable unconditionally, not only when a dependency happens to be present.

**`trust_remote_code=True` is an accepted tradeoff, not an oversight.** Both
guard encoders (`pii-detector`, `policy-linter`) use custom architectures and
execute code from their Hugging Face repository at load time. Presidio,
which they replaced, required nothing of the sort. Mitigated by pinning
`PII_DETECTOR_REVISION` and `POLICY_LINTER_REVISION`, each verified against
the Hugging Face API rather than guessed, not eliminated. State this plainly
in README.md as well; it is a real supply-chain risk taken on inside a
privacy tool and must not be buried in a call-site comment.

**The Policy Linter has no published benchmark.** Liquid's own release post
calls both fine-tunes "proof-of-concept demonstrations... not formally
evaluated research contributions." The PII-Detector, by contrast, is
benchmarked on six public corpora and is best on five. The only evidence for
the Policy Linter is this project's own `eval/`, on a synthetic dataset built
for this project. A later reader must not assume it was measured externally;
it was not.

**`eval/`'s numbers are an upper bound, not field performance.** The
PII-Detector scored 1.00 precision on `eval/dataset.jsonl` against 0.428 and
0.236 on the hardest public corpora it is actually benchmarked on. The
synthetic set is markedly easier than real text. Say so wherever an `eval/`
number is cited, so nobody reads it as expected accuracy in the wild.

**Everything outbound passes through `envelope`.** It is the single choke
point, which is why concern sanitising happens there. Guard explanations are
model-written text and will quote what they blocked if not re-checked.

**The receipt describes what airlock did, never what it found.** Paths, match
counts and topics are content. A receipt carrying content-derived facts is an
unguarded oracle, because the guard inspects answer text and never sees
metadata. `airlock_open` once returned a directory listing and gave away
`medical_records_2026.pdf` before any question was asked.

**In `serve`, stdout is the JSON-RPC channel.** One stray character corrupts
the stream and drops the client. Use `err_console`. `print(..., file=sys.stderr)`
is also fine; `console.print` is not.

## Known weaknesses

**Policy linter rule 5 (confidential business) was reworded, not just
rethresholded (item-3 fix).** The prior wording, "Flag confidential business
information such as unannounced acquisitions or a customer leaving," fired
on ordinary business vocabulary alone (`shipment`, `inventory`, `ledger`
each tripped it with no other context, 3/8 of a bare-word sample) and
accounted for 52% of the bake-off's false positives. The wording is now
"Flag disclosure of non-public company information that has not been
announced, such as a pending acquisition, a major customer ending its
contract, or an internal investigation." Against `eval/dataset.jsonl`
(contextual block-class as positives, every approve-class record as
negatives): all 6 rules under the prior wording scored recall 0.9500,
false-block 0.4062; removing rule 5 outright dropped to recall 0.8000,
false-block 0.4000 (a 0.15 recall loss for almost nothing, so the wording
was the defect, not the rule); the reworded rule held recall at 0.9500 and
brought false-block down to 0.3438, with the bare-word trip rate dropping
from 3/8 to 0/8. Two rewordings were tried and rejected before this one: an
abstract harm/reputational-harm framing scored 0.00 recall on the
contextual set, too vague for the model to match anything; an event-list
framing (naming categories like acquisitions and customer churn without a
non-public/unannounced qualifier) kept the false-block rate high, the same
defect as the prior wording. The qualifier ("has not been announced") and
concrete examples, not a bare noun list, is what separates announced
business talk from an actual leak. The rule is not silent even reworded: it
still accounts for a meaningful share of the linter's false positives, and
this is a linter-wide precision problem (0.34 false-block over the
approve-class dataset), not something rule 5 alone still carries. Wording,
not threshold, was still the right lever: raising the threshold enough to
quiet a noisy rule costs the recall it exists for, which a wording fix does
not have to trade away.

**`PII_DETECTOR_ENTITY_THRESHOLDS` is a per-entity override, not an
exclusion list like Presidio's `BLOCKING_ENTITIES`.** Unfiltered,
`scan_pii_model` blocked on any non-O label with no notion of confidence,
and 2.7% of bare number-shaped job answers (8/300 sampled) false-flagged as
`contact.postal_code`. No category here fires on ordinary text the way
Presidio's `DATE_TIME`/`URL` did, so a threshold is the fix rather than an
exclusion; if a category-level problem is measured later, exclude it
outright instead of thresholding it to the point of never firing.

**`contact.postal_code` no longer trusts the threshold alone (item-3
fix).** The false-positive and true-positive score distributions provably
overlapped at the 0.70 threshold: one measured false positive scored 0.856,
above the lowest measured true positive at 0.845, so no single global
threshold on this entity could separate them. A `contact.postal_code`
finding now also requires at least one letter in the scanned text,
alongside the 0.70 threshold, not instead of it: a real postal code always
travels with an address, city, or an explicit "zip"/"postal code" label,
none of which a bare extracted number carries. Re-measured: a 600-string
sweep of bare, tax-extraction-shaped numbers found 5 scoring above 0.70
before the gate (0.83%) and 0 after (0/600, by construction, since none of
them contain a letter); six real postal-code-in-address sentences fired
identically before and after the gate (the gate is a no-op on text that
already has a letter). This closes the residual for bare numbers
specifically. It does not raise the PII detector's own recall on postal
codes in general, which is a separate, unmeasured-here limit of the model
itself, not something this gate touches.

**`identity.person_name` fires on bare single common nouns that double as
given names.** Measured directly against the model: "cherry" 0.90, "kiwi"
0.96, "lemon" 0.64, "olive" 0.98, while business vocabulary and short prose
measured clean (0/27 sampled). Narrow and rare enough in what a real
extraction job returns that it did not meet the bar for a threshold override
the way `contact.postal_code` did, but it is why
`tests/test_round_guard.py`'s benign-round fixture uses business words
rather than a fruit list.

**`reassembles_identifier` matches whole released values, not individual
characters.** A character-level subsequence test (ignoring which value each
character came from) was tried first and rejected: on legitimate rounds of
twelve numeric answers it false-blocked 38.0%, because a round normalises
to roughly 60 characters and a coincidental in-order digit match is not
rare at that length. Matching whole values instead keeps a false block a
needed conjunction of real fragments, and measured zero false blocks on
the same rounds.

**Padding used to defeat `reassembles_identifier` entirely; numeric
padding is now closed.** Substring containment lets a fragment padded with
extra characters break the contiguous run a source needs: measured over
200 trials per shape with benign jobs interleaved, suffix, prefix,
both-sides and prose padding all drove detection to 0.00. Closed by
re-running the same subset test on a digits-only projection of each value,
restricted to all-digit sources, since non-digit padding vanishes from the
projection while the identifier's own digits stay contiguous. Detection
returned to 1.00 on all four shapes, with 0.000 false blocking on six
legitimate round shapes including twelve 16-digit values -- the shape that
drove a rejected alternative (letting each value contribute any contiguous
substring, not just whole values) to 100% false blocking.

**A residual six-digit floor remains, not closed.** Short (six-digit)
all-digit sources against a digit-dense round of ordinary prose, amounts,
dates, box and reference numbers can coincidentally reconstruct one of
them even though nothing was split; six digits is reachable in practice
because `labelled_account` accepts `[0-9][0-9-]{6,}`, so a hyphenated
sort-code-shaped account number lands exactly at `MIN_REASSEMBLY_LENGTH`.
Measured over 300 seeded trials (`eval/reassembly_residuals.py`), 20/40/60
six-digit sources against such a round: 0.0000 to 0.0133 false blocking
for the shipped function, 0.0000 to 0.0067 for the raw pass alone (so the
digits projection adds to this floor rather than creating it); eight- and
nine-digit sources measured 0.000 for both. Every figure stays well under
the 12.8% that disqualified the rejected substring-contribution design
above.

**`advance_reassembly_state` tracks matches as edges, not a prefix walk,
so fragment release order cannot be assumed.** A caller chooses what order
to issue jobs in and can reassemble pieces in any order once they leave
the sandbox, so the state must not assume the fragment that completes an
identifier is the one released last. A pure prefix walk (extend forward
only from position 0) lacks that property: a value released before the
fragment that would make it reachable is tested against a reach set that
does not know about that fragment yet, and is never retried once it
arrives, so releasing pieces in reverse order would defeat it. Recording
every match as a directed edge and re-running shortest-path avoids that,
since an edge's position does not depend on when it arrived. This is also
tiling, not overlap: an edge only ever chains from exactly where the
previous one ended, matching `reassembles_identifier`'s own concatenation
model, measured head to head against an explicit overlap-cover
implementation on the same edge sets (200 sessions, 240 released values
each) at 0 disagreements in minimum piece count -- see the piece-bound
entry below for the one case (0.5 percentage points) where the model
choice did cost something.

**Cross-round reassembly's piece bound reduces false blocking but does not
eliminate it, and the rate depends on the caller's own answer shape.**
`advance_reassembly_state` blocks a source only when the cheapest way to
concatenate released values into it uses `REASSEMBLY_PIECE_BOUND` (5) pieces
or fewer, because unbounded coverage never forgets across a session and a
long enough benign session eventually covers some workspace identifier by
coincidence. Before this bound existed (uncapped piece count), 200
synthetic benign sessions per length measured: 12 released values 0/200,
30 values 1/200 (0.5%), 60 values 3/200 (1.5%), 240 values 23/200 (11.5%).
The discriminator is how many distinct pieces the cheapest covering needs:
a real attack (three fragments of one identifier) always needs exactly 3,
while this measurement's false positives at 240 values needed at least 6
pieces each, and nothing coincidentally covered at 30 values in 6 pieces
or fewer -- `REASSEMBLY_PIECE_BOUND` sits inside that gap. Measured over
200 synthetic sessions per length, two different
benign-value generators (both committed as named functions in
`tests/test_cross_round.py`, `benign_value_freeform` and
`benign_value_shaped`), with the bound applied: 0.0% false-blocked at 12,
30 and 60 released values under either generator; at 240, 0.0% for the
coordinator's own generator, 1.0% for this project's reproduction of that
same shape, and 11.5% for the wider, more digit-run-heavy generator. Neither
number is "the" rate; the rate is a property of the caller's answer
distribution as much as of the bound, and this file cannot know that
distribution in advance. Separately, the model choice (pieces must abut
exactly, i.e. tiling, versus pieces allowed to overlap as long as their
union covers the source) was measured to explain under one percentage point
of the gap, not the double-digit spread between generators, so tiling was
kept for consistency with `reassembles_identifier`'s own concatenation
model, not because it closes more cases. Overlap-based reassembly, where a
caller merges `"91284"` and `"847731"` by recognising the shared `"84"`
rather than concatenating whole released values, is not covered by either
check. An attacker who splits a value into more than the bound's worth of
pieces evades this specific check entirely, at the cost of one job and one
round per extra piece, and is still guarded round by round on the way out
regardless. See `REASSEMBLY_PIECE_BOUND`'s comment in `airlock.py` and
`task-1-report.md` fix rounds 1-2 for the full measurements. This tracking
is wired into `run_jobs` only, `airlock_extract`'s pipeline; `run_jobs` is
its sole call site. A fragment released through `airlock_ask`'s free-form
path, or a value split between an `airlock_ask` call and an
`airlock_extract` job, is not folded into this state at all and is
untracked cross-round. Each `airlock_ask` reply is still guarded on its
own; what is missing is the accumulation across calls that
`airlock_extract` gets. See README.md's "Limitations" for the user-facing
version of this gap.

**Two more round-guard holes are closed; two remain, on purpose.**
`reassembles_identifier`'s subset-concatenation pass preserved job order,
so a caller issuing fragments out of order defeated it, and its digits-only
projection could not help an alphanumeric identifier such as an API key,
since discarding the letters would discard what makes the match meaningful.
Both are closed: order independence reuses `advance_reassembly_state`'s
reachability primitive on a round-scoped, throwaway state (no new
algorithm, and it inherits that primitive's `REASSEMBLY_PIECE_BOUND` cap);
alphanumeric padding is closed by `_alnum_runs`, extracting maximal
alphanumeric runs from each raw value and running the same order-free pass
over the expanded run list. Order independence was measured directly:
across five arrangements (in order / reversed / shuffled / scattered in
order / scattered reversed, 400 legitimate rounds per numeric shape), the
order-free pass detects all five while the raw pass alone only catches the
two that keep job order, with false blocking staying 0.000 across every
shape tested (numeric, small, year, amount, 16-digit, ids, longnum).
Measured false blocking also stayed at 0.000 in
every check re-run for this change: the 160 approve-labelled records in
`eval/dataset.jsonl`, used as a wider prose corpus than the twelve
hand-written phrases the run-projection design was first tried against
(400 rounds, 0/400); the existing six/eight/nine-digit residual sweep in
`eval/reassembly_residuals.py` (unchanged from its prior figures); and
`eval/public_corpora.py`'s 877-record stack measurement (unaffected in
principle, since it calls `evaluate()` directly and never touches
`reassembles_identifier`, but re-run anyway to treat that as the deciding
check). What remains OPEN, stated plainly rather than implied by omission:
overlap-based reassembly (merging `"91284"` and `"847731"` via the shared
`"84"` rather than concatenating whole pieces) is still uncovered by any
pass in this file, and a caller who splits into more pieces than
`REASSEMBLY_PIECE_BOUND` and also issues them out of order still evades the
order-free check, the same residual `advance_reassembly_state` already
carries for cross-round accumulation.

**A blocked round used to poison the rest of the session; it no longer
does (fix wave, item 1).** `run_jobs` folded a round's `released` values
into `session.reassembly_state` before deciding whether that round itself
blocks, so a round that completed a cross-round reassembly and returned
`blocked` still recorded its own fragments as if the caller had received
them, even though a blocked round carries no results. Once a source's
stored edges reached `REASSEMBLY_PIECE_BOUND` that way, they stayed there:
every later round in the session matched against them regardless of its
own content, since `_fold_source_edges` recomputes the cheapest covering
from all stored edges, old and new, and the round-3 edges never left.
Concretely: `["912"]` -> ok, `["84"]` -> ok, `["7731"]` -> blocked
(correctly, it completes the SSN), then `["forecast"]` -> also blocked, for
the rest of the session, no matter what was asked. This turned the
measured false-block rate above (up to 11.5% at 240 released values) into
a per-session-fatal event instead of a per-round one: one coincidental trip
anywhere in a session doomed everything after it.

Fixed by snapshotting `session.reassembly_state` before the fold and
restoring it whenever the round blocks or the fold errors, so only rounds
that actually release their values leave a mark. Ruling on whether a
tripped session should stay blocked for the rest of its life: no, not as a
deliberate policy, and no separate "stay blocked" flag was added. With the
fix, a session's stored state, immediately after any round that returns
`ok`, never has a source at or under `REASSEMBLY_PIECE_BOUND` pieces --
otherwise that round would have blocked and its own contribution would
have been rolled back -- so a later round can only trip by contributing
new fragments of its own, never off residue from an earlier blocked one. A
caller who keeps re-submitting the exact fragment that completes a source
will keep getting blocked on that specific submission, which is
fail-closed working as intended, not stickiness; an unrelated round right
after a block proceeds normally (see `tests/test_cross_round.py`'s
`wiring_blocked_round_does_not_poison_state_case`, which is also the
positive control that rounds 1 and 2's legitimately released fragments are
still tracked correctly after the fix).

**`SESSION_CAP` and `SESSION_IDLE_SECONDS` bound orphaned sessions, not an
actively-used one's growth.** `airlock_close` pops one `SESSIONS` entry,
but a caller that never closes (a crashed client, a disconnected
transport) leaves its `Session` in memory; eviction bounds that specific
cost. It does NOT bound how much one busy session accumulates:
`touch_session` refreshes `last_active` on every call, so a session that
keeps being called never idles out and never hits the TTL, no matter how
many rounds or values it releases, and there is no separate per-session
round or value cap. What actually keeps a single session's
`reassembly_state` bounded is geometry, not eviction: `_fold_source_edges`'
own comment shows the edge set for one source is capped by that source's
length squared regardless of how many rounds fold into it, so
`reassembly_state`'s size tracks the workspace's identifiers, not session
length or round count. Size is bounded; the false-block *rate*
`advance_reassembly_state` measures (up to 11.5% at 240 released values in
one distribution) is not, since nothing caps released-value count for a
session that keeps getting used. A cap AND a TTL are both needed, not just
one: a cap alone still lets crashed/disconnected sessions pile up before
the TTL retires them; a TTL alone still lets concurrent-session count grow
if sessions open faster than idle ones retire. `SESSION_CAP = 200` and
`SESSION_IDLE_SECONDS = 3600` are reasoned about, not measured against an
`eval/` figure: both are generous for a single local process serving one
cloud assistant.

**`MAX_REASSEMBLY_LENGTH`'s ceiling still costs seconds, not
milliseconds, at its own worst case.** Before this bound existed, 12
unshaped answers of `FILE_SLICE_CHARS` (4000 characters) each against 400
workspace identifiers took 18.0s on the guard path itself, a denial of
service on the path meant to prevent one; the length check now rejects
that round in O(1) before subset enumeration runs. At the bound's own
ceiling (12 values summing to 4000 characters) against 400 non-matching
identifiers, `reassembles_identifier` still costs seconds:
`eval/reassembly_residuals.py` measured a mean of 4.452s (median 4.416s, 5
reps). A round of shaped jobs cannot approach that: twelve
"line"-shaped answers (`JOB_SHAPES` `maxLength` 80) sum to at most 960
characters, and identifier count decides the rest -- the same script
measured 10ms at one identifier, 153ms at fifty, 1230ms at four hundred,
and a three-document workspace yields five identifiers, so 17ms is
realistic; the four-hundred-identifier figures above are pathological, not
representative. `FILE_SLICE_CHARS` is a generous ceiling that leaves
realistic traffic untouched while bounding unshaped free-text answers.

**The web console exists because `confirm_on_tty` cannot cover the case
that matters most.** `build_server` opens `/dev/tty` for `--approve gate-*`
and raises when it is absent, deliberately, rather than downgrading a
requested gate to nothing. But absent is the normal case: Claude Desktop,
Cursor, VS Code and Zed are launched by the window manager, not a shell, so
there is no controlling terminal and gate mode could not be used at all in
exactly the clients airlock is for. `--ui` supplies the missing channel.
`confirm_in_browser` is `confirm_on_tty`'s counterpart and fails the same
way: an unanswered gate returns False on timeout, never True, because a
gate nobody answered has granted nothing. Verified as a positive control
rather than assumed, in `tests/test_console.py`: the timeout path is
asserted to both return False and to have actually waited, since a function
that returned False instantly would pass the first assertion while proving
nothing about the gate.

**Loopback is not an access control, and the token alone is not either.**
Any page open in the operator's browser can POST to `127.0.0.1`, so binding
there keeps nothing out. The console requires the run's token in an
`X-Airlock-Token` header, which cross-origin JavaScript cannot set without
a preflight, and refuses any request carrying a foreign `Origin`, which
refuses that preflight too. Both, not either: the header requirement is
what a same-origin-unaware attacker hits, and the Origin check is what
stops a token that has leaked into a screenshot or a shell history from
being replayed by a page. The token is generated per run, printed once on
stderr, and never written to disk; the page strips it from the address bar
with `history.replaceState` on load so it does not survive in browser
history. The page shell itself is served without a token on purpose, since
it is inert until one is supplied, and requiring a token to see an empty
frame would only mean an operator who reloads loses their own console.

**`CONSOLE_HTML` and `ui/index.html` are two copies of the same file, kept
honest by a test rather than machinery.** The page ships embedded so that
`uv run --script airlock.py` works from any directory, which reading it
from disk would break; it is edited as a real file because editing HTML
inside a Python string literal is how mistakes get made. `tools/sync_console.py`
copies one into the other and `tests/test_console.py` fails when they
differ. Same arrangement, and same reasoning, as the PEP 723 header and
`pyproject.toml`'s dependency lists.

**The console loads nothing from the network, and that cost a typeface.**
The design used Bricolage Grotesque and Figtree from Google Fonts. A
privacy console that fetches its own fonts announces to Google every time
the operator opens it, which is precisely the class of thing this tool
exists to prevent, so the page uses system faces and the CSP declares
`default-src 'none'`. A test asserts no `googleapis`, `gstatic` or CDN
reference survives, because this is the kind of line that gets added back
by someone improving the design later.

**Polling, not server-sent events.** The page asks `/api/state` every 1.5
seconds and re-renders. SSE would be tidier and is not worth a second
transport, a reconnect path and a second set of failure modes for a page
one person has open on their own machine. The whole state is small enough
to send every time, which also means there is no incremental-update bug
class to get wrong.

**The CLI is organised around what a person does, not around airlock's
parts, and that was a rewrite rather than a tidy-up.** The previous surface
was `doctor / ask / guard / serve / mcp` with seven global flags including a
five-value `--approve` enum and a 0.0-to-1.0 float on a model's internals.
Every one of those names described a piece of airlock. None described a
thing anyone wanted to do, and getting to a working setup took five steps,
one of which was "find your client's config file yourself". `serve` was in
the help but is never typed: the client spawns it. The replacement is
`connect / status / disconnect / check / chat` with two visible flags, and
`airlock <folder>` is `connect`. Breaking existing invocations was chosen
deliberately over carrying both surfaces.

`--approve`'s five values collapsed to `--ask always|writes|never` with
`--allow-writes` becoming `--write`. The old matrix still exists internally,
derived by `resolve_ask_mode`, because gate-versus-hint is a real
distinction the MCP spec forces; it is just not a choice a person should
have to make from a help listing. `--model`, `--linter-threshold`,
`--trace` and `--objective` still work and carry `help=SUPPRESS`: they exist
for measurement, and README.md documents them.

**`argparse` cannot express "an optional positional OR a subcommand", and
the two ways of faking it both have a trap.** A top-level parser holding
both `FOLDER` and subparsers gives the positional priority, so `airlock
status` parsed as a folder named "status"; the folder lives on its own
parent parser now, added only to the subcommands that take one. The argv
shim that turns `airlock ~/x` into `airlock connect ~/x` originally scanned
for the first token not starting with `-`, which put `connect` in the middle
of `--ask always ~/x`, because a flag's value is a bare word too. Only the
first token decides now. Knowing which flags take values would have meant
keeping a second copy of the parser's knowledge in sync with the parser.
Separately, `help=argparse.SUPPRESS` on a subparser renders as the literal
`==SUPPRESS==` in the command list; omitting `help=` is what actually hides
`serve`.

**Detecting an installed client from a path is where this can do damage,
so it only ever writes where something already exists.** `client_config_path`
accepts a candidate when the file exists, or when its parent directory
exists, and never creates a directory tree. A path the table gets wrong
therefore cannot leave a stray config in the wrong place; it degrades to
"airlock could not find your config", which is a message rather than
damage. Every path in `CLIENT_CONFIG_PATHS` was checked against a real
machine, not recalled.

The parent-directory rule needed one exception, found by running the flow
against an empty temporary `HOME`: `~/.claude.json` sits directly in the
home directory, which always exists, so Claude Code was reported as
installed everywhere, including in a `HOME` containing nothing at all. The
rule now excludes the home directory itself, and a dotfile living there must
exist to count.

**Editing somebody else's config file is the risky part of `connect`, and
the codex path broke in a way only a round trip could show.** Every write
backs the file up to `<name>.airlock-backup`, goes through a temporary file
in the same directory, and replaces atomically, so an interrupt cannot
truncate a live Cursor config. Every other key in the file is preserved:
airlock is one entry among many. A malformed config raises rather than being
overwritten.

codex is TOML, `tomllib` reads but cannot write, and a TOML writer is a
dependency for one section of one file, so its block is merged textually.
The regex first written for that matched the table header followed by
`[^\[]*`, meaning "up to the next bracket" -- and the block's own body
contains one, in `args = ["serve", ...]`. Adding airlock worked, because
that path only appends; replacing or removing it cut the match mid-array and
left a file that no longer parsed as TOML. It now matches to the next table
header at the start of a line. Adding, replacing and removing are three
different code paths through one function, and only the first was exercised
until a test did all three.

**Two functions were named `resolve_approval`, and the module-level one
defined second silently won.** The web console's `resolve_approval(id,
granted)` answers a call the operator is holding; a new CLI
`resolve_approval(args)` derived the approval posture from flags. Python does
not warn about this, no test failed, and `/api/approve` would have called the
wrong one. Caught by diffing duplicate top-level definitions after a botched
edit, not by anything looking for it. The CLI one is `resolve_ask_mode` now.
The general lesson is that a name collision in a single-file module is a
shadowing bug with no diagnostic, so new top-level names are worth grepping
for before adding them.

**Four console defects survived every unit test and died in the first
end-to-end run.** The suites drove `evaluate`, the HTTP endpoints and the
approval primitive directly, and all of them passed while the page was
wrong in ways only real traffic shows.

The one that mattered: an approved answer with no `disclosure_request`
never leaves the machine (the caller gets a receipt), but the console
labelled it "Sent" and printed the local model's draft next to that label.
It told the operator their content had gone out when it had not. `ui_note`
now distinguishes three outcomes, not two -- `sent`, `kept`, `held` --
because "the guard approved this text" and "this text was released" are
different facts, the same conflation `envelope`'s `grounded` field exists
to prevent elsewhere.

The other three: the summary line read "Waiting for the first question."
while a question was visibly running, since it counted only finished ones;
a real workspace path is long enough to wrap the header onto two lines, and
the `direction: rtl` trick that keeps a path's tail visible also moves its
leading slash to the end, rendering `/a/b/c` as `a/b/c/`, so truncation is
done in JavaScript instead; and guard concerns are sentences the model
wrote, not the short labels the rail was designed around.

**Polling and expandable rows fight each other, and polling wins by
default.** `renderFeed` replaced the feed's innerHTML every 1.5 seconds, so
a drawer the operator opened closed again before it could be read: the
interval always beat the reader. Fixed by keying each exchange on
`session|timestamp`, holding open keys in a set that survives the rebuild,
and skipping the rebuild entirely when the rendered signature has not
changed. This is the cost of the polling decision recorded above, not an
argument against it; the fix is smaller than a second transport would be.

## Things that look like bugs and are not

`check()` renders through `Text.assemble`, which does not parse rich markup.
Tags in a `check` detail print literally. `console.print` does parse them.

The worker model must honour JSON schema constraints. Installed and usable are
different properties: `qwen3.5:0.8b-mlx` ignores the schema and returns a bare
enum value, so every step fails. `doctor` probes for this.

`detect-secrets` entropy plugins are filtered out deliberately. They assume
source code; on prose they fire on nearly every sentence.

## Testing conventions

**Credentials in tests are generated, never written down.** `fake_credential`
builds a shaped string from `secrets`. Two reasons, and the second matters
more:

A literal that looks like a live key trips secret scanning and blocks the
push. That is a fair call, and it happened here: a fabricated Stripe key was
close enough to the real shape that GitHub rejected the repository.

More importantly, one example per vendor is what let a real bug ship. The
Stripe pattern required a hyphen (`sk-`) while Stripe uses an underscore
(`sk_live_`), and a single hand-picked fixture never exercised the variants.
`CREDENTIAL_SHAPES` covers every prefix a vendor issues, several samples each,
so a detector covering one member of a shape but not another fails the suite.

Faker is the obvious library and is the wrong tool: it has no vendor
credential provider, and its own documentation says not to use it for tokens
or keys. Generating a shaped string is one line of stdlib.

The one literal that remains is AWS's own published documentation key, which
is allowlisted by scanners precisely because it is public and inert.

**Groups are isolated.** A crash in one is recorded as a failure and the run
continues. An early version aborted on an `AttributeError` in group A and
printed a traceback instead of a summary, so nothing else ran.

**Skips are reported, and low totals fail.** A suite that silently collects
fewer tests reads exactly like one that passed, so the runner exits non-zero
when the collected count is implausible.

**Distinguish "withheld" from "never ran".** Both produce no content, so a
containment assertion cannot tell them apart, and the second makes every leak
check pass for the wrong reason. Group C reports INCONCLUSIVE instead.

## Style

Least code that works. Stdlib before dependencies, one line before fifty.
No abstraction with one implementation, no config for a constant.

Comments explain why, not what. If a comment restates the line below it,
delete the comment. If it explains a decision that outlives the line, consider
whether it belongs in this file instead.

Non-trivial logic leaves one runnable check in `tests/`.
