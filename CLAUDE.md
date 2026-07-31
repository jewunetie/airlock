# Working on airlock

Notes for anyone, human or agent, changing this code. Everything here was
learned by something breaking. The reasoning lives here so `airlock.py` can
stay readable; the file states what the code does, this states why.

User-facing behaviour belongs in README.md. Do not repeat it here.

## Shape

One file, `airlock.py`, with PEP 723 inline dependencies. Tests live in
`tests/`, never in the shipped file. The single-file structure is deliberate:
it can be run with `uv run --script` from anywhere with nothing installed.

Keep it that way. New helpers go in the same file unless they are test-only.

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

## Invariants

**The guard fails closed.** Any error, timeout, or unparseable payload is
`block`, never `approve`. A guard that approves on error manufactures
confidence.

**Deterministic layers run before model layers,** and must not be reachable
only through an optional dependency. `pii-patterns` duplicates part of
Presidio on purpose: an earlier version delegated all PII detection to
Presidio, and `--no-presidio` then approved an email and a phone number.

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

## Things that look like bugs and are not

`check()` renders through `Text.assemble`, which does not parse rich markup.
Tags in a `check` detail print literally. `console.print` does parse them.

The worker model must honour JSON schema constraints. Installed and usable are
different properties: `qwen3.5:0.8b-mlx` ignores the schema and returns a bare
enum value, so every step fails. `doctor` probes for this.

`detect-secrets` entropy plugins are filtered out deliberately. They assume
source code; on prose they fire on nearly every sentence.

Presidio's spaCy model is named explicitly. Left to its default it downloads
`en_core_web_lg`, roughly 400MB, even when a smaller one is present.

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
