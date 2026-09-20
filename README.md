# airlock

An MCP server that lets a cloud assistant consult a private directory without ever seeing its contents.

A small local model reads and reasons over one sandboxed directory. Everything it tries to send outward passes through a layered privacy guard first. The cloud assistant receives findings, structure, and answers. It does not receive your files.

The name is the metaphor: a sealed chamber between a private space and an external one, where everything is inspected before it is allowed through.

## The problem

Cloud assistants are useful over your own documents, and sending those documents to a cloud provider is exactly what you may not want to do. The usual answers are to send everything and trust the provider, or to send nothing and lose the capability.

airlock takes a third position. The local model does the reading. The cloud model does the reasoning. A guard decides what is allowed to cross between them, and it is the guard, not the local model, that has final say.

**Passing the guard means the content was judged safe to disclose. It does not mean the content is accurate.** The guard checks disclosure, not correctness, and the worker is a small local model: it can misread a file, report a permission error as "the file does not exist," or answer confidently having read nothing at all. An approved reply is vetted for privacy, not verified for truth.

## How it works

```
cloud assistant
      |
      |  airlock_ask("what themes appear across these files?")
      v
  +-------------------------------------------+
  |  airlock (MCP server)                     |
  |                                           |
  |   local worker model                      |
  |     reads files, only inside the folder   |
  |            |                              |
  |            v  draft reply                 |
  |   layered privacy guard                   |
  |     approve / revise / block              |
  |            |                              |
  |            +--> revise: worker redrafts   |
  |                 (up to 3 cycles)          |
  +-------------------------------------------+
      |
      v  approved message only
cloud assistant
```

On a `revise` verdict the worker redrafts against the guard's stated concern and the cycle repeats, to a maximum of three attempts. On `block` nothing leaves.

## The guard

Four layers run in order. Any one of them can stop a message. The deterministic layers run first because they are fast, exact, and not persuadable.

| Layer | Mechanism | Catches |
|---|---|---|
| `secrets` | Regex plus `detect-secrets` named detectors | API keys, tokens, private keys, credentials |
| `pii-patterns` | Local regex, always runs | Email, phone, SSN, credit card, IBAN, street address, date of birth |
| `pii-detector` | [LiquidAI LFM2.5-Encoder-350M-PII-Detector](https://huggingface.co/LiquidAI/LFM2.5-Encoder-350M-PII-Detector), a 350M token classifier | Names, locations, and 40 PII types the pattern layer above cannot express, including health, legal, and credential identifiers |
| `policy-linter` | [LiquidAI LFM2.5-Encoder-350M-Policy-Linter](https://huggingface.co/LiquidAI/LFM2.5-Encoder-350M-Policy-Linter), a 350M zero-shot rule scorer | Medical, financial, legal, immigration, and confidential-business disclosure written in prose that names no identifier at all |

Two design decisions are worth naming, because both are deliberate and both cost something.

**The guard fails closed.** If either encoder cannot load, times out, or a call to it fails, the verdict is `block`, not `approve`. A guard that approves on error is worse than no guard, because it produces confidence rather than a leak you would notice.

**`pii-patterns` always runs.** This layer duplicates part of the PII detector's coverage on purpose, and does not depend on torch or transformers being installed at all. An earlier version delegated all PII detection to a single model layer, and running with that layer disabled approved a message containing an email address and a phone number. Structured identifiers are now checked deterministically no matter what happens to the model layers below.

### A supply-chain tradeoff: `trust_remote_code=True`

Both encoders use custom architectures with no standard-library equivalent, so loading either executes code from its Hugging Face repository at load time. Presidio, the layer these replace, required nothing of the sort. This is a real tradeoff taken on inside a privacy tool, mitigated but not eliminated: both models are pinned to a specific revision (`PII_DETECTOR_REVISION`, `POLICY_LINTER_REVISION` in `airlock.py`), each verified against the Hugging Face API before being written into the file, so a later push to either repository cannot silently change what runs on your machine.

### What is, and is not, independently benchmarked

The PII-Detector is benchmarked by its authors on six public PII corpora and scores best on five of six. The Policy Linter has **no published benchmarks**; Liquid's own release post describes both fine-tunes as "proof-of-concept demonstrations... not formally evaluated research contributions." The only evidence for the policy linter's behaviour is this project's own synthetic measurements, run against a synthetic dataset built for this project, not an external corpus.

That harness's numbers should be read as an upper bound, not as expected field performance: the PII-Detector scored 1.00 precision on the synthetic dataset now generated by `test.build_dataset()`, against 0.428 and 0.236 on the two hardest public corpora it is benchmarked on. The synthetic set is easier than real text, on purpose, to isolate what was being tested. See the testing section below for the current measurements and their limits.

## MCP tools

| Tool | Purpose |
|---|---|
| `airlock_open(objective)` | Start a session. Returns a session id and file and directory **counts**, never names. |
| `airlock_ask(session, question)` | Ask the local model about the workspace. The reply is guarded. |
| `airlock_close(session)` | End a session and discard its state. |
| `airlock_extract(session, jobs)` | Extract one fact per job from a specific document, or write a value into one, without routing it through free-form prose. Prefer this over `airlock_ask` for anything with structure. |
| `airlock_guard_check(text)` | Test whether a given string would pass the guard. Useful for calibration. |

### Disclosure is opt-in

`airlock_ask` returns a **receipt** by default: how many steps ran, which kinds
of action, and the guard's decision. Not the answer.

To receive the answer, the caller sets `disclosure_request` to a short
statement of what it needs and why. That statement is recorded in the trace and
shown to you next to whatever is released.

The reason it is a sentence rather than a boolean: a boolean is free to set, so
every caller would set it on every call, and a control everyone always trips is
not a control. A justification carries friction proportional to the ask and
leaves an artifact you can hold against what actually left.

**What the receipt may contain is a deliberate line.** It describes what
airlock *did*, never what it *found*:

| Reported | Withheld |
|---|---|
| step count, action kinds | file paths and names |
| guard decision, layers, rules | match counts, topics |
| whether anything was withheld | anything derived from file contents |
| whether the answer was grounded in a successful read | which files were read, or how many |

A receipt carrying content-derived facts would be an unguarded oracle. The
guard inspects answer text and never sees this metadata, so "how many files
mention cancer" would return a count and leak the fact without any disclosure
request at all. Repeated queries would map the directory.

Note the asymmetry with the activity log below: the same events, redacted
differently. You see the file paths, because it is your machine. The caller
does not.

**Honest limit.** A caller can write any justification it likes. This is a
governance control, not a security one: it produces a record and a decision
point, not a guarantee.

### Approval policy

```
--ask always     airlock holds every call until you answer
--ask writes     airlock holds calls that can alter files  (default)
--ask never      airlock holds nothing
```

`--ask writes` means different things depending on whether writes are on at
all. With `--write`, a call that can alter files is held until you answer.
Without it there is nothing to hold, so the tools are annotated with
`destructiveHint` and the client may prompt if it chooses;
[the MCP specification is explicit](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)
that annotations are hints a client may ignore. Holding is a real control;
annotating is a request.

That is why writes cannot be switched on while approval is quietly left off:
`--write` upgrades the default from annotate to hold, and only an explicit
`--ask never` turns both off.

**Holding a call needs somewhere to ask.** While serving, stdin is the
JSON-RPC stream, so terminal prompts go to `/dev/tty`, which does not exist
when a GUI client launches the server as a subprocess. Claude Desktop, Cursor,
VS Code and Zed are all in that category, which is why the web console is on
by default: it is the only channel those clients have.

```sh
airlock ~/tax-2025 --write --ask always    # you answer in the console
```

With `--no-ui` and no terminal, airlock refuses to start rather than
downgrading to no approval, because silently turning a requested hold into
nothing is the worst available outcome.

**A gate approves a call, not its consequences.** One `airlock_ask` with writes
enabled may perform several writes internally, and approving the call approves
all of them. Per-write approval would need the gate inside the worker loop,
which is not what this does.

Tool annotations are computed at startup from `--write`, so
`airlock_ask` reports `readOnlyHint: true` only when it is actually read-only.

## Install

Install `airlock` on your `PATH` with `uv`, or run the script directly.

**`uv tool install`** (primary path):

```sh
git clone https://github.com/jewunetie/airlock.git
cd airlock
uv tool install .
```

This registers an `airlock` command backed by its own isolated environment, the same way `uv tool install` works for any Python CLI. Update by pulling and re-running the same command; remove with `uv tool uninstall airlock`.

**Run the script directly** (alternative, for reading or hacking on the source): `airlock.py` keeps its PEP 723 header, so it stays runnable with nothing installed beforehand beyond `uv` itself:

```sh
git clone https://github.com/jewunetie/airlock.git
cd airlock
./airlock.py doctor
```

`uv` resolves the dependencies declared in that header on first run. This is the form every example below uses interchangeably with the installed `airlock` command; swap `./airlock.py` for `airlock` once it is on `PATH`.

Either way, a single file is still what you are trusting: `uv tool install` builds from the same `airlock.py` that you can run directly. See the "Shape" section of CLAUDE.md for why that property, not the ability to run with zero setup, is what this project actually protects.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com/) running locally, for the worker model
- `torch` and `transformers`, for the two guard encoders

`torch`, `transformers`, and the rest of `airlock`'s dependencies total roughly 2.6GB with the two guard encoders' model weights. Installed via `uv tool install`, they are resolved once into that isolated environment. Run directly with `uv run --script`, they are declared inline in `airlock.py` via PEP 723 and resolved into a cache on first run instead. Either way there is no separate `pip install` step.

```sh
ollama pull qwen3.5:0.8B               # worker
```

**Do not use an `-mlx` tag for the worker.** MLX is the faster backend on Apple
Silicon, but measured on Ollama 0.32.0, `qwen3.5:0.8B-mlx` ignores
grammar-constrained decoding: asked for an object matching the worker schema it
returns the bare string `answer`, so every step fails and no session completes.
The plain tag on the same machine, same Ollama, same prompt, honours the schema.

The entire worker loop is schema-constrained JSON, so correctness settles this
over speed.

`doctor` checks for exactly this, and is worth re-running whenever you change
the worker tag:

```
 fail  worker emits valid JSON  Model returned unparseable JSON. First 200 chars: 'answer'
```

Any Ollama model works for the worker role. The default is set in `airlock.py` and overridden with `--model`.

The guard's two encoders are not Ollama models. They are downloaded once from
Hugging Face on first load, roughly 350MB each (~700MB total), then cached
locally like any other Hugging Face model. `doctor` reports whether each is
already cached before triggering that download. See [A supply-chain
tradeoff](#a-supply-chain-tradeoff-trust_remote_codetrue) above before relying
on this in an environment where executing third-party model code is a concern.

## Quickstart

```sh
airlock ~/some-project
```

airlock prints the folder it is about to expose, finds your assistant, runs the
full setup check, shows the exact line it will write, and writes it once you
say yes. Restart the client and it can ask about that folder, through the
guard, without seeing the files.

If anything is missing it walks you through fixing it: a model tag that is not
pulled yet can be pulled from the prompt, and everything else prints the exact
command. First run and a broken install are handled the same way, since they
look identical from here.

The folder defaults to the one you are in. Your home directory or the
filesystem root puts everything beneath them in scope, so those two cases ask
for confirmation rather than proceeding quietly.

## Check the setup

```sh
airlock status
```

Lists which assistants are connected and to which folder, read back out of
each client's own config, then runs the full check: the workspace resolves,
both guard encoders load, Ollama and the worker model are reachable, the
worker honours JSON schema constraints, and three live guard cases (a
credential, a person, innocuous text) return the right verdict with the right
layers firing.

Run this first when something is wrong. It catches nearly every
misconfiguration, and it distinguishes "the deterministic layers passed and
the model call failed" from "the guard is broken", which are different
problems.

## Connect an assistant

```sh
airlock ~/tax-2025
```

That is the whole thing. airlock finds which assistants are installed, asks
which one, checks that everything it needs is working, shows you exactly what
it is about to write, and writes it after you say yes. Restart the client and
it can ask about that folder.

It backs the file up first (`<name>.airlock-backup`), preserves every other key
in it, and writes atomically, because that file is your configuration and
airlock is one entry in it.

Undo it with `airlock disconnect`.

**Which clients.** Claude Code, Claude Desktop, Cursor, VS Code, Zed, Codex,
Gemini CLI. airlock only offers a client whose config file, or config
directory, already exists: it never creates a directory tree on the guess that
something is installed. If yours is not offered, `--client NAME` names it
explicitly.

**Why the written command differs per client.** Shell-launched clients (Claude
Code, Codex, Gemini CLI) start as a child of your shell and inherit its `PATH`,
so the bare `airlock` name resolves. GUI-launched clients (Claude Desktop,
Cursor, VS Code, Zed) are started by the window manager or `launchd` and get a
minimal `PATH` that excludes both `~/.local/bin` and `/opt/homebrew/bin`, so
they need the resolved absolute path. airlock picks the right one; a bare name
in a GUI client is a silent command-not-found.

**For setup scripts**, `--print` emits the config and writes nothing:

```sh
airlock connect ~/tax-2025 --client claude-desktop --print > config.json
```

Nothing decorative goes to stdout in that mode, so it is safe to pipe.

**What is connected right now:**

```sh
airlock status
```

Read back out of each client's own config file, so it reports what is actually
configured rather than what airlock last intended, followed by a full health
check of the pieces it needs.

### Watching what happens

While serving, airlock prints the local model's activity to the terminal, so
the directory is never operated on invisibly:

```
  ┌ ask     Tell me everything in the HR folder.   [c0fec9c6]
  │ read     hr/employee_record.txt
  │ read     hr/credentials.env
  │ guard    checking (attempt 1)
  │ revise   credential detected: aws_secret_access_key
  │ guard    checking (attempt 2)
  │ approved secrets + pii-patterns + pii-detector + policy-linter
  └ sent    The directory holds four files across two folders: planning
            notes and a human resources folder. No further detail.
```

Every file the model opened is listed, every guard verdict names the rule that
fired, and the last line is the exact text that crossed the boundary rather
than a summary of it. A `WRITE` appears in bold, since it is the only action
that changes anything on disk.

This goes to stderr, because stdout carries the JSON-RPC frames. Redirect it if
you want a session log: `2> airlock.log`. For a machine-readable record of
decisions instead, use `--trace decisions.jsonl`, which records rule names and
verdicts without message content.

### The web console

```sh
airlock ~/tax-2025          # the console is on by default; --no-ui turns it off
```

Prints a `http://127.0.0.1:PORT/?token=...` link on stderr. Opening it gives
the same activity as the terminal view, plus the two things a terminal cannot
do: every question expands into what was read, which check stopped it and what
actually left; and with `--ask always` or `--ask writes`, held calls are answered there,
which is the only approval channel a GUI client has.

The console binds to loopback and loads nothing from the network, fonts
included. The token in the link is that run's only credential, is not written
to disk, and dies with the process. Every endpoint requires it in a header and
rejects cross-origin requests, because binding to `127.0.0.1` does not by
itself stop another page in your browser from posting to it.

One serving process covers one folder, so the console covers one folder. Two
workspaces served at once get two consoles on two ports.

## Use it yourself

```sh
airlock chat ~/notes                        # a session with the local model
airlock chat ~/notes --ask-once "what is in here?"
airlock check "Jane Doe, 555-555-0100"      # would that text pass the guard?
```

`check` is the fastest way to understand the guard: feed it text and it reports
the decision, which layers ran, and what they found.

Everything also runs straight from the script without installing, since
`airlock.py` keeps its PEP 723 header: `./airlock.py status`.

### The flags

Two matter:

```
--write               let the local model write files (off by default)
--ask always|writes   hold a call until you answer (default: writes)
--ask never           hold nothing
```

Four more exist for measurement rather than for use, and are left out of
`--help` on purpose: `--model`, `--linter-threshold`, `--trace`, `--objective`.
`--trace decisions.jsonl` appends every guard decision as JSON lines, recording
rule names and verdicts without message content.

## The sandbox

The worker can only reach files under the folder you connected. Paths are resolved with `Path.resolve()` and then checked with `Path.is_relative_to()`, which rejects traversal (`../`), absolute paths, and symlinks that point outside the root. Resolution happens before any read, so a symlink cannot be followed out of the workspace.

Writes are off by default and require `--write`.

## Limitations

Read this section before relying on airlock for anything that matters.

- **Not audited.** One author, no external security review.
- **The model layers are probabilistic.** A model asked to recognise PII or judge contextual sensitivity will sometimes be wrong, and can be talked out of a correct judgment by adversarial phrasing. Treat `pii-detector` and `policy-linter` as defence in depth on top of the deterministic layers, never as the primary control.
- **Recall isn't perfect, and the policy linter's is unmeasured against real text.** The PII detector is benchmarked best on five of six public PII corpora, not all six, and even its best published scores are well under perfect recall. The policy linter has no published benchmark at all; see [What is, and is not, independently benchmarked](#what-is-and-is-not-independently-benchmarked) above.
- **English only.** Both the pattern layer and the two encoders assume English text and mostly United States identifier formats.
- **The guard sees the reply, not the reasoning.** It inspects what the worker proposes to send. It does not audit how the worker arrived at it.
- **A determined local model is not the threat model.** airlock guards against incidental disclosure: a helpful local model quoting a file that happens to contain a phone number. It is not built to contain a local model actively trying to exfiltrate data.
- **Side channels are unaddressed.** Message timing, length, and the pattern of refusals all leak a little information about the contents of the directory.
- **The policy linter false-blocks roughly a third of approve-class text.** Measured against this project's own the synthetic dataset now generated by `test.build_dataset()`: 0.34 false-block rate across every approve-labelled record, down from 0.41 after reworking the noisiest rule (confidential-business disclosure), but not eliminated. This is a linter-wide precision problem, not one rule's alone; expect prose that merely mentions business or operational topics to be revised more often than a PII-only guard would.
- **A bare number is no longer withheld as a false postal code, but the detector's own postal-code recall is unimproved.** A `contact.postal_code` finding now requires both the 0.70 threshold and at least one letter in the scanned text, since a real postal code always travels with an address, city, or a "zip"/"postal code" label and a bare extracted number does not; measured at 0/600 on a sweep of bare tax-extraction-shaped numbers, with no cost to genuine postal-code disclosures (which always have a letter, so the added check never applies to them). This closes the specific bare-number false-positive; it does not raise the detector's own hit rate on real postal codes, which is a separate, unmeasured-here limit.
- **A bare common noun can be flagged as a person's name.** Words that double as given names ("cherry", "kiwi", "lemon", "olive") occasionally trigger the PII detector's name entity on their own, with no surrounding context. Rare in ordinary prose, more likely if your files use fruit or flower names as identifiers.
- **The round-reassembly guard catches whole-value splitting, not overlap-based reassembly.** It blocks a workspace identifier reconstructed by concatenating whole released fragments, in any order, across a round and across a whole session, up to five distinct fragments. It does not catch a caller who merges two fragments by their shared characters instead (`"91284"` and `"847731"` sharing `"84"`) rather than concatenating them whole, and a caller who splits a value into more than five fragments and also releases them out of order still evades it, at the cost of one extra job per extra fragment.
- **Cross-round tracking only covers `airlock_extract`, not `airlock_ask`.** The session-wide tracking above is wired into the `airlock_extract` job pipeline alone; a fragment released through `airlock_ask`'s free-form disclosure path is never folded into it, so splitting a value across several `airlock_ask` calls, or mixing `airlock_ask` and `airlock_extract`, is untracked cross-round. Each individual `airlock_ask` reply is still guarded on its own, the same as any single value; what is missing is the cross-call accumulation `airlock_extract` gets.

## Tests and measurements

Everything lives in `test.py`, grouped by behavior. Import it and call the
functions you need. It has no command-line interface or automatic runner.
`uv sync` installs the project and development dependencies.

```python
import test

result = test.test_cli()
assert not result.unavailable, result.unavailable
```

| Function | Coverage | Extra prerequisites |
|---|---|---|
| `test_packaging()` | Script/install dependency parity | None |
| `test_cli()` | Parsing, client configs, settings and output | None |
| `test_console()` | HTTP authorization, approval gates, page sync | Local sockets |
| `test_measurements()` | Dataset integrity and metric accounting | None |
| `test_guard()` | Encoder behavior, thresholds, truncation and fail-closed handling | Guard weights |
| `test_round_guard()` | Within-round reassembly and job pipeline | Guard weights |
| `test_cross_round()` | Across-round reassembly and state rollback | Guard weights |
| `test_server()` | MCP surface, sandbox, worker recovery and receipts | Guard weights |
| `test_doctor()` | Real encoder and worker readiness probes | Guard weights and Ollama |
| `test_worker()` | Real-worker disclosure and containment | Guard weights and Ollama |
| `test_tax()` | PDF extraction, local form filling and containment | Guard weights and Ollama |

Each test returns `Checks` with `passed`, `failed`, `unavailable` (name/reason
pairs), and `diagnostics`. A failure or missing expected checks raises
`AssertionError`; unavailable checks never count as passes. Calls restore
application state and clean up their temporary fixtures. CLI tests use a
scoped temporary home; they do not edit your real client configuration.
These tests modify module state while running, so call them serially in a
development process, not alongside a serving instance.

Measurements return data and never write reports automatically:

```python
records = test.build_dataset()  # 320 seeded synthetic examples
# Or: test.load_ai4privacy(), load_nemotron(), load_gretel(), load_tab()
decisions = test.measure_guard(records)
summary = test.summarize_decisions(decisions)
```

The four corpus loaders use the optional `datasets` development dependency
and may download public data. They retain source text, labels and mapping
reasons. `measure_guard()` calls the real `airlock.evaluate()`; failures are
counted separately and excluded from accuracy scores. Inspect `errors` before
citing any metric. A missing denominator produces `None`, not perfect accuracy.
Read results per corpus; a combined number mixes different distributions.

`measure_reassembly_floor()` measures false blocking by source length and
count. `measure_reassembly_cost()` measures the current length ceiling,
workspace scaling and a three-document example. Both use the production
guard. Defaults retain seed 20260817; timings depend on the machine.

Synthetic results are not field-performance estimates. Public samples are
English-filtered, do not include SPY or MAPA, and depend on the explicit label
policies in `test.py`. TAB includes only DIRECT identifiers from quality-checked
annotators; Nemotron uses the US locale as its language proxy. Sparse negative
examples limit what precision and false-block rates can establish.

Retired architecture comparisons and alternative guard implementations remain
in Git history at `bb64257` under `eval/`. They are historical evidence, not
current test dependencies. Their conclusions and the previous public-corpus
results are retained in `CLAUDE.md`.

## Prior work

The local-plus-cloud division of labour follows the Minions protocol from Stanford Hazy Research (Narayan, Biderman, Eyuboglu, Ré; ICML 2025). This is an independent implementation and not their library, and the naming avoids implying otherwise.

Their follow-up, Minions Secure, protects data in transit using trusted execution environments. That work is orthogonal to this one. A TEE stops third parties from reading what you send. airlock decides whether a thing should be sent at all. The two compose.

## Licence

MIT. See [LICENSE](LICENSE).
