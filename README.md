# airlock

An MCP server that lets a cloud assistant consult a private directory without ever seeing its contents.

A small local model reads and reasons over one sandboxed directory. Everything it tries to send outward passes through a layered privacy guard first. The cloud assistant receives findings, structure, and answers. It does not receive your files.

The name is the metaphor: a sealed chamber between a private space and an external one, where everything is inspected before it is allowed through.

## The problem

Cloud assistants are useful over your own documents, and sending those documents to a cloud provider is exactly what you may not want to do. The usual answers are to send everything and trust the provider, or to send nothing and lose the capability.

airlock takes a third position. The local model does the reading. The cloud model does the reasoning. A guard decides what is allowed to cross between them, and it is the guard, not the local model, that has final say.

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
  |     reads files, only inside --root       |
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

Five layers run in order. Any one of them can stop a message. The deterministic layers run first because they are fast, exact, and not persuadable.

| Layer | Mechanism | Catches |
|---|---|---|
| `secrets` | Regex plus `detect-secrets` named detectors | API keys, tokens, private keys, credentials |
| `pii-patterns` | Local regex, always runs | Email, phone, SSN, credit card, IBAN, street address, date of birth |
| `presidio` | Microsoft Presidio with spaCy NER | Names, locations, passports, licences, bank and crypto accounts, IP addresses |
| `guardian` | A purpose-built judging model, optional | Health, financial, employment, legal, and family circumstances |
| `model` | The general guard model, JSON-constrained | Anything the earlier layers do not encode |

Two design decisions are worth naming, because both are deliberate and both cost something.

**The guard fails closed.** If the guard model errors, times out, or returns an unparseable payload, the verdict is `block`, not `approve`. A guard that approves on error is worse than no guard, because it produces confidence rather than a leak you would notice.

**`pii-patterns` always runs, including with `--no-presidio`.** This layer duplicates part of Presidio's coverage on purpose. An earlier version delegated all PII detection to Presidio, and running with Presidio disabled then approved a message containing an email address and a phone number. Structured identifiers are now checked deterministically no matter how the tool is configured.

## MCP tools

| Tool | Purpose |
|---|---|
| `airlock_open(objective)` | Start a session. Returns a session id and file and directory **counts**, never names. |
| `airlock_ask(session, question)` | Ask the local model about the workspace. The reply is guarded. |
| `airlock_close(session)` | End a session and discard its state. |
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
--approve gate-all       airlock holds every call until you answer
--approve gate-writes    airlock holds calls that can alter files
--approve hint-all       every tool annotated; the client decides whether to ask
--approve hint-writes    altering tools annotated; the client decides  (default)
--approve none           no prompts
```

`gate-*` and `hint-*` differ in kind, which is why the names say so. A gate
blocks the call. A hint sets `destructiveHint` and trusts the client to prompt,
and [the MCP specification is explicit](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)
that annotations are hints a client may ignore.

Passing `--allow-writes` promotes `hint-writes` to `gate-writes` automatically,
so writes cannot be switched on while approval is quietly left off.

**`gate-*` requires a terminal.** While serving, stdin is the JSON-RPC stream,
so prompts go to `/dev/tty`, which does not exist when a GUI client launches
the server as a subprocess. In that situation airlock refuses to start rather
than downgrading to no approval, because silently turning a requested gate into
nothing is the worst available outcome.

**A gate approves a call, not its consequences.** One `airlock_ask` with writes
enabled may perform several writes internally, and approving the call approves
all of them. Per-write approval would need the gate inside the worker loop,
which is not what this does.

Tool annotations are computed at startup from `--allow-writes`, so
`airlock_ask` reports `readOnlyHint: true` only when it is actually read-only.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com/) running locally
- Two local models, a worker and a guard

Dependencies are declared inline in `airlock.py` using PEP 723, so `uv` resolves them on first run. There is nothing to install beforehand.

```sh
ollama pull qwen3.5:0.8b               # worker
ollama pull granite4.1-guardian:8b     # guard
```

**Do not use an `-mlx` tag for the worker.** MLX is the faster backend on Apple
Silicon, but measured on Ollama 0.32.0, `qwen3.5:0.8b-mlx` ignores
grammar-constrained decoding: asked for an object matching the worker schema it
returns the bare string `answer`, so every step fails and no session completes.
The plain tag on the same machine, same Ollama, same prompt, honours the schema.

The entire worker loop is schema-constrained JSON, so correctness settles this
over speed. The guard model is unaffected, since its verdict is a single token.

`doctor` checks for exactly this, and is worth re-running whenever you change
tags:

```
 fail  worker emits valid JSON  Model returned unparseable JSON. First 200 chars: 'answer'
```

Any Ollama model works for either role. Defaults are set in `airlock.py` and overridden with `--model` and `--guard-model`.

## Quickstart

```sh
cd ~/some-project
./airlock.py
```

With no arguments, airlock prints the directory it is about to expose, runs the
full setup check, and then offers to start a session.

If anything is missing it walks you through fixing it: a model tag that is not
pulled yet can be pulled from the prompt, and everything else prints the exact
command. First run and a broken install are handled the same way, since they
look identical from here.

The workspace defaults to the current directory. Running from your home
directory or the filesystem root puts everything beneath them in scope, so
those two cases ask for confirmation before continuing rather than proceeding
quietly.

Point it somewhere else with `--root`, which works before or after a
subcommand:

```sh
./airlock.py --root ~/notes
```

## Check the setup

```sh
./airlock.py doctor --root ~/some-directory
```

`doctor` verifies the workspace resolves, reports the Ollama version and installed models, confirms both model tags exist, and then runs three live guard cases: a credential, a person, and innocuous text. It prints which layers fired on each. If a case fails it says whether the deterministic layers passed and the model call failed, which are different problems.

Run this first. It catches nearly every misconfiguration.

## Use as an MCP server

Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "airlock": {
      "command": "uv",
      "args": [
        "run", "--script", "/absolute/path/to/airlock.py",
        "serve", "--root", "/absolute/path/to/private-directory",
        "--guardian-model", "granite4.1-guardian:8b"
      ]
    }
  }
}
```

Claude Code:

```sh
claude mcp add airlock -- uv run --script /absolute/path/to/airlock.py \
  serve --root /absolute/path/to/private-directory
```

Both paths must be absolute. `--root` is the only directory the worker can reach.

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
  │ approved secrets + pii-patterns + model
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

## Use from the terminal

```sh
./airlock.py --root ~/notes               # interactive session (default)
./airlock.py ask "what is in here?" --root ~/notes
./airlock.py guard "Jane Doe, 555-555-0100"
./airlock.py doctor --root ~/notes
```

`guard` is the fastest way to understand the guard's behaviour. Feed it text and it reports the decision, the layers that ran, and what it found.

Add `--trace decisions.jsonl` to any command to append every guard decision as JSON lines, for later review or scoring.

## The sandbox

The worker can only reach files under `--root`. Paths are resolved with `Path.resolve()` and then checked with `Path.is_relative_to()`, which rejects traversal (`../`), absolute paths, and symlinks that point outside the root. Resolution happens before any read, so a symlink cannot be followed out of the workspace.

Writes are off by default and require `--allow-writes`.

## Limitations

Read this section before relying on airlock for anything that matters.

- **Not audited.** One author, no external security review.
- **The LLM layers are probabilistic.** A model asked to judge whether text leaks private information will sometimes be wrong, and can be talked out of a correct judgment by adversarial phrasing. Treat the `guardian` and `model` layers as defence in depth on top of the deterministic layers, never as the primary control.
- **NER misses names.** Presidio's default spaCy pipeline is `en_core_web_sm`, which trades recall for size. Unusual names, transliterations, and names in unexpected contexts get through. `--spacy-model en_core_web_lg` improves recall at roughly 400MB.
- **English only.** Both the patterns and the NER models assume English text and mostly United States identifier formats.
- **The guard sees the reply, not the reasoning.** It inspects what the worker proposes to send. It does not audit how the worker arrived at it.
- **A determined local model is not the threat model.** airlock guards against incidental disclosure: a helpful local model quoting a file that happens to contain a phone number. It is not built to contain a local model actively trying to exfiltrate data.
- **Side channels are unaddressed.** Message timing, length, and the pattern of refusals all leak a little information about the contents of the directory.

## Running the tests

```sh
uv run --script tests/test_server.py
```

Three groups. **A** drives the real MCP SDK with its in-memory client and
checks the tool surface: registration, annotations, and the optional
`disclosure_request`. **B** covers the sandbox and the deterministic guard
layers, which are pure Python. **C** exercises the whole loop and needs Ollama.

Expect around 50 checks. The suite exits non-zero if the total comes in low,
because a run that silently collects fewer tests reads exactly like one that
passed. Group C reports INCONCLUSIVE rather than pass when the worker model
fails, since a containment assertion proves nothing when there was no content
to contain.

## Prior work

The local-plus-cloud division of labour follows the Minions protocol from Stanford Hazy Research (Narayan, Biderman, Eyuboglu, Ré; ICML 2025). This is an independent implementation and not their library, and the naming avoids implying otherwise.

Their follow-up, Minions Secure, protects data in transit using trusted execution environments. That work is orthogonal to this one. A TEE stops third parties from reading what you send. airlock decides whether a thing should be sent at all. The two compose.

## Licence

MIT. See [LICENSE](LICENSE).
