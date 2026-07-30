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
| `airlock_open(objective)` | Start a session. Returns a session id, the workspace name, and a top level listing. |
| `airlock_ask(session, question)` | Ask the local model about the workspace. The reply is guarded. |
| `airlock_close(session)` | End a session and discard its state. |
| `guard_check(text)` | Test whether a given string would pass the guard. Useful for calibration. |

`airlock_ask` returns an envelope with the decision, the message if approved, the layers that ran, and whether anything was withheld. The cloud assistant is told plainly when a reply was generalised or refused, rather than being handed a silent substitution.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com/) running locally
- Two local models, a worker and a guard

Dependencies are declared inline in `airlock.py` using PEP 723, so `uv` resolves them on first run. There is nothing to install beforehand.

```sh
ollama pull qwen3.5:0.8b-mlx           # worker, Apple Silicon
ollama pull granite4.1-guardian:8b     # guard
```

On Linux or Windows, use `qwen3.5:0.8b` instead. The `-mlx` tags run on Ollama's MLX engine and apply to Apple Silicon only.

Any Ollama model works for either role. Defaults are set in `airlock.py` and overridden with `--model` and `--guard-model`.

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

## Use from the terminal

```sh
./airlock.py chat --root ~/notes          # interactive session
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

## Prior work

The local-plus-cloud division of labour follows the Minions protocol from Stanford Hazy Research (Narayan, Biderman, Eyuboglu, Ré; ICML 2025). This is an independent implementation and not their library, and the naming avoids implying otherwise.

Their follow-up, Minions Secure, protects data in transit using trusted execution environments. That work is orthogonal to this one. A TEE stops third parties from reading what you send. airlock decides whether a thing should be sent at all. The two compose.

## Licence

MIT. See [LICENSE](LICENSE).
