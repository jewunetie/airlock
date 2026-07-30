#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp[cli]>=2.0",
#     "rich>=13.7",
#     "presidio-analyzer>=2.2",
#     "spacy>=3.7",
#     "detect-secrets>=1.5",
# ]
# ///
"""airlock: a guarded local model that works over one directory.

A small local model reads and reasons over a single directory. Anything it
tries to send outward passes through a layered guard first. Use it
interactively, or serve it over MCP so a cloud assistant can consult your
files without ever seeing their contents.

The name is the metaphor: a sealed chamber between a private space and an
external one, where everything is inspected before it is allowed through.

Modes
-----
    airlock doctor              check that everything is set up
    airlock chat                talk to the local model interactively
    airlock ask "question"      one-shot question
    airlock guard "text"        test whether text would pass the guard
    airlock serve               run as an MCP server for a cloud assistant

Relationship to prior work
--------------------------
The local-plus-cloud division of labour follows the Minions protocol from
Stanford Hazy Research (Narayan, Biderman, Eyuboglu, Re; ICML 2025). This is
an independent implementation, not their library, and the naming avoids
implying otherwise. Their follow-up, Minions Secure, protects data in transit
with trusted execution environments. That is orthogonal: a TEE stops third
parties reading what you send, while this decides whether a thing should be
sent at all.

The guard, and why it is layered
--------------------------------
Three layers, cheapest and most certain first:

1. Regular expressions for secrets and credentials. API keys, private key
   blocks, and JWTs have rigid formats, so a pattern match is effectively
   exact. Presidio does not ship recognizers for these, so this layer is not
   redundant.

2. Microsoft Presidio for personally identifiable information. This is the
   part regular expressions genuinely cannot do: recognising that a string is
   a person's name or a home location requires named-entity recognition.
   Presidio also validates structured identifiers with checksums.

3. A local language model for contextual sensitivity, such as health or
   financial disclosure written in prose that names no identifier at all.

No layer can overrule an earlier one. Any layer failing blocks the message,
because a guard that cannot evaluate must never approve.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Literal

from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
REQUEST_TIMEOUT = 120
MAX_REVISIONS = 3
MAX_WORKER_STEPS = 8
FILE_SLICE_CHARS = 4000
MAX_LISTING_ENTRIES = 200
# Verified working on Apple Silicon 2026-07-30. The -mlx tag runs on Ollama's
# MLX engine and is a drop-in for the plain qwen3.5:0.8b tag; both are
# multimodal and carry a 256K context. Override with --model on Linux or
# elsewhere, where the plain tag is the right choice.
DEFAULT_MODEL = "qwen3.5:0.8b-mlx"

# The guard deliberately does not default to DEFAULT_MODEL. A general-purpose
# model asked to judge whether text leaks private information is doing a job it
# was not trained for, and the failure that matters here is a false approve,
# which is a leak rather than a slowdown. Guard cost is also nearly all prefill,
# since the verdict is a single token, so a larger guard is cheap.
DEFAULT_GUARD_MODEL = "granite4.1-guardian:8b"

# Presidio entities that block a message. DATE_TIME and URL are deliberately
# excluded: they fire constantly on ordinary text and would make the guard
# useless through false positives.
BLOCKING_ENTITIES: set[str] = {
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "CRYPTO",
    "MEDICAL_LICENSE",
    "LOCATION",
    "NRP",
    "IP_ADDRESS",
}
PRESIDIO_THRESHOLD = 0.5

# --------------------------------------------------------------------------
# Layer 1: secrets and credentials
#
# Two detectors in union, because measurement showed neither is sufficient.
#
# Yelp's detect-secrets contributes vendor coverage this file would otherwise
# have to hand-maintain: Stripe, Slack, Basic Auth, JWT, IBM, Azure and more.
#
# Two things it does NOT do well here, both established by testing rather than
# assumption:
#
#   1. Its entropy plugins are tuned for scanning source code, where a random
#      string is inherently suspicious. Run against ordinary English prose they
#      fire constantly: the sentence "The folder contains twelve planning
#      files about budgets." produced six "Base64 High Entropy String" hits.
#      Since this guard inspects natural language, entropy detectors are
#      filtered out or the guard would block everything.
#
#   2. With entropy disabled it missed both a GitHub token and an OpenAI key
#      that the patterns below catch.
#
# So the two run together and their findings are merged. Neither is redundant.
# --------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "generic_secret_assignment": re.compile(
        r"\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
        re.I,
    ),
}


def mask(value: str) -> str:
    """Replace the middle of a string with asterisks for safe display."""
    stripped = value.strip()
    if len(stripped) <= 4:
        return "*" * len(stripped)
    return f"{stripped[:2]}{'*' * (len(stripped) - 4)}{stripped[-2:]}"


# Structured personal identifiers with rigid formats. These deliberately
# duplicate part of Presidio's coverage and always run, including when
# Presidio is disabled.
#
# The reason is a bug found in testing: with PII detection delegated entirely
# to Presidio, running with --no-presidio approved a message containing an
# email address and a phone number, because nothing deterministic was left and
# the small guard model let it through. An escape hatch must not silently
# remove every reliable check. Presidio still adds what patterns cannot do,
# which is recognising names and places.
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "street_address": re.compile(
        r"\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+"
        r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b"
    ),
    "date_of_birth": re.compile(
        r"\b(?:dob|date of birth)\b[:\s]*\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b", re.I
    ),
}


def _luhn_ok(digits: str) -> bool:
    """Return True if a digit string passes the Luhn checksum.

    Keeps the broad credit-card pattern from flagging ordinary long numbers.
    """
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def scan_pii_patterns(text: str) -> list[dict[str, str]]:
    """Find structured personal identifiers. Always runs, Presidio or not."""
    findings: list[dict[str, str]] = []
    for name, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            if name == "credit_card" and not _luhn_ok(value):
                continue
            findings.append(
                {"rule": name, "masked": mask(value), "layer": "pii:pattern"}
            )
    return findings


def scan_secrets_patterns(text: str) -> list[dict[str, str]]:
    """Find credentials using the local patterns above."""
    findings: list[dict[str, str]] = []
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append(
                {"rule": name, "masked": mask(match.group(0)), "layer": "secrets:pattern"}
            )
    return findings


def scan_secrets_library(text: str) -> list[dict[str, str]]:
    """Find credentials using detect-secrets, excluding its entropy plugins.

    Entropy detectors are dropped deliberately. They assume source code, and on
    natural language they produce a false positive on nearly every sentence,
    which would make the guard unusable. Named vendor detectors are precise and
    are kept.

    Returns an empty list rather than raising if the library is missing, since
    the pattern detector above still runs and doctor reports the degraded
    state explicitly.
    """
    try:
        from detect_secrets.core import scan
        from detect_secrets.settings import default_settings
    except ImportError:
        return []

    findings: list[dict[str, str]] = []
    try:
        with default_settings():
            for line in text.splitlines():
                for secret in scan.scan_line(line):
                    if "Entropy" in secret.type:
                        continue
                    findings.append(
                        {
                            "rule": secret.type,
                            "masked": "detected",
                            "layer": "secrets:detect-secrets",
                        }
                    )
    except Exception:  # noqa: BLE001 - a scanner failure must not approve by default
        return [
            {
                "rule": "detect-secrets failed",
                "masked": "",
                "layer": "secrets:detect-secrets",
            }
        ]
    return findings


def scan_secrets(text: str) -> list[dict[str, str]]:
    """Union of both credential detectors, de-duplicated by rule name."""
    combined = scan_secrets_patterns(text) + scan_secrets_library(text)
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for finding in combined:
        if finding["rule"] in seen:
            continue
        seen.add(finding["rule"])
        unique.append(finding)
    return unique


# --------------------------------------------------------------------------
# Layer 2: Presidio
# --------------------------------------------------------------------------


class PresidioUnavailable(Exception):
    """Raised when Presidio or its language model cannot be loaded."""


# Which spaCy pipeline backs Presidio's named-entity recognition. Overridable
# with --spacy-model.
#
# This is set explicitly rather than left to Presidio's default for a concrete
# reason found in testing: constructing AnalyzerEngine() with no configuration
# reaches out and downloads en_core_web_lg, roughly 400MB, even when a smaller
# model is already installed. Naming the model keeps startup predictable and
# offline. The small pipeline is around 12MB and less accurate at names than
# the large one, so use --spacy-model en_core_web_lg if recall matters more
# than footprint.
DEFAULT_SPACY_MODEL = "en_core_web_sm"


@lru_cache(maxsize=2)
def get_analyzer(spacy_model: str = DEFAULT_SPACY_MODEL) -> Any:
    """Load the Presidio analyzer once per model and cache it.

    Loading pulls a spaCy pipeline into memory and takes a few seconds, so it
    happens lazily on first use rather than at import. Raises
    PresidioUnavailable with actionable guidance if anything is missing, and
    callers treat that as a block rather than a pass.
    """
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError as exc:
        raise PresidioUnavailable(f"presidio-analyzer is not installed: {exc}")

    try:
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": spacy_model}],
            }
        )
        engine = provider.create_engine()
        return AnalyzerEngine(nlp_engine=engine, supported_languages=["en"])
    except Exception as exc:  # noqa: BLE001 - usually a missing spaCy model
        raise PresidioUnavailable(
            f"Presidio could not start with '{spacy_model}' ({exc}). Install it:\n"
            f"  uv run --with spacy python -m spacy download {spacy_model}"
        )


def scan_pii(text: str, spacy_model: str = DEFAULT_SPACY_MODEL) -> list[dict[str, str]]:
    """Find personally identifiable information using Presidio.

    Only entities in BLOCKING_ENTITIES above the confidence threshold are
    returned. The matched span is masked so that a finding never itself leaks
    the value into logs or into the reply envelope.
    """
    analyzer = get_analyzer(spacy_model)
    results = analyzer.analyze(text=text, language="en")
    findings: list[dict[str, str]] = []
    for result in results:
        if result.entity_type not in BLOCKING_ENTITIES:
            continue
        if result.score < PRESIDIO_THRESHOLD:
            continue
        findings.append(
            {
                "rule": result.entity_type,
                "masked": mask(text[result.start : result.end]),
                "score": f"{result.score:.2f}",
                "layer": "presidio",
            }
        )
    return findings


# --------------------------------------------------------------------------
# Filesystem sandbox
#
# There is no established Python library for this. The recommended practice,
# per the OpenStack security guidelines and similar sources, is exactly what
# is implemented below: canonicalise the path with resolve(), which follows
# symlinks, then confirm containment. Python 3.9 added Path.is_relative_to,
# which expresses that check directly.
#
# Two honest limitations. First, this is a logical boundary, not an OS
# enforced one: real isolation would mean sandbox-exec on macOS, Landlock on
# Linux, or a container. Second, there is a small time-of-check to time-of-use
# window between resolving a path and opening it, which matters only if an
# attacker can already create symlinks inside the workspace.
# --------------------------------------------------------------------------


class SandboxError(Exception):
    """Raised when a path escapes the workspace root."""


@dataclass
class Sandbox:
    """The single directory the local model may touch."""

    root: Path
    allow_writes: bool = False

    def __post_init__(self) -> None:
        self.root = self.root.expanduser().resolve(strict=True)
        if not self.root.is_dir():
            raise SandboxError(f"Root is not a directory: {self.root}")

    def resolve(self, relative: str) -> Path:
        """Resolve a path and confirm it stays inside the root."""
        candidate = (self.root / relative).expanduser()
        try:
            resolved = candidate.resolve()
        except OSError as exc:
            raise SandboxError(f"Cannot resolve path: {exc}")
        if not resolved.is_relative_to(self.root):
            raise SandboxError(f"Path escapes the workspace: {relative}")
        return resolved

    def list_dir(self, relative: str = ".") -> list[str]:
        """List visible entries, marking directories with a trailing slash."""
        target = self.resolve(relative)
        if not target.is_dir():
            raise SandboxError(f"Not a directory: {relative}")
        entries: list[str] = []
        for child in sorted(target.iterdir()):
            if child.name.startswith("."):
                continue
            entries.append(f"{child.name}/" if child.is_dir() else child.name)
            if len(entries) >= MAX_LISTING_ENTRIES:
                entries.append(f"... truncated at {MAX_LISTING_ENTRIES}")
                break
        return entries

    def read_text(self, relative: str) -> str:
        """Read a bounded slice of a text file."""
        target = self.resolve(relative)
        if not target.is_file():
            raise SandboxError(f"Not a file: {relative}")
        try:
            data = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise SandboxError(f"Cannot read {relative}: {exc}")
        return (
            data[:FILE_SLICE_CHARS] + "\n... truncated ..."
            if len(data) > FILE_SLICE_CHARS
            else data
        )

    def write_text(self, relative: str, content: str) -> str:
        """Write a file, refusing unless writes were explicitly enabled."""
        if not self.allow_writes:
            raise SandboxError("Writes are disabled. Restart with --allow-writes.")
        target = self.resolve(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"wrote {len(content)} characters to {relative}"

    def search(self, needle: str, limit: int = 40) -> list[str]:
        """Case-insensitive substring search across files under the root."""
        hits: list[str] = []
        lowered = needle.lower()
        for path in self.root.rglob("*"):
            if not path.is_file() or path.name.startswith("."):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if lowered in text.lower():
                hits.append(str(path.relative_to(self.root)))
            if len(hits) >= limit:
                break
        return hits

    def stats(self) -> dict[str, int]:
        """Count files and directories under the root, for the banner."""
        files = dirs = 0
        for path in self.root.rglob("*"):
            if path.name.startswith("."):
                continue
            if path.is_file():
                files += 1
            elif path.is_dir():
                dirs += 1
        return {"files": files, "directories": dirs}


# --------------------------------------------------------------------------
# Local model access
# --------------------------------------------------------------------------


def strip_thinking(text: str) -> str:
    """Remove reasoning blocks some models emit before their answer."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.I)
    text = re.sub(r"<thinking>.*?</thinking>", "", text, flags=re.DOTALL | re.I)
    return text.strip()


def ollama_version() -> str:
    """Return the running Ollama version, or an empty string if unavailable.

    Reported by doctor because Ollama 0.19 moved the Apple Silicon backend to
    MLX, which changes performance substantially, but only on machines with 32GB
    or more of unified memory. Below that threshold the older Metal path is used
    and MLX-tagged models bring no benefit.
    """
    try:
        with urllib.request.urlopen(f"{OLLAMA_HOST}/api/version", timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8")).get("version", "")
    except Exception:  # noqa: BLE001 - informational only
        return ""


def ollama_models() -> list[str]:
    """Return installed model tags, or raise RuntimeError if Ollama is down."""
    try:
        with urllib.request.urlopen(f"{OLLAMA_HOST}/api/tags", timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Ollama unreachable at {OLLAMA_HOST}: {exc.reason}")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Ollama error: {exc}")
    return [m.get("name", "") for m in data.get("models", [])]


def ollama_chat(
    model: str, prompt: str, schema: dict[str, Any] | None = None
) -> dict[str, Any] | str:
    """Send a prompt to a local model, optionally constrained to a JSON schema.

    Note on approach: Ollama also supports native tool calling, where the
    Python SDK derives schemas from type hints. That is the nicer API, but its
    reliability depends heavily on model size, with 14B and above recommended
    for dependable tool selection. This tool targets sub-1B models, where
    grammar-constrained JSON generation is the more reliable mechanism because
    the decoder cannot emit anything off-schema. Revisit if the default model
    grows.
    """
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        # Thinking-capable models (the qwen3 family, deepseek-r1 and similar)
        # turn reasoning ON by default when `think` is unset. The reasoning then
        # goes to a separate `thinking` field and `response` can come back
        # EMPTY, which reads as a broken guard and blocks every message. There
        # is no benefit to reasoning traces for a fixed-schema classification,
        # so it is disabled explicitly.
        "think": False,
        "options": {"temperature": 0},
    }
    if schema is not None:
        payload["format"] = schema
    request = urllib.request.Request(
        f"{OLLAMA_HOST}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Ollama unreachable at {OLLAMA_HOST}: {exc.reason}")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Ollama request failed: {exc}")

    text = strip_thinking(body.get("response", ""))

    # Fallback for servers that ignore `think: false`, or models that answer
    # inside the reasoning trace anyway. Better to recover the object from
    # `thinking` than to block a message because of where the model put it.
    if not text:
        text = strip_thinking(body.get("thinking", "") or "")

    if schema is None:
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Salvage attempt. Small models sometimes wrap the object in prose or a
    # fenced code block even under a schema, and older Ollama builds ignore a
    # full JSON Schema in `format`, returning free text. Extracting the first
    # balanced object recovers those cases instead of failing the whole run.
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        start = text.find("{")
        if start != -1:
            depth = 0
            for i, ch in enumerate(text[start:], start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = text[start : i + 1]
                        break
    if candidate:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    if not text.strip():
        raise RuntimeError(
            "Model returned an empty response. If this is a reasoning model, the "
            "server may be ignoring `think: false`. Try a non-thinking model for "
            "the guard, or raise the token budget."
        )
    raise RuntimeError(
        f"Model returned unparseable JSON. First 200 chars: {text[:200]!r}"
    )


# --------------------------------------------------------------------------
# Layer 3 and the combined guard
# --------------------------------------------------------------------------

GUARD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["approve", "revise"]},
        "concerns": {"type": "array", "items": {"type": "string"}},
        "instruction": {"type": "string"},
    },
    "required": ["verdict", "concerns", "instruction"],
}

GUARD_PROMPT = """You are a privacy guard. A message is about to leave a private
computer for an external cloud AI service. Decide whether it is safe.

Structured identifiers have already been checked by other tools. Your job is
the judgement they cannot make. Reject the message if it reveals:
- medical or health information about a specific person
- financial circumstances, salary, debts, or account standing
- private contents of personal correspondence
- someone's employment problems, legal matters, or family situation
- anything else a reasonable person would not want sent to a third party

Approve if it describes work in general terms: file names, structure, counts,
topics, or technical findings without personal detail.

verdict: "approve" or "revise".
concerns: short reasons, empty if approving.
instruction: if revising, say exactly what to remove or generalise.

Message:
---
{message}
---
"""


# --------------------------------------------------------------------------
# Optional layer 3a: IBM Granite Guardian
#
# A purpose-built judging model rather than a general instruct model, so it is
# a better shape for this job. Two constraints from IBM's model card drive how
# it is used here:
#
#   1. Its built-in taxonomy covers harm, bias, jailbreak, violence, profanity,
#      sexual content and unethical behaviour. There is NO privacy or PII
#      category, so privacy has to be supplied through Bring Your Own Criteria.
#      IBM warns that custom criteria must be tested before production use, so
#      treat this as advisory until measured on your own examples.
#
#   2. It is documented as intended "only in the prescribed yes/no scoring
#      mode", where deviation may produce unsafe output. So it is NOT asked for
#      our JSON schema. It is called in its native guardian format and returns
#      a score, and the revision instruction is supplied separately below.
# --------------------------------------------------------------------------

GUARDIAN_CRITERIA = (
    "The text reveals private or sensitive information about a specific person. "
    "This includes health or medical details, financial circumstances such as "
    "salary, debts or account standing, employment problems, legal matters, "
    "family situations, or the contents of private correspondence. "
    "Descriptions of files, folder structure, counts, topics, or technical "
    "findings that contain no personal detail do NOT meet this criterion."
)

GUARDIAN_BLOCK = """<guardian>/nothink

### Criteria: {criteria}

### Scoring Schema: If the last assistant's text meets the criteria, return 'yes'; otherwise, return 'no'.
"""


def granite_guardian_verdict(model: str, message: str) -> bool | None:
    """Ask Granite Guardian whether a message reveals private information.

    Returns True when flagged as sensitive, False when clean, and None when the
    model could not be used, so the caller can fail closed rather than guess.

    Uses the chat endpoint because the protocol requires the text under review
    to be the final assistant message, with the criteria appended as the final
    user message.
    """
    payload = {
        "model": model,
        "messages": [
            {"role": "assistant", "content": message},
            {"role": "user", "content": GUARDIAN_BLOCK.format(criteria=GUARDIAN_CRITERIA)},
        ],
        "stream": False,
        "think": False,
        "options": {"temperature": 0},
    }
    request = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            body = json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - caller fails closed on None
        return None

    text = (body.get("message") or {}).get("content", "") or ""
    match = re.search(r"<score>\s*(yes|no)\s*</score>", text, re.I)
    if match:
        return match.group(1).lower() == "yes"
    # Fall back to a bare yes/no if the tags are absent, but nothing looser:
    # guessing from prose would defeat the point of a scoring model.
    stripped = strip_thinking(text).strip().lower().rstrip(".")
    if stripped in ("yes", "no"):
        return stripped == "yes"
    return None


@dataclass
class GuardVerdict:
    """Result of a guard evaluation."""

    decision: Literal["approve", "revise", "block"]
    concerns: list[str] = field(default_factory=list)
    instruction: str = ""
    findings: list[dict[str, str]] = field(default_factory=list)
    layers_run: list[str] = field(default_factory=list)

    @property
    def approved(self) -> bool:
        """True only for an explicit approval."""
        return self.decision == "approve"


def evaluate(
    message: str,
    guard_model: str,
    use_presidio: bool = True,
    spacy_model: str = DEFAULT_SPACY_MODEL,
    guardian_model: str | None = None,
) -> GuardVerdict:
    """Run every guard layer over a candidate message.

    Layers run cheapest first and short-circuit, since a confirmed match needs
    no further opinion. Any layer that cannot run blocks the message rather
    than being skipped, so a missing dependency degrades into refusal rather
    than into silent permissiveness.
    """
    layers: list[str] = []

    secrets = scan_secrets(message)
    layers.append("secrets")
    if secrets:
        rules = sorted({f["rule"] for f in secrets})
        return GuardVerdict(
            decision="revise",
            concerns=[f"credential detected: {r}" for r in rules],
            instruction=(
                "Remove the credential or key material entirely. Never quote "
                "secrets, even partially."
            ),
            findings=secrets,
            layers_run=layers,
        )

    # Structured identifiers always run, regardless of Presidio, so that
    # disabling Presidio degrades coverage rather than removing it.
    pii_patterns = scan_pii_patterns(message)
    layers.append("pii-patterns")
    if pii_patterns:
        rules = sorted({f["rule"] for f in pii_patterns})
        return GuardVerdict(
            decision="revise",
            concerns=[f"personal identifier detected: {r}" for r in rules],
            instruction=(
                "Remove the following and describe it generally instead: "
                f"{', '.join(rules)}. Refer to people by role, not by contact details."
            ),
            findings=pii_patterns,
            layers_run=layers,
        )

    if use_presidio:
        try:
            pii = scan_pii(message, spacy_model)
            layers.append("presidio")
        except PresidioUnavailable as exc:
            return GuardVerdict(
                decision="block",
                concerns=[f"PII detector unavailable: {exc}"],
                instruction="Install the PII detector, or run with --no-presidio "
                "to fall back to the model layer alone, accepting weaker detection.",
                layers_run=layers,
            )
        if pii:
            rules = sorted({f["rule"] for f in pii})
            return GuardVerdict(
                decision="revise",
                concerns=[f"personal information detected: {r}" for r in rules],
                instruction=(
                    "Remove the following and describe it generally instead: "
                    f"{', '.join(rules)}. Refer to people by role rather than name, "
                    "and to places by type rather than name."
                ),
                findings=pii,
                layers_run=layers,
            )

    # Layer 3a. A dedicated judging model, when configured, runs before the
    # general model and short-circuits on a positive finding.
    if guardian_model:
        flagged = granite_guardian_verdict(guardian_model, message)
        layers.append("guardian")
        if flagged is None:
            return GuardVerdict(
                decision="block",
                concerns=[f"guardian model '{guardian_model}' returned no usable score"],
                instruction="Check the guardian model is installed and supports yes/no scoring.",
                layers_run=layers,
            )
        if flagged:
            return GuardVerdict(
                decision="revise",
                concerns=["guardian model judged this to reveal private information"],
                # A scoring model returns no guidance, so the instruction is
                # derived from the criteria it evaluated against.
                instruction=(
                    "Remove personal details about any individual: health, finances, "
                    "employment or legal matters, family situation, or private "
                    "correspondence. Describe the work in general terms instead."
                ),
                layers_run=layers,
            )

    try:
        result = ollama_chat(guard_model, GUARD_PROMPT.format(message=message), GUARD_SCHEMA)
        layers.append("model")
    except RuntimeError as exc:
        return GuardVerdict(
            decision="block", concerns=[f"guard model unavailable: {exc}"], layers_run=layers
        )
    if not isinstance(result, dict):
        return GuardVerdict(
            decision="block", concerns=["guard returned bad payload"], layers_run=layers
        )

    verdict = str(result.get("verdict", "")).lower()
    if verdict == "approve":
        return GuardVerdict(decision="approve", layers_run=layers)
    if verdict == "revise":
        return GuardVerdict(
            decision="revise",
            concerns=[str(c) for c in result.get("concerns", [])],
            instruction=str(result.get("instruction", "Remove sensitive details.")),
            layers_run=layers,
        )
    return GuardVerdict(
        decision="block", concerns=[f"unrecognised verdict: {verdict!r}"], layers_run=layers
    )


# --------------------------------------------------------------------------
# The worker loop
# --------------------------------------------------------------------------

WORKER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {"type": "string", "enum": ["list", "read", "search", "write", "answer"]},
        "path": {"type": "string"},
        "query": {"type": "string"},
        "content": {"type": "string"},
        "answer": {"type": "string"},
    },
    "required": ["action"],
}

WORKER_PROMPT = """You are a local assistant working inside one directory. You
answer questions from someone who cannot see these files.

Choose one action:
- list: list a directory. Set path.
- read: read a file. Set path.
- search: find files containing text. Set query.
- write: write a file. Set path and content.
- answer: give your final answer. Set answer.

In your final answer, describe what you found in general terms. Do not include
names, addresses, phone numbers, email addresses, account numbers, or
credentials. Refer to people by role.

Objective: {objective}
Question: {question}

What you have done so far:
{history}

Respond with one action.
"""

REVISE_PROMPT = """Your answer was rejected by the privacy guard.

Your answer:
---
{answer}
---

Concerns: {concerns}
Required changes: {instruction}

Rewrite it to convey the same useful information without the flagged content.
Respond with action "answer".
"""


@dataclass
class Session:
    """One conversation between a caller and the local worker."""

    session_id: str
    objective: str
    sandbox: Sandbox
    worker_model: str
    guard_model: str
    use_presidio: bool = True
    spacy_model: str = DEFAULT_SPACY_MODEL
    guardian_model: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    exchanges: int = 0
    blocked: int = 0
    revisions: int = 0


SESSIONS: dict[str, Session] = {}
StepCallback = Callable[[str, str], None]

# Optional structured trace. Set by --trace. Written as JSON lines so runs can
# be replayed, diffed, and scored later, which is the only way to know whether
# the guard is actually working rather than merely running. Deliberately plain
# files rather than a tracing framework: this is a security boundary, and a
# readable append-only log is easier to audit than a vendor pipeline.
TRACE_PATH: Path | None = None


def trace(event: str, **fields: Any) -> None:
    """Append one structured event to the trace file, if tracing is enabled.

    Never records message bodies or file contents. Only decisions, rule names,
    and counts, so a trace can be shared or reviewed without leaking the very
    data the guard exists to protect.
    """
    if TRACE_PATH is None:
        return
    record = {"ts": datetime.now().isoformat(), "event": event, **fields}
    try:
        with TRACE_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except OSError:
        pass


def run_worker(
    session: Session, question: str, on_step: StepCallback | None = None
) -> dict[str, Any]:
    """Run the local model over the workspace, then guard its answer.

    Raw file content never reaches the return value; only guard-approved prose
    does. on_step, when supplied, reports progress for interactive callers.
    """

    def note(action: str, detail: str) -> None:
        if on_step:
            on_step(action, detail)

    history: list[str] = []
    draft = ""

    for _ in range(MAX_WORKER_STEPS):
        prompt = WORKER_PROMPT.format(
            objective=session.objective,
            question=question,
            history="\n".join(history) if history else "(nothing yet)",
        )
        try:
            step = ollama_chat(session.worker_model, prompt, WORKER_SCHEMA)
        except RuntimeError as exc:
            return envelope(session, "blocked", "", [f"local model failed: {exc}"])
        if not isinstance(step, dict):
            return envelope(session, "blocked", "", ["local model returned bad output"])

        # Hand-rolled dispatch rather than Ollama's native tool calling, for
        # the reliability reason documented on ollama_chat above.
        action = str(step.get("action", "")).lower()
        try:
            if action == "list":
                target = step.get("path", ".")
                note("list", target)
                result = "\n".join(session.sandbox.list_dir(target))
            elif action == "read":
                target = step.get("path", "")
                note("read", target)
                result = session.sandbox.read_text(target)
            elif action == "search":
                query = step.get("query", "")
                note("search", query)
                result = "\n".join(session.sandbox.search(query))
            elif action == "write":
                target = step.get("path", "")
                note("write", target)
                result = session.sandbox.write_text(target, step.get("content", ""))
            elif action == "answer":
                draft = str(step.get("answer", "")).strip()
                break
            else:
                result = f"unknown action: {action}"
        except SandboxError as exc:
            # Sandbox refusals are fed back as input so the model can correct
            # course, rather than raised so the run dies.
            note("refused", str(exc))
            result = f"refused: {exc}"
        history.append(f"{action} -> {result[:600]}")
    else:
        draft = "I could not finish within the allowed number of steps."

    if not draft:
        return envelope(session, "blocked", "", ["the local model produced no answer"])

    for attempt in range(MAX_REVISIONS):
        note("guard", f"checking (attempt {attempt + 1})")
        verdict = evaluate(draft, session.guard_model, session.use_presidio, session.spacy_model, session.guardian_model)
        trace(
            "guard_verdict",
            session=session.session_id,
            attempt=attempt + 1,
            decision=verdict.decision,
            layers=verdict.layers_run,
            rules=[f["rule"] for f in verdict.findings],
            draft_chars=len(draft),
        )
        if verdict.approved:
            session.exchanges += 1
            note("approved", " + ".join(verdict.layers_run))
            return envelope(session, "approved", draft, [])
        if verdict.decision == "block":
            session.blocked += 1
            note("blocked", "; ".join(verdict.concerns))
            return envelope(session, "blocked", "", verdict.concerns)

        session.revisions += 1
        note("revise", "; ".join(verdict.concerns))
        try:
            revised = ollama_chat(
                session.worker_model,
                REVISE_PROMPT.format(
                    answer=draft,
                    concerns="; ".join(verdict.concerns),
                    instruction=verdict.instruction,
                ),
                WORKER_SCHEMA,
            )
        except RuntimeError as exc:
            session.blocked += 1
            return envelope(session, "blocked", "", [f"revision failed: {exc}"])
        if isinstance(revised, dict):
            draft = str(revised.get("answer", "")).strip() or draft

    session.blocked += 1
    return envelope(session, "blocked", "", ["could not produce a message passing the guard"])


def envelope(
    session: Session, status: str, message: str, concerns: list[str]
) -> dict[str, Any]:
    """Build the structured reply, stating plainly when content was withheld."""
    return {
        "session": session.session_id,
        "status": status,
        "message": message,
        "withheld": bool(concerns),
        "guard_concerns": concerns,
        "counters": {
            "exchanges": session.exchanges,
            "revisions": session.revisions,
            "blocked": session.blocked,
        },
        "note": (
            "This reply passed a local privacy guard. Content may have been "
            "generalised or withheld."
        ),
    }


# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------

STEP_STYLE = {
    "list": ("dim cyan", "ls"),
    "read": ("dim cyan", "read"),
    "search": ("dim cyan", "grep"),
    "write": ("yellow", "write"),
    "refused": ("red", "refused"),
    "guard": ("dim magenta", "guard"),
    "revise": ("yellow", "revise"),
    "approved": ("green", "ok"),
    "blocked": ("red", "blocked"),
}


def print_step(action: str, detail: str) -> None:
    """Render one worker step as a dim status line."""
    style, label = STEP_STYLE.get(action, ("dim", action))
    text = Text(f"  {label:<8}", style=style)
    text.append(detail[:80], style="dim")
    console.print(text)


def banner(session_like: Any) -> None:
    """Print the startup panel."""
    sandbox = session_like.sandbox
    counts = sandbox.stats()
    console.print(
        Panel(
            Group(
                Text.assemble(("workspace  ", "dim"), (str(sandbox.root), "bold")),
                Text.assemble(
                    ("contents   ", "dim"),
                    (f"{counts['files']} files, {counts['directories']} directories", ""),
                ),
                Text.assemble(("worker     ", "dim"), (session_like.worker_model, "cyan")),
                Text.assemble(("guard      ", "dim"), (session_like.guard_model, "magenta")),
                Text.assemble(
                    ("layers     ", "dim"),
                    ("secrets + presidio + model" if session_like.use_presidio
                     else "secrets + model (presidio off)", ""),
                ),
                Text.assemble(
                    ("writes     ", "dim"),
                    ("enabled", "yellow") if sandbox.allow_writes else ("disabled", "green"),
                ),
            ),
            title="airlock",
            border_style="cyan",
            padding=(1, 2),
        )
    )


def render_reply(result: dict[str, Any]) -> None:
    """Render a reply, making withheld content obvious."""
    if result.get("status") == "approved":
        console.print(
            Panel(result.get("message", ""), title="answer", border_style="green", padding=(1, 2))
        )
    else:
        concerns = "\n".join(f"• {c}" for c in result.get("guard_concerns", []))
        console.print(
            Panel(
                Text.assemble(
                    ("The guard withheld this reply.\n\n", "bold red"),
                    (concerns or "no reason given", ""),
                ),
                title="blocked",
                border_style="red",
                padding=(1, 2),
            )
        )


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def check(label: str, ok: bool, detail: str = "") -> bool:
    """Print one doctor line and return the result unchanged."""
    mark = Text("  ok  ", style="bold green") if ok else Text(" fail ", style="bold red")
    console.print(Text.assemble(mark, (f" {label}", ""), (f"  {detail}", "dim")))
    return ok


def cmd_doctor(args: argparse.Namespace) -> int:
    """Verify the environment and explain how to fix whatever is broken."""
    console.print(Rule("airlock doctor", style="cyan"))
    ok = True

    try:
        sandbox = Sandbox(root=args.root, allow_writes=args.allow_writes)
        counts = sandbox.stats()
        check("workspace", True, f"{sandbox.root} ({counts['files']} files)")
    except (SandboxError, FileNotFoundError) as exc:
        check("workspace", False, str(exc))
        return 1

    if args.no_presidio:
        check("pii detector", True, "disabled by --no-presidio (weaker detection)")
    else:
        try:
            get_analyzer(args.spacy_model)
            check("pii detector", True, "presidio ready")
        except PresidioUnavailable as exc:
            check("pii detector", False, str(exc).split("\n")[0])
            console.print(
                "\n[dim]  uv run --with spacy python -m spacy download en_core_web_lg[/dim]"
            )
            ok = False

    try:
        installed = ollama_models()
        version = ollama_version()
        check("ollama", True, f"{OLLAMA_HOST}, {len(installed)} models"
              + (f", v{version}" if version else ""))
        # Apple Silicon note. Ollama 0.31 added multi-token prediction for
        # Gemma 4 on the MLX engine, on by default and with no configuration.
        # That is worth surfacing because airlock's guard loop is generation
        # heavy: every draft is written once and re-checked, and on a revise
        # verdict the whole cycle repeats.
        if sys.platform == "darwin" and version:
            try:
                major, minor = (int(p) for p in version.split(".")[:2])
                if (major, minor) < (0, 31):
                    console.print(
                        "       [dim]Ollama 0.31+ adds multi-token prediction "
                        "for Gemma 4 on Apple Silicon. Upgrading is the "
                        "cheapest speedup available here[/dim]"
                    )
                elif not any("-mlx" in name for name in installed):
                    console.print(
                        "       [dim]no -mlx tagged models installed; on Apple "
                        "Silicon those use the MLX engine[/dim]"
                    )
            except ValueError:
                pass
        # List them. When a guard test fails for being over-strict, the fix is a
        # bigger guard model, and the only authoritative source for which tags
        # exist is this machine. Printing them avoids guessing from memory.
        if installed:
            console.print(f"       [dim]{', '.join(sorted(installed))}[/dim]")
    except RuntimeError as exc:
        check("ollama", False, str(exc))
        console.print("\n[dim]  ollama serve[/dim]")
        return 1

    def has(tag: str) -> bool:
        return tag in installed or any(m.split(":")[0] == tag.split(":")[0] for m in installed)

    guard_model = args.guard_model or args.model
    if not check("worker model", has(args.model), args.model):
        ok = False
        console.print(f"\n[dim]  ollama pull {args.model}[/dim]")
    if not check("guard model", has(guard_model), guard_model):
        ok = False
        console.print(f"\n[dim]  ollama pull {guard_model}[/dim]")

    if ok:
        cases = [
            ("blocks a credential", "my key is sk-abcdefghijklmnop1234", False),
            ("blocks a person", "Jane Doe lives in Springfield", False),
            ("allows safe text", "The folder contains twelve planning files.", True),
        ]
        for label, sample, should_pass in cases:
            verdict = evaluate(sample, guard_model, not args.no_presidio, args.spacy_model, args.guardian_model)
            passed = verdict.approved == should_pass
            detail = f"{verdict.decision} via {' + '.join(verdict.layers_run)}"
            if not check(label, passed, detail):
                ok = False
                # Show why. Without this the operator sees only a decision and
                # has no way to tell a real detection from a broken dependency.
                for concern in verdict.concerns:
                    console.print(f"       [dim]{concern}[/dim]")
                if verdict.decision == "block" and "model" not in verdict.layers_run:
                    console.print(
                        "       [dim]the deterministic layers passed this text; "
                        "the failure is in the guard model call[/dim]"
                    )

    console.print()
    console.print(
        "[bold green]Ready.[/bold green] Try: [cyan]airlock chat[/cyan]"
        if ok
        else "[bold red]Not ready.[/bold red] Fix the items above."
    )
    return 0 if ok else 1


def make_session(args: argparse.Namespace, objective: str) -> Session:
    """Build a session from CLI arguments."""
    return Session(
        session_id=uuid.uuid4().hex[:12],
        objective=objective,
        sandbox=Sandbox(root=args.root, allow_writes=args.allow_writes),
        worker_model=args.model,
        guard_model=args.guard_model or args.model,
        use_presidio=not args.no_presidio,
        spacy_model=args.spacy_model,
        guardian_model=args.guardian_model,
    )


HELP_TEXT = """[bold]Commands[/bold]
  [cyan]/help[/cyan]      show this
  [cyan]/stats[/cyan]     session counters
  [cyan]/files[/cyan]     list the workspace
  [cyan]/guard[/cyan]     test text, e.g. /guard my ssn is 123-45-6789
  [cyan]/objective[/cyan] change the objective
  [cyan]/exit[/cyan]      quit

Ask anything else in plain language. The local model reads your files and
answers. Every answer is screened before it reaches you, and the same
screening applies when a cloud assistant asks through MCP."""


def cmd_chat(args: argparse.Namespace) -> int:
    """Interactive loop against the local model."""
    try:
        session = make_session(args, args.objective)
    except (SandboxError, FileNotFoundError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 1

    banner(session)
    if session.sandbox.allow_writes and not Confirm.ask(
        "[yellow]Writes are enabled. The model can modify files. Continue?[/yellow]",
        default=False,
    ):
        return 0
    console.print("[dim]Type /help for commands, /exit to quit.[/dim]\n")

    while True:
        try:
            line = Prompt.ask("[bold cyan]you[/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]bye[/dim]")
            break
        if not line:
            continue

        if line.startswith("/"):
            command, _, rest = line.partition(" ")
            if command in ("/exit", "/quit"):
                break
            if command == "/help":
                console.print(Panel(HELP_TEXT, border_style="dim", padding=(1, 2)))
            elif command == "/stats":
                table = Table(show_header=False, box=None, padding=(0, 2))
                table.add_row("exchanges", str(session.exchanges))
                table.add_row("revisions", str(session.revisions))
                table.add_row("blocked", str(session.blocked))
                console.print(table)
            elif command == "/files":
                for entry in session.sandbox.list_dir("."):
                    console.print(f"  [dim]{entry}[/dim]")
            elif command == "/objective":
                session.objective = rest or session.objective
                console.print(f"[dim]objective: {session.objective}[/dim]")
            elif command == "/guard":
                verdict = evaluate(rest, session.guard_model, session.use_presidio, session.spacy_model, session.guardian_model)
                colour = "green" if verdict.approved else "red"
                console.print(f"  [{colour}]{verdict.decision}[/{colour}]  [dim]"
                              f"{' + '.join(verdict.layers_run)}[/dim]")
                for concern in verdict.concerns:
                    console.print(f"    [dim]{concern}[/dim]")
            else:
                console.print(f"[dim]unknown command {command}, try /help[/dim]")
            continue

        with console.status("[dim]thinking...[/dim]", spinner="dots"):
            result = run_worker(session, line, on_step=print_step)
        render_reply(result)

    console.print(
        f"[dim]{session.exchanges} answered, {session.revisions} revised, "
        f"{session.blocked} blocked[/dim]"
    )
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    """Answer a single question and exit."""
    try:
        session = make_session(args, args.objective)
    except (SandboxError, FileNotFoundError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        return 1
    if not args.quiet:
        banner(session)
    result = run_worker(session, args.question, on_step=None if args.quiet else print_step)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        render_reply(result)
    return 0 if result.get("status") == "approved" else 2


def cmd_guard(args: argparse.Namespace) -> int:
    """Test whether a piece of text would pass the guard."""
    verdict = evaluate(args.text, args.guard_model or args.model, not args.no_presidio, args.spacy_model, args.guardian_model)
    colour = {"approve": "green", "revise": "yellow", "block": "red"}[verdict.decision]
    console.print(
        Panel(
            Group(
                Text.assemble(("decision  ", "dim"), (verdict.decision, colour)),
                Text.assemble(("layers    ", "dim"), (" + ".join(verdict.layers_run), "")),
                Text.assemble(
                    ("concerns  ", "dim"),
                    ("\n            ".join(verdict.concerns) or "none", ""),
                ),
                Text.assemble(
                    ("findings  ", "dim"),
                    (
                        ", ".join(f"{f['rule']}={f['masked']}" for f in verdict.findings)
                        or "none",
                        "",
                    ),
                ),
            ),
            title="guard",
            border_style=colour,
            padding=(1, 2),
        )
    )
    return 0 if verdict.approved else 2


def cmd_serve(args: argparse.Namespace) -> int:
    """Run as an MCP server so a cloud assistant can consult the workspace."""
    # MCPServer is the server class in MCP Python SDK v2. It replaced FastMCP,
    # and mcp.server.fastmcp.* was removed rather than deprecated, so there is
    # no older path worth supporting. The dependency pin above requires v2.
    from mcp.server import MCPServer

    try:
        sandbox = Sandbox(root=args.root, allow_writes=args.allow_writes)
    except (SandboxError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    guard_model = args.guard_model or args.model
    use_presidio = not args.no_presidio
    mcp = MCPServer("airlock")

    @mcp.tool()
    def airlock_open(objective: str) -> dict[str, Any]:
        """Start a session with the local model over the sandboxed workspace.

        Args:
            objective: What you want to achieve, in one or two sentences.

        Returns:
            Session id, workspace name, top level listing, and configuration.
        """
        session = Session(
            session_id=uuid.uuid4().hex[:12],
            objective=objective.strip(),
            sandbox=sandbox,
            worker_model=args.model,
            guard_model=guard_model,
            use_presidio=use_presidio,
            spacy_model=args.spacy_model,
            guardian_model=args.guardian_model,
        )
        SESSIONS[session.session_id] = session
        return {
            "session": session.session_id,
            "workspace": sandbox.root.name,
            "entries": sandbox.list_dir("."),
            "writes_enabled": sandbox.allow_writes,
            "protocol": (
                "Call airlock_ask with this session id. Replies pass a layered "
                "privacy guard and may be generalised or withheld."
            ),
        }

    @mcp.tool()
    def airlock_ask(session: str, question: str) -> dict[str, Any]:
        """Ask the local model about the workspace. Replies are guarded.

        Args:
            session: Session id from airlock_open.
            question: A question about structure, topics, or findings. Requests
                for identifiers, contact details, or credentials are blocked.

        Returns:
            An envelope with status, the message if approved, and whether
            anything was withheld.
        """
        found = SESSIONS.get(session)
        if found is None:
            return {"status": "error", "message": "Unknown session."}
        return run_worker(found, question.strip())

    @mcp.tool()
    def airlock_close(session: str) -> dict[str, Any]:
        """End a session and discard its state.

        Args:
            session: Session id from airlock_open.
        """
        found = SESSIONS.pop(session, None)
        if found is None:
            return {"status": "error", "message": "Unknown session."}
        return {"status": "closed", "exchanges": found.exchanges}

    @mcp.tool()
    def guard_check(text: str) -> dict[str, Any]:
        """Test whether text would pass the privacy guard.

        Args:
            text: The text to evaluate.
        """
        verdict = evaluate(text, guard_model, use_presidio, args.spacy_model, args.guardian_model)
        return {
            "decision": verdict.decision,
            "approved": verdict.approved,
            "concerns": verdict.concerns,
            "layers_run": verdict.layers_run,
            "findings": verdict.findings,
        }

    print(f"airlock serving {sandbox.root} over MCP", file=sys.stderr)
    mcp.run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line interface."""
    parser = argparse.ArgumentParser(
        prog="airlock",
        description="A guarded local model that works over one directory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  airlock doctor --root .\n"
            "  airlock chat --root ~/project\n"
            '  airlock ask --root . "what topics do these files cover?"\n'
            '  airlock guard "Jane Doe, 555-555-0100"\n'
            "  airlock serve --root ~/project\n"
        ),
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", type=Path, default=Path("."), help="Workspace directory.")
    common.add_argument("--model", default=DEFAULT_MODEL, help="Local worker model.")
    common.add_argument(
        "--guard-model",
        default=DEFAULT_GUARD_MODEL,
        help=f"Guard model (default: {DEFAULT_GUARD_MODEL}). Pass --guard-model "
        "with the worker tag to run both roles on one model.",
    )
    common.add_argument("--allow-writes", action="store_true", help="Let the model write files.")
    common.add_argument(
        "--no-presidio",
        action="store_true",
        help="Skip the PII layer. Faster to start, materially weaker detection.",
    )
    common.add_argument(
        "--spacy-model",
        default=DEFAULT_SPACY_MODEL,
        help=f"spaCy pipeline behind Presidio (default: {DEFAULT_SPACY_MODEL}). "
        "Use en_core_web_lg for better name recall at ~400MB.",
    )
    common.add_argument(
        "--guardian-model",
        default=None,
        help="Optional dedicated judging model (for example granite4.1-guardian:8b) "
        "run before the general guard model, using its native yes/no scoring.",
    )
    common.add_argument(
        "--trace",
        type=Path,
        default=None,
        help="Append guard decisions as JSON lines for later review or scoring. "
        "Records rule names and verdicts only, never message content.",
    )
    objective = argparse.ArgumentParser(add_help=False)
    objective.add_argument(
        "--objective",
        default="Help the user understand and work with the files in this directory.",
        help="Framing for the local model.",
    )

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", parents=[common], help="Check the setup.").set_defaults(
        func=cmd_doctor
    )
    sub.add_parser("chat", parents=[common, objective], help="Interactive session.").set_defaults(
        func=cmd_chat
    )
    p_ask = sub.add_parser("ask", parents=[common, objective], help="One-shot question.")
    p_ask.add_argument("question", help="What to ask.")
    p_ask.add_argument("--json", action="store_true", help="Emit the raw envelope.")
    p_ask.add_argument("--quiet", action="store_true", help="Suppress banner and steps.")
    p_ask.set_defaults(func=cmd_ask)

    p_guard = sub.add_parser("guard", parents=[common], help="Test text against the guard.")
    p_guard.add_argument("text", help="Text to evaluate.")
    p_guard.set_defaults(func=cmd_guard)

    sub.add_parser("serve", parents=[common], help="Run as an MCP server.").set_defaults(
        func=cmd_serve
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    global TRACE_PATH
    args = build_parser().parse_args(argv)
    TRACE_PATH = getattr(args, "trace", None)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        console.print("\n[dim]interrupted[/dim]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
