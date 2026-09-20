#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     # Bounded both sides on purpose; see CLAUDE.md before widening.
#     "mcp[cli]>=2.0.0,<2.1.0",
#     "torch>=2.13.0,<2.14.0",
#     "transformers>=5.15.0,<5.16.0",
#     "rich>=13.7",
#     "detect-secrets>=1.5",
#     "pypdf>=5.0",
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
    airlock FOLDER              connect that folder to an assistant (default)
    airlock status              what is connected, and whether it works
    airlock disconnect          remove airlock from an assistant
    airlock check "text"        test whether text would pass the guard
    airlock chat FOLDER         talk to the local model yourself

Follows the local-plus-cloud split of the Minions protocol (Stanford Hazy
Research, ICML 2025), adding the content guard that work did not have. See
README.md for the architecture and CLAUDE.md for design notes.

The guard, and why it is layered
--------------------------------
Four layers, cheapest and most certain first:

1. Regular expressions for secrets and credentials. API keys, private key
   blocks, and JWTs have rigid formats, so a pattern match is effectively
   exact.

2. Regular expressions for structured PII: email, phone, SSN, credit card,
   IBAN, street address, date of birth. Deterministic and independent of the
   model layers below, so it still runs if either is unavailable.

3. A local encoder model (LiquidAI's LFM2.5-Encoder-350M-PII-Detector) for
   PII a fixed pattern cannot express: names, locations, and identifier types
   outside layer 2's list, recognised from context rather than shape.

4. A local encoder model (LiquidAI's LFM2.5-Encoder-350M-Policy-Linter) for
   contextual sensitivity, such as health or financial disclosure written in
   prose that names no identifier at all.

Layers 3 and 4 load through `trust_remote_code=True` and are pinned to a
fixed revision; see README.md and CLAUDE.md before changing either. No layer
can overrule an earlier one. Any layer failing blocks the message, because a
guard that cannot evaluate must never approve.
"""

from __future__ import annotations

import argparse
import json
import os
import hmac
import itertools
import re
import secrets
import shutil
import subprocess
import sys
import threading
import tempfile
import textwrap
import urllib.error
import urllib.request
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Literal

from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# First tagged value for a project that ships as "copy one file and uv run
# --script it" rather than through a package index: a bug report needs a
# revision to reference. Starts at 0.1.0, not 1.0.0: there is no
# compatibility guarantee yet and no prior release for 1.0 to mean anything
# against.
__version__ = "0.1.0"

console = Console()

# A second console bound to stderr. Required in serve mode, where stdout is the
# MCP JSON-RPC channel: a single stray character written there corrupts the
# stream and the client drops the connection. Anything printed while serving
# must go here.
err_console = Console(stderr=True)

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
REQUEST_TIMEOUT = 120
# How long Ollama holds a model in memory after a request. Ollama's default is
# five minutes, and it queues every request while swapping one model out for
# another. airlock alternates between a worker and a differently-sized guard on
# every single step, so on a machine that cannot hold both it spends more time
# loading weights than generating. Holding them for the length of a session
# removes that entirely.
KEEP_ALIVE = "30m"
MAX_REVISIONS = 3
MAX_WORKER_STEPS = 8
FILE_SLICE_CHARS = 4000
MAX_LISTING_ENTRIES = 200
# Deliberately NOT the -mlx build, despite MLX being the faster backend on
# Apple Silicon.
DEFAULT_MODEL = "qwen3.5:0.8B"

# --------------------------------------------------------------------------
# Layer 1: secrets and credentials  Two detectors in union, because
# measurement showed neither is sufficient.

# Shape-based rules. Each matches the credential's own form, with no
# requirement on surrounding text, so they fire inside ordinary prose. Patterns
# follow the gitleaks rule set, which is written this way for the same reason.
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    # sk- and sk_ both appear in the wild: OpenAI uses the hyphen, Stripe the
    # underscore. An earlier hyphen-only pattern let every Stripe key through.
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
    "stripe_key": re.compile(r"\b(?:sk|rk|pk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    "gitlab_token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    "aws_access_key": re.compile(r"\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[0-9A-Z]{16}\b"),
    # Closing lookahead, not \b: a key ending in "-" has no word boundary
    # after it, so \b silently misses roughly one in twenty-seven of them.
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{44,}"),
    # Length is a floor, not an exact count. Vendors lengthen tokens over time
    # and an exact quantifier turns that into a silent miss.
    "sendgrid_key": re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}"),
    "npm_token": re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    "pypi_token": re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"),
    "digitalocean_token": re.compile(r"\bdo[oprsv]_v1_[a-f0-9]{64}\b"),
    "twilio_key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    # Captures the value alone in group 1, mirroring the CONTEXT_SECRET_PATTERNS
    # rules below: _document_identifiers needs the value on its own so a
    # caller splitting only the secret VALUE across jobs is still caught,
    # not just the label-plus-value string. group(0) is unchanged for masking.
    "generic_secret_assignment": re.compile(
        r"\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?([^\s'\"]{8,})",
        re.I,
    ),
}

# --------------------------------------------------------------------------
# Shapeless credentials, caught by context instead of form
# --------------------------------------------------------------------------
# Some credentials have no distinguishing shape at all.
CONTEXT_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    # No \b after the keywords. Underscore is a word character, so \baws\b does
    # not match the AWS_SECRET_ACCESS_KEY= form that these keys most often
    # appear in. The leading \b is kept so that "laws" and "flaws" do not match.
    "aws_secret_access_key": re.compile(
        r"\baws[^\n]{0,40}?(?:secret|access|key|token|credential)[^\n]{0,20}?"
        r"[\s:=\"']([A-Za-z0-9/+]{40})",
        re.I,
    ),
    # The bare word "key" is included despite being common English. The 24
    # character floor on the token is what makes that safe: no ordinary word
    # following "key" is that long in this character class, so "key findings"
    # and "the key to good documentation" do not fire, while "key is <40 chars
    # of base64>" does. Verified against a false-positive corpus.
    # Identifiers with no distinguishing shape, caught by the words around
    # them. A bare nine-digit run is a phone number, an order id, or an SSN,
    # and only the label separates them.
    "labelled_ssn": re.compile(
        r"\b(?:ssn|social security(?:\s+number)?|taxpayer id)\b[^\n]{0,24}?"
        r"\b(\d{9})\b",
        re.I,
    ),
    "labelled_account": re.compile(
        r"\b(?:account|acct|routing|iban|policy)(?:\s*(?:number|no|#))?\b"
        r"[^\n]{0,20}?[\s:=#]([0-9][0-9\-]{6,})",
        re.I,
    ),
    # us_ein stays hyphen-only in PII_PATTERNS: a bare 2-7 digit split is a
    # shape ordinary prose produces constantly (amounts, counts, part
    # numbers), unlike SSN's more distinctive 3-2-4 across two separators.
    # The space form is only trustworthy near a label, same reasoning as
    # labelled_ssn above.
    "labelled_ein": re.compile(
        r"\b(?:ein|employer id(?:entification)?(?:\s+number)?|federal tax id)\b"
        r"[^\n]{0,24}?\b(\d{2}[-\s]\d{7})\b",
        re.I,
    ),
    "labelled_opaque_token": re.compile(
        r"\b(?:secret|api[_-]?key|access[_-]?token|bearer|auth[_-]?token|key|credentials?)"
        r"[^\n]{0,20}?[\s:=\"']([A-Za-z0-9/+_-]{24,})",
        re.I,
    ),
}


def mask(value: str) -> str:
    """Replace the middle of a string with asterisks for safe display."""
    stripped = value.strip()
    if len(stripped) <= 4:
        return "*" * len(stripped)
    return f"{stripped[:2]}{'*' * (len(stripped) - 4)}{stripped[-2:]}"


PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    # Hyphens or spaces. A bare nine-digit run is handled by a context rule
    # below, because on its own it is indistinguishable from any other number.
    "us_ssn": re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"),
    # Employer and payer identification numbers: two digits, hyphen, seven.
    "us_ein": re.compile(r"\b\d{2}-\d{7}\b"),
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
    """Find structured personal identifiers. Always runs, regardless of the
    model layers below."""
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


def scan_secrets_context(text: str) -> list[dict[str, str]]:
    """Find credentials that have no distinguishing shape, using nearby words.

    Runs only against what the shape rules did not already claim. Ordering
    matters: this pass is the false-positive-prone one, so it should decide as
    little as possible.
    """
    findings: list[dict[str, str]] = []
    for name, pattern in CONTEXT_SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1)
            # A token already matched by a shape rule needs no second opinion,
            # and reporting it twice would misrepresent which layer caught it.
            if any(p.search(value) for p in SECRET_PATTERNS.values()):
                continue
            findings.append(
                {"rule": name, "masked": mask(value), "layer": "secrets:context"}
            )
    return findings


def scan_secrets(text: str) -> list[dict[str, str]]:
    """Union of all credential detectors, de-duplicated by rule name."""
    combined = (
        scan_secrets_patterns(text) + scan_secrets_library(text) + scan_secrets_context(text)
    )
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for finding in combined:
        if finding["rule"] in seen:
            continue
        seen.add(finding["rule"])
        unique.append(finding)
    return unique


# --------------------------------------------------------------------------
# Layer 2: bidirectional encoder guards  Two 350M LiquidAI encoders, replacing
# Presidio and the general-purpose guard model: a PII token classifier and a
# zero-shot policy linter for contextual sensitivity that has no span to
# detect at all. Wired into evaluate() below.
# See README.md for the evidence behind this replacement and CLAUDE.md for
# the trust_remote_code=True tradeoff it takes on.
# --------------------------------------------------------------------------


class GuardModelUnavailable(Exception):
    """Raised when a guard encoder cannot be loaded or run."""


def _chunk_text(text: str, window: int, overlap: int) -> list[str]:
    """Slide a `window`-character window over `text` with `overlap` shared
    between consecutive chunks, covering every character at least once.

    Handing a whole document to a tokenizer's own truncation makes everything
    past the cut invisible, and an empty finding list looks identical to a
    clean scan: the same fail-open shape GuardModelUnavailable exists to
    prevent for a failed load, just relocated to input length. Both guard
    scanners return entity types or rule indices rather than spans, so a
    union of per-chunk findings is correct with no stitching. The overlap
    exists so a value straddling a chunk boundary still lands whole inside at
    least one chunk, as long as that value is shorter than the overlap.
    """
    if len(text) <= window:
        return [text]
    step = window - overlap
    assert step > 0, "overlap must be smaller than window, or pos never advances"
    chunks: list[str] = []
    pos = 0
    while True:
        chunks.append(text[pos : pos + window])
        if pos + window >= len(text):
            break
        pos += step
    return chunks


PII_DETECTOR_MODEL = "LiquidAI/LFM2.5-Encoder-350M-PII-Detector"
# Pinned so a later change to the model repo cannot silently alter what runs
# under trust_remote_code=True below.
PII_DETECTOR_REVISION = "b8c9cf3d2d6ae52501b35a27ba46f271449c9ce2"
PII_DETECTOR_THRESHOLD = 0.5

# A per-entity threshold, not Presidio's exclusion list: unfiltered,
# scan_pii_model blocked on ANY non-O label, and 2.7% of bare number-shaped
# job answers (8/300 sampled) false-flagged as contact.postal_code. Mirrors
# POLICY_LINTER_RULE_THRESHOLDS's shape: a sparse override dict,
# PII_DETECTOR_THRESHOLD as the default for every entity not listed. See
# CLAUDE.md's "Known weaknesses" for the design argument and the
# identity.person_name false-positive case left unfixed.
PII_DETECTOR_ENTITY_THRESHOLDS: dict[str, float] = {
    # 0.70 separates the false-positive cluster (0.524-0.565, bare numbers)
    # from true positives (0.845-0.998 in address context, with one real
    # address recall miss at 0.000, already below any threshold considered),
    # but not cleanly: a residual false positive can still outscore the
    # lowest true positive. See CLAUDE.md's "Known weaknesses" for the full
    # measurement and why this is the best tradeoff found, not a clean
    # separator.
    "contact.postal_code": 0.70,
}

# max_length below (512 tokens) is a hard model limit. Measured against the
# real tokenizer: ordinary English runs about 5 chars/token, but a dense
# alphanumeric blob, the shape of the credentials PII_PATTERNS and
# SECRET_PATTERNS already look for, can run as low as ~1 char/token. Sizing
# the window off the friendly ratio would silently reintroduce truncation on
# exactly the content this scanner most needs to see. 500 stays under 512
# tokens even at that measured worst case.
PII_CHUNK_CHARS = 500
# Longer than the longest credential shape this project's own tests exercise
# (test.py's CREDENTIAL_SHAPES: "dop_v1_" + 64 hex chars = 71
# chars), with margin, so a credential split by a chunk boundary still lands
# whole inside at least one chunk. An unbounded-length secret (SECRET_PATTERNS'
# generic_secret_assignment has no upper bound) can still exceed this; that
# residual is inherent to any finite overlap, not something this bound closes.
PII_CHUNK_OVERLAP_CHARS = 200


def resolve_device(choice: str = "auto") -> str:
    """Pick a torch device: MPS on Apple Silicon, then CUDA, then CPU.

    Both encoders are
    single-forward-pass models with no MLX build, so MPS is the free win on a
    Mac and CPU is the only universal fallback.
    """
    import torch

    if choice != "auto":
        return choice
    if torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


@lru_cache(maxsize=1)
def _load_pii_detector(device: str = "auto") -> tuple[Any, Any, Any, str, dict[int, str]]:
    """Load the PII token classifier once and cache it.

    trust_remote_code=True executes code from the model repository at load
    time: a bespoke bidirectional backbone with a BIOES token-classification
    head, for which no standard-architecture equivalent exists. That is an
    accepted supply-chain risk recorded in README.md and CLAUDE.md,
    not one to reconsider quietly at this call site. The revision above is
    pinned so a later push to the repo cannot change what that code does.
    """
    try:
        import torch
        from transformers import AutoModelForTokenClassification, AutoTokenizer
    except ImportError as exc:
        raise GuardModelUnavailable(f"torch/transformers not installed: {exc}")
    try:
        resolved = resolve_device(device)
        tok = AutoTokenizer.from_pretrained(
            PII_DETECTOR_MODEL, revision=PII_DETECTOR_REVISION, trust_remote_code=True
        )
        model = (
            AutoModelForTokenClassification.from_pretrained(
                PII_DETECTOR_MODEL, revision=PII_DETECTOR_REVISION, trust_remote_code=True
            )
            .eval()
            .to(resolved)
        )
    except Exception as exc:  # noqa: BLE001 - any load failure fails closed
        raise GuardModelUnavailable(f"PII detector could not load: {exc}")
    raw = model.config.id2label
    id2label = (
        {int(k): v for k, v in raw.items()} if isinstance(raw, dict) else dict(enumerate(raw))
    )
    return torch, model, tok, resolved, id2label


def _scan_pii_region(chunk: str) -> list[str]:
    """Score one region for entity types above their threshold.

    Each entity's confidence is checked against PII_DETECTOR_ENTITY_THRESHOLDS,
    falling back to PII_DETECTOR_THRESHOLD for any entity not listed there.

    PII_CHUNK_CHARS assumes a measured worst-case ratio (~1.06 chars/token
    over ASCII identifier-shaped samples), but that is not a proven floor:
    BPE byte-fallback on CJK, emoji or other non-ASCII scripts commonly
    tokenizes below 1 char/token, so a PII_CHUNK_CHARS-sized window of dense
    non-ASCII text can still exceed 512 tokens. Rather than trust the ratio,
    this asks the tokenizer directly: encode without truncation and check
    the real length. If it still overflows, bisect the region in half (no
    overlap at this level: the caller's PII_CHUNK_OVERLAP_CHARS already
    covers the boundary between PII_CHUNK_CHARS windows, and reusing that
    large an overlap at ever-smaller recursion depths would blow up the
    number of windows scanned here, the same DoS shape the round-reassembly
    guard's own length bound exists to prevent) and score each half the same
    way. A region too short to bisect further that still overflows fails
    closed: at that point no window size could have scanned it safely.
    """
    torch, model, tok, device, id2label = _load_pii_detector()
    enc = tok(chunk, return_tensors="pt")
    if enc["input_ids"].shape[1] > 512:
        if len(chunk) <= 1:
            raise GuardModelUnavailable(
                "PII detector: text does not fit the 512-token budget even "
                "at a single character; refusing to scan it truncated"
            )
        half = len(chunk) // 2
        found: list[str] = []
        for region in _chunk_text(chunk, half, 0):
            for entity in _scan_pii_region(region):
                if entity not in found:
                    found.append(entity)
        return found

    enc = {k: v.to(device) for k, v in enc.items()}
    with torch.no_grad():
        logits = model(**enc).logits.float().cpu()
    conf, ids = logits.softmax(-1)[0].max(-1)
    found: list[str] = []
    for c, i in zip(conf.tolist(), ids.tolist()):
        label = id2label.get(i, "O")
        if label == "O":
            continue
        entity = re.sub(r"^[BIES]-", "", label)
        if c < PII_DETECTOR_ENTITY_THRESHOLDS.get(entity, PII_DETECTOR_THRESHOLD):
            continue
        # Narrow, entity-specific gate, not a general rule: the threshold
        # alone cannot separate contact.postal_code's overlapping score
        # distributions (see PII_DETECTOR_ENTITY_THRESHOLDS' comment and
        # CLAUDE.md). A letter in the scanned text is a proxy for address
        # context: a real postal code always travels with a street, city,
        # state, or an explicit "zip"/"postal code" label, none of which a
        # bare extracted number carries. Zero measured recall cost, since
        # every bare number this silences has no letter by construction and
        # every real disclosure measured still has one.
        if entity == "contact.postal_code" and not re.search(r"[A-Za-z]", chunk):
            continue
        if entity not in found:
            found.append(entity)
    return found


def scan_pii_model(text: str) -> list[dict[str, str]]:
    """Entity types found by the PII detector, above threshold.

    Scans in overlapping PII_CHUNK_CHARS-character windows rather than
    handing the whole text to the tokenizer's own truncation: max_length=512
    tokens is roughly 2000 characters of ordinary English and far less for
    dense identifier-shaped text, and everything past a silent truncation cut
    would be indistinguishable from "found nothing" to a caller. Each window
    is then re-checked by _scan_pii_region, which bisects further if that
    window alone still overflows the token budget (see its docstring for
    why a char ratio alone cannot be trusted to prevent that). Findings are
    entity types, not spans, so unioning across chunks and regions needs no
    stitching.

    Returns findings shaped like the other scanners: rule, masked, layer.
    The model's own output is a per-token entity label, not a reconstructed
    span, so there is no matched text to mask in the first place; "masked"
    mirrors scan_secrets_library's "detected" for the same reason. Raises
    GuardModelUnavailable on any load or inference failure rather than
    returning an empty list, so a caller cannot mistake "could not run" for
    "found nothing".
    """
    found: list[str] = []
    for chunk in _chunk_text(text, PII_CHUNK_CHARS, PII_CHUNK_OVERLAP_CHARS):
        try:
            for entity in _scan_pii_region(chunk):
                if entity not in found:
                    found.append(entity)
        except GuardModelUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - inference failure fails closed too
            raise GuardModelUnavailable(f"PII detector inference failed: {exc}")
    return [{"rule": entity, "masked": "detected", "layer": "pii:model"} for entity in found]


POLICY_LINTER_MODEL = "LiquidAI/LFM2.5-Encoder-350M-Policy-Linter"
POLICY_LINTER_REVISION = "2a56cb94a7083a90263ea5270523ccc10e7ce8af"
POLICY_LINTER_THRESHOLD = 0.70
# Rule 1 (financial hardship) and rule 4 (immigration) raised above the
# global threshold: measured at 40 and 24 false positives respectively at a
# global 0.70. Rule 5 (confidential business) deliberately stays low: it is
# the only rule that catches the hardest contextual cases (see CLAUDE.md's
# "Known weaknesses").
POLICY_LINTER_RULE_THRESHOLDS: dict[int, float] = {1: 0.98, 4: 0.98}

# Free-text rules, scored per token, zero-shot. Order is the rule index used
# in findings ("rule0" .. "rule5").
# Identifier rules are deliberately absent: the linter measures poorly on
# exact identifiers, that coverage belongs to scan_pii_model.
#
# Rule 5's wording below was chosen by measurement, not first draft: see
# CLAUDE.md's "Known weaknesses" for the prior wording it replaced, the two
# rejected rewordings, and the recall/false-block numbers behind each.
CONTEXTUAL_RULES: list[str] = [
    "Flag disclosure of a medical condition, diagnosis, treatment, or mental health.",
    "Flag disclosure of financial hardship, debt, bankruptcy, or inability to pay.",
    "Flag disclosure of a lawsuit, legal dispute, settlement, or investigation.",
    "Flag disclosure of addiction, recovery, or substance use.",
    "Flag disclosure of immigration or visa status.",
    "Flag disclosure of non-public company information that has not been "
    "announced, such as a pending acquisition, a major customer ending its "
    "contract, or an internal investigation.",
]

# max_length=2048 tokens, minus the rule prefix (measured 92 tokens for the
# rules above) and a little headroom. Same worst-case-ratio reasoning as
# PII_CHUNK_CHARS: dense text can run near 1 char/token under this tokenizer
# too, so 1800 stays under budget even then, not only at ordinary English's
# ~5 chars/token.
POLICY_CHUNK_CHARS = 1800
# A single disclosure sentence runs well under this; sized generously so one
# is never split across a chunk boundary with only a fragment on each side.
POLICY_CHUNK_OVERLAP_CHARS = 400


def _policy_prefix() -> str:
    """Build the rule-listing prefix from the live CONTEXTUAL_RULES.

    Deliberately not cached. scan_policy's pool construction already reads
    CONTEXTUAL_RULES live on every call, computing each rule's character
    offsets from scratch; a prefix string baked once at load time and reused
    forever would drift the moment CONTEXTUAL_RULES changed after that first
    load, misaligning the pool's offsets against a prefix that no longer
    matches, with no error raised. One function both scan_policy and
    _load_policy_linter's docstring can point to is cheaper than proving the
    two can never disagree.
    """
    return "Policy:\n" + "\n".join(f"- {r}" for r in CONTEXTUAL_RULES) + "\n\nText:\n"


@lru_cache(maxsize=1)
def _load_policy_linter(device: str = "auto") -> tuple[Any, Any, Any, str]:
    """Load the policy linter once and cache it.

    Same accepted risk as _load_pii_detector: trust_remote_code=True runs
    code from the model repository (a GLiNER-style rule-matching head), taken
    on deliberately and recorded in README.md and CLAUDE.md, and
    pinned to a fixed revision for the same reason. Returns no prefix: that is
    _policy_prefix()'s job, computed fresh on every call rather than cached
    alongside the model, so it can never go stale relative to CONTEXTUAL_RULES.
    """
    try:
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:
        raise GuardModelUnavailable(f"torch/transformers not installed: {exc}")
    try:
        resolved = resolve_device(device)
        tok = AutoTokenizer.from_pretrained(
            POLICY_LINTER_MODEL, revision=POLICY_LINTER_REVISION, trust_remote_code=True
        )
        model = (
            AutoModel.from_pretrained(
                POLICY_LINTER_MODEL, revision=POLICY_LINTER_REVISION, trust_remote_code=True
            )
            .eval()
            .to(resolved)
        )
    except Exception as exc:  # noqa: BLE001 - any load failure fails closed
        raise GuardModelUnavailable(f"policy linter could not load: {exc}")
    return torch, model, tok, resolved


def _scan_policy_region(chunk: str, threshold: float | None = None) -> set[int]:
    """Score one region against the rule pool.

    Same deterministic-overflow handling as _scan_pii_region, and for the
    same reason: POLICY_CHUNK_CHARS' char ratio is a measurement, not a
    proven floor, and dense non-ASCII text can tokenize below it. The
    encoded length of prefix + chunk is checked directly against the
    2048-token budget; an overflowing region is bisected in half (no
    overlap at this level, same DoS reasoning as _scan_pii_region) and each
    half scored the same way. A region too short to bisect further that
    still overflows fails closed.

    threshold, when given, replaces POLICY_LINTER_THRESHOLD for this call
    only; POLICY_LINTER_RULE_THRESHOLDS' per-rule overrides still take
    precedence regardless, same as before. Passed explicitly rather than
    through the module global so a per-call override (evaluate()'s
    linter_threshold parameter) cannot affect a concurrent caller sharing
    this process; POLICY_LINTER_THRESHOLD itself remains mutable for the
    eval harness and tests, which override it as a module global on purpose.
    """
    torch, model, tok, device = _load_policy_linter()
    prefix = _policy_prefix()
    full = prefix + chunk
    enc = tok(full, return_offsets_mapping=True, return_tensors="pt")
    if enc["input_ids"].shape[1] > 2048:
        if len(chunk) <= 1:
            raise GuardModelUnavailable(
                "policy linter: text does not fit the 2048-token budget even "
                "at a single character; refusing to scan it truncated"
            )
        half = len(chunk) // 2
        found: set[int] = set()
        for region in _chunk_text(chunk, half, 0):
            found |= _scan_policy_region(region, threshold)
        return found

    offsets = enc.pop("offset_mapping")[0].tolist()
    pool = torch.zeros(1, len(CONTEXTUAL_RULES), len(offsets))
    pos = len("Policy:\n")
    for ri, rule in enumerate(CONTEXTUAL_RULES):
        start = pos + 2
        end = start + len(rule)
        idx = [i for i, (a, b) in enumerate(offsets) if a < end and b > start and a != b]
        if idx:
            pool[0, ri, idx] = 1 / len(idx)
        pos = end + 1
    enc = {k: v.to(device) for k, v in enc.items()}
    pool = pool.to(device)
    with torch.no_grad():
        probs = model(**enc, rule_pool=pool)["logits"].float().sigmoid()[0].cpu()

    text_start = len(prefix)
    keep = [i for i, (a, b) in enumerate(offsets) if b > text_start and a != b]
    if not keep:
        return set()
    sub = probs[keep]
    fallback = POLICY_LINTER_THRESHOLD if threshold is None else threshold
    found = set()
    for ri in range(len(CONTEXTUAL_RULES)):
        if float(sub[:, ri].max()) > POLICY_LINTER_RULE_THRESHOLDS.get(ri, fallback):
            found.add(ri)
    return found


def scan_policy(text: str, threshold: float | None = None) -> list[dict[str, str]]:
    """Rules the policy linter scores above their threshold.

    Scans in overlapping POLICY_CHUNK_CHARS-character windows for the same
    reason scan_pii_model does: max_length=2048 tokens minus the rule prefix
    leaves headroom for ordinary English but far less for dense text, and a
    silent truncation is indistinguishable from a clean scan. Each window is
    then re-checked by _scan_policy_region, which bisects further if that
    window (plus the rule prefix) alone still overflows the token budget
    (see its docstring for why a char ratio alone cannot be trusted to
    prevent that). Findings are rule indices, not spans, so unioning across
    chunks and regions needs no stitching. Each region gets its own rule
    prefix prepended and its own pool built against that region's own token
    offsets, because the pool's positions are computed from the
    prefix-plus-region string, not from the whole document.

    threshold overrides POLICY_LINTER_THRESHOLD for this call only, without
    touching the module global; evaluate() uses this so a per-session
    linter_threshold cannot leak into a concurrent call. Leave it None to
    read POLICY_LINTER_THRESHOLD (and POLICY_LINTER_RULE_THRESHOLDS, which a
    per-call threshold never overrides) as module globals at call time, so a
    caller overriding either constant directly, as the eval harness and
    tests do, still takes effect immediately. Each rule's pooled span must
    land on that rule's own tokens inside the prompt prefix, not on the input
    text. Raises GuardModelUnavailable rather than returning empty on any
    failure, matching scan_pii_model.
    """
    found: set[int] = set()
    for chunk in _chunk_text(text, POLICY_CHUNK_CHARS, POLICY_CHUNK_OVERLAP_CHARS):
        try:
            found |= _scan_policy_region(chunk, threshold)
        except GuardModelUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - inference failure fails closed too
            raise GuardModelUnavailable(f"policy linter inference failed: {exc}")
    return [
        {"rule": f"rule{ri}", "masked": "detected", "layer": "policy:model"}
        for ri in sorted(found)
    ]


# --------------------------------------------------------------------------
# Filesystem sandbox  There is no established Python library for this.


class SandboxError(Exception):
    """Raised when a path escapes the workspace root."""


def extract_pdf_text(path: Path) -> str:
    """Pull the text layer out of a PDF.

    Without this the worker receives raw PDF structure and cannot answer
    anything about the document, which rules out the formats most personal
    records arrive in. Extraction only, never rendering or script execution.

    A scanned PDF has no text layer and yields nothing. That is reported
    plainly rather than as an empty read, because silence would look like an
    empty document instead of an unreadable one.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        raise SandboxError(
            "Reading PDFs needs pypdf. Install it, or convert the file to text."
        )
    try:
        pages = [page.extract_text() or "" for page in PdfReader(str(path)).pages]
    except Exception as exc:  # noqa: BLE001 - any parse failure is a read failure
        raise SandboxError(f"Cannot parse PDF {path.name}: {exc}")
    text = "\n".join(pages).strip()
    if not text:
        raise SandboxError(
            f"{path.name} has no text layer, likely a scan. OCR it first."
        )
    return text


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
            # The refusal is fed back to the model as input, so it should say
            # what to do instead. A worker was observed burning an entire step
            # budget on absolute paths because the error only said "no".
            hint = relative.lstrip("/").split("/")[-1] or "."
            raise SandboxError(
                f"Path escapes the workspace: {relative}. Paths are relative to "
                f"the workspace root, with no leading slash. Try {hint!r}."
            )
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
        """Read a bounded slice of a file, extracting text from PDFs."""
        target = self.resolve(relative)
        if not target.is_file():
            raise SandboxError(f"Not a file: {relative}")
        if target.suffix.lower() == ".pdf":
            data = extract_pdf_text(target)
        else:
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
            raise SandboxError(
                "Writes are disabled. Enable with --write, or /config writes on."
            )
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
        "keep_alive": KEEP_ALIVE,
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
# Guard verdict and the combined evaluator
# --------------------------------------------------------------------------


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


def evaluate(message: str, linter_threshold: float | None = None) -> GuardVerdict:
    """Run every guard layer over a candidate message.

    Layers run cheapest and most certain first and short-circuit, since a
    confirmed match needs no further opinion:

        secrets -> pii-patterns -> pii-detector -> policy-linter

    Any layer that cannot run blocks the message rather than being skipped, so
    a missing dependency (here: torch/transformers, or a model that fails to
    load) degrades into refusal rather than into silent permissiveness.

    linter_threshold defaults to None rather than to POLICY_LINTER_THRESHOLD
    directly: a default bound to the module global at import time would freeze
    whatever value was current then, so a bare evaluate(text) call would keep
    using that stale value even after something changes the global at
    runtime (the eval harness and tests both do). Resolving None here instead
    reads the global at call time.
    """
    if linter_threshold is None:
        linter_threshold = POLICY_LINTER_THRESHOLD
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

    try:
        pii_model = scan_pii_model(message)
        layers.append("pii-detector")
    except GuardModelUnavailable as exc:
        return GuardVerdict(
            decision="block",
            concerns=[f"PII detector unavailable: {exc}"],
            instruction="Install torch and transformers so the PII detector encoder can load.",
            layers_run=layers,
        )
    if pii_model:
        rules = sorted({f["rule"] for f in pii_model})
        return GuardVerdict(
            decision="revise",
            concerns=[f"personal information detected: {r}" for r in rules],
            instruction=(
                "Remove the following and describe it generally instead: "
                f"{', '.join(rules)}. Refer to people by role rather than name, "
                "and to places by type rather than name."
            ),
            findings=pii_model,
            layers_run=layers,
        )

    # linter_threshold is passed straight through as a call argument, not
    # swapped into the POLICY_LINTER_THRESHOLD module global: a global is
    # process-wide, so mutating it here would apply this call's threshold to
    # any concurrent call too, including one running a different session's
    # setting. scan_policy still falls back to the module global when no
    # threshold is given, which is how the eval harness and tests override
    # it directly.
    try:
        policy = scan_policy(message, linter_threshold)
        layers.append("policy-linter")
    except GuardModelUnavailable as exc:
        return GuardVerdict(
            decision="block",
            concerns=[f"policy linter unavailable: {exc}"],
            instruction="Install torch and transformers so the policy linter encoder can load.",
            layers_run=layers,
        )
    if policy:
        rules = sorted({f["rule"] for f in policy})
        return GuardVerdict(
            decision="revise",
            concerns=[f"contextual policy concern detected: {r}" for r in rules],
            # The linter returns a rule index, not guidance, so the
            # instruction is derived from what the rule pool covers.
            instruction=(
                "Remove personal details about any individual: health, finances, "
                "employment or legal matters, family situation, or private "
                "correspondence. Describe the work in general terms instead."
            ),
            findings=policy,
            layers_run=layers,
        )

    return GuardVerdict(decision="approve", layers_run=layers)


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

Every path is relative to the directory listed below. Never start a path with
a slash and never write an absolute path: "W2.pdf" and "notes/w2.pdf" are
valid, "/W2.pdf" and "/Users/me/W2.pdf" are not.

Choose one action:
- list: list a directory. Set path. Use "." for this directory.
- read: read a file. Set path.
- search: find files containing text. Set query.
- write: write a file. Set path and content.
- answer: give your final answer. Set answer.

In your final answer, describe what you found in general terms. Do not include
names, addresses, phone numbers, email addresses, account numbers, or
credentials. Refer to people by role.

Files in this directory:
{files}

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
    linter_threshold: float = POLICY_LINTER_THRESHOLD
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    exchanges: int = 0
    blocked: int = 0
    revisions: int = 0
    # Cross-round reassembly state. Keyed per normalised source identifier
    # (see advance_reassembly_state), so this is bounded by the workspace's
    # identifier count, not by how many rounds the session has run. Holds
    # only integer offsets into each source, never the fragments themselves;
    # see advance_reassembly_state's docstring for why that is enough.
    reassembly_state: dict[str, set[int]] = field(default_factory=dict)
    # Last airlock_ask/airlock_extract call, for evict_stale_sessions' TTL
    # check below. Separate from created_at: a long-running, actively used
    # session must not be evicted just because it is old.
    last_active: str = field(default_factory=lambda: datetime.now().isoformat())


SESSIONS: dict[str, Session] = {}
StepCallback = Callable[[str, str], None]

# SESSIONS is a process-global dict; eviction bounds an orphaned Session
# (a crashed or disconnected caller that never closes) but NOT an
# actively-used one's growth -- touch_session keeps a busy session from
# ever going idle. reassembly_state stays bounded regardless, by geometry
# rather than eviction; see CLAUDE.md's "Known weaknesses" for why, and for
# where the 200/one-hour numbers below come from.
SESSION_CAP = 200
SESSION_IDLE_SECONDS = 3600


def touch_session(session: Session) -> None:
    """Mark a session as active now, for evict_stale_sessions' TTL check."""
    session.last_active = datetime.now().isoformat()


def evict_stale_sessions(now: datetime | None = None) -> None:
    """Bound SESSIONS: drop sessions idle past the TTL, then oldest-idle
    first while still over the cap. Enforces len(SESSIONS) <= SESSION_CAP as
    a postcondition, so a session sitting exactly at the cap is left alone.

    Called after a new session is registered (airlock_open), so the bound
    holds immediately once every open returns, not only on some later call.
    Eviction is a plain dict pop, the same primitive airlock_close already
    uses, so an evicted session's id fails exactly the way a closed one
    does: the next call with that id finds SESSIONS.get(...) is None, and
    gets a clear "Unknown session." refusal, never a silent new session and
    never a crash.
    """
    now = now or datetime.now()
    for sid, sess in list(SESSIONS.items()):
        idle = (now - datetime.fromisoformat(sess.last_active)).total_seconds()
        if idle > SESSION_IDLE_SECONDS:
            SESSIONS.pop(sid, None)
    if len(SESSIONS) > SESSION_CAP:
        oldest_idle_first = sorted(SESSIONS.items(), key=lambda kv: kv[1].last_active)
        excess = len(SESSIONS) - SESSION_CAP
        for sid, _ in oldest_idle_first[:excess]:
            SESSIONS.pop(sid, None)


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


def evaluate_session(session: Session, text: str) -> GuardVerdict:
    """Run the guard using a session's configuration."""
    return evaluate(text, session.linter_threshold)


# --------------------------------------------------------------------------
# Round-level reassembly guard.
#
# A caller can split a protected value across several jobs and scatter benign
# jobs between the fragments; the shape-based scanners above miss that
# because they need the fragments adjacent. This anchors on the identifiers
# actually present in the workspace instead, so it matches a known value
# rather than a shape and survives dilution and interleaving.
# --------------------------------------------------------------------------

MIN_REASSEMBLY_LENGTH = 6

# Bounds the total normalised length of one round's values, not just their
# count, since cost scales with both value length and workspace identifier
# count (see _subset_concatenations/_subset_contains). Exists because 12
# unshaped answers of FILE_SLICE_CHARS (4000) each against 400 workspace
# identifiers took 18.0s on the guard path itself before this bound
# existed -- a denial of service on the path meant to prevent one. See
# CLAUDE.md's "Known weaknesses" for realistic-vs-pathological cost figures
# at this bound.
MAX_REASSEMBLY_LENGTH = FILE_SLICE_CHARS


def normalise_identifier(value: str) -> str:
    """Lowercase alphanumerics only, for separator-independent comparison.

    "912-84-7731" and "912 84 7731" both normalise to "912847731".
    """
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _document_identifiers(text: str) -> set[str]:
    """Normalised identifiers found in one document's text.

    Deliberately re-walks PII_PATTERNS, SECRET_PATTERNS and
    CONTEXT_SECRET_PATTERNS directly rather than calling scan_pii_patterns or
    scan_secrets: those return mask(value) by design, and this needs the raw
    value to normalise. The caller (source_identifiers) must keep this
    private and never let a raw or normalised value escape into a return
    value, concern, receipt, trace record, or exception message.

    detect-secrets is excluded on purpose, a coverage limit rather than an
    oversight: its finds have no fixed span to recover reliably, and are the
    class least likely to be reconstructed from constrained job answers.
    """
    values: list[str] = []
    for name, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            if name == "credit_card" and not _luhn_ok(value):
                continue
            values.append(value)
    for pattern in SECRET_PATTERNS.values():
        for match in pattern.finditer(text):
            # generic_secret_assignment captures a label plus the value; only
            # the value is the identifier, same reasoning as the context
            # rules below. Patterns with no capture group have none to prefer.
            values.append(match.group(1) if pattern.groups else match.group(0))
    for pattern in CONTEXT_SECRET_PATTERNS.values():
        for match in pattern.finditer(text):
            # These rules match a label plus the value; only the value is the
            # identifier. Patterns with no capture group have none to prefer.
            values.append(match.group(1) if pattern.groups else match.group(0))
    return {
        normalised
        for value in values
        if len(normalised := normalise_identifier(value)) >= MIN_REASSEMBLY_LENGTH
    }


def source_identifiers(sandbox: Sandbox) -> set[str]:
    """Normalised identifiers present in the workspace documents.

    Holds raw protected values. Never returned to a caller, never logged,
    never placed in a concern. Raises SandboxError, which the caller turns
    into a block.
    """
    # list_dir appends a literal "... truncated at N" sentinel once a listing
    # hits MAX_LISTING_ENTRIES. It is not a file, so read_text raises on it.
    # list_dir's contract keeps the sentinel visible to other callers; this
    # is the one caller that must skip it rather than treat it as a document.
    truncated_marker = f"... truncated at {MAX_LISTING_ENTRIES}"
    sources: set[str] = set()
    for entry in sandbox.list_dir("."):
        if entry.endswith("/") or entry == truncated_marker:
            continue
        sources |= _document_identifiers(sandbox.read_text(entry))
    return sources


def _subset_concatenations(normalised: list[str]) -> set[str]:
    """Every string obtainable by keeping some subset of the values, in job
    order, and concatenating what is kept.

    This is the model of what a caller can actually do: it received these job
    results in this order and can discard any of them, but cannot reorder or
    split one. Exhaustive because MAX_JOBS_PER_ROUND bounds the round to 12
    values, so 2**12 = 4096 subsets at most. Built once per round by the
    caller and reused across every source identifier, rather than rebuilt per
    identifier, since it does not depend on which identifier is being tested.
    """
    concatenations: set[str] = set()
    n = len(normalised)
    for mask in range(1, 1 << n):
        parts = [normalised[i] for i in range(n) if mask & (1 << i)]
        concatenations.add("".join(parts))
    return concatenations


def _subset_contains(values: list[str], sources: set[str]) -> bool:
    """True if some source is a substring of some subset concatenation.

    Shared by reassembles_identifier's raw pass and its digits-only
    projection pass, so the subset-containment loop exists once rather than
    twice.
    """
    concatenations = _subset_concatenations(values)
    return any(source in c for source in sources for c in concatenations)


def _order_free_reassembles(values: list[str], sources: set[str]) -> bool:
    """advance_reassembly_state on a throwaway, round-scoped state.

    Shared by reassembles_identifier's two order-free passes (raw values and
    alnum runs), so the round-scoped state and the fail-closed wrapper exist
    once. The state dict is discarded when this returns: nothing here
    persists across calls, unlike run_jobs' own use of the same function
    against session.reassembly_state.

    Fails closed on any error, per CLAUDE.md's guard invariant and matching
    run_jobs' own handling of the persistent cross-round call: a check that
    cannot run must never stand in for a check that ran and passed.
    """
    try:
        return advance_reassembly_state({}, values, sources)
    except Exception:  # noqa: BLE001 - a tracking failure must not approve
        return True


_ALNUM_RUN = re.compile(r"[0-9A-Za-z]+")


def _alnum_runs(value: str) -> list[str]:
    """Maximal alphanumeric runs in one raw value, each normalised.

    The analogue of the digits-only projection for a source that has a
    letter in it: that identifier's meaning cannot be reduced to digits, so
    padding cannot be stripped character-by-character the way it is for a
    numeric source. What survives instead is the run boundary: padding that
    sits next to a fragment rather than inside it (a space, a hyphen, a
    sentence) still separates the fragment into its own contiguous run,
    exactly the way non-digit padding already falls out of the digits
    projection. A run glued directly onto padding with no separator at all
    is not recoverable by this or any projection here; see
    reassembles_identifier's docstring.
    """
    return [normalise_identifier(run) for run in _ALNUM_RUN.findall(value)]


def reassembles_identifier(values: list[str], sources: set[str]) -> bool:
    """True if the values together reconstruct a source identifier that none
    of them contains on its own.

    Matches whole values, not characters: a source counts as reconstructed
    once it is a substring of the concatenation of some subset of the
    round's normalised values, kept in job order. Handles three ways a
    caller can dodge that: fragments issued out of order, numeric padding,
    and alphanumeric padding (e.g. an API key) where digits can't be
    projected out. Cross-round accumulation is out of scope here; that is
    advance_reassembly_state's job, called separately by run_jobs.

    Bounded at MAX_JOBS_PER_ROUND and MAX_REASSEMBLY_LENGTH rather than
    trusting the caller (run_jobs enforcing those upstream is a
    convention, not a guarantee). A round that exceeds either is treated
    as a block, same as `evaluate` when a layer is unavailable: a guard
    that cannot evaluate must never approve.

    See CLAUDE.md's "Known weaknesses" for what was measured getting here.
    """
    if len(values) > MAX_JOBS_PER_ROUND:
        return True
    normalised = [normalise_identifier(v) for v in values]
    if sum(len(v) for v in normalised) > MAX_REASSEMBLY_LENGTH:
        return True
    candidates = {
        source
        for source in sources
        if len(source) >= MIN_REASSEMBLY_LENGTH
        and not any(source in v for v in normalised)
    }
    if not candidates:
        return False
    if _subset_contains(normalised, candidates):
        return True

    # Order-free pass. Only reached when the order-preserving raw pass above
    # misses. Reuses advance_reassembly_state rather than adding permutation
    # logic: it is already order-independent and piece-bounded (see its own
    # docstring), and a throwaway state dict here scopes it to this round
    # alone, never touching session state. advance_reassembly_state also
    # runs its own digits-only pass internally for all-digit sources, so
    # this single call covers an out-of-order numeric split too.
    if _order_free_reassembles(values, candidates):
        return True

    # Digits-only projection. Only reached when both passes above miss,
    # which costs a second full subset enumeration; what keeps the common
    # case cheap is `not candidates` above and `not numeric` below, since a
    # round with no matching source at all, or with only alphanumeric
    # sources, returns before either enumeration runs twice. Restricted to
    # sources that are themselves all-digit: projecting an alphanumeric
    # identifier would discard the letters that make the match meaningful,
    # so those keep relying on the raw pass.
    numeric = {source for source in candidates if source.isdigit()}
    if numeric:
        projected = ["".join(c for c in v if c.isdigit()) for v in normalised]
        if any(projected) and _subset_contains(projected, numeric):
            return True

    # Alphanumeric-run projection, the direct analogue of the digits
    # projection for a source with a letter in it. Restricted to
    # non-numeric candidates: an all-digit source already gets both the raw
    # and digits-projected order-free passes above via
    # advance_reassembly_state, so extracting alnum runs from it would only
    # rediscover the same digit runs at extra cost. Order-free from the
    # start, unlike the raw and digits passes: a run-projected round has no
    # natural "job order" once a single value can contribute several runs,
    # so there is no cheap order-preserving check to try first.
    alnum_candidates = {source for source in candidates if not source.isdigit()}
    if alnum_candidates:
        runs = [run for v in values for run in _alnum_runs(v)]
        if runs and _order_free_reassembles(runs, alnum_candidates):
            return True

    return False


# Plain coverage is not enough: state never forgets across a session, so a
# long enough benign session eventually covers some workspace source by
# coincidence. REASSEMBLY_PIECE_BOUND caps how many distinct pieces a
# covering may use before it counts as completion, reducing false blocking
# without eliminating it -- the rate depends on the caller's own answer
# distribution too. An attacker who splits into more pieces than this
# evades the check entirely, at the cost of one job and one round per extra
# piece, and remains guarded round by round on the way out regardless. See
# CLAUDE.md's "Known weaknesses" for the bound's derivation and the
# measured false-block rates.
REASSEMBLY_PIECE_BOUND = 5


def _min_pieces(edges: set[tuple[int, int]], target: int) -> int | None:
    """Fewest edges needed to reach `target` from position 0.

    `edges` is a directed graph on integer positions 0..target, where an
    edge (start, end) means some released value matched source[start:end]
    exactly. Every edge costs one piece, so plain BFS (not Dijkstra; no
    weights to relax) finds the shortest path in edge count. Returns None
    if `target` is not reachable from 0 with the edges given.

    O(V + E) per call: V is at most len(source) + 1 and E is bounded by
    _fold_source_edges' own bound, so this stays polynomial in source
    length and released-value count, never exponential in either.
    """
    if target == 0:
        return 0
    adjacency: dict[int, list[int]] = {}
    for start, end in edges:
        adjacency.setdefault(start, []).append(end)
    visited = {0}
    frontier: deque[tuple[int, int]] = deque([(0, 0)])
    while frontier:
        pos, hops = frontier.popleft()
        for nxt in adjacency.get(pos, ()):
            if nxt == target:
                return hops + 1
            if nxt not in visited:
                visited.add(nxt)
                frontier.append((nxt, hops + 1))
    return None


def _fold_source_edges(
    state: dict[str, set[int]], source: str, values: list[str], key: str | None = None
) -> int | None:
    """Discover new value/source matches and return the cheapest covering.

    `state[key]` (key defaults to `source`) holds a set of integers that
    each encode one discovered (start, end) edge: some released value
    matched source[start:end] exactly, packed as `(start << 32) | end` so a
    directed edge with two endpoints fits the `set[int]` shape without a
    second collection. Each new value is matched against every position it
    occurs at in `source` (there may be none, one, or several); every match
    is folded into the edge set, old and new together, and
    _min_pieces then finds the fewest edges needed to span the whole
    source, or None if it cannot be spanned yet.

    Order-independent by construction, same as the interval-merge design
    this replaces: an edge is recorded by where it sits in `source`, not by
    what already connects to it, so a value released before the piece that
    would make it reachable is not discarded, only added, and a later value
    can still complete a path through it.

    Shared by advance_reassembly_state's raw pass and its digits-only
    projection pass; `key` lets the digit pass keep a separate edge set from
    the raw pass under the same source, since the two passes match different
    projections of the same values.

    Bounded, not growing with how many values have been folded in: distinct
    (start, end) pairs for one source are capped by that source's own
    length (at most roughly len(source) choose 2), so flooding a session
    with many more values than the source has characters cannot grow this
    past that geometric ceiling. State size tracks identifier length, not
    session length.
    """
    state_key = key if key is not None else source
    edges = {(code >> 32, code & 0xFFFFFFFF) for code in state.get(state_key, set())}
    for value in values:
        if not value or len(value) > len(source):
            continue
        start = 0
        while True:
            idx = source.find(value, start)
            if idx == -1:
                break
            edges.add((idx, idx + len(value)))
            start = idx + 1
    state[state_key] = {(s << 32) | e for s, e in edges}
    return _min_pieces(edges, len(source))


def advance_reassembly_state(
    state: dict[str, set[int]], values: list[str], sources: set[str]
) -> bool:
    """Fold newly released values into per-source reachability.

    Mutates state. Returns True when any source has become reconstructible
    from at most REASSEMBLY_PIECE_BOUND distinct pieces of everything
    released this session, not just this round: reassembles_identifier
    only bounds one round, so a caller spreading one fragment per round
    needs state carried between calls, which is what this tracks.

    Order-independent and tiling, not overlap: records every discovered
    value/source match as a directed edge between two positions in the
    source, then finds the cheapest (fewest-edge) path across them, so a
    covering is always an exact concatenation of whole values regardless
    of release order. Applied twice per source (raw values, and, for an
    all-digit source, their digits-only projection) and bounded without an
    exponential term: the edge set for one source is capped by that
    source's own length squared, not by session length.

    See CLAUDE.md's "Known weaknesses" for why order-independence needs an
    edge graph rather than a prefix walk, the piece bound's derivation, and
    what remains open.
    """
    completed = False
    normalised = [normalise_identifier(v) for v in values]
    projected = ["".join(ch for ch in v if ch.isdigit()) for v in normalised]
    for source in sources:
        if not source:
            continue
        # A source already whole inside one of this round's own values is
        # reassembles_identifier's exclusion too ("not any(source in v for v
        # in normalised)"): a source that one released value already
        # carries in full is the per-job guard's business, not a reassembly
        # finding. Without this, a single value equal to a source on a
        # session's very first round -- no prior state, nothing to combine
        # with -- still returned True here, and run_jobs' block message
        # ("combine with values released earlier in this session") was then
        # wrong about a round with no earlier rounds at all.
        if any(source in v for v in normalised):
            continue
        pieces = _fold_source_edges(state, source, normalised)
        if pieces is not None and pieces <= REASSEMBLY_PIECE_BOUND:
            completed = True
        if source.isdigit():
            digit_pieces = _fold_source_edges(
                state, source, projected, key="digits:" + source
            )
            if digit_pieces is not None and digit_pieces <= REASSEMBLY_PIECE_BOUND:
                completed = True
    return completed


MAX_JOBS_PER_ROUND = 12

# Grammar-constrained shapes for extraction jobs. Asked for a number in prose,
# a small model returns the number along with whatever sat beside it on the
# form, and on a W-2 what sits beside box 1 is the employer EIN. The guard then
# correctly withholds the whole answer and a legitimate figure is lost.
# Constraining the decoder makes that class of answer unrepresentable rather
# than merely discouraged.
JOB_SHAPES: dict[str, dict[str, Any]] = {
    "number": {
        "type": "object",
        "properties": {"value": {"type": "number"}},
        "required": ["value"],
    },
    "digits": {
        "type": "object",
        "properties": {"value": {"type": "string", "pattern": "^[0-9-]{1,20}$"}},
        "required": ["value"],
    },
    "line": {
        "type": "object",
        "properties": {"value": {"type": "string", "maxLength": 80}},
        "required": ["value"],
    },
}

JOB_PROMPT = """You are reading one document and answering one narrow question
about it. Do not plan, do not choose tools, do not refer to other documents.

Document:
{document}

Question: {instruction}

Reply with the answer only. If the document does not contain it, reply exactly:
NOT PRESENT
"""


def fill_field(sandbox: Sandbox, name: str, field: str, value: str) -> str:
    """Replace the text after "field:" in a document, in place.

    Used by jobs that move a value from one local document into another
    without returning it. A taxpayer's SSN belongs on their 1040 and nowhere
    near the caller, and there is no reason those two facts should conflict.
    """
    body = sandbox.read_text(name)
    pattern = re.compile(rf"^(\s*{re.escape(field)}\s*:).*$", re.M)
    if not pattern.search(body):
        raise SandboxError(f"no field {field!r} in that document")
    sandbox.write_text(name, pattern.sub(rf"\1 {value}", body, count=1))
    return field


def run_jobs(
    session: Session, jobs: list[dict[str, Any]], on_step: StepCallback | None = None
) -> dict[str, Any]:
    """Execute independent single-shot jobs, one document each, then guard.

    The decompose-execute-aggregate shape from the Minions protocol (Narayan
    et al., ICML 2025), where a 3B local model reaches 93.4% of cloud-only
    accuracy against 87% for a chat protocol. The agent loop this replaces
    asked one small model to choose an action, choose a path, carry state
    across turns and do arithmetic in a single call. Each job here asks it for
    exactly one fact from exactly one document, with no history and no tools.

    Two deliberate departures from the paper, both for privacy:

    Jobs are structured data, never code. MinionS has the remote model emit
    Python to build jobs. The remote model here is the untrusted party and
    must never have code executed on its behalf.

    The concatenation of a round is guarded, not only each result. Splitting a
    protected value across jobs is a leak that the undivided protocol cannot
    have: "912", "84" and "7731" each pass, and reassemble on the caller's
    side into an SSN.
    """

    def note(action: str, detail: str) -> None:
        if on_step:
            on_step(action, detail)

    if not jobs:
        return envelope(session, "blocked", "", ["no jobs supplied"])
    if len(jobs) > MAX_JOBS_PER_ROUND:
        # A cap, because many narrow questions are how a caller fishes for a
        # value the guard would refuse to release in one piece.
        return envelope(
            session, "blocked", "",
            [f"too many jobs in one round: {len(jobs)} exceeds {MAX_JOBS_PER_ROUND}"],
        )

    truncated_marker = f"... truncated at {MAX_LISTING_ENTRIES}"
    try:
        documents = sorted(
            name
            for name in session.sandbox.list_dir(".")
            if not name.endswith("/") and name != truncated_marker
        )
    except SandboxError as exc:
        # The concern is a FIXED string, never str(exc): a SandboxError can
        # carry a filename and an absolute host path (see the read failure
        # below, which definitely does), and the caller never referenced
        # either. Per CLAUDE.md the receipt describes what airlock did, never
        # what it found. The full detail still goes to the operator, on
        # stderr only, since stdout is the JSON-RPC channel in serve mode.
        err_console.print(
            Text.assemble(("  │ cannot list workspace: ", "bold red"), (str(exc), "dim"))
        )
        return envelope(session, "blocked", "", ["the workspace could not be listed"])

    # Snapshotted here, before any job runs, not after the loop: a job can
    # fill_field mid-round (reachable with --allow-writes) and overwrite the
    # very document a fragment came from, erasing the evidence a post-loop
    # scan would need. The identifiers present when the round began are
    # exactly the ones its jobs could have extracted from, so this is the
    # correct reading, not only the safer one.
    try:
        sources = source_identifiers(session.sandbox)
    except SandboxError as exc:
        # Same reasoning as the list failure above: source_identifiers reads
        # every document, so exc here routinely contains a filename the
        # caller never referenced and its absolute host path, e.g.
        # "Cannot read medical_records_2026.txt: [Errno 13] ... '/private/
        # var/.../medical_records_2026.txt'". That is exactly the class of
        # leak CLAUDE.md names by example. Fixed string outbound; detail to
        # the operator only.
        err_console.print(
            Text.assemble(("  │ cannot read workspace: ", "bold red"), (str(exc), "dim"))
        )
        return envelope(session, "blocked", "", ["a workspace document could not be read"])

    results: list[dict[str, Any]] = []
    for index, job in enumerate(jobs):
        doc_index = job.get("document")
        instruction = str(job.get("extract", "")).strip()
        target = job.get("into")
        field = str(job.get("field", "")).strip()
        literal = job.get("value")

        # A literal supplied by the caller: its own text, so nothing to guard
        # on the way in, and no source document to validate. Still bounded by
        # the sandbox on the way out.
        if literal is not None and isinstance(target, int):
            if not 0 <= target < len(documents) or not field:
                results.append({"job": index, "status": "error",
                                "detail": "value needs a valid into and field"})
                continue
            try:
                fill_field(session.sandbox, documents[target], field, str(literal))
            except SandboxError as exc:
                results.append({"job": index, "status": "error", "detail": str(exc)})
                continue
            note("write", f"{field} into document {target}")
            results.append({"job": index, "status": "filled", "field": field})
            continue

        if not isinstance(doc_index, int) or not 0 <= doc_index < len(documents):
            results.append({"job": index, "status": "error",
                            "detail": f"no document {doc_index}"})
            continue
        if not instruction:
            results.append({"job": index, "status": "error", "detail": "empty extract"})
            continue

        name = documents[doc_index]
        note("read", name)
        try:
            body = session.sandbox.read_text(name)
        except SandboxError as exc:
            results.append({"job": index, "status": "error", "detail": str(exc)})
            continue

        shape = JOB_SHAPES.get(str(job.get("as", "")).lower())
        try:
            answer = ollama_chat(
                session.worker_model,
                JOB_PROMPT.format(document=body, instruction=instruction),
                shape,
            )
            if shape is not None:
                if not isinstance(answer, dict) or "value" not in answer:
                    results.append({"job": index, "status": "error",
                                    "detail": "model ignored the requested shape"})
                    continue
                answer = answer["value"]
        except RuntimeError as exc:
            results.append({"job": index, "status": "error",
                            "detail": f"local model failed: {exc}"})
            continue

        answer = str(answer).strip()

        # Fill mode. The value goes straight from one local document into
        # another and is never returned, so the guard has nothing to inspect
        # and the caller learns only that the field was filled.
        if isinstance(target, int) and field:
            # Never write the not-found sentinel into a document. Reporting
            # "filled" for a field now containing NOT PRESENT is worse than
            # reporting failure: the caller believes a form is complete and
            # cannot look at it to find out otherwise.
            if not answer or answer.upper().startswith("NOT PRESENT"):
                note("refused", f"{field}: not found in that document")
                results.append({"job": index, "status": "not_found", "field": field})
                continue
            if not 0 <= target < len(documents):
                results.append({"job": index, "status": "error",
                                "detail": f"no document {target}"})
                continue
            try:
                fill_field(session.sandbox, documents[target], field, answer)
            except SandboxError as exc:
                results.append({"job": index, "status": "error", "detail": str(exc)})
                continue
            note("write", f"{field} into document {target}")
            results.append({"job": index, "status": "filled", "field": field})
            continue

        # Same failure the fill-mode branch above already guards against:
        # the worker found nothing to extract. An empty string trips none of
        # the four guard layers, so handing it to evaluate_session would get
        # a trivial approve and release status=="ok" with an empty value --
        # the same "the guard approved this text" standing in for "the
        # operation succeeded" conflation run_worker's step-exhaustion path
        # has below. not_found, matching the vocabulary above, rather than a
        # guarded, empty "ok".
        if not answer or answer.upper().startswith("NOT PRESENT"):
            note("refused", f"job {index}: not found in that document")
            results.append({"job": index, "document": doc_index, "status": "not_found"})
            continue

        verdict = evaluate_session(session, answer)
        if verdict.approved:
            note("approved", f"job {index}")
            results.append({"job": index, "document": doc_index,
                            "status": "ok", "value": answer})
        else:
            session.blocked += 1
            note("blocked", f"job {index}: {'; '.join(verdict.concerns)[:60]}")
            results.append({"job": index, "document": doc_index, "status": "withheld",
                            "detail": sanitise_concerns(verdict.concerns)})

    # The round as a whole. Individually harmless fragments become an
    # identifier once the caller puts them back together. Two independent
    # checks, since each catches what the other misses: evaluate_session
    # catches semantic reassembly with no fixed identifier, and the
    # source-anchored check below catches a workspace identifier
    # reconstructed from job results even when scattered among benign ones,
    # which evaluate_session's shape-based scanners need adjacent to see.
    combined = " ".join(str(r.get("value", "")) for r in results)
    round_verdict = evaluate_session(session, combined) if combined.strip() else None
    released = [str(r["value"]) for r in results if r.get("status") == "ok"]
    reassembled = reassembles_identifier(released, sources)

    if reassembled or (round_verdict is not None and not round_verdict.approved):
        note("blocked", "the round reassembles into protected content")
        session.blocked += 1
        return envelope(
            session, "blocked", "",
            ["the results are individually safe but reassemble into protected "
             "content, so the whole round was withheld"],
        )

    # Cross-round reassembly. reassembles_identifier above only bounds this
    # round; advance_reassembly_state carries state across rounds instead,
    # keyed by source identifier so its cost tracks the workspace, not
    # session length. Any error here blocks rather than approves: a check
    # that cannot run must never stand in for one that ran and passed.
    #
    # Snapshot/restore around the call: a round that blocks below releases
    # nothing, so its fragments must not be recorded as released either.
    # See CLAUDE.md's "Known weaknesses" ("A blocked round used to poison
    # the rest of the session") for the incident this fixed, and
    # test.py's _cross_wiring_blocked_round_does_not_poison_state check.
    snapshot = {k: set(v) for k, v in session.reassembly_state.items()}
    try:
        session_reassembled = advance_reassembly_state(
            session.reassembly_state, released, sources
        )
    except Exception:  # noqa: BLE001 - a tracking failure must not approve by default
        session_reassembled = True

    if session_reassembled:
        session.reassembly_state = snapshot
        note("blocked", "the round completes a reassembly begun in an earlier round")
        session.blocked += 1
        return envelope(
            session, "blocked", "",
            ["the results are individually safe but combine with values "
             "released earlier in this session to reconstruct protected "
             "content, so the whole round was withheld"],
        )

    session.exchanges += 1
    trace("jobs", session=session.session_id, count=len(jobs),
          withheld=sum(1 for r in results if r.get("status") == "withheld"))
    return {
        "session": session.session_id,
        "status": "ok",
        "results": results,
        "note": (
            "Each value was guarded on its own and the round was guarded as a "
            "whole. Withheld entries carry no content."
        ),
    }


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
    # Whether any "read" step actually succeeded, tracked so the caller can
    # tell a grounded answer from a fabricated one (a clean-context tester's
    # finding: a wrong answer or a misreported permission error is
    # indistinguishable from a correct one otherwise, since the guard checks
    # disclosure, not correctness). Set only on a successful read, never on
    # an attempted one: a SandboxError raised by read_text below is caught
    # before this line runs, so a failed read leaves grounded exactly as it
    # was, which is the point.
    grounded = False
    # Signatures of sandbox actions already run this session, so a repeat can
    # be recognised and short-circuited without re-running the sandbox call
    # (it still costs the step -- `continue` consumes a loop iteration the
    # same as any other turn; see the in-loop comment below): a 0.8B worker
    # measured spending its entire step budget on eight identical `list`
    # calls, never reaching an answer it already had after the first one.
    seen_actions: set[tuple[str, str | None, str | None]] = set()
    try:
        listing = "\n".join(session.sandbox.list_dir(".")) or "(empty)"
    except SandboxError as exc:
        listing = f"(unavailable: {exc})"

    for _ in range(MAX_WORKER_STEPS):
        # The file list is given rather than discovered. The caller is not
        # allowed to know these names, but the worker can already see them, so
        # making it spend a step on `list` buys nothing and costs a step it
        # does not have. A 0.8B worker observed spending its entire budget
        # listing the same directory never reached the question at all.
        prompt = WORKER_PROMPT.format(
            files=listing,
            objective=session.objective,
            question=question,
            history="\n".join(history) if history else "(nothing yet)",
        )
        try:
            step = ollama_chat(session.worker_model, prompt, WORKER_SCHEMA)
        except RuntimeError as exc:
            return envelope(session, "blocked", "", [f"local model failed: {exc}"], grounded)
        if not isinstance(step, dict):
            return envelope(session, "blocked", "", ["local model returned bad output"], grounded)

        # Hand-rolled dispatch rather than Ollama's native tool calling, for
        # the reliability reason documented on ollama_chat above.
        action = str(step.get("action", "")).lower()

        # A repeated action is fed back as input, the same way sandbox
        # refusals already are, rather than executed again: the model already
        # has this result in history and gains nothing from a second copy of
        # it, only a step closer to running out.
        #
        # Wrapped in its own try: "path"/"query" are schema-suggested, not
        # enforced, and a dict or list there makes `signature` unhashable.
        # Unwrapped, that TypeError used to escape run_worker instead of
        # returning the block envelope every other malformed-step path here
        # does. See CLAUDE.md's "fail closed" rule for the full incident.
        try:
            signature = (action, step.get("path"), step.get("query"))
            if action in {"list", "read", "search", "write"} and signature in seen_actions:
                note("repeated", f"{action} {step.get('path') or step.get('query') or ''}".strip())
                result = (
                    f"you already ran {action} with these exact arguments; the result "
                    "is already above in what you have done so far. Do not repeat it: "
                    "answer the question now with what you already know."
                )
                history.append(f"{action} -> {result[:600]}")
                continue
            seen_actions.add(signature)
        except TypeError:
            return envelope(
                session, "blocked", "", ["local model returned a malformed step"], grounded
            )

        try:
            if action == "list":
                target = step.get("path", ".")
                note("list", target)
                result = "\n".join(session.sandbox.list_dir(target))
            elif action == "read":
                target = step.get("path", "")
                note("read", target)
                result = session.sandbox.read_text(target)
                grounded = True
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
                if draft:
                    break
                # Schema-valid and useless: only "action" is required, so a
                # small model can emit {"action": "answer"} with no text and
                # end the run with nothing. Feed the mistake back instead of
                # dead-ending, the same way sandbox refusals are handled.
                note("refused", "empty answer")
                result = "your answer field was empty. Put the reply text in it."
            else:
                result = f"unknown action: {action}"
        except SandboxError as exc:
            # Sandbox refusals are fed back as input so the model can correct
            # course, rather than raised so the run dies.
            note("refused", str(exc))
            result = f"refused: {exc}"
        history.append(f"{action} -> {result[:600]}")
    else:
        # Step budget exhausted with no answer. This must not fall through to
        # the guard: a fixed, code-written fallback string is not model
        # output, but it is well-formed prose, and the guard would correctly
        # approve it as harmless, at which point the caller reads
        # status=="approved" as "the operation succeeded" when the worker
        # never actually answered at all. That conflation is the bug, not
        # anything the guard does; block here, the same way an explicit empty
        # answer already does one line below, rather than let a "the guard
        # approved this text" result stand in for "the operation succeeded".
        return envelope(
            session, "blocked", "",
            ["the local model could not finish within the allowed number of "
             "steps and produced no answer"],
            grounded,
        )

    if not draft:
        return envelope(
            session, "blocked", "", ["the local model produced no answer"], grounded
        )

    # Concerns from the previous revise verdict, to notice when a revision
    # changed nothing.
    previous_concerns: list[str] | None = None
    for attempt in range(MAX_REVISIONS):
        note("guard", f"checking (attempt {attempt + 1})")
        verdict = evaluate_session(session, draft)
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
            return envelope(session, "approved", draft, [], grounded)
        if verdict.decision == "block":
            session.blocked += 1
            note("blocked", "; ".join(verdict.concerns))
            return envelope(session, "blocked", "", verdict.concerns, grounded)

        # The same rejection reason twice in a row means the last revision
        # did not change anything the guard cares about, most often because
        # the answer's whole point was the withheld content (naming a file
        # the operator cannot know exists, for example): no rewording fixes
        # that, so the remaining revisions would just repeat this. Stop here
        # rather than spend them, and say plainly why, without repeating what
        # was withheld: the message must not name the file, path, or content,
        # so sanitise_concerns (via envelope) never sees them either.
        if previous_concerns is not None and set(verdict.concerns) == set(previous_concerns):
            session.blocked += 1
            note("blocked", "repeated guard rejection")
            return envelope(
                session, "blocked", "",
                ["the question cannot be answered without disclosing content "
                 "the guard withholds, and revising the answer did not change "
                 "that"],
                grounded,
            )
        previous_concerns = verdict.concerns

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
            return envelope(session, "blocked", "", [f"revision failed: {exc}"], grounded)
        if isinstance(revised, dict):
            draft = str(revised.get("answer", "")).strip() or draft

    session.blocked += 1
    return envelope(
        session, "blocked", "", ["could not produce a message passing the guard"], grounded
    )


def sanitise_concerns(concerns: list[str]) -> list[str]:
    """Strip guard explanations that quote the content they objected to.

    Concerns from the model layer are free text the guard model wrote, and a
    helpful model explains itself: "the message reveals the email
    alice@example.com". Returning that verbatim means the guard leaks exactly
    what it just blocked, on the block path, which is the one path where
    nothing is supposed to get out. Found by testing the envelope directly.

    Each concern is re-checked with the same deterministic detectors that
    inspect outbound messages. Anything that trips them is replaced rather
    than redacted in place, because partial redaction of a sentence still
    leaks its shape.
    """
    safe: list[str] = []
    for concern in concerns:
        if scan_secrets(concern) or scan_pii_patterns(concern):
            safe.append("withheld: the explanation itself contained sensitive content")
        else:
            safe.append(concern)
    return safe


def envelope(
    session: Session, status: str, message: str, concerns: list[str],
    grounded: bool = False,
) -> dict[str, Any]:
    """Build the structured reply, stating plainly when content was withheld.

    The single choke point for anything leaving for the caller, which is why
    concern sanitising happens here rather than at each call site.

    grounded reports whether the worker successfully read anything from the
    workspace before producing this message. It is an operation fact, not a
    content-derived one (CLAUDE.md's receipt invariant): it says nothing
    about which files, how many, or what they contained, only whether at
    least one read actually succeeded. Default False so call sites that never
    read anything (a malformed step, a listing failure) do not need to pass
    it explicitly.
    """
    return {
        "session": session.session_id,
        "status": status,
        "message": message,
        "withheld": bool(concerns),
        "guard_concerns": sanitise_concerns(concerns),
        "grounded": grounded,
        "counters": {
            "exchanges": session.exchanges,
            "revisions": session.revisions,
            "blocked": session.blocked,
        },
        "note": (
            "This reply passed a local privacy guard: the content was judged "
            "safe to disclose. That is not a guarantee it is accurate -- the "
            "guard checks disclosure, not correctness. Content may also have "
            "been generalised or withheld."
        ),
    }


# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------

STEP_STYLE: dict[str, tuple[str, str]] = {
    "list": ("list", "cyan"),
    "read": ("read", "cyan"),
    "search": ("search", "cyan"),
    "write": ("WRITE", "bold yellow"),
    "refused": ("refused", "yellow"),
    "guard": ("guard", "dim"),
    "revise": ("revise", "yellow"),
    "approved": ("approved", "green"),
    "blocked": ("BLOCKED", "bold red"),
}


def print_step(action: str, detail: str) -> None:
    """Render one worker step as a dim status line."""
    label, style = STEP_STYLE.get(action, (action, "dim"))
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
                # lean: the guard is now two fixed encoders, not a selectable
                # model, so there is nothing session-specific left to print
                # here beyond the layer names themselves. A real per-layer
                # status (loaded, threshold in use) is doctor/config screen
                # territory, not this banner's.
                Text.assemble(
                    ("layers     ", "dim"),
                    ("secrets + pii-patterns + pii-detector + policy-linter", "magenta"),
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

    # First, unconditionally: a bug report needs a revision to reference,
    # and this is the one line here that cannot itself fail.
    check("version", True, __version__)

    try:
        sandbox = Sandbox(root=args.root, allow_writes=args.allow_writes)
        counts = sandbox.stats()
        check("workspace", True, f"{sandbox.root} ({counts['files']} files)")
    except (SandboxError, FileNotFoundError) as exc:
        check("workspace", False, str(exc))
        return 1

    # The MCP SDK is only imported by `serve`, so every other subcommand works
    # even when the dependency cannot resolve. That is convenient and it also
    # means a broken pin stays invisible until the moment you try to serve,
    # which is the worst time to find out. Report it here instead.
    sdk = installed_version("mcp")
    if sdk:
        # No rich markup in a check() detail: it is rendered through
        # Text.assemble, which prints tags literally rather than parsing them.
        # The detail is already styled dim by check itself.
        check("mcp sdk", True, f"mcp {sdk} (pin this version)")
    else:
        check(
            "mcp sdk",
            False,
            "not installed. Only `serve` needs it, so the rest of airlock still works",
        )

    # The guard's model layers are two local encoders now, not an Ollama
    # tag, so what is worth checking changed completely: importability,
    # loadability, the selected device, and a real verdict from each on a
    # fixed probe. trust_remote_code=True model repos are fetched from
    # Hugging Face the first time either encoder loads, so that is stated
    # before it happens, not discovered mid-download.
    def encoder_cached(repo_id: str, revision: str) -> bool | None:
        try:
            from huggingface_hub import try_to_load_from_cache
        except ImportError:
            return None  # cannot tell; huggingface_hub itself unavailable
        return isinstance(
            try_to_load_from_cache(repo_id, "config.json", revision=revision), str
        )

    try:
        import torch as _torch
        import transformers as _transformers

        torch_ok = check(
            "torch/transformers importable",
            True,
            f"torch {_torch.__version__}, transformers {_transformers.__version__}",
        )
    except ImportError as exc:
        torch_ok = check("torch/transformers importable", False, str(exc))
    if not torch_ok:
        ok = False
    else:
        missing = [
            name
            for name, cached in (
                ("the PII detector", encoder_cached(PII_DETECTOR_MODEL, PII_DETECTOR_REVISION)),
                ("the policy linter", encoder_cached(POLICY_LINTER_MODEL, POLICY_LINTER_REVISION)),
            )
            if cached is False
        ]
        if missing:
            console.print(
                f"       [dim]first run downloads {' and '.join(missing)} from Hugging "
                "Face, roughly 350MB each (~700MB total). This happens once and can "
                "take a while[/dim]"
            )

        device = resolve_device()
        check("device", True, device)

        try:
            _load_pii_detector()
            check("PII detector loadable", True, f"device={device}")
        except GuardModelUnavailable as exc:
            check("PII detector loadable", False, str(exc))
            ok = False

        try:
            _load_policy_linter()
            check("policy linter loadable", True, f"device={device}")
        except GuardModelUnavailable as exc:
            check("policy linter loadable", False, str(exc))
            ok = False

        if ok:
            # Fixed probes, not the "blocks a credential/person" cases below:
            # those exercise the whole evaluate() stack, these confirm each
            # encoder on its own returns a real, expected verdict rather than
            # merely having loaded. Same literals as SSN_TEXT/MEDICAL_TEXT in
            # test.py, already measured there to trigger
            # an identity finding and rule0 respectively.
            try:
                rules = {f["rule"] for f in scan_pii_model("My social security number is 912-84-7731.")}
                passed = any(r.split(".")[0] == "identity" for r in rules)
                if not check("PII detector probe", passed, ",".join(sorted(rules)) or "no findings"):
                    ok = False
            except GuardModelUnavailable as exc:
                check("PII detector probe", False, str(exc))
                ok = False

            try:
                rules = {
                    f["rule"]
                    for f in scan_policy(
                        "I was recently diagnosed with stage 2 breast cancer and "
                        "started chemotherapy last week."
                    )
                }
                passed = "rule0" in rules
                if not check("policy linter probe", passed, ",".join(sorted(rules)) or "no findings"):
                    ok = False
            except GuardModelUnavailable as exc:
                check("policy linter probe", False, str(exc))
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
                elif "-mlx" in args.model:
                    # This advisory used to recommend -mlx tags for speed.
                    # That advice was wrong for the worker: the MLX build of
                    # qwen3.5:0.8b ignores the JSON schema and breaks every
                    # step. Speed is worth nothing if the loop cannot run.
                    console.print(
                        "       [dim]worker is an -mlx tag; MLX builds have been "
                        "observed ignoring JSON schemas. The check below is the "
                        "one that matters[/dim]"
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
        """Whether this exact tag is installed.

        Matched case-insensitively, because tags are pulled with whatever
        casing the user typed and qwen3.5:0.8B and qwen3.5:0.8b are the same
        model. An implicit :latest is treated as equivalent to the bare name.

        Previously this compared only the family before the colon, so any
        sibling satisfied it: qwen3.5:99b-nonexistent reported as present
        because qwen3.5:0.8B was installed. That turned a missing model into
        a confusing failure later instead of a clear one here.
        """
        names = {m.lower() for m in installed}
        want = tag.lower()
        return want in names or f"{want}:latest" in names or want.removesuffix(":latest") in names

    # Only the worker still runs on Ollama; the guard is the two local
    # encoders checked (indirectly, via the evaluate() cases below) rather
    # than an installed Ollama tag.
    if not check("worker model", has(args.model), args.model):
        ok = False
        console.print(f"\n[dim]  ollama pull {args.model}[/dim]")

    # The worker has to emit JSON matching WORKER_SCHEMA, and nothing above
    # checks that it can.
    if ok:
        try:
            probe = ollama_chat(
                args.model,
                "Reply with the action 'answer' and a one word answer.",
                WORKER_SCHEMA,
            )
            valid = isinstance(probe, dict) and "action" in probe
            if not check(
                "worker emits valid JSON",
                valid,
                "schema honoured" if valid else f"got {type(probe).__name__}: {str(probe)[:40]!r}",
            ):
                ok = False
                console.print(
                    "       [dim]this model is not honouring the JSON schema, so every "
                    "worker step will fail[/dim]"
                )
                console.print(
                    "       [dim]try a different tag: a larger model, or the non-mlx "
                    "build of the same one[/dim]"
                )
        except RuntimeError as exc:
            check("worker emits valid JSON", False, str(exc)[:70])
            ok = False

    if ok:
        cases = [
            ("blocks a credential", "my key is sk-abcdefghijklmnop1234", False),
            ("blocks a person", "Jane Doe lives in Springfield", False),
            ("allows safe text", "The folder contains twelve planning files.", True),
        ]
        for label, sample, should_pass in cases:
            verdict = evaluate(sample, args.linter_threshold)
            passed = verdict.approved == should_pass
            detail = f"{verdict.decision} via {' + '.join(verdict.layers_run)}"
            if not check(label, passed, detail):
                ok = False
                # Show why. Without this the operator sees only a decision and
                # has no way to tell a real detection from a broken dependency.
                for concern in verdict.concerns:
                    console.print(f"       [dim]{concern}[/dim]")
                if verdict.decision == "block":
                    # block is only reachable via GuardModelUnavailable now;
                    # the deterministic layers below it never block on their
                    # own, only revise or pass through.
                    console.print(
                        "       [dim]a guard encoder failed to load; see the "
                        "concern above[/dim]"
                    )

    console.print()
    console.print(
        "[bold green]Ready.[/bold green] Run [cyan]airlock <folder>[/cyan] to connect it "
        "to an assistant, or [cyan]airlock chat <folder>[/cyan] to ask it yourself."
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
        linter_threshold=args.linter_threshold,
    )


HELP_TEXT = """[bold]Commands[/bold]
  [cyan]/help[/cyan]      show this
  [cyan]/config[/cyan]    view and change settings: worker model, linter threshold, writes
  [cyan]/mcp[/cyan]       how to connect a cloud assistant to this workspace
  [cyan]/stats[/cyan]     session counters
  [cyan]/files[/cyan]     list the workspace
  [cyan]/guard[/cyan]     test text, e.g. /guard my ssn is 123-45-6789
  [cyan]/objective[/cyan] change the objective
  [cyan]/exit[/cyan]      quit

Ask anything else in plain language. The local model reads your files and
answers. Every answer is screened before it reaches you, and the same
screening applies when a cloud assistant asks through MCP."""


def read_key() -> str:
    """Read one keypress, decoding arrow keys, or "" if stdin is not a terminal.

    Uses termios directly rather than adding a dependency: this is the only
    place airlock needs raw input, and a menu is not worth a package. Returns
    "" when there is no terminal so callers can fall back to a numbered
    prompt, which is also what makes the config screen testable.
    """
    try:
        import termios
        import tty
    except ImportError:  # not POSIX
        return ""
    if not sys.stdin.isatty():
        return ""
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        char = sys.stdin.read(1)
        if char == "\x1b":  # escape sequence, possibly an arrow
            char += sys.stdin.read(2)
        return char
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


KEY_UP, KEY_DOWN = ("\x1b[A", "k"), ("\x1b[B", "j")

# What each setting does, shown for whichever row the cursor is on. Written to
# say what changes as a consequence, not what the field is named: someone
# opening this screen can already read the label.
SETTING_NOTES: dict[str, str] = {
    "worker": (
        "The local model that reads your files and drafts every answer. It must return "
        "JSON matching a fixed schema, and a model that cannot do that fails every step, "
        "so confirm with a question after changing it."
    ),
    "linter threshold": (
        "Score above which the policy linter's contextual rules revise a message. Lower "
        "catches more disclosures at the cost of more false positives. The PII detector's "
        "threshold and the per-rule overrides are constants, not adjustable here, until "
        "measured otherwise."
    ),
    "writes": (
        "Whether the local model may create or modify files in this workspace. Off by "
        "default. The sandbox boundary is unaffected either way: nothing outside the "
        "workspace is reachable."
    ),
    "trace": (
        "Appends every guard decision to a file as JSON lines, recording rule names and "
        "verdicts but never message content, so a trace can be reviewed or shared "
        "without leaking what the guard was protecting."
    ),
    "objective": (
        "The standing framing handed to the local model with every question. Steers what "
        "it looks for; it does not change what the guard permits."
    ),
}


def choose(
    title: str,
    rows: list[tuple[str, str]],
    footer: str = "",
    start: int = 0,
    notes: dict[str, str] | None = None,
) -> int | None:
    """Arrow-key picker. Returns the chosen index, or None if cancelled.

    Clears and redraws rather than rewinding counted lines, so any number of
    nested screens works. Assumes the caller has entered the alternate screen
    buffer. Falls back to a numbered prompt when there is no terminal.
    """
    notes = notes or {}
    if not sys.stdin.isatty():
        console.print(f"[bold]{title}[/bold]")
        for index, (label, value) in enumerate(rows, 1):
            console.print(f"  {index}. {label}  [dim]{value}[/dim]")
            if label in notes:
                console.print(f"       [dim]{notes[label]}[/dim]")
        answer = Prompt.ask("number, or blank to go back", default="")
        return int(answer) - 1 if answer.strip().isdigit() else None

    cursor = max(0, min(start, len(rows) - 1))
    # Reserve the description area so the list does not jump as the cursor
    # moves between a one-line note and a two-line one.
    note_lines = max((len(textwrap.wrap(n, 74)) for n in notes.values()), default=0)
    while True:
        sys.stdout.write("\x1b[H\x1b[J")  # home, then clear to end of screen
        console.print(f"[bold]{title}[/bold]\n")
        for index, (label, value) in enumerate(rows):
            mark = "[cyan]>[/cyan]" if index == cursor else " "
            style = "bold" if index == cursor else "dim"
            console.print(f" {mark} [{style}]{label:11}[/{style}] [dim]{value}[/dim]")
        if notes:
            console.print("")
            current = textwrap.wrap(notes.get(rows[cursor][0], ""), 74)
            for line in current:
                console.print(f"   [italic dim]{line}[/italic dim]")
            for _ in range(note_lines - len(current)):
                console.print("")
        if footer:
            console.print(f"\n[dim]{footer}[/dim]")
        console.print("\n[dim]up/down move, enter select, esc back[/dim]")
        sys.stdout.flush()

        key = read_key()
        if key in KEY_UP:
            cursor = (cursor - 1) % len(rows)
        elif key in KEY_DOWN:
            cursor = (cursor + 1) % len(rows)
        elif key in ("\r", "\n"):
            return cursor
        elif key in ("\x1b", "q", "\x03"):
            return None


def config_tui(session: Session, args: argparse.Namespace) -> None:
    """Interactive settings screen.

    Runs on the alternate screen buffer so the chat scrollback survives.
    Messages are collected as notices and printed after leaving, because
    anything written inside that buffer vanishes with it. Models are picked
    from what is installed rather than typed.
    """
    global TRACE_PATH
    notices: list[str] = []
    interactive = sys.stdin.isatty()
    if interactive:
        sys.stdout.write("\x1b[?1049h")  # enter alternate screen
        sys.stdout.flush()
    try:
        _config_loop(session, args, notices)
    finally:
        if interactive:
            sys.stdout.write("\x1b[?1049l")  # restore, chat history intact
            sys.stdout.flush()
    for notice in notices:
        console.print(notice)


def _config_loop(session: Session, args: argparse.Namespace, notices: list[str]) -> None:
    """The settings loop itself, separated so the screen is always restored."""
    global TRACE_PATH

    def models() -> list[str]:
        try:
            return sorted(ollama_models())
        except RuntimeError as exc:
            # A notice, not a print: anything written here is on the alternate
            # screen and disappears the moment the user leaves it.
            notices.append(f"[red]cannot list models:[/red] {exc}")
            return []

    def pick_model(label: str, current: str | None, allow_none: bool) -> Any:
        available = models()
        if not available:
            return False
        rows = [(m, "current" if m == current else "") for m in available]
        if allow_none:
            rows.append(("(none)", "current" if current is None else ""))
        # Open on the current value rather than the top of the list, so Enter
        # without moving is a no-op instead of a silent change.
        start = available.index(current) if current in available else len(rows) - 1
        index = choose(f"{label} model", rows, start=start)
        if index is None or not 0 <= index < len(rows):
            return False
        if allow_none and index == len(available):
            return None
        return available[index]

    cursor = 0
    while True:
        rows = [
            ("worker", session.worker_model),
            ("writes", "enabled" if session.sandbox.allow_writes else "disabled"),
            ("trace", str(args.trace) if args.trace else "off"),
            ("objective", session.objective[:44]),
            ("linter threshold", str(session.linter_threshold)),
        ]
        choice = choose(
            "settings",
            rows,
            footer=f"workspace {session.sandbox.root}  approval {args.approve}",
            start=cursor,
            notes=SETTING_NOTES,
        )
        if choice is None or not 0 <= choice < len(rows):
            return
        # Reopen where the user left off, so changing two settings does not
        # mean navigating from the top again.
        cursor = choice

        name = rows[choice][0]
        if name == "worker":
            picked = pick_model("worker", session.worker_model, allow_none=False)
            if picked and picked != session.worker_model:
                session.worker_model = args.model = picked
                notices.append(
                    f"[green]worker[/green] -> {picked}  [dim]ask something to confirm it "
                    "honours the JSON schema; installed and usable differ[/dim]"
                )
        elif name == "writes":
            if session.sandbox.allow_writes:
                session.sandbox.allow_writes = args.allow_writes = False
                notices.append("[green]writes disabled[/green]")
            elif Confirm.ask(
                "\n[yellow]Let the local model modify files in this workspace?[/yellow]",
                default=False,
            ):
                # Asked rather than toggled, because gaining the ability to
                # change the user's files is a capability change and should
                # not read like flipping a preference.
                session.sandbox.allow_writes = args.allow_writes = True
                notices.append(
                    "[yellow]writes enabled[/yellow] [dim]the local model can now modify "
                    "files in this workspace[/dim]"
                )
        elif name == "trace":
            entered = Prompt.ask("trace file, or blank for off", default="").strip()
            TRACE_PATH = args.trace = Path(entered).expanduser() if entered else None
        elif name == "objective":
            entered = Prompt.ask("objective", default=session.objective).strip()
            if entered:
                session.objective = entered
        elif name == "linter threshold":
            entered = Prompt.ask(
                "linter threshold (0.0-1.0)", default=str(session.linter_threshold)
            ).strip()
            try:
                value = float(entered)
            except ValueError:
                notices.append(f"[red]not a number:[/red] {entered!r}")
            else:
                if 0.0 <= value <= 1.0:
                    session.linter_threshold = args.linter_threshold = value
                    notices.append(f"[green]linter threshold[/green] -> {value}")
                else:
                    notices.append("[red]out of range:[/red] must be between 0.0 and 1.0")


# --------------------------------------------------------------------------
# MCP client configuration
# --------------------------------------------------------------------------
# Two families of MCP client need two different launch forms for the same
# command, not just cosmetic ones. Shell-launched clients (Claude Code,
# Codex, Gemini CLI) start as a child of the user's interactive shell and
# inherit its PATH, so the bare "airlock" name resolves for them exactly as
# it does in this process. GUI-launched clients (Claude Desktop, Cursor, VS
# Code, Zed) are started by the window manager/launchd, not a shell:
# verified on this machine, `launchctl getenv PATH` is empty, so a
# Dock-launched app gets the system default `/usr/bin:/bin:/usr/sbin:/sbin`,
# which contains neither `~/.local/bin` (uv tool install) nor
# `/opt/homebrew/bin` (Homebrew). A bare "airlock" in a GUI client's config
# is therefore a silent command-not-found there; only the resolved absolute
# path works.
_EPHEMERAL_PATH_MARKERS = {".venv", "venv", "build", "builds-v0", "tmp", "temp"}


def _looks_ephemeral(path: Path) -> bool:
    """True if `path` sits inside a venv, temp dir, or build cache.

    A resolution like that works only because the current process happens
    to be running inside it (an ephemeral `uv run --script` venv, a git
    worktree's own .venv, a uv build cache used to compile a wheel), not
    because a stable "airlock" install exists there. Checked by path
    component instead of an allowlist of known install prefixes, since uv
    tool install and Homebrew are not the only ways a package ends up on
    PATH, and naming what is known to be unstable is the more robust rule
    than naming everywhere considered stable.
    """
    parts = {p.lower() for p in path.parts}
    if parts & _EPHEMERAL_PATH_MARKERS:
        return True
    try:
        return path.is_relative_to(Path(tempfile.gettempdir()).resolve())
    except OSError:
        return False


def _airlock_launch_forms(script_path: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Decide how to launch airlock for shell- and GUI-launched MCP clients.

    Returns (shell_form, gui_form, reason). Each form is a
    {"command": str, "args": list[str]} launch prefix; a caller appends the
    `serve FOLDER --model ...` arguments after it.

    Prefers the installed "airlock" command, found through shutil.which,
    over the `uv run --script` fallback, since a name on PATH survives the
    checkout moving or being upgraded and a filesystem path does not. But
    shutil.which can resolve to a path that will not exist once this
    process exits, if this process happens to be running inside an
    ephemeral uv venv. Emitting that path into a client's config would
    register a command that works today and breaks silently on the next
    launch, so an ephemeral-looking resolution is treated the same as "not
    found": both forms fall back to `uv run --script <absolute path>`,
    which needs nothing installed beyond uv itself.

    The emitted GUI path is the one shutil.which reports, not its fully
    resolved target: `uv tool install` and Homebrew both put a stable
    symlink on PATH (`~/.local/bin/airlock`, `/opt/homebrew/bin/airlock`)
    pointing at an internal venv, and that symlink is the documented,
    recognisable location, not an implementation detail to dereference
    away. The ephemeral check still looks at both the symlink and what it
    points to, since either could turn out to be the doomed path.
    """
    fallback_args = ["run", "--script", str(script_path)]
    which_path = shutil.which("airlock")

    if which_path is None:
        reason = "'airlock' is not on PATH, falling back to uv run --script"
        form = {"command": "uv", "args": list(fallback_args)}
        return dict(form), dict(form), reason

    candidate = Path(which_path)
    if not candidate.is_absolute():
        candidate = candidate.resolve()

    if _looks_ephemeral(candidate) or _looks_ephemeral(candidate.resolve()):
        reason = (
            f"'airlock' resolved to {candidate}, which looks ephemeral (inside a "
            "venv, temp dir, or build cache) and may not exist later, falling "
            "back to uv run --script"
        )
        form = {"command": "uv", "args": list(fallback_args)}
        return dict(form), dict(form), reason

    reason = f"using the installed 'airlock' command, found on PATH at {candidate}"
    shell_form = {"command": "airlock", "args": []}
    gui_form = {"command": str(candidate), "args": []}
    return shell_form, gui_form, reason


# Client -> (which launch form it needs, which config schema it reads).
# Contracts as verified against each client's own docs: claude-code,
# claude-desktop, cursor and gemini-cli share the "mcpServers" JSON key;
# codex reads TOML under "mcp_servers", snake_case; vscode requires a
# "type": "stdio" field under "servers"; zed requires a "source": "custom"
# field under "context_servers". Extend this dict only after checking a
# client's real schema, not by guessing it matches one already here.
MCP_CLIENTS: dict[str, dict[str, str]] = {
    "claude-code": {"launch": "shell", "schema": "mcpServers"},
    "gemini-cli": {"launch": "shell", "schema": "mcpServers"},
    "codex": {"launch": "shell", "schema": "codex"},
    "claude-desktop": {"launch": "gui", "schema": "mcpServers"},
    "cursor": {"launch": "gui", "schema": "mcpServers"},
    "vscode": {"launch": "gui", "schema": "vscode"},
    "zed": {"launch": "gui", "schema": "zed"},
}


def _toml_str(value: str) -> str:
    """Minimal TOML basic-string quoting for the two fields codex needs.

    Command names and script paths never carry control characters or other
    TOML-special bytes, so this is not a general TOML writer, just enough of
    one for `command` and `args`. Adding a TOML-writing dependency for that
    would be the wrong trade per CLAUDE.md's dependency ladder; tomllib in
    the standard library only reads.
    """
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_client_config(client: str, form: dict[str, Any], server_args: list[str]) -> str:
    """Render one MCP client's config as text, in its own schema.

    `form` is a {"command", "args"} launch prefix from
    `_airlock_launch_forms`; `server_args` is the `serve FOLDER ...` tail
    appended after it.
    """
    command = form["command"]
    args = form["args"] + server_args
    schema = MCP_CLIENTS[client]["schema"]

    if schema == "codex":
        args_toml = ", ".join(_toml_str(a) for a in args)
        return (
            "[mcp_servers.airlock]\n"
            f"command = {_toml_str(command)}\n"
            f"args = [{args_toml}]\n"
        )
    if schema == "vscode":
        config = {"servers": {"airlock": {"type": "stdio", "command": command, "args": args}}}
    elif schema == "zed":
        config = {
            "context_servers": {
                "airlock": {"source": "custom", "command": command, "args": args}
            }
        }
    else:  # mcpServers: claude-code, claude-desktop, cursor, gemini-cli
        config = {"mcpServers": {"airlock": {"command": command, "args": args}}}
    return json.dumps(config, indent=2)


# Where each client keeps its MCP configuration, most specific first. Every
# path here was verified by looking for it on a real machine, not recalled;
# the ones that could not be checked directly are simply absent, which costs
# nothing because of the rule below.
#
# airlock only ever writes to a candidate that already exists, or whose
# parent directory already exists (which is itself evidence the client is
# installed and has a config directory). It never creates a directory tree.
# A path this table gets wrong therefore cannot produce a stray file in the
# wrong place; it degrades to "airlock could not find your config", which is
# a message, not damage.
CLIENT_CONFIG_PATHS: dict[str, list[str]] = {
    "claude-desktop": [
        "~/Library/Application Support/Claude/claude_desktop_config.json",
        "~/.config/Claude/claude_desktop_config.json",
        "~/AppData/Roaming/Claude/claude_desktop_config.json",
    ],
    "claude-code": ["~/.claude.json"],
    "cursor": ["~/.cursor/mcp.json"],
    "vscode": [
        "~/Library/Application Support/Code/User/mcp.json",
        "~/.config/Code/User/mcp.json",
        "~/AppData/Roaming/Code/User/mcp.json",
    ],
    "zed": ["~/.config/zed/settings.json"],
    "codex": ["~/.codex/config.toml"],
    "gemini-cli": ["~/.gemini/settings.json"],
}

CLIENT_LABELS: dict[str, str] = {
    "claude-desktop": "Claude Desktop",
    "claude-code": "Claude Code",
    "cursor": "Cursor",
    "vscode": "VS Code",
    "zed": "Zed",
    "codex": "Codex",
    "gemini-cli": "Gemini CLI",
}


def client_config_path(client: str) -> Path | None:
    """The config file airlock may write for this client, or None.

    Usable means the file exists, or its directory does. Creating a whole
    tree would mean guessing that a client is installed from nothing but a
    path this table happens to contain.
    """
    home = Path.home()
    for candidate in CLIENT_CONFIG_PATHS.get(client, []):
        path = Path(candidate).expanduser()
        if path.exists():
            return path
        # A config directory that exists is evidence the client is installed.
        # The home directory is not: it always exists, so this rule applied to
        # a dotfile sitting directly in $HOME (~/.claude.json) reported every
        # machine as having Claude Code installed.
        if path.parent.is_dir() and path.parent != home:
            return path
    return None


def installed_clients() -> list[str]:
    """Clients that look installed, in the order they are offered."""
    return [c for c in MCP_CLIENTS if client_config_path(c) is not None]


@dataclass
class Registration:
    """The result of writing (or planning to write) one client's config."""

    client: str
    path: Path
    action: Literal["added", "updated", "unchanged", "removed", "absent"]
    backup: Path | None = None


def _server_args(root: Path, args: argparse.Namespace) -> list[str]:
    """The `serve ...` tail a client is configured to run."""
    tail = ["serve", str(root), "--model", args.model]
    if getattr(args, "write", False):
        tail.append("--write")
    ask = getattr(args, "ask", "writes")
    if ask != "writes":
        tail += ["--ask", ask]
    if not getattr(args, "no_ui", False):
        tail.append("--ui")
    return tail


def airlock_launch_entry(root: Path, args: argparse.Namespace, client: str) -> dict[str, Any]:
    """The {"command", "args"} a client should run, in that client's flavour."""
    shell_form, gui_form, _ = _airlock_launch_forms(Path(__file__).resolve())
    form = gui_form if MCP_CLIENTS[client]["launch"] == "gui" else shell_form
    return {"command": form["command"], "args": form["args"] + _server_args(root, args)}


def _merge_json_config(text: str, client: str, entry: dict[str, Any] | None) -> str:
    """Add, replace or remove airlock inside one client's JSON config.

    Every other key in the file is preserved untouched, because this is
    somebody's live configuration and airlock is one entry in it.
    """
    schema = MCP_CLIENTS[client]["schema"]
    key = {"vscode": "servers", "zed": "context_servers"}.get(schema, "mcpServers")
    data = json.loads(text) if text.strip() else {}
    if not isinstance(data, dict):
        raise ValueError("config file is not a JSON object")
    servers = data.get(key)
    if not isinstance(servers, dict):
        servers = {}
    if entry is None:
        servers.pop("airlock", None)
    elif schema == "vscode":
        servers["airlock"] = {"type": "stdio", **entry}
    elif schema == "zed":
        servers["airlock"] = {"source": "custom", **entry}
    else:
        servers["airlock"] = dict(entry)
    if servers or entry is not None:
        data[key] = servers
    return json.dumps(data, indent=2) + "\n"


# Matches codex's own airlock block: the table header through to the next
# table header at the start of a line, or end of file. tomllib reads TOML and
# cannot write it, and a TOML writer is a dependency for one section of one
# file.
#
# Deliberately not "everything up to the next [". The block's own body
# contains one: `args = ["serve", ...]`. That version stopped the match in
# the middle of the args line, so replacing or removing airlock left the
# remainder of the array behind and the file no longer parsed as TOML.
_CODEX_BLOCK = re.compile(r"(?ms)^\[mcp_servers\.airlock\].*?(?=^\[|\Z)")


def _merge_toml_config(text: str, entry: dict[str, Any] | None) -> str:
    """Add, replace or remove codex's [mcp_servers.airlock] table."""
    if entry is None:
        return _CODEX_BLOCK.sub("", text).rstrip() + "\n"
    args_toml = ", ".join(_toml_str(a) for a in entry["args"])
    block = (
        "[mcp_servers.airlock]\n"
        f"command = {_toml_str(entry['command'])}\n"
        f"args = [{args_toml}]\n"
    )
    if _CODEX_BLOCK.search(text):
        return _CODEX_BLOCK.sub(lambda _: block, text, count=1)
    return (text.rstrip() + "\n\n" + block) if text.strip() else block


def write_client_config(
    client: str, root: Path, args: argparse.Namespace, remove: bool = False
) -> Registration:
    """Register or unregister airlock in one client's config file.

    Backs the file up before touching it. Writes through a temporary file in
    the same directory and replaces atomically, so an interrupted write
    cannot leave somebody's editor config truncated.
    """
    path = client_config_path(client)
    if path is None:
        return Registration(client, Path(), "absent")

    before = path.read_text() if path.exists() else ""
    entry = None if remove else airlock_launch_entry(root, args, client)
    if MCP_CLIENTS[client]["schema"] == "codex":
        after = _merge_toml_config(before, entry)
    else:
        after = _merge_json_config(before, client, entry)

    if after == before:
        return Registration(client, path, "unchanged")

    backup = None
    if path.exists():
        backup = path.with_suffix(path.suffix + ".airlock-backup")
        backup.write_text(before)
    tmp = path.with_suffix(path.suffix + ".airlock-tmp")
    tmp.write_text(after)
    tmp.replace(path)
    action = "removed" if remove else ("updated" if before.strip() else "added")
    return Registration(client, path, action, backup)


def render_mcp_help(args: argparse.Namespace) -> None:
    """Print ready-to-paste client configuration for this exact workspace.

    Shown because a user who has just started chatting has no way to
    discover that the same workspace can be served to a cloud assistant,
    and GUI clients need an absolute path, which is the detail people get
    wrong. See `_airlock_launch_forms` for why shell- and GUI-launched
    clients need different forms, and `airlock connect --client NAME --print`
    for a non-interactive way to get any one client's exact config.
    """
    root = Path(args.root).expanduser().resolve()
    shell_form, gui_form, reason = _airlock_launch_forms(Path(__file__).resolve())
    server_args = _server_args(root, args)

    gui_config = render_client_config("claude-desktop", gui_form, server_args)
    claude_code_cmd = (
        f"claude mcp add airlock -- {shell_form['command']} "
        f"{' '.join(shell_form['args'] + server_args)}"
    )

    console.print(
        Panel(
            Group(
                Text("Serve this workspace to a cloud assistant.", style="bold"),
                Text(f"airlock v{__version__}", style="dim"),
                Text(reason, style="dim"),
                Text(""),
                Text(
                    "Claude Desktop, Cursor, VS Code, Zed "
                    "(GUI-launched, need an absolute path):",
                    style="dim",
                ),
                Text(gui_config, style="cyan"),
                Text(""),
                Text(
                    "Claude Code, Codex, Gemini CLI (shell-launched, inherit PATH):",
                    style="dim",
                ),
                Text(claude_code_cmd, style="cyan"),
                Text(""),
                Text(
                    "Run 'airlock connect FOLDER --client NAME --print' for any "
                    "client's exact "
                    "schema, including codex's TOML and vscode/zed's own keys.",
                    style="dim",
                ),
                Text(""),
                Text(
                    "The assistant receives guarded answers, never your files. "
                    "It gets a receipt by default and must ask explicitly for content.",
                    style="dim",
                ),
            ),
            title="connect over MCP",
            border_style="magenta",
            padding=(1, 2),
        )
    )


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
    console.print(
        "[dim]Type /help for commands, /config for settings, /mcp to connect a "
        "cloud assistant, /exit to quit.[/dim]\n"
    )

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
            elif command == "/config":
                config_tui(session, args)
            elif command == "/mcp":
                render_mcp_help(args)
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
                verdict = evaluate_session(session, rest)
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
    verdict = evaluate(args.text, args.linter_threshold)
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


# --------------------------------------------------------------------------
# Approval policy
# --------------------------------------------------------------------------
# Two independent choices, flattened into one flag because they are always
# decided together: what needs approving (everything, or only calls that can
# alter files), and who does the asking.
APPROVE_MODES = ("gate-all", "gate-writes", "hint-all", "hint-writes", "none")


def installed_version(package: str) -> str:
    """Return an installed distribution's version, or "" if it is absent.

    Reported by doctor so the version in use is observable rather than assumed.
    Uses importlib.metadata so it works without importing the package, which
    matters for mcp: importing it is what fails when the pin is wrong, and a
    diagnostic that crashes on the thing it is diagnosing is no use.
    """
    try:
        from importlib.metadata import version

        return version(package)
    except Exception:  # noqa: BLE001 - informational only
        return ""


def tty_handle() -> Any:
    """Open the controlling terminal, or return None if there is not one.

    Prompting cannot use stdin while serving, because stdin is the JSON-RPC
    input stream and reading from it would consume protocol frames. The
    controlling terminal is a separate channel, and it does not exist at all
    when a GUI client spawns the server as a background subprocess.
    """
    try:
        return open("/dev/tty", "r+")
    except OSError:
        return None


def approval_required(mode: str, alters: bool) -> bool:
    """Whether this call needs a human answer before it runs."""
    if mode == "gate-all":
        return True
    if mode == "gate-writes":
        return alters
    return False


def confirm_on_tty(handle: Any, question: str) -> bool:
    """Ask a yes or no question on the terminal. Anything but yes is no.

    Returns False if the terminal disappears mid-session, because a gate that
    cannot ask must not approve.
    """
    try:
        handle.write(f"\n  {question} [y/N] ")
        handle.flush()
        answer = handle.readline().strip().lower()
    except (OSError, ValueError):
        return False
    return answer in ("y", "yes")


# How each worker action is rendered in the serve activity log. Reads and
# writes are coloured differently from everything else because they are the
# operations that touch the operator's files, and a write is the only one that
# changes them.


WORKER_ACTIONS = frozenset({"list", "read", "search", "write", "refused"})


def receipt(result: dict[str, Any], actions: list[str]) -> dict[str, Any]:
    """Describe what airlock DID, with nothing about what it FOUND.

    Reports step counts, action kinds, guard verdicts, and whether the
    answer was grounded in a successful read. Never paths, match counts,
    topics or anything else derived from file contents: the guard inspects
    answer text and never sees this metadata, so content-derived facts here
    would be an unguarded oracle. See CLAUDE.md. grounded is the same kind of
    fact as steps/action_kinds: whether a read succeeded, not which file or
    how many, so it stays on the allowed side of that line.
    """
    # Only actions that touched the workspace. The callback also reports guard
    # lifecycle events (guard, revise, approved, blocked), and passing those
    # through would both pad the count and hand the caller a running tally of
    # how many redrafts the guard forced, which is a signal about the content
    # rather than about the operation.
    worker_actions = [a for a in actions if a in WORKER_ACTIONS]
    return {
        "session": result.get("session", ""),
        "status": result.get("status", ""),
        "performed": True,
        "steps": len(worker_actions),
        "action_kinds": sorted(set(worker_actions)),
        "grounded": result.get("grounded", False),
        "guard": {
            "withheld": result.get("withheld", False),
            "concerns": result.get("guard_concerns", []),
        },
        "disclosure": (
            "No content returned. This is a receipt describing the operation only. "
            "To receive the local model's answer, call again with disclosure_request "
            "set to a short statement of what you need and why."
        ),
    }


def serve_reporter(session_id: str) -> StepCallback:
    """Render one session's worker activity to stderr as it happens.

    This is the operator's only view of what the cloud model caused to happen
    on their disk. Everything goes to stderr: stdout carries JSON-RPC frames
    and cannot be written to.
    """

    def report(action: str, detail: str) -> None:
        label, style = STEP_STYLE.get(action, (action, "dim"))
        err_console.print(
            Text.assemble(
                ("  │ ", "dim"),
                (f"{label:9}", style),
                (detail[:96], "dim" if action == "guard" else ""),
            )
        )

    return report


# The page, verbatim from ui/index.html. It is embedded rather than read
# from disk so `uv run --script airlock.py` keeps working from anywhere,
# and kept honest by test.test_console(), which fails if the two copies
# differ. Same arrangement as the PEP 723 header and pyproject.toml's
# dependency lists: a test, not machinery. Edit ui/index.html, then rerun
# `python3 tools/sync_console.py`.
CONSOLE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>airlock</title>
<style>
:root{
  --paper:#FBFBF9; --card:#FFFFFF; --ink:#1B1B18; --muted:#75756D;
  --faint:#A3A39A;          /* dots and hairlines only, never text */ --line:#ECECE6;
  --held:#2E4A7D;            /* airlock stopped something */
  --held-wash:#F0F3F9;
  --wait:#9A7B18;            /* airlock is waiting on you */
  --wait-wash:#FBF6E7;
  --ok:#5E8C6A;
  /* System faces only. A privacy console that fetches its own fonts from
     Google announces to Google every time it is opened. */
  --b:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --d:var(--b);
  --m:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --r:10px;
}
*{box-sizing:border-box}
html{-webkit-font-smoothing:antialiased}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--b);
  font-size:15px;line-height:1.6}
.wrap{max-width:1080px;margin:0 auto;padding:0 32px}
button{font:inherit;cursor:pointer}
:focus-visible{outline:2px solid var(--held);outline-offset:2px;border-radius:4px}
[hidden]{display:none !important}

/* ---------- header: identity, where, what view ---------- */
header{position:sticky;top:0;z-index:40;background:var(--paper);
  border-bottom:1px solid var(--line)}
.bar{display:flex;align-items:center;gap:12px;height:56px}
.name{font-family:var(--d);font-size:18px;font-weight:600;letter-spacing:-.03em}
.live{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--muted)}
.live i{width:6px;height:6px;border-radius:50%;background:var(--ok);flex:none}

/* the workspace is the most consequential setting, so it is a control in the
   header rather than a line of text buried in a settings page */
.ws{display:inline-flex;align-items:center;gap:8px;margin-left:6px;padding:5px 10px;
  background:transparent;border:1px solid var(--line);border-radius:99px;
  font-family:var(--m);font-size:12.5px;color:var(--muted)}
.ws:hover{color:var(--ink);border-color:var(--muted)}
.ws b{font-weight:400;color:var(--ink);white-space:nowrap}
.ws span{white-space:nowrap}
.ws svg{opacity:.5}
.wsmenu{position:absolute;top:52px;left:0;z-index:50;min-width:300px;background:var(--card);
  border-radius:var(--r);padding:6px;box-shadow:0 8px 28px rgba(20,20,16,.10),0 0 0 1px rgba(20,20,16,.07)}
.wsmenu button{display:flex;width:100%;gap:10px;align-items:baseline;text-align:left;
  background:none;border:0;padding:9px 11px;border-radius:7px;font-size:13.5px;color:var(--ink)}
.wsmenu button:hover{background:var(--paper)}
.wsmenu .p{font-family:var(--m);font-size:12px;color:var(--muted)}
.wsmenu .n{font-size:12px;color:var(--muted);margin-left:auto}
.wsmenu hr{border:0;border-top:1px solid var(--line);margin:6px 0}
.wshost{position:relative}

nav{margin-left:auto;display:flex;gap:2px}
nav button{background:none;border:0;padding:7px 13px;border-radius:7px;
  font-size:14px;color:var(--muted)}
nav button:hover{color:var(--ink)}
nav button[aria-current=page]{color:var(--ink);background:#F1F1EC;font-weight:500}

/* ---------- the interrupt: airlock is holding a call ---------- */
/* Placed above everything and sticky, because a gated call is blocking a real
   process somewhere. It must not be something you scroll past. */
.ask{position:sticky;top:56px;z-index:30;margin:0 -32px;padding:18px 32px;
  background:var(--wait-wash);border-bottom:1px solid #EFE3BE}
.ask .row{display:flex;align-items:center;gap:16px;max-width:1016px;margin:0 auto}
.ask .k{font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
  color:var(--wait);display:flex;align-items:center;gap:8px;flex:none}
.ask .k i{width:7px;height:7px;border-radius:50%;background:var(--wait);flex:none;
  animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{50%{opacity:.25}}
@media(prefers-reduced-motion:reduce){.ask .k i{animation:none}}
.ask .what{font-size:15.5px;line-height:1.45}
.ask .what code{font-family:var(--m);font-size:13.5px;background:#fff;padding:2px 7px;
  border-radius:5px;box-shadow:0 0 0 1px #EFE3BE}
.ask .acts{margin-left:auto;display:flex;gap:8px;flex:none}
.ask .acts button{padding:8px 16px;border-radius:8px;font-size:14px;font-weight:500;
  border:1px solid var(--ink);background:var(--card);color:var(--ink)}
.ask .acts button:hover{background:#F5F5F0}
.ask .sub{max-width:1016px;margin:8px auto 0;font-size:13px;color:var(--wait)}
.ask .sub button{background:none;border:0;padding:0;color:var(--wait);
  text-decoration:underline;text-underline-offset:2px;font-size:13px}

/* ---------- summary strip: replaces the fixed hero ---------- */
/* The old page spent a third of the first screen on one sentence. It reads well
   once and then never changes. This keeps the sentence and gives the space back. */
.strip{display:flex;align-items:flex-end;gap:24px;padding:34px 0 20px}
.strip p{font-family:var(--d);font-size:25px;line-height:1.3;font-weight:500;
  letter-spacing:-.02em;margin:0;max-width:520px}
.strip em{font-style:normal;color:var(--held)}
.filters{margin-left:auto;display:flex;gap:6px;flex:none}
.filters button{padding:5px 13px;border-radius:99px;font-size:13px;color:var(--muted);
  background:var(--card);border:1px solid var(--line)}
.filters button:hover{color:var(--ink)}
.filters button[aria-pressed=true]{background:var(--ink);color:var(--paper);border-color:var(--ink)}

.cols{display:grid;grid-template-columns:minmax(0,1fr) 264px;gap:56px;
  padding-bottom:88px;align-items:start}
.eyebrow{font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;
  color:var(--muted);margin:0 0 14px}
.day{margin:26px 0 14px}
.day:first-child{margin-top:0}

/* ---------- activity ---------- */
.item{background:var(--card);border-radius:var(--r);margin-bottom:10px;
  box-shadow:0 1px 2px rgba(20,20,16,.05),0 0 0 1px rgba(20,20,16,.045)}
.item.held{box-shadow:0 1px 2px rgba(46,74,125,.07),0 0 0 1px rgba(46,74,125,.14)}
.head{display:block;width:100%;text-align:left;background:none;border:0;
  padding:18px 22px;border-radius:var(--r)}
.head:hover{background:#FDFDFB}
.meta{display:flex;align-items:center;gap:10px;margin-bottom:9px}
/* the row header is a <button>, so its parts are spans and need to be told
   to stack; a <div> here would not be keyboard-operable */
.head .q,.head .why,.head .out{display:block}
.tag{font-size:12px;font-weight:600;color:var(--muted)}
.tag.held{color:var(--held);background:var(--held-wash);padding:2px 9px;border-radius:99px}
.dot{width:3px;height:3px;border-radius:50%;background:var(--faint);flex:none}
.time{font-family:var(--m);font-size:11.5px;color:var(--muted);margin-left:auto}
.chev{width:9px;height:9px;border-left:1.5px solid var(--faint);border-bottom:1.5px solid var(--faint);
  transform:rotate(-45deg);margin-left:10px;flex:none;transition:transform .15s}
[aria-expanded=true] .chev{transform:rotate(135deg)}
.q{font-size:16px;line-height:1.45;margin:0;letter-spacing:-.005em}
.out{font-family:var(--m);font-size:13.5px;background:var(--paper);border-radius:7px;
  padding:10px 13px;margin-top:12px}
.why{font-size:14px;color:var(--muted);line-height:1.6;margin:12px 0 0}
.why b{color:var(--held);font-weight:500}

/* detail is collapsed by default: the feed answers "what happened", the drawer
   answers "prove it", and only one of those is wanted on every row */
.detail{padding:0 22px 20px;border-top:1px solid var(--line);margin-top:2px}
.detail dl{display:grid;grid-template-columns:112px 1fr;gap:9px 18px;margin:16px 0 0;
  font-size:13.5px}
.detail dt{color:var(--muted)}
.detail dd{margin:0}
.trail{display:flex;flex-wrap:wrap;gap:5px}
.trail span{font-family:var(--m);font-size:11.5px;color:var(--muted);background:var(--paper);
  padding:2px 8px;border-radius:5px}
.trail span.stop{color:var(--held);background:var(--held-wash)}
.grounded{display:flex;align-items:center;gap:8px;margin-top:16px;font-size:12.5px;color:var(--muted)}
.grounded i{width:5px;height:5px;border-radius:50%;background:var(--ok);flex:none}
.grounded.none i{background:var(--wait)}

.empty{padding:44px 0;color:var(--muted);font-size:14px}

/* ---------- rail: live state only, no setup ---------- */
.rail{position:sticky;top:80px}
.rail section+section{margin-top:34px}
.gate{display:flex;align-items:center;gap:10px;padding:8px 0;font-size:14px;
  border-bottom:1px solid var(--line)}
.gate:last-of-type{border-bottom:0}
.gate .s{margin-left:auto;font-size:12.5px;color:var(--muted);flex:none}
.gate .t{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;
  overflow:hidden;line-height:1.4}
.gate.on{color:var(--held)} .gate.on .s{color:var(--held)}
.gate i{width:5px;height:5px;border-radius:50%;background:var(--line);flex:none}
.gate.on i{background:var(--held)}
.kv{display:flex;justify-content:space-between;gap:12px;padding:8px 0;font-size:13.5px;
  border-bottom:1px solid var(--line)}
.kv:last-of-type{border-bottom:0}
.kv span:first-child{color:var(--muted)}
.kv span:last-child{font-family:var(--m);font-size:12.5px;text-align:right}
button.stop{margin-top:14px;width:100%;padding:8px;border-radius:8px;background:var(--card);
  border:1px solid var(--line);color:var(--muted);font-size:13.5px}
button.stop:hover{color:var(--ink);border-color:var(--muted)}

/* ---------- setup ---------- */
.setup{padding:34px 0 96px;max-width:660px}
.setup h1{font-family:var(--d);font-size:27px;font-weight:600;letter-spacing:-.02em;margin:0 0 6px}
.setup .intro{color:var(--muted);margin:0 0 34px}
.block{padding:24px 0;border-top:1px solid var(--line)}
.block h2{font-size:15px;font-weight:600;margin:0 0 3px}
.block p.h{font-size:13.5px;color:var(--muted);margin:0 0 16px;line-height:1.55}
.field{display:flex;align-items:center;gap:14px;padding:9px 0}
.field label{font-size:14px;min-width:150px;color:var(--muted)}
.field input[type=text],.field select{font:inherit;font-size:13.5px;padding:7px 11px;
  border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);
  flex:1;min-width:0;font-family:var(--m)}
.field .hint{font-size:12.5px;color:var(--muted)}
.range{display:flex;align-items:center;gap:12px;flex:1}
.range input{flex:1;accent-color:var(--held)}
.range output{font-family:var(--m);font-size:12.5px;color:var(--muted);min-width:34px}
.pick{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 14px}
.pick button{font-size:13px;padding:5px 12px;border-radius:99px;
  background:var(--card);color:var(--muted);border:1px solid var(--line)}
.pick button:hover{color:var(--ink)}
.pick button[aria-pressed=true]{background:var(--ink);color:var(--paper);border-color:var(--ink)}
pre{font-family:var(--m);font-size:11.5px;line-height:1.7;background:var(--card);
  border-radius:9px;padding:14px;margin:0;color:var(--muted);
  box-shadow:0 0 0 1px rgba(20,20,16,.045);white-space:pre-wrap;overflow-wrap:anywhere}
pre b{color:var(--ink);font-weight:400}
.copy{margin-top:10px;padding:6px 13px;border-radius:8px;background:var(--card);
  border:1px solid var(--line);font-size:13px;color:var(--muted)}
.copy:hover{color:var(--ink);border-color:var(--muted)}
.note{font-size:12.5px;color:var(--muted);line-height:1.55;margin:12px 0 0}
.check{display:flex;align-items:center;gap:10px;padding:8px 0;font-size:14px}
.check i{width:5px;height:5px;border-radius:50%;background:var(--ok);flex:none}
.check.bad i{background:var(--wait)}
.check .s{margin-left:auto;font-family:var(--m);font-size:12px;color:var(--muted)}

.privacy{margin-top:8px;padding:14px 16px;background:var(--card);border-radius:9px;
  box-shadow:0 0 0 1px rgba(20,20,16,.045);font-size:13px;color:var(--muted);line-height:1.6}
.privacy b{color:var(--ink);font-weight:500}

@media(max-width:860px){
  .cols{grid-template-columns:1fr;gap:40px}
  .rail{position:static}
  .strip{flex-wrap:wrap;gap:16px}
  .strip p{font-size:22px}
  .filters{margin-left:0}
  .wrap{padding:0 20px}
  .ask{margin:0 -20px;padding:16px 20px}
}
@media(max-width:640px){
  /* the interrupt must stay usable at this width, so the buttons drop to their
     own row rather than shrinking to nothing next to the sentence */
  .ask .row{flex-wrap:wrap}
  .ask .acts{margin-left:0;flex-basis:100%}
  .ask .acts button{flex:1}
  /* shorthand padding here would wipe .wrap's horizontal padding, since .bar
     and .wrap are the same element */
  .bar{height:auto;flex-wrap:wrap;padding-top:10px;padding-bottom:10px;gap:10px}
  nav{margin-left:auto}
  /* the flex child is .wshost, not the button inside it */
  .wshost{order:5;flex-basis:100%}
  .ws{margin-left:0;width:100%;justify-content:space-between}
  .ask{top:0;position:static}
  header{position:static}
  /* the reason already appears in full below the question, so the abbreviated
     one in the meta row only costs a wrapped line here */
  .meta .dot,.meta .tag+.tag{display:none}
  .detail dl{grid-template-columns:1fr;gap:3px 0}
  .detail dt{margin-top:10px}
  .field{flex-wrap:wrap;gap:6px}
  .field label{min-width:0;flex-basis:100%}
}

/* the workspace is fixed for a serving process, so it reports rather than
   switches; one serve process is one folder */
span.ws{cursor:default}
.gate.warn{color:var(--wait)} .gate.warn i{background:var(--wait)}
.gatebox{max-width:420px;margin:80px auto;padding:26px;background:var(--card);
  border-radius:var(--r);box-shadow:0 1px 2px rgba(20,20,16,.05),0 0 0 1px rgba(20,20,16,.045)}
.gatebox h2{font-family:var(--d);font-size:20px;font-weight:600;margin:0 0 8px;letter-spacing:-.02em}
.gatebox p{color:var(--muted);font-size:14px;margin:0 0 16px}
.gatebox input{width:100%;font-family:var(--m);font-size:13px;padding:9px 11px;
  border:1px solid var(--line);border-radius:8px;background:var(--paper)}
.gatebox button{margin-top:10px;padding:8px 16px;border-radius:8px;border:1px solid var(--ink);
  background:var(--ink);color:var(--paper);font-size:14px}
.running{color:var(--muted)}
</style>
</head>
<body>

<header>
  <div class="wrap bar">
    <span class="name">airlock</span>
    <span class="live"><i id="livedot"></i><span id="livetext">connecting</span></span>
    <span class="wshost"><span class="ws" id="ws"><b id="wspath">&hellip;</b><span id="wsmeta"></span></span></span>
    <nav>
      <button id="nav-activity" aria-current="page">Activity</button>
      <button id="nav-setup">Setup</button>
    </nav>
  </div>
</header>

<div class="wrap" id="tokengate" hidden>
  <div class="gatebox">
    <h2>Token needed</h2>
    <p>airlock printed a link when it started, with a token in it. Open that link,
       or paste the token here. It is this run&rsquo;s only credential and is not stored on disk.</p>
    <input id="tokenin" type="text" spellcheck="false" placeholder="token">
    <button id="tokengo">Connect</button>
  </div>
</div>

<!-- ============ ACTIVITY ============ -->
<div id="view-activity">
<div class="wrap">
  <div class="ask" id="ask" hidden role="alertdialog" aria-live="assertive" aria-label="Waiting for your decision">
    <div class="row">
      <span class="k"><i></i>Waiting on you</span>
      <span class="what" id="askwhat"></span>
      <span class="acts">
        <button id="deny">Deny</button>
        <button id="allow">Allow once</button>
      </span>
    </div>
    <p class="sub" id="asksub">Nothing happens until you answer.</p>
  </div>
</div>

<div class="wrap">
  <div class="strip">
    <p id="summary">Waiting for the first question.</p>
    <div class="filters" role="group" aria-label="Filter activity">
      <button data-f="all" aria-pressed="true">All</button>
      <button data-f="held" aria-pressed="false">Held</button>
      <button data-f="sent" aria-pressed="false">Sent</button>
    </div>
  </div>

  <div class="cols">
    <main id="feed"></main>
    <aside class="rail">
      <section><p class="eyebrow">Sessions</p><div id="sess"></div></section>
      <section><p class="eyebrow">Concerns raised</p><div id="concerns"></div></section>
      <section>
        <p class="privacy"><b>Only you see this page.</b> It runs on your machine, loads
          nothing from the network, and is never sent anywhere. The assistant sees far
          less than you do here.</p>
      </section>
    </aside>
  </div>
</div>
</div>

<!-- ============ SETUP ============ -->
<div id="view-setup" hidden>
<div class="wrap setup">
  <h1>Setup</h1>
  <p class="intro">What this run is configured to do. Changing any of it means restarting
     airlock with different flags.</p>

  <div class="block">
    <h2>Folder</h2>
    <p class="h">The only directory airlock can read. Nothing outside it is reachable,
      by you or by the assistant.</p>
    <div class="field"><label>Folder</label><input type="text" id="s-root" readonly><span class="hint" id="s-files"></span></div>
    <div class="field"><label>Writes</label><span class="hint" id="s-writes"></span></div>
    <div class="field"><label>Approval</label><span class="hint" id="s-approve"></span></div>
    <div class="field"><label>Worker model</label><span class="hint" id="s-model"></span></div>
  </div>

  <div class="block">
    <h2>Guard</h2>
    <p class="h">Four checks run on every answer before it leaves. The first two are fixed
      rules with no sensitivity and cannot be turned off. The last two are local models.</p>
    <div class="check"><i></i>Secrets<span class="s">detect-secrets</span></div>
    <div class="check"><i></i>Personal identifiers<span class="s">patterns</span></div>
    <div class="check"><i></i>PII detector<span class="s">LFM2.5-350M</span></div>
    <div class="check"><i></i>Policy linter<span class="s" id="s-thr"></span></div>
  </div>

  <div class="block">
    <h2>Connect an assistant</h2>
    <p class="h">Paste this into the client&rsquo;s config, then restart it.</p>
    <div class="pick" id="clients" role="group" aria-label="Choose a client"></div>
    <pre id="cfg">&hellip;</pre>
    <button class="copy" id="copy">Copy</button>
    <p class="note" id="cfgnote"></p>
  </div>
</div>
</div>

<script>
const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=t=>String(t).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* ---- token: from the printed link, else from sessionStorage, else ask ---- */
let TOKEN = new URLSearchParams(location.search).get('token') || sessionStorage.getItem('airlock-token') || '';
if (new URLSearchParams(location.search).get('token')) {
  sessionStorage.setItem('airlock-token', TOKEN);
  // keep the credential out of the address bar, history and any screenshot
  history.replaceState(null, '', location.pathname);
}
$('#tokengo').onclick = () => { TOKEN = $('#tokenin').value.trim();
  sessionStorage.setItem('airlock-token', TOKEN); $('#tokengate').hidden = true; poll(); };

const api = (path, opts={}) => fetch(path, {...opts, headers:{...(opts.headers||{}),
  'X-Airlock-Token': TOKEN, ...(opts.body?{'Content-Type':'application/json'}:{})}});

/* ---- views ---- */
const views={activity:[$('#nav-activity'),$('#view-activity')],setup:[$('#nav-setup'),$('#view-setup')]};
for (const [k,[btn]] of Object.entries(views)) btn.onclick=()=>{
  for (const [k2,[b2,e2]] of Object.entries(views)) { e2.hidden=k2!==k;
    k2===k?b2.setAttribute('aria-current','page'):b2.removeAttribute('aria-current'); }
  scrollTo(0,0);
};

/* ---- an exchange is one question and everything that happened to it ---- */
function exchanges(events){
  const out=[]; let cur=null;
  for (const e of events) {
    if (e.kind==='asked') { cur={q:e.detail,ts:e.ts,session:e.session,steps:[],outcome:null,why:'',
      key:e.session+'|'+e.ts}; out.push(cur); continue; }
    if (!cur) continue;
    if (['sent','kept','held','denied'].includes(e.kind)) { cur.outcome=e.kind; cur.why=e.detail; cur=null; continue; }
    cur.steps.push(e.kind);
  }
  return out.reverse();
}
const clock = iso => { try { return new Date(iso).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}); }
                       catch { return ''; } };

const LABEL={sent:['Sent','Released to the assistant'],
             kept:['Kept local','The assistant got a receipt, not this text'],
             held:['Held','Withheld by the guard'],
             denied:['Denied','You declined this call'],
             null:['Running','In progress']};

const OPEN = new Set();

function row(x,i){
  const [tag,sub]=LABEL[x.outcome]||LABEL.null;
  const stopped = x.outcome==='held'||x.outcome==='denied';
  const local = x.outcome==='kept';
  const trail = x.steps.map(s=>`<span>${esc(s)}</span>`).join('')
    + (stopped?`<span class="stop">${esc(x.outcome)}</span>`:'');
  return `<article class="item${stopped?' held':''}" data-k="${stopped?'held':(x.outcome?'sent':'run')}">
    <button class="head" aria-expanded="${OPEN.has(x.key)}" aria-controls="d${i}" data-key="${esc(x.key)}">
      <span class="meta"><span class="tag${stopped?' held':''}">${tag}</span><span class="dot"></span>
        <span class="tag" style="color:var(--muted)">${esc(sub)}</span>
        <span class="time">${clock(x.ts)}</span><span class="chev"></span></span>
      <span class="q">${esc(x.q)}</span>
      ${(x.outcome==='sent'||local)&&x.why?`<span class="out">${esc(x.why)}</span>`:''}
      ${local?'<span class="why">Nothing left this machine. The assistant was told the work happened, and must ask explicitly to receive any of it.</span>':''}
      ${stopped&&x.why?`<span class="why">${esc(x.why)}</span>`:''}
      ${x.outcome===null?'<span class="why running">Still running.</span>':''}
    </button>
    <div class="detail" id="d${i}"${OPEN.has(x.key)?'':' hidden'}>
      <dl>
        <dt>Session</dt><dd>${esc(x.session)}</dd>
        <dt>Steps</dt><dd class="trail">${trail||'<span>none</span>'}</dd>
        <dt>Sent out</dt><dd>${stopped
          ? 'Nothing. The assistant was told a check failed, not what it found.'
          : local ? 'Nothing. A receipt describing the operation, with no content in it.'
          : (x.outcome==='sent' ? 'The answer above, and nothing else.' : 'Not decided yet.')}</dd>
      </dl>
    </div></article>`;
}

let FILTER='all';
$$('.filters button').forEach(b=>b.onclick=()=>{
  $$('.filters button').forEach(o=>o.setAttribute('aria-pressed',o===b));
  FILTER=b.dataset.f; applyFilter();
});
function applyFilter(){
  let shown=0;
  $$('#feed .item').forEach(it=>{ const on=FILTER==='all'||it.dataset.k===FILTER;
    it.hidden=!on; if(on)shown++; });
  const e=$('#empty'); if(e) e.hidden=shown>0;
}

let LAST_FEED='';
function renderFeed(xs){
  // Poll-and-replace wipes the DOM every 1.5s. Without this, a drawer the
  // operator opened closed again before they could read it: the interval
  // always won. Skip the rebuild when nothing changed, and carry the open
  // set across the rebuilds that do happen.
  const sig = JSON.stringify(xs.map(x=>[x.key,x.outcome,x.steps.length,x.why]));
  if (sig===LAST_FEED) return;
  LAST_FEED = sig;
  $('#feed').innerHTML = xs.length
    ? xs.map(row).join('') + '<p class="empty" id="empty" hidden>Nothing matches that filter.</p>'
    : '<p class="empty">No questions yet. Ask the assistant something about this folder.</p>';
  $$('.head').forEach(h=>h.onclick=()=>{
    const open=h.getAttribute('aria-expanded')==='true';
    h.setAttribute('aria-expanded',!open);
    $('#'+h.getAttribute('aria-controls')).hidden=open;
    open ? OPEN.delete(h.dataset.key) : OPEN.add(h.dataset.key);
  });
  applyFilter();
}

/* ---- setup, filled from the running process rather than hardcoded ---- */
let CLIENTS={};
function renderSetup(c){
  $('#s-root').value=c.workspace||'';
  $('#s-files').textContent=(c.files??'?')+' files';
  $('#s-writes').textContent=c.allow_writes?'allowed':'read only';
  $('#s-approve').textContent=c.approve||'';
  $('#s-model').textContent=c.model||'';
  $('#s-thr').textContent='threshold '+(c.linter_threshold??'');
  if (JSON.stringify(c.mcp||{})===JSON.stringify(CLIENTS)) return;
  CLIENTS=c.mcp||{};
  const names=Object.keys(CLIENTS);
  $('#clients').innerHTML=names.map((n,i)=>
    `<button aria-pressed="${i===0}" data-c="${esc(n)}">${esc(n)}</button>`).join('');
  $$('#clients button').forEach(b=>b.onclick=()=>{
    $$('#clients button').forEach(o=>o.setAttribute('aria-pressed',o===b)); showCfg(b.dataset.c); });
  if (names.length) showCfg(names[0]);
}
function showCfg(name){
  $('#cfg').textContent=CLIENTS[name]||'';
  $('#cfgnote').textContent=/desktop|cursor|vscode|zed/.test(name)
    ? 'This client is launched by the window manager, not a terminal, so it needs the full path rather than just the name.'
    : 'This client inherits your shell PATH, so the bare command name is enough.';
}
$('#copy').onclick=()=>navigator.clipboard.writeText($('#cfg').textContent)
  .then(()=>{$('#copy').textContent='Copied';setTimeout(()=>$('#copy').textContent='Copy',1200);})
  .catch(()=>{$('#copy').textContent='Select and copy';});

/* ---- the interrupt ---- */
let PENDING=null;
function renderAsk(p){
  PENDING=p;
  $('#ask').hidden=!p;
  document.title=(p?'\u25cf ':'')+'airlock';
  if (!p) return;
  $('#askwhat').innerHTML=(p.alters?'The assistant wants to run a call that can write to this folder: '
    :'The assistant is asking: ')+`<code>${esc(p.question)}</code>`;
}
const answer=g=>{ if(!PENDING) return;
  api('/api/approve',{method:'POST',body:JSON.stringify({id:PENDING.id,granted:g})})
    .then(()=>{renderAsk(null);poll();}); };
$('#allow').onclick=()=>answer(true);
$('#deny').onclick=()=>answer(false);

/* ---- poll ---- */
function renderRail(st){
  $('#sess').innerHTML = st.sessions.length
    ? st.sessions.map(s=>`<div class="kv"><span>${esc(s.id)}</span><span>${s.exchanges} asked &middot; ${s.blocked} held</span></div>`).join('')
    : '<div class="kv"><span>none open</span><span></span></div>';
  const counts={};
  for (const e of st.events) if (e.kind==='held'&&e.detail)
    for (const c of e.detail.split('; ')) if(c) counts[c]=(counts[c]||0)+1;
  const rows=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,6);
  $('#concerns').innerHTML = rows.length
    ? rows.map(([c,n])=>`<div class="gate on" title="${esc(c)}"><i></i>`+
        `<span class="t">${esc(c)}</span><span class="s">${n}</span></div>`).join('')
    : '<div class="gate"><i></i>Nothing withheld yet<span class="s">clear</span></div>';
}
function renderSummary(xs){
  const done=xs.filter(x=>x.outcome);
  const held=done.filter(x=>x.outcome==='held'||x.outcome==='denied').length;
  const running=xs.length-done.length;
  if (!xs.length) { $('#summary').textContent='Waiting for the first question.'; return; }
  const tail = running ? `<em>${running} running.</em>`
    : held ? `<em>${held} ${held===1?'was':'were'} held.</em>` : 'None were held.';
  $('#summary').innerHTML = done.length
    ? `${done.length} question${done.length===1?'':'s'} so far. ${tail}`
    : `${running} question${running===1?'':'s'} running.`;
}
let FAILS=0;
async function poll(){
  if(!TOKEN){ $('#tokengate').hidden=false; return; }
  try{
    const r=await api('/api/state');
    if(r.status===401){ $('#tokengate').hidden=false; return; }
    if(!r.ok) throw new Error(r.status);
    const st=await r.json();
    FAILS=0; $('#tokengate').hidden=true;
    $('#livedot').style.background='var(--ok)'; $('#livetext').textContent='serving';
    const c=st.config||{};
      // Truncated from the left, in JS rather than with CSS. direction:rtl
    // does keep the tail visible, but it also reorders the leading slash to
    // the end, so a path rendered as ".../scratchpad/tax-2025/".
    const path=c.workspace||'';
    $('#wspath').textContent = path.length>46 ? '\u2026'+path.slice(-45) : path;
    $('#ws').title=c.workspace||'';
    $('#wsmeta').textContent=(c.files!=null?` \u00b7 ${c.files} files`:'')+(c.allow_writes?' \u00b7 writable':' \u00b7 read only');
    const xs=exchanges(st.events||[]);
    renderSummary(xs); renderFeed(xs); renderRail({...st,sessions:st.sessions||[],events:st.events||[]});
    renderSetup(c); renderAsk(st.pending);
  }catch(e){
    // a stopped server is the normal end of a session, not an error worth shouting about
    if(++FAILS>1){ $('#livedot').style.background='var(--wait)'; $('#livetext').textContent='not connected'; }
  }
}
poll(); setInterval(poll, 1500);
</script>
</body>
</html>
"""


# The console exists because confirm_on_tty cannot cover the case that
# matters most. A GUI client spawns this server with no controlling
# terminal, so /dev/tty does not open and build_server refuses to start in
# gate mode at all. The browser is the only approval channel available
# there. Everything below is stdlib: a privacy tool should not need a web
# framework to show the operator what it did.

UI_EVENT_CAP = 200
UI_APPROVAL_TIMEOUT = 300.0

UI_LOCK = threading.Lock()
UI_CONFIG: dict[str, Any] = {}
UI_EVENTS: deque[dict[str, Any]] = deque(maxlen=UI_EVENT_CAP)
UI_PENDING: dict[str, PendingApproval] = {}


@dataclass
class PendingApproval:
    """One gated call, parked until the operator answers in the browser."""

    id: str
    session: str
    question: str
    alters: bool
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    answered: threading.Event = field(default_factory=threading.Event)
    granted: bool = False

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session": self.session[:8],
            "question": self.question,
            "alters": self.alters,
            "created_at": self.created_at,
        }


def ui_note(kind: str, session: str, detail: str) -> None:
    """Record one activity event for the console to render."""
    with UI_LOCK:
        UI_EVENTS.append(
            {
                "ts": datetime.now().isoformat(),
                "kind": kind,
                "session": session[:8],
                "detail": detail[:200],
            }
        )


def confirm_in_browser(
    session: str, question: str, alters: bool, timeout: float = UI_APPROVAL_TIMEOUT
) -> bool:
    """Park a gated call until the operator answers in the console.

    Returns False on timeout, matching confirm_on_tty: a gate nobody answered
    has not granted anything.
    """
    pending = PendingApproval(
        id=secrets.token_urlsafe(9), session=session, question=question, alters=alters
    )
    with UI_LOCK:
        UI_PENDING[pending.id] = pending
    try:
        if not pending.answered.wait(timeout):
            return False
        return pending.granted
    finally:
        with UI_LOCK:
            UI_PENDING.pop(pending.id, None)


def resolve_approval(approval_id: str, granted: bool) -> bool:
    """Answer a parked call. False if it is unknown or already answered."""
    with UI_LOCK:
        pending = UI_PENDING.get(approval_id)
        if pending is None or pending.answered.is_set():
            return False
        pending.granted = granted
        pending.answered.set()
    return True


def console_state() -> dict[str, Any]:
    """Everything the page renders, as one snapshot."""
    with UI_LOCK:
        events = list(UI_EVENTS)
        pending = [p.as_json() for p in UI_PENDING.values() if not p.answered.is_set()]
    return {
        "config": UI_CONFIG,
        "events": events,
        "pending": pending[0] if pending else None,
        "sessions": [
            {
                "id": sid[:8],
                "objective": sess.objective[:120],
                "exchanges": sess.exchanges,
                "blocked": sess.blocked,
                "revisions": sess.revisions,
                "created_at": sess.created_at,
            }
            for sid, sess in SESSIONS.items()
        ],
    }


class ConsoleHandler(BaseHTTPRequestHandler):
    """Serve the console page and its two endpoints, nothing else."""

    server_version = "airlock"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        """Silence the default access log; stderr is the activity log."""

    def _authorised(self) -> bool:
        """Token plus origin. Both, because either alone is not enough.

        Binding to loopback does not keep other origins out: any page in the
        operator's browser can POST to 127.0.0.1. The token is the real
        check, and the Origin test refuses the cross-site preflight before a
        token guess is even attempted.
        """
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.origins:  # type: ignore[attr-defined]
            return False
        supplied = self.headers.get("X-Airlock-Token", "")
        return hmac.compare_digest(supplied, self.server.token)  # type: ignore[attr-defined]

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # The page loads nothing remote by design, so the policy that says so
        # costs nothing and stops a tampered page from sending anything out.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; img-src data:; form-action 'none'; base-uri 'none'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, payload: dict[str, Any]) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        path, _, query = self.path.partition("?")
        if path == "/":
            # The page is public; everything it can act on is not. Serving the
            # shell without a token lets the operator open a bare URL and paste
            # the token, rather than losing access to their own console.
            self._send(200, CONSOLE_HTML.encode(), "text/html; charset=utf-8")
            return
        if path == "/api/state":
            if not self._authorised():
                self._json(401, {"error": "bad or missing token"})
                return
            self._json(200, console_state())
            return
        self._json(404, {"error": "no such path"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        if self.path != "/api/approve":
            self._json(404, {"error": "no such path"})
            return
        if not self._authorised():
            self._json(401, {"error": "bad or missing token"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 4096:
                raise ValueError("body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            approval_id = body["id"]
            granted = body["granted"]
            if not isinstance(approval_id, str) or not isinstance(granted, bool):
                raise ValueError("id must be a string and granted a boolean")
        except (ValueError, KeyError, TypeError) as exc:
            self._json(400, {"error": str(exc)})
            return
        if not resolve_approval(approval_id, granted):
            self._json(409, {"error": "that call is no longer waiting"})
            return
        self._json(200, {"ok": True})


def console_client_configs(args: argparse.Namespace) -> dict[str, str]:
    """Ready-to-paste config for every supported client, for the console.

    Each client gets whichever launch form matches how it starts, which is
    the distinction _airlock_launch_forms exists to make; getting it wrong
    is a silent command-not-found in the GUI clients.
    """
    root = Path(args.root).expanduser().resolve()
    shell_form, gui_form, _ = _airlock_launch_forms(Path(__file__).resolve())
    server_args = _server_args(root, args)
    out: dict[str, str] = {}
    for client, spec in MCP_CLIENTS.items():
        form = gui_form if spec["launch"] == "gui" else shell_form
        try:
            out[client] = render_client_config(client, form, server_args)
        except Exception:  # noqa: BLE001 - one unrenderable client must not blank the page
            continue
    return out


def start_console(config: dict[str, Any] | None = None, port: int = 0) -> tuple[str, str]:
    """Start the console on loopback. Returns its URL and token.

    Port 0 asks the OS for a free one, so two workspaces served at once do
    not collide. The thread is a daemon: the console must never be the
    reason the server outlives its client.
    """
    UI_CONFIG.update(config or {})
    token = secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), ConsoleHandler)
    httpd.token = token  # type: ignore[attr-defined]
    bound = httpd.server_address[1]
    httpd.origins = {f"http://127.0.0.1:{bound}", f"http://localhost:{bound}"}  # type: ignore[attr-defined]
    threading.Thread(target=httpd.serve_forever, daemon=True, name="airlock-console").start()
    return f"http://127.0.0.1:{bound}/?token={token}", token


def build_server(args: argparse.Namespace) -> Any:
    """Construct the MCP server object without running a transport.

    Split out of cmd_serve so tests can drive the real server in memory with
    the SDK's own Client, which is the only way to exercise MCPServer, the
    annotation types, and the tool signatures against the installed package
    rather than against assumptions about it.

    Raises SandboxError, FileNotFoundError, or RuntimeError rather than
    printing and exiting, so a caller can decide what to do.
    """
    # MCPServer is the server class in MCP Python SDK v2. It replaced FastMCP,
    # and mcp.server.fastmcp.* was removed rather than deprecated, so there is
    # no older path worth supporting. The dependency pin above requires v2.
    from mcp.server import MCPServer

    # mcp_types, not mcp.types. SDK v2 moved the protocol wire types into a
    # standalone `mcp-types` distribution and removed the `mcp.types`
    # submodule outright, so the old import raises ImportError. The package
    # arrives as a dependency of `mcp`, which is why it is not declared
    # separately above: pinning mcp pins this with it.
    from mcp_types import ToolAnnotations

    sandbox = Sandbox(root=args.root, allow_writes=args.allow_writes)

    # Enabling writes raises the approval posture on its own, so that writes
    # cannot be turned on while approval is quietly left off.
    if args.approve == "hint-writes" and args.allow_writes:
        args.approve = "gate-writes"

    gating = args.approve.startswith("gate")
    use_console = bool(getattr(args, "ui", False))
    tty = tty_handle() if gating and not use_console else None
    if gating and not use_console and tty is None:
        # Refusing is the point. Falling back to no approval would turn a
        # request for a gate into silence, which is the worst of the available
        # outcomes and the one that happens if nobody checks.
        raise RuntimeError(
            f"--ask {getattr(args, 'ask', 'writes')} needs somewhere to ask, and there "
            "is nowhere.\n"
            "  stdin is the JSON-RPC stream here, so prompting uses /dev/tty, which does\n"
            "  not exist when a GUI client launches this server as a subprocess.\n"
            "  Drop --no-ui so you can answer in the web console, run airlock from a\n"
            "  terminal, or use --ask never to let the client decide instead."
        )

    mcp = MCPServer("airlock", version=__version__)

    # Annotations are computed here, not hardcoded, because whether asking a
    # question can alter anything depends on --allow-writes. A fixed
    # read_only_hint=True would be a lie in precisely the configuration where
    # the lie matters, and clients use these to decide what to auto-approve.
    can_alter = sandbox.allow_writes
    ask_annotations = ToolAnnotations(
        title="Ask the sandboxed local model",
        read_only_hint=not can_alter,
        destructive_hint=can_alter,
        idempotent_hint=False,
        open_world_hint=False,
    )
    read_only = ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False)

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Open an airlock session",
            read_only_hint=True,
            idempotent_hint=False,
            open_world_hint=False,
        )
    )
    def airlock_open(objective: str) -> dict[str, Any]:
        """Start a session with the local model over the sandboxed workspace.

        This server sits between you and a private directory you cannot see.
        A local model reads the files; a privacy guard decides what may be
        returned to you. Please work with that grain rather than against it:

        - Ask for the minimum that answers your question. Structure and
          summaries are usually enough, and are far more likely to be released
          than verbatim content.
        - Do not ask for identifiers, contact details, credentials, or
          personal circumstances. Those are blocked, and asking wastes a turn.
        - A withheld reply is a correct outcome, not an error. Do not retry it
          with rephrasing intended to get around the guard.
        - Prefer several narrow questions over one broad request for
          everything, so that less is exposed if any single answer is released.

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
            linter_threshold=args.linter_threshold,
        )
        SESSIONS[session.session_id] = session
        # After registering, not before: the new session's own last_active
        # is always the newest, so it is never the one evicted, and the
        # cap is enforced (len(SESSIONS) <= SESSION_CAP) the instant this
        # call returns rather than only from the next open onward.
        evict_stale_sessions()
        counts = sandbox.stats()
        # Counts, never names.
        truncated_marker = f"... truncated at {MAX_LISTING_ENTRIES}"
        try:
            names = sorted(
                n
                for n in sandbox.list_dir(".")
                if not n.endswith("/") and n != truncated_marker
            )
        except SandboxError:
            names = []
        # Indices and extensions, never names. The caller needs to be able to
        # address a document to decompose work over it; it does not need to
        # know that one of them is called medical_records_2026.pdf.
        documents = [
            {"document": i, "kind": (Path(n).suffix.lstrip(".") or "file")}
            for i, n in enumerate(names)
        ]
        return {
            "session": session.session_id,
            "workspace": sandbox.root.name,
            "files": counts["files"],
            "directories": counts["directories"],
            "documents": documents,
            "writes_enabled": sandbox.allow_writes,
            "protocol": (
                "File and directory names are not disclosed. Ask questions with "
                "airlock_ask instead: the local model reads the files and a "
                "layered privacy guard decides what may be returned. Replies "
                "may be generalised or withheld."
            ),
        }

    @mcp.tool(annotations=ask_annotations)
    def airlock_ask(
        session: str, question: str, disclosure_request: str | None = None
    ) -> dict[str, Any]:
        """Ask the local model about the workspace. Returns a receipt by default.

        By default this returns only a description of what was done: how many
        steps ran, which kinds of action, and the guard's decision. It does NOT
        return the local model's answer. That is deliberate, so that content
        crosses the boundary only when something explicitly asks for it.

        To receive the answer, set disclosure_request to a short statement of
        what you need and why, for example "a two sentence summary of the
        project status, to draft a status update". The statement is recorded
        and shown to the operator alongside whatever is released, so write one
        you would be willing to have read back to you. Request the least that
        answers the question.

        Args:
            session: Session id from airlock_open.
            question: A question about structure, topics, or findings. Requests
                for identifiers, contact details, or credentials are blocked.
            disclosure_request: Optional. What you need returned and why.
                Omit it when you only need to know the work happened.

        Returns:
            A receipt, or, when disclosure_request is given, the guarded answer.
        """
        found = SESSIONS.get(session)
        if found is None:
            return {"status": "error", "message": "Unknown session."}
        touch_session(found)

        err_console.print(
            Text.assemble(
                ("\n  ┌ ask     ", "bold cyan"),
                (question.strip()[:96], ""),
                (f"   [{session[:8]}]", "dim"),
            )
        )
        if disclosure_request:
            err_console.print(
                Text.assemble(
                    ("  │ wants   ", "bold yellow"), (disclosure_request.strip()[:96], "")
                )
            )

        if approval_required(args.approve, can_alter):
            if use_console:
                allowed = confirm_in_browser(session, question.strip(), can_alter)
            else:
                allowed = confirm_on_tty(
                    tty, f"Allow this call on {sandbox.root.name}? ({question.strip()[:60]})"
                )
            trace("approval", session=session, granted=allowed, mode=args.approve)
            if not allowed:
                err_console.print(Text.assemble(("  └ denied  ", "bold red"), ("by operator", "")))
                ui_note("denied", session, "declined by the operator")
                return {"status": "denied", "message": "The operator declined this call."}

        actions: list[str] = []
        reporter = serve_reporter(session)

        def watch(action: str, detail: str) -> None:
            actions.append(action)
            reporter(action, detail)
            ui_note(action, session, detail)

        ui_note("asked", session, question.strip())
        result = run_worker(found, question.strip(), on_step=watch)

        # The governing fact is what actually crossed the boundary, so print
        # the approved text itself rather than a summary of it.
        status = result.get("status", "?")
        if status == "approved":
            if disclosure_request:
                err_console.print(
                    Text.assemble(
                        ("  └ sent    ", "bold green"), (result.get("message", "")[:200], "")
                    )
                )
            else:
                err_console.print(
                    Text.assemble(
                        ("  └ receipt ", "bold green"),
                        ("no content released, caller did not request disclosure", "dim"),
                    )
                )
        else:
            err_console.print(
                Text.assemble(
                    ("  └ withheld ", "bold red"),
                    ("; ".join(result.get("guard_concerns", []))[:160], "dim"),
                )
            )

        # Three outcomes, not two. An approved answer with no
        # disclosure_request never leaves this machine: the caller gets a
        # receipt. Calling that "sent" and showing the text beside it tells
        # the operator their content went out when it did not.
        if status != "approved":
            ui_note("held", session, "; ".join(result.get("guard_concerns", []))[:160])
        elif disclosure_request:
            ui_note("sent", session, result.get("message", "")[:200])
        else:
            ui_note("kept", session, result.get("message", "")[:200])
        trace(
            "disclosure",
            session=session,
            requested=bool(disclosure_request),
            purpose=(disclosure_request or "")[:200],
            released_chars=len(result.get("message", "")) if disclosure_request else 0,
        )
        if disclosure_request:
            return result
        return receipt(result, actions)

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Close an airlock session", read_only_hint=False, open_world_hint=False
        )
    )
    def airlock_close(session: str) -> dict[str, Any]:
        """End a session and discard its state.

        Args:
            session: Session id from airlock_open.
        """
        found = SESSIONS.pop(session, None)
        if found is None:
            return {"status": "error", "message": "Unknown session."}
        return {"status": "closed", "exchanges": found.exchanges}

    @mcp.tool(annotations=read_only)
    def airlock_extract(session: str, jobs: list[dict[str, Any]]) -> dict[str, Any]:
        """Extract specific facts from specific documents, one job per fact.

        Prefer this over airlock_ask for anything with structure. You decide
        what to extract and from which document; the local model only reads and
        answers. It is a small model, and asking it to plan is what makes it
        fail, so keep each job to one fact from one document.

        Address documents by the index from airlock_open. Names are not
        disclosed and are not needed.

        Each value is screened on its own, and the round is screened as a
        whole, so splitting a protected value across several jobs does not
        release it.

        A job takes one of three forms:

            {"document": 1, "extract": "the value in box 1", "as": "number"}
                read document 1, return the value if the guard allows it.
                Always set "as" when the answer has a shape: "number" for
                amounts, "digits" for identifiers, "line" for a short string.
                It constrains the decoder, so the model cannot return the
                figure bundled with whatever sat next to it on the page.

            {"document": 1, "extract": "the employee SSN",
             "into": 0, "field": "SSN"}
                read document 1, write the value into document 0 next to
                "SSN:", and return only that the field was filled. The value
                never reaches you. Use this for anything identifying: you do
                not need to see a taxpayer's SSN to put it on their return.

            {"into": 0, "field": "1a", "value": "102650.00"}
                write a value you computed yourself into document 0.

        Args:
            session: Session id from airlock_open.
            jobs: Up to 12 jobs, each in one of the forms above.

        Returns:
            One result per job: ok with a value, filled, withheld, or error.
        """
        found = SESSIONS.get(session)
        if found is None:
            return {"status": "error", "message": "Unknown session."}
        touch_session(found)
        err_console.print(
            Text.assemble(("\n  \u250c jobs    ", "bold cyan"),
                          (f"{len(jobs)} extraction job(s)", ""),
                          (f"   [{session[:8]}]", "dim")))
        result = run_jobs(found, jobs, on_step=serve_reporter(session))
        kept = sum(1 for r in result.get("results", []) if r.get("status") == "ok")
        err_console.print(
            Text.assemble(("  \u2514 sent    ", "bold green"),
                          (f"{kept} of {len(jobs)} values released", "")))
        return result

    @mcp.tool(annotations=read_only)
    def airlock_guard_check(text: str) -> dict[str, Any]:
        """Test whether text would pass the privacy guard.

        Args:
            text: The text to evaluate.
        """
        verdict = evaluate(text, args.linter_threshold)
        return {
            "decision": verdict.decision,
            "approved": verdict.approved,
            "concerns": verdict.concerns,
            "layers_run": verdict.layers_run,
            "findings": verdict.findings,
        }

    return mcp


def cmd_serve(args: argparse.Namespace) -> int:
    """Run as an MCP server so a cloud assistant can consult the workspace."""
    try:
        mcp = build_server(args)
    except (SandboxError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Both guard encoders otherwise load lazily inside whichever tool call
    # happens to run first, which means a cloud assistant's first request
    # would silently block on a ~700MB Hugging Face download with no
    # explanation visible on its side of the connection. Loading them here,
    # before mcp.run() starts the transport, means readiness is only
    # announced once the guard can actually run, and a load failure is a
    # startup failure with a clear message rather than a server that starts
    # and then fails closed on every request forever. stdout is the
    # JSON-RPC channel once mcp.run() starts (CLAUDE.md), so this, like
    # everything else in serve, goes to err_console only.
    err_console.print(
        f"airlock v{__version__}: loading guard encoders "
        "(first run may download ~700MB from Hugging Face)..."
    )
    try:
        _load_pii_detector()
        _load_policy_linter()
    except GuardModelUnavailable as exc:
        err_console.print(f"error: guard encoders failed to load: {exc}")
        return 1
    err_console.print("airlock: guard encoders ready")

    if getattr(args, "ui", False):
        url, _ = start_console(
            {
                "workspace": str(Path(args.root).resolve()),
                # Bounded: a workspace pointed at a huge tree must not stall
                # startup just to render a count in the header.
                "files": sum(
                    1 for _ in itertools.islice(
                        (p for p in Path(args.root).resolve().rglob("*") if p.is_file()), 10000
                    )
                ),
                "model": args.model,
                "approve": args.approve,
                "allow_writes": bool(args.allow_writes),
                "linter_threshold": args.linter_threshold,
                "version": __version__,
                # Reuses render_mcp_help's own builders rather than
                # reimplementing seven client schemas in JavaScript.
                "mcp": console_client_configs(args),
            }
        )
        # stdout is the JSON-RPC channel once mcp.run() starts (CLAUDE.md).
        err_console.print(f"airlock console: {url}")
        err_console.print(
            "  Open that link. The token in it is this run's only credential; "
            "it is not written to disk."
        )

    print(f"airlock serving {Path(args.root).resolve()} over MCP", file=sys.stderr)
    mcp.run()
    return 0


def offer_repairs(args: argparse.Namespace) -> bool:
    """Walk the user through fixing whatever is missing. Returns True if fixed.

    Deliberately narrow. It repairs the one class of problem that is both
    common and unambiguous, a model tag that is not pulled yet, and for
    everything else it prints the command rather than running it. Guessing at
    someone's Ollama installation or Python environment is how a setup helper
    turns into the thing that broke their machine.
    """
    # doctor has already printed the diagnosis and the fix command for each
    # failure. This function only adds what doctor cannot: doing the work.
    # Anything it prints that doctor already said is noise.
    try:
        installed = set(ollama_models())
    except RuntimeError:
        console.print("\n[dim]Not installed? https://ollama.com/download[/dim]")
        return False

    # Only the worker still runs on Ollama; the guard encoders come from
    # Hugging Face and are not something `ollama pull` can fix.
    wanted = [("worker", args.model)]
    missing = [(role, tag) for role, tag in wanted if tag not in installed]
    if not missing:
        return False

    # Pulling a model downloads gigabytes. Always ask, never assume.
    console.print()
    plural = "s" if len(missing) > 1 else ""
    if not Confirm.ask(
        f"Pull the {len(missing)} missing model{plural} now?", default=True
    ):
        console.print("[dim]Skipped. The commands above will do it.[/dim]")
        return False

    fixed = False
    for role, tag in missing:
        console.print(f"\n[dim]pulling {tag} ...[/dim]")
        try:
            done = subprocess.run(["ollama", "pull", tag], check=False)
        except FileNotFoundError:
            console.print("[red]The 'ollama' command is not on your PATH.[/red]")
            console.print(f"[dim]Pull it manually: ollama pull {tag}[/dim]")
            return fixed
        if done.returncode == 0:
            fixed = True
        else:
            console.print(f"[red]Could not pull {tag}.[/red] Check the tag name at")
            console.print("[dim]https://ollama.com/library[/dim]")
    return fixed


def _ask_yes_no(question: str, default: bool) -> bool:
    """Confirm, treating an unanswerable prompt as no.

    stdin is a pipe under a setup script or CI, where Confirm.ask raises
    EOFError. Aborting is the safe reading: every call site here is about to
    change somebody's configuration.
    """
    try:
        return bool(Confirm.ask(question, default=default))
    except EOFError:
        console.print("[dim]no answer available on stdin; stopping[/dim]")
        return False


def _confirm_scope(root: Path) -> bool:
    """Refuse to treat a home directory or / as a workspace without a yes.

    The workspace is the whole security boundary, and the two defaults that
    quietly widen it to everything are the ones worth interrupting for.
    """
    if root != Path.home() and root != root.parent:
        return True
    where = "your home directory" if root == Path.home() else "the filesystem root"
    console.print(f"[yellow]That is {where}.[/yellow] Every file beneath it is in scope.")
    return _ask_yes_no("Use it anyway?", default=False)


def _pick_client(preselected: str | None) -> str | None:
    """Which assistant to connect. None if there is nothing to connect to."""
    if preselected:
        if preselected not in MCP_CLIENTS:
            console.print(f"[red]Unknown client {preselected!r}.[/red] "
                          f"Known: {', '.join(MCP_CLIENTS)}")
            return None
        return preselected
    found = installed_clients()
    if not found:
        console.print("[yellow]No assistant found on this machine.[/yellow]")
        console.print("[dim]airlock looks for an existing config file for each one. "
                      "Pass --client NAME to write one anyway.[/dim]")
        return None
    if len(found) == 1:
        console.print(f"Found [bold]{CLIENT_LABELS[found[0]]}[/bold].")
        return found[0]
    console.print("Found these assistants:\n")
    for index, client in enumerate(found, 1):
        console.print(f"  [cyan]{index}[/cyan]  {CLIENT_LABELS[client]}")
    console.print()
    try:
        choice = Prompt.ask(
            "Connect which one", choices=[str(i) for i in range(1, len(found) + 1)],
            default="1",
        )
    except EOFError:
        console.print("[dim]no answer available on stdin; pass --client NAME[/dim]")
        return None
    return found[int(choice) - 1]


def cmd_connect(args: argparse.Namespace) -> int:
    """`airlock [FOLDER]`: make one folder readable by one assistant.

    The whole job in one command. Everything it does was previously five
    steps, one of which was "find your client's config file yourself".
    """
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        console.print(f"[red]No such folder:[/red] {root}")
        return 1

    # --print exists to be piped into a config file or a setup script, so it
    # returns before anything decorative is written to stdout. A banner above
    # the JSON would make `airlock connect --print | jq` fail.
    if getattr(args, "print_only", False):
        client = getattr(args, "client", None)
        if client is None:
            found = installed_clients()
            if not found:
                print("error: no assistant found; pass --client NAME", file=sys.stderr)
                return 1
            client = found[0]
        elif client not in MCP_CLIENTS:
            print(f"error: unknown client {client!r}", file=sys.stderr)
            return 1
        shell_form, gui_form, _ = _airlock_launch_forms(Path(__file__).resolve())
        form = gui_form if MCP_CLIENTS[client]["launch"] == "gui" else shell_form
        print(render_client_config(client, form, _server_args(root, args)))
        return 0

    console.print(Rule("airlock", style="cyan"))
    console.print(Text.assemble(("folder  ", "dim"), (str(root), "bold yellow")))
    console.print("[dim]the only directory the assistant can reach, and only through "
                  "the guard[/dim]\n")
    if not _confirm_scope(root):
        return 0

    client = _pick_client(getattr(args, "client", None))
    if client is None:
        return 1

    entry = airlock_launch_entry(root, args, client)
    if cmd_doctor(args) != 0:
        if not offer_repairs(args):
            return 1
        console.print()
        if cmd_doctor(args) != 0:
            return 1

    path = client_config_path(client)
    console.print()
    console.print(Text.assemble(("writing ", "dim"), (str(path), "bold")))
    console.print(f"[dim]{entry['command']} {' '.join(entry['args'])}[/dim]\n")
    if not _ask_yes_no(f"Add airlock to {CLIENT_LABELS[client]}?", default=True):
        return 0

    try:
        done = write_client_config(client, root, args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]Could not write {path}:[/red] {exc}")
        console.print("[dim]Nothing was changed. Run with --print to get the config "
                      "and paste it yourself.[/dim]")
        return 1

    console.print(f"\n[green]Connected.[/green] {CLIENT_LABELS[client]} can now ask about "
                  f"{root.name}.")
    if done.backup:
        console.print(f"[dim]previous config saved as {done.backup.name}[/dim]")
    console.print(f"[bold]Restart {CLIENT_LABELS[client]}[/bold] for it to take effect.")
    if not getattr(args, "no_ui", False):
        # Deliberately not "run airlock status to see it": the console lives
        # inside the process the client spawns, and its token is never written
        # to disk, so no other process can report the link.
        console.print("[dim]The web console prints its address on stderr when your "
                      "assistant starts airlock; look in that client's MCP log.[/dim]")
    return 0


def cmd_disconnect(args: argparse.Namespace) -> int:
    """Remove airlock from a client's config, restoring what was there."""
    client = _pick_client(getattr(args, "client", None))
    if client is None:
        return 1
    path = client_config_path(client)
    try:
        done = write_client_config(client, Path("."), args, remove=True)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]Could not write {path}:[/red] {exc}")
        return 1
    if done.action == "unchanged":
        console.print(f"airlock was not in {CLIENT_LABELS[client]}'s config.")
        return 0
    console.print(f"[green]Removed[/green] airlock from {CLIENT_LABELS[client]}.")
    if done.backup:
        console.print(f"[dim]previous config saved as {done.backup.name}[/dim]")
    console.print(f"[bold]Restart {CLIENT_LABELS[client]}[/bold] for it to take effect.")
    return 0


def _registered_root(client: str) -> str | None:
    """Which folder a client is currently configured to serve, if any.

    Read back out of the client's own file rather than remembered anywhere,
    so this reports what is actually configured and not what airlock last
    intended.
    """
    path = client_config_path(client)
    if path is None or not path.exists():
        return None
    try:
        text = path.read_text()
        if MCP_CLIENTS[client]["schema"] == "codex":
            match = _CODEX_BLOCK.search(text)
            entry_args = re.findall(r'"([^"]*)"', match.group(0)) if match else []
        else:
            data = json.loads(text) if text.strip() else {}
            key = {"vscode": "servers", "zed": "context_servers"}.get(
                MCP_CLIENTS[client]["schema"], "mcpServers"
            )
            entry = (data.get(key) or {}).get("airlock")
            entry_args = entry.get("args", []) if isinstance(entry, dict) else []
    except (OSError, ValueError):
        return None
    if "serve" not in entry_args:
        return None
    after = entry_args[entry_args.index("serve") + 1 :]
    return after[0] if after and not after[0].startswith("-") else "(unspecified)"


def cmd_status(args: argparse.Namespace) -> int:
    """What is connected, and whether the pieces it needs are working."""
    console.print(Rule("airlock", style="cyan"))
    table = Table(show_header=True, header_style="dim", box=None, padding=(0, 2))
    table.add_column("assistant")
    table.add_column("airlock")
    table.add_column("folder")
    any_connected = False
    for client in MCP_CLIENTS:
        path = client_config_path(client)
        if path is None:
            continue
        where = _registered_root(client)
        any_connected = any_connected or where is not None
        table.add_row(
            CLIENT_LABELS[client],
            "[green]connected[/green]" if where else "[dim]not connected[/dim]",
            where or "",
        )
    console.print(table)
    if not any_connected:
        console.print("\n[dim]Nothing connected yet. Run 'airlock <folder>' to "
                      "connect one.[/dim]")
    console.print()
    return cmd_doctor(args)


def _linter_threshold_type(raw: str) -> float:
    """Parse --linter-threshold and reject anything outside the sigmoid's range.

    argparse's bare type=float converts but never validates, so a typo like
    2 parsed silently and was applied as-is: sigmoid output tops out at 1.0,
    so a threshold above that makes every rule without its own
    POLICY_LINTER_RULE_THRESHOLDS override permanently unreachable, and the
    guard fails open on the linter layer with nothing surfacing it. The
    interactive config screen already enforces 0.0-1.0 (see the "linter
    threshold" branch of _config_loop); this matches that range at the
    other entry point.
    """
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{raw!r} is not a number")
    if not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError(f"{raw!r} must be between 0.0 and 1.0")
    return value


ASK_MODES = ("always", "writes", "never")


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line interface.

    Organised around what a person does (connect a folder, see what happened)
    rather than around airlock's own parts. The knobs that exist for
    measurement rather than for use are still accepted, and still documented
    in README.md, but carry help=SUPPRESS so `--help` stays readable: a
    0.0-to-1.0 float on a model's internals is not a decision anyone can make
    from a help listing.
    """
    # The folder lives on a separate parent from the flags. A parser that has
    # both an optional positional and subparsers gives the positional
    # priority, so a top level carrying FOLDER would swallow the subcommand
    # name itself; `airlock status` became FOLDER="status".
    workspace = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    workspace.add_argument("root", nargs="?", type=Path, metavar="FOLDER",
                           help="Folder to work over (default: the current one).")

    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("--write", action="store_true",
                        help="Let the local model write files. Off by default.")
    common.add_argument("--ask", choices=ASK_MODES,
                        help="When airlock holds a call until you answer: always, "
                        "writes (default), or never.")
    common.add_argument("--model", help=argparse.SUPPRESS)
    common.add_argument("--linter-threshold", type=_linter_threshold_type,
                        help=argparse.SUPPRESS)
    common.add_argument("--trace", type=Path, help=argparse.SUPPRESS)
    common.add_argument("--objective", help=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(
        prog="airlock",
        description="Let an assistant use one folder without seeing what is in it.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
        epilog=(
            "examples:\n"
            "  airlock ~/tax-2025               connect that folder to your assistant\n"
            "  airlock                          same, for the folder you are in\n"
            "  airlock status                   what is connected, and is it working\n"
            "  airlock disconnect               remove airlock from an assistant\n"
            '  airlock check "Jane Doe, 555-555-0100"    would that text pass?\n'
            "  airlock chat ~/notes             ask the local model yourself\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"airlock {__version__}")
    parser.set_defaults(func=cmd_connect)

    # metavar, because the auto-generated {a,b,c} list would name `serve`,
    # which nobody types.
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    assert set(COMMANDS) == {
        "connect", "status", "disconnect", "check", "chat", "serve"
    }, "COMMANDS and the subparsers below must name the same set"

    p_connect = sub.add_parser("connect", parents=[common, workspace],
                               help="Connect a folder to an assistant. The default.")
    p_connect.add_argument("--client", choices=sorted(MCP_CLIENTS),
                           help="Skip the picker and use this client.")
    p_connect.add_argument("--print", dest="print_only", action="store_true",
                           help="Print the config instead of writing it. For scripts.")
    p_connect.add_argument("--no-ui", action="store_true",
                           help="Do not open the web console while serving.")
    p_connect.set_defaults(func=cmd_connect)

    sub.add_parser("status", parents=[common],
                   help="What is connected, and whether it works.").set_defaults(
        func=cmd_status)

    p_disconnect = sub.add_parser("disconnect", parents=[common],
                                  help="Remove airlock from an assistant.")
    p_disconnect.add_argument("--client", choices=sorted(MCP_CLIENTS),
                              help="Skip the picker and use this client.")
    p_disconnect.set_defaults(func=cmd_disconnect)

    p_check = sub.add_parser("check", parents=[common],
                             help="Test whether some text would pass the guard.")
    p_check.add_argument("text", help="Text to evaluate.")
    p_check.set_defaults(func=cmd_guard)

    p_chat = sub.add_parser("chat", parents=[common, workspace],
                            help="Talk to the local model yourself.")
    p_chat.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    p_chat.add_argument("--quiet", action="store_true", help=argparse.SUPPRESS)
    p_chat.add_argument("--ask-once", dest="question",
                        help="Ask one question and stop, instead of a session.")
    p_chat.set_defaults(func=cmd_chat_or_ask)

    # Not in the help. Nobody types this: it is what a client spawns, and its
    # arguments are written into the client's config by `connect`.
    # No help= at all: argparse renders help=SUPPRESS on a subparser as the
    # literal "==SUPPRESS==", while omitting it keeps the command working and
    # out of the listing.
    p_serve = sub.add_parser("serve", parents=[common, workspace])
    p_serve.add_argument("--ui", action="store_true", help=argparse.SUPPRESS)
    p_serve.add_argument("--port", type=int, default=0, help=argparse.SUPPRESS)
    p_serve.set_defaults(func=cmd_serve)

    # COMMANDS drives the argv shim above and is what stops `airlock status`
    # being read as a folder named "status". A command added here and not
    # there would silently become unreachable, so the two are compared rather
    # than trusted to stay in step.
    assert set(sub.choices) == set(COMMANDS), (
        f"COMMANDS {sorted(COMMANDS)} does not match subparsers {sorted(sub.choices)}"
    )
    return parser


def cmd_chat_or_ask(args: argparse.Namespace) -> int:
    """`chat` with a question is one-shot; without one it is a session."""
    return cmd_ask(args) if getattr(args, "question", None) else cmd_chat(args)


# `airlock ~/notes` has to mean `airlock connect ~/notes` while `airlock
# status` keeps meaning status. argparse cannot express "an optional
# positional OR a subcommand", so the first token decides, once, here.
#
# Only the first token, deliberately. An earlier version scanned for the
# first token not starting with "-", which put `connect` in the middle of
# `--ask always ~/x`, since a flag's value is a bare word too. Knowing which
# flags take values would mean keeping a second copy of the parser's own
# knowledge in sync with it.
COMMANDS = ("connect", "status", "disconnect", "check", "chat", "serve")


def insert_default_command(argv: list[str]) -> list[str]:
    """Prefix `connect` unless the first token already says what to do."""
    if not argv or argv[0] in COMMANDS or argv[0] in ("-h", "--help", "--version"):
        return argv
    return ["connect"] + argv


# `airlock ~/notes` has to mean `airlock connect ~/notes` while `airlock
# status` keeps meaning status. argparse cannot express "an optional
# positional OR a subcommand", so the first non-flag token decides, once,
# here. Explicit and testable, unlike teaching argparse to backtrack.
# Applied after parsing rather than through argparse defaults, because every
# shared option carries argument_default=SUPPRESS so an option nobody typed is
# absent rather than present-with-a-default.
CLI_DEFAULTS: dict[str, Any] = {
    "root": Path("."),
    "model": DEFAULT_MODEL,
    "write": False,
    "ask": "writes",
    # Derived from the two above by resolve_ask_mode, which main() always
    # runs. They are listed here so that a Namespace built straight from this
    # table -- which is how tests drive build_server and cmd_doctor without
    # going through main -- is already complete rather than missing the two
    # fields the rest of the module actually reads.
    "allow_writes": False,
    "approve": "hint-writes",
    "linter_threshold": POLICY_LINTER_THRESHOLD,
    "trace": None,
    "objective": "Help the user understand and work with the files in this directory.",
}


def resolve_ask_mode(args: argparse.Namespace) -> None:
    """Turn --ask/--write into the internal approval posture.

    Named for the flag rather than the concept: `resolve_approval` is already
    taken by the web console, where it answers a call the operator is holding.
    Two functions with that name in one module is a shadowing bug, and the
    one that loses is whichever is defined first.

    `--ask writes` means different things depending on whether writes are on
    at all: with them, hold the call; without them, there is nothing to hold,
    so the tools are annotated and the client may prompt. Keeping that
    derivation here means the five-value --approve matrix no longer has to be
    something a person picks from.
    """
    args.allow_writes = bool(getattr(args, "write", False))
    ask = getattr(args, "ask", "writes")
    if ask == "always":
        args.approve = "gate-all"
    elif ask == "never":
        args.approve = "none"
    else:
        args.approve = "gate-writes" if args.allow_writes else "hint-writes"


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    global TRACE_PATH
    argv = insert_default_command(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    for name, value in CLI_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, value)
    resolve_ask_mode(args)
    TRACE_PATH = getattr(args, "trace", None)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        console.print("\n[dim]interrupted[/dim]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
