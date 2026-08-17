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
    airlock doctor              check that everything is set up
    airlock                     talk to the local model interactively (default)
    airlock ask "question"      one-shot question
    airlock guard "text"        test whether text would pass the guard
    airlock serve               run as an MCP server for a cloud assistant

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
import re
import subprocess
import sys
import textwrap
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
# detect at all. Wired into evaluate() below. Scoring logic ported from
# eval/bakeoff.py's PIIDetectorGuard and PolicyLinterGuard, not reinvented.
# See PLAN-liquid-guard.md for the evidence behind this replacement and the
# trust_remote_code=True tradeoff it takes on.
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

# Blocking policy for the detector's 40-type taxonomy. The Presidio layer
# this replaced had BLOCKING_ENTITIES, a curated set with a one-line reason
# for each exclusion (see git history before the swap: "DATE_TIME and URL
# are deliberately excluded: they fire constantly on ordinary text and would
# make the guard useless through false positives"). That concept was dropped
# in the swap, and PLAN-liquid-guard.md's fix round 2 is the reason it is
# back: scan_pii_model was blocking on ANY non-O label with no notion of
# which ones warrant it or at what confidence, and 2.7% of bare
# number-shaped job answers (measured: 8/300 sampled) false-flagged as
# contact.postal_code, landing squarely on the tax-extraction workflow this
# tool exists for.
#
# No entity type is excluded outright, unlike Presidio's set. Measurement
# found no category here that fires on ordinary text the way DATE_TIME/URL
# did: this taxonomy has no generic date/time label to begin with, and
# sample URL-bearing sentences never triggered online.url at all. The
# precision problem measured was confidence-level on one type, not
# category-level noise, so the fix below is a per-entity threshold, not an
# exclusion list. If a category-level problem is measured later, exclude it
# here with the same one-sentence-justification bar this comment describes,
# rather than lowering its threshold to the point of never firing.
#
# Also measured, and recorded rather than fixed: identity.person_name fires
# on bare single common nouns that double as given names ("cherry" 0.90,
# "kiwi" 0.96, "lemon" 0.64, "olive" 0.98), while business vocabulary and
# short prose measured clean (0/27 sampled). This is why
# tests/test_round_guard.py's twelve-item benign-round fixture uses
# business/operational words rather than a fruit list: the detector was
# doing its job on an unrepresentative fixture, not regressing. Narrow
# enough, and rare enough in what a real extraction job returns, that it did
# not meet the bar for a threshold override the way contact.postal_code did.
#
# Mirrors POLICY_LINTER_RULE_THRESHOLDS's shape on the linter side: a sparse
# override dict, PII_DETECTOR_THRESHOLD as the default for every entity not
# listed.
PII_DETECTOR_ENTITY_THRESHOLDS: dict[str, float] = {
    # Measured directly against this model (scratch script, not committed):
    # bare context-free numbers that false-flag as a postal code score
    # 0.524-0.565 (matches the 8/300 sweep above); real postal codes and
    # addresses in surrounding context score 0.845-0.998, with one real
    # address recall miss at 0.000 (already below any threshold considered,
    # so raising this cannot cost that case further). 0.70 sits above that
    # first cluster, which is why it cuts the false-positive rate.
    #
    # It does not eliminate it. A follow-up 300-sample sweep at 0.70
    # (task-4-report.md) found 2/300 (0.67%, roughly one bare number in 150
    # on this workflow) still false-flag, at 0.856 and 0.764. 0.856 is
    # *above* the lowest measured true positive (0.845): the false-positive
    # and true-positive score distributions overlap, so no single global
    # threshold on this entity separates them cleanly. Raising the threshold
    # past 0.856 to catch that case would also silence the 0.845 true
    # positive, trading a smaller false-positive rate for a directly
    # measured recall loss. 0.70 is the best tradeoff point found, not a
    # clean separator.
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
# (tests/test_server.py's CREDENTIAL_SHAPES: "dop_v1_" + 64 hex chars = 71
# chars), with margin, so a credential split by a chunk boundary still lands
# whole inside at least one chunk. An unbounded-length secret (SECRET_PATTERNS'
# generic_secret_assignment has no upper bound) can still exceed this; that
# residual is inherent to any finite overlap, not something this bound closes.
PII_CHUNK_OVERLAP_CHARS = 200


def resolve_device(choice: str = "auto") -> str:
    """Pick a torch device: MPS on Apple Silicon, then CUDA, then CPU.

    Ported from eval/bakeoff.py's resolve_device. Both encoders are
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
    accepted supply-chain risk recorded in PLAN-liquid-guard.md and README.md,
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
# global 0.70. Rule 5 (confidential business) deliberately stays low; see the
# operating-point note in PLAN-liquid-guard.md.
POLICY_LINTER_RULE_THRESHOLDS: dict[int, float] = {1: 0.98, 4: 0.98}

# Free-text rules, scored per token, zero-shot. Order is the rule index used
# in findings ("rule0" .. "rule5") and ported verbatim from eval/bakeoff.py.
# Identifier rules are deliberately absent: the linter measures poorly on
# exact identifiers, that coverage belongs to scan_pii_model.
CONTEXTUAL_RULES: list[str] = [
    "Flag disclosure of a medical condition, diagnosis, treatment, or mental health.",
    "Flag disclosure of financial hardship, debt, bankruptcy, or inability to pay.",
    "Flag disclosure of a lawsuit, legal dispute, settlement, or investigation.",
    "Flag disclosure of addiction, recovery, or substance use.",
    "Flag disclosure of immigration or visa status.",
    "Flag confidential business information such as unannounced acquisitions or a customer leaving.",
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
    on deliberately and recorded in PLAN-liquid-guard.md and README.md, and
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
    tests do, still takes effect immediately. Rule-pool construction is
    ported unchanged from eval/bakeoff.py's PolicyLinterGuard.decide: each
    rule's pooled span has to land on that rule's own tokens inside the
    prompt prefix, not on the input text, which is fiddly and already
    measured there. Raises GuardModelUnavailable rather than returning empty
    on any failure, matching scan_pii_model.
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
                "Writes are disabled. Enable with --allow-writes, or /config writes on."
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


def evaluate(message: str, linter_threshold: float = POLICY_LINTER_THRESHOLD) -> GuardVerdict:
    """Run every guard layer over a candidate message.

    Layers run cheapest and most certain first and short-circuit, since a
    confirmed match needs no further opinion:

        secrets -> pii-patterns -> pii-detector -> policy-linter

    Any layer that cannot run blocks the message rather than being skipped, so
    a missing dependency (here: torch/transformers, or a model that fails to
    load) degrades into refusal rather than into silent permissiveness.
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


def evaluate_session(session: Session, text: str) -> GuardVerdict:
    """Run the guard using a session's configuration."""
    return evaluate(text, session.linter_threshold)


# --------------------------------------------------------------------------
# Round-level reassembly guard. See PLAN-round-reassembly.md.
#
# A caller can split a protected value across several jobs and scatter benign
# jobs between the fragments; the shape-based scanners above miss that
# because they need the fragments adjacent. This anchors on the identifiers
# actually present in the workspace instead, so it matches a known value
# rather than a shape and survives dilution and interleaving.
# --------------------------------------------------------------------------

MIN_REASSEMBLY_LENGTH = 6

# Bounds the total normalised length of one round's values, not just their
# count. _subset_concatenations' cost scales with the number of subsets
# (2**len(values), already capped by MAX_JOBS_PER_ROUND) and the length of
# what gets copied into each one; _subset_contains then tests every source
# identifier against every subset, so cost also scales with how many
# identifiers are in the workspace, not with length alone. This bound exists
# because of a pre-bound measurement: 12 unshaped answers of FILE_SLICE_CHARS
# (4000) each against 400 workspace identifiers took 18.0 seconds on the
# guard path itself, a denial of service on the path that is supposed to
# protect against one. That exact scenario is no longer reachable through
# this function: the length check below now rejects a round that large in
# O(1), before the subset enumeration ever runs. At the bound's own ceiling
# (12 values summing to 4000 characters) against 400 non-matching workspace
# identifiers, the bounded function still costs seconds, not milliseconds:
# eval/reassembly_residuals.py measured a mean of 4.452s (median 4.416s) over
# 5 reps. A round of shaped jobs cannot approach that ceiling: twelve
# "line"-shaped answers (JOB_SHAPES maxLength 80) sum to at most 960
# characters, and identifier count is what actually decides the rest: the same
# script measured 10ms at one identifier, 153ms at fifty and 1230ms at four
# hundred, and a workspace built from three ordinary documents yields five
# identifiers, so that round costs 17ms. The four-hundred figures above are
# pathological rather than representative.
# FILE_SLICE_CHARS, the size of a single document slice, is a generous
# ceiling for a whole round that leaves realistic traffic untouched while
# still bounding unshaped free-text answers.
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


def reassembles_identifier(values: list[str], sources: set[str]) -> bool:
    """True if the values together reconstruct a source identifier that none
    of them contains on its own.

    Benign job results routinely sit between the fragments, since that costs
    a caller nothing and is exactly how the round-level shape check upstream
    was defeated (see PLAN-round-reassembly.md). So this does not require the
    fragments adjacent: a source identifier counts as reconstructed once it is
    a substring of the concatenation of SOME subset of the round's normalised
    values, kept in job order.

    A character-level subsequence test (ignoring which values the characters
    came from) was tried first and rejected: measured on legitimate rounds of
    twelve numeric answers, it false-blocked 38.0% of them, because a round
    normalises to roughly 60 characters and a coincidental in-order digit
    match is not actually rare at that length. Matching whole values instead
    of loose characters is what keeps a false block a needed conjunction of
    real fragments rather than a coincidence of stray digits, and it measured
    zero false blocks on the same rounds.

    Residual, stated rather than implied: this preserves job order and does
    not permute, so a caller that issues its jobs out of order defeats it.
    Closing that costs 12! arrangements for a full round and was judged not
    worth it. Reassembly across separate rounds is also out of scope here.

    A second gap, now CLOSED for numeric identifiers: this tests substring
    containment, so a fragment padded with extra characters can defeat it,
    because the padding sits between fragments in the concatenation and
    breaks the contiguous run the source identifier needs. Measured over 200
    trials per padding shape with benign jobs interleaved, every shape
    (suffix, prefix, both sides, and prose filler) drove detection to 0.00,
    not just one side of the fragment as an earlier version of this comment
    implied. Closed by re-running the same subset test on a digits-only
    projection of each value, restricted to sources that are themselves
    all-digit: non-digit padding is not a digit, so it vanishes from the
    projection while the identifier's own digits stay contiguous in job
    order. That brought detection back to 1.00 on all four padding shapes,
    with 0.000 false blocking measured on six legitimate round shapes
    including twelve 16-digit values, the shape that took a rejected
    alternative (letting each value contribute any contiguous substring
    instead of only whole values) to 100% false blocking.

    The gap remains OPEN for alphanumeric identifiers such as API keys,
    padded on every fragment: an identifier with a letter in it is excluded
    from the projection by construction, since the projection would discard
    the letters that make the match meaningful, so those still rely on the
    raw pass above.

    A residual the padding measurement did not probe, since it varied round
    shape but not source length or source count: false blocking at the
    MIN_REASSEMBLY_LENGTH floor. Many short (six digit) all-digit sources
    against a digit-dense round of ordinary prose, amounts, dates, box
    numbers and reference numbers can coincidentally reconstruct one of
    them, even though nothing was actually split. Six digits is reachable
    in practice because labelled_account accepts [0-9][0-9-]{6,}, so a
    hyphenated sort-code-shaped account number normalises to exactly six
    digits, right at the floor. A digit-dense round also produces incidental
    digit runs of its own (dates, amounts, box and reference numbers
    concatenated in job order can abut without a separator), so this floor
    is not unique to the digits-only projection: the raw pass false-blocks
    here too. Measured over 300 seeded trials (eval/reassembly_residuals.py),
    20/40/60 six-digit sources against such a round: 0.0000 to 0.0133 false
    blocking for the shipped function, 0.0000 to 0.0067 for the raw pass
    alone, so the projection adds to the raw pass's floor rather than
    creating it. Eight- and nine-digit sources measured 0.000 for both.
    Every figure stays well under the 12.8% that disqualified the rejected
    substr design, and it errs toward blocking rather than approving, so
    this is not a reason to change the design, only to state it.

    Bounded defensively at MAX_JOBS_PER_ROUND and MAX_REASSEMBLY_LENGTH
    rather than trusting the caller: _subset_concatenations is
    2**len(values) and its cost per subset scales with total value length,
    and run_jobs enforcing MAX_JOBS_PER_ROUND upstream is a convention, not a
    guarantee this function can rely on. A round this function cannot
    evaluate within bound is treated as a block, the same rule `evaluate`
    follows when a layer is unavailable: a guard that cannot evaluate must
    never approve.
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

    # Digits-only projection. Only reached when the raw pass above misses,
    # which costs a second full subset enumeration; what keeps the common
    # case cheap is `not candidates` above and `not numeric` below, since a
    # round with no matching source at all, or with only alphanumeric
    # sources, returns before either enumeration runs twice. Restricted to
    # sources that are themselves all-digit: projecting an alphanumeric
    # identifier would discard the letters that make the match meaningful,
    # so those keep relying on the raw pass.
    numeric = {source for source in candidates if source.isdigit()}
    if not numeric:
        return False
    projected = ["".join(c for c in v if c.isdigit()) for v in normalised]
    if not any(projected):
        return False
    return _subset_contains(projected, numeric)


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
        # had (see task-2-report.md fix round 2). not_found, matching the
        # vocabulary above, rather than a guarded, empty "ok".
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
    # which evaluate_session's shape-based scanners need adjacent to see (see
    # PLAN-round-reassembly.md).
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
        )

    if not draft:
        return envelope(session, "blocked", "", ["the local model produced no answer"])

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
    session: Session, status: str, message: str, concerns: list[str]
) -> dict[str, Any]:
    """Build the structured reply, stating plainly when content was withheld.

    The single choke point for anything leaving for the caller, which is why
    concern sanitising happens here rather than at each call site.
    """
    return {
        "session": session.session_id,
        "status": status,
        "message": message,
        "withheld": bool(concerns),
        "guard_concerns": sanitise_concerns(concerns),
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
            # tests/test_liquid_guard.py, already measured there to trigger
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
        "[bold green]Ready.[/bold green] Run [cyan]airlock[/cyan] to start a session."
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


def render_mcp_help(args: argparse.Namespace) -> None:
    """Print ready-to-paste client configuration for this exact workspace.

    Shown because a user who has just started chatting has no way to discover
    that the same workspace can be served to a cloud assistant, and the paths
    have to be absolute, which is the detail people get wrong.
    """
    root = Path(args.root).expanduser().resolve()
    script = Path(__file__).resolve()
    config = {
        "mcpServers": {
            "airlock": {
                "command": "uv",
                "args": [
                    "run", "--script", str(script),
                    "serve", "--root", str(root),
                    "--model", args.model,
                ],
            }
        }
    }
    console.print(
        Panel(
            Group(
                Text("Serve this workspace to a cloud assistant.", style="bold"),
                Text(""),
                Text("Claude Desktop, in claude_desktop_config.json:", style="dim"),
                Text(json.dumps(config, indent=2), style="cyan"),
                Text(""),
                Text("Claude Code:", style="dim"),
                Text(
                    f"claude mcp add airlock -- uv run --script {script} "
                    f"serve --root {root}",
                    style="cyan",
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

    Reports step counts, action kinds and guard verdicts. Never paths, match
    counts, topics or anything else derived from file contents: the guard
    inspects answer text and never sees this metadata, so content-derived
    facts here would be an unguarded oracle. See CLAUDE.md.
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

    tty = tty_handle() if args.approve.startswith("gate") else None
    if args.approve.startswith("gate") and tty is None:
        # Refusing is the point. Falling back to no approval would turn a
        # request for a gate into silence, which is the worst of the available
        # outcomes and the one that happens if nobody checks.
        raise RuntimeError(
            f"--approve {args.approve} needs a terminal to ask on, and there is none.\n"
            "  stdin is the JSON-RPC stream here, so prompting uses /dev/tty, which does\n"
            "  not exist when a GUI client launches this server as a subprocess.\n"
            "  Run airlock in a terminal, or choose --approve hint-writes to let the "
            "client ask."
        )

    mcp = MCPServer("airlock")

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
            allowed = confirm_on_tty(
                tty, f"Allow this call on {sandbox.root.name}? ({question.strip()[:60]})"
            )
            trace("approval", session=session, granted=allowed, mode=args.approve)
            if not allowed:
                err_console.print(Text.assemble(("  └ denied  ", "bold red"), ("by operator", "")))
                return {"status": "denied", "message": "The operator declined this call."}

        actions: list[str] = []
        reporter = serve_reporter(session)

        def watch(action: str, detail: str) -> None:
            actions.append(action)
            reporter(action, detail)

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


def cmd_quickstart(args: argparse.Namespace) -> int:
    """Bare `airlock`, with no arguments: orient, check, then start a session.

    The workspace defaults to the current directory, which is convenient and
    also the one genuinely dangerous default in this tool, so it is printed
    before anything else happens and confirmed below when it is too broad.
    """
    console.print(Rule("airlock", style="cyan"))
    console.print(
        "A local model reads one directory and answers questions about it.\n"
        "Nothing reaches an external service until a privacy guard approves it.\n"
    )

    root = Path(args.root).expanduser().resolve()
    console.print(Text.assemble(("workspace   ", "dim"), (str(root), "bold yellow")))
    console.print("[dim]readable by the local model, nothing above it[/dim]\n")

    # Running from a home directory or the filesystem root would expose far
    # more than anyone means to. Neither is refused outright, because there are
    # legitimate reasons, but neither is the default answer either.
    if root == Path.home() or root == root.parent:
        where = "your home directory" if root == Path.home() else "the filesystem root"
        console.print(f"[yellow]That is {where}.[/yellow] Every file beneath it is in scope.")
        console.print("[dim]Prefer: cd into a specific project, or pass --root[/dim]\n")
        if not Confirm.ask("Continue anyway?", default=False):
            return 0

    # First run and a broken install look identical from here, so there is no
    # need to detect which one this is: if doctor is unhappy, offer to fix what
    # is fixable and check again. One retry only, because a second failure of
    # the same repair means the problem is not the one being repaired.
    if cmd_doctor(args) != 0:
        if not offer_repairs(args):
            return 1
        console.print()
        if cmd_doctor(args) != 0:
            return 1

    # Straight into the session. Typing `airlock` is the request; asking
    # "start a session?" afterwards would be confirming something already
    # said. The one prompt kept above is the home-directory guard, which
    # asks about scope rather than intent.
    console.print()
    return cmd_chat(args)


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


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line interface."""
    # Every shared option carries argument_default=SUPPRESS, so an option
    # the user did not type is absent from the namespace rather than present
    # with a default value.
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("--root", type=Path, help="Workspace directory (default: .).")
    common.add_argument("--model", help=f"Local worker model (default: {DEFAULT_MODEL}).")
    common.add_argument("--allow-writes", action="store_true", help="Let the model write files.")
    common.add_argument(
        "--linter-threshold",
        type=_linter_threshold_type,
        help=f"Score above which the policy linter's contextual rules revise a "
        f"message (default: {POLICY_LINTER_THRESHOLD}). Must be between 0.0 and 1.0. "
        "The PII detector's threshold and the per-rule overrides are constants, "
        "not flags, until measured otherwise.",
    )
    common.add_argument(
        "--trace",
        type=Path,
        help="Append guard decisions as JSON lines for later review or scoring. "
        "Records rule names and verdicts only, never message content.",
    )
    common.add_argument(
        "--approve",
        choices=APPROVE_MODES,
        help="Who approves tool calls, and which ones (default: hint-writes, which "
        "becomes gate-writes automatically with --allow-writes). gate-* means airlock "
        "holds the call until you answer on the terminal and is a real control. hint-* "
        "means the tools are annotated so the client can prompt, which it is free to "
        "ignore. none disables both.",
    )
    objective = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS)
    objective.add_argument("--objective", help="Framing for the local model.")

    parser = argparse.ArgumentParser(
        prog="airlock",
        description="A guarded local model that works over one directory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common, objective],
        epilog=(
            "examples:\n"
            "  airlock                          check the setup, then start a session here\n"
            "  airlock --root ~/notes           same, over a specific directory\n"
            "  airlock doctor --root .          check the setup and stop\n"
            '  airlock ask --root . "what topics do these files cover?"\n'
            '  airlock guard "Jane Doe, 555-555-0100"\n'
            "  airlock serve --root ~/project   run as an MCP server\n"
        ),
    )
    parser.set_defaults(func=cmd_quickstart)

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("doctor", parents=[common], help="Check the setup.").set_defaults(
        func=cmd_doctor
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


# Applied after parsing rather than through argparse defaults. See the comment
# in build_parser for why set_defaults cannot be used for these.
CLI_DEFAULTS: dict[str, Any] = {
    "root": Path("."),
    "model": DEFAULT_MODEL,
    "allow_writes": False,
    "linter_threshold": POLICY_LINTER_THRESHOLD,
    "trace": None,
    "approve": "hint-writes",
    "objective": "Help the user understand and work with the files in this directory.",
}


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    global TRACE_PATH
    args = build_parser().parse_args(argv)
    for name, value in CLI_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, value)
    TRACE_PATH = getattr(args, "trace", None)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        console.print("\n[dim]interrupted[/dim]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
