#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "torch>=2.2",
#     "transformers>=4.57",
#     "detect-secrets>=1.5",
#     "rich>=13.7",
#     "datasets>=3.0",
# ]
# ///
"""Measure airlock's full guard stack against public annotated PII corpora.

Every threshold in the guard was tuned on eval/dataset.jsonl, 320 records
generated for this project. That set is measurably easier than reality: the
PII detector scores 1.00 precision on it against 0.428 and 0.236 on the
hardest corpora its own model card reports (SPY and MAPA). Real-world
precision and recall were, until this script, unmeasured. See eval/README.md
for the numbers this run produced.

"Full stack" means airlock.evaluate(), not the encoders alone: scan_secrets
and scan_pii_patterns run first and short-circuit before either model is
asked. The model card's numbers cover the encoder in isolation; this is the
first measurement of the combination airlock actually ships.

Corpora, all public and unauthenticated:

    ai4privacy/pii-masking-300k
    nvidia/Nemotron-PII
    gretelai/synthetic_pii_finance_multilingual
    mattmdjaga/text-anonymization-benchmark-val-test  (community mirror of TAB)

SPY and MAPA, the two hardest corpora on the PII detector's own model card,
are not publicly obtainable and are not measured here. SPY is the hardest of
the two (0.428 precision on the model card); its absence means the numbers
below are not directly comparable to the model card's full table, and are
plausibly optimistic relative to what SPY would have shown.

English only. All four corpora are multilingual; airlock's patterns and
rules are English. Each loader filters to English (or the closest field a
corpus offers) and states what it filtered.

The label mapping is the crux of this measurement, so it is data, not a
conditional, with a one-line reason for every inclusion and exclusion. See
the *_BLOCK / *_EXCLUDE dicts below. A record's gold label is "block" if it
contains at least one span in that corpus's BLOCK set, "approve" otherwise:
negatives come from the same corpus and the same distribution as positives,
not from imported clean text.

Usage:

    uv run --script eval/public_corpora.py
    uv run --script eval/public_corpora.py --sample 100 --corpora ai4privacy,tab
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.table import Table

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from airlock import evaluate, mask  # noqa: E402

console = Console()

# Same seed build_dataset.py uses, for the same reason: fixed, so the sample
# drawn from each corpus is identical across runs.
DEFAULT_SEED = 20260817
DEFAULT_SAMPLE = 250


@dataclass
class Record:
    corpus: str
    record_id: str
    text: str
    gold: str  # "block" or "approve"
    blocking: list[dict[str, str]] = field(default_factory=list)  # [{"label","value"}]
    all_labels: set[str] = field(default_factory=set)


@dataclass
class Decision:
    record: Record
    predicted: str
    layer: str
    latency_ms: float
    error: str = ""


def _check_coverage(corpus: str, seen: set[str], block: dict[str, str], exclude: dict[str, str]) -> None:
    """Every label the sample actually contains must have a mapping decision.

    A label with no entry is neither obviously safe to ignore nor obviously
    identifying, so silently treating it as "approve" would understate
    recall without anyone deciding that on purpose.
    """
    unknown = seen - set(block) - set(exclude)
    assert not unknown, (
        f"{corpus}: unmapped labels {sorted(unknown)}. Add each to its BLOCK "
        "or EXCLUDE dict with a one-line reason before running."
    )


# ---------------------------------------------------------------------------
# ai4privacy/pii-masking-300k
#
# field: source_text   spans: privacy_mask [{value,start,end,label}]
# language field has values "English", "Dutch", "French"; filtered to English.
# ---------------------------------------------------------------------------

AI4PRIVACY_BLOCK: dict[str, str] = {
    "EMAIL": "email address, direct identifier",
    "TEL": "phone number, direct identifier",
    "SOCIALNUMBER": "national id",
    "IDCARD": "national id",
    "PASSPORT": "national id / travel document",
    "DRIVERLICENSE": "national id",
    "BOD": "date of birth, kept unlike generic dates",
    "GIVENNAME1": "person name",
    "GIVENNAME2": "person name",
    "LASTNAME1": "person name",
    "LASTNAME2": "person name",
    "LASTNAME3": "person name",
    "STREET": "address component",
    "BUILDING": "address component",
    "SECADDRESS": "address component",
    "POSTCODE": "address component",
    "PASS": "password, a credential",
    "IP": "network identifier, akin to an account number for a device",
    "GEOCOORD": "precise geocoordinate, address-equivalent identifier",
}
AI4PRIVACY_EXCLUDE: dict[str, str] = {
    "TIME": "generic time of day; blocking a bare timestamp would be wrong",
    "DATE": "generic date, not a date of birth",
    "USERNAME": "handle/alias, not a real-world direct identifier",
    "STATE": "generic geography, too coarse alone to identify",
    "CITY": "generic geography, too coarse alone to identify",
    "COUNTRY": "generic geography, too coarse alone to identify",
    "SEX": "generic demographic attribute, not a direct identifier",
    "TITLE": "honorific (Mr./Dr.), not identifying",
    "CARDISSUER": "card brand name (e.g. Visa), not an account number",
}


def load_ai4privacy(sample_n: int, seed: int) -> list[Record]:
    from datasets import load_dataset

    ds = load_dataset("ai4privacy/pii-masking-300k", split="validation")
    ds = ds.filter(lambda r: r["language"] == "English")
    ds = ds.shuffle(seed=seed).select(range(min(sample_n, len(ds))))

    records: list[Record] = []
    seen_labels: set[str] = set()
    for i, row in enumerate(ds):
        spans = row["privacy_mask"]
        labels = {m["label"] for m in spans}
        seen_labels |= labels
        blocking = [
            {"label": m["label"], "value": m["value"]}
            for m in spans
            if m["label"] in AI4PRIVACY_BLOCK
        ]
        records.append(
            Record(
                corpus="ai4privacy",
                record_id=row.get("id") or f"ai4privacy-{i}",
                text=row["source_text"],
                gold="block" if blocking else "approve",
                blocking=blocking,
                all_labels=labels,
            )
        )
    _check_coverage("ai4privacy", seen_labels, AI4PRIVACY_BLOCK, AI4PRIVACY_EXCLUDE)
    return records


# ---------------------------------------------------------------------------
# nvidia/Nemotron-PII
#
# field: text   spans: spans, a python-repr string of [{start,end,text,label}]
# locale field has values "us" and "intl"; filtered to "us" as the clearly
# English-language subset (there is no separate language field).
# ---------------------------------------------------------------------------

NEMOTRON_BLOCK: dict[str, str] = {
    "account_number": "account/card number",
    "api_key": "credential",
    "bank_routing_number": "account/card number",
    "biometric_identifier": "direct identifier",
    "blood_type": "medical",
    "certificate_license_number": "national id / license",
    "coordinate": "precise geocoordinate, address-equivalent identifier",
    "credit_debit_card": "account/card number",
    "customer_id": "direct identifier",
    "cvv": "account/card number",
    "date_of_birth": "date of birth, kept unlike generic dates",
    "device_identifier": "direct identifier",
    "email": "email address, direct identifier",
    "employee_id": "direct identifier",
    "fax_number": "phone number, direct identifier",
    "first_name": "person name",
    "health_plan_beneficiary_number": "medical",
    "http_cookie": "session credential",
    "ipv4": "network identifier",
    "ipv6": "network identifier",
    "last_name": "person name",
    "license_plate": "vehicle identifier",
    "mac_address": "device identifier",
    "medical_record_number": "medical",
    "national_id": "national id",
    "password": "credential",
    "phone_number": "phone number, direct identifier",
    "pin": "credential",
    "postcode": "address component",
    "ssn": "national id",
    "street_address": "address component",
    "swift_bic": "account/card number",
    "tax_id": "national id",
    "unique_id": "direct identifier",
    "vehicle_identifier": "vehicle identifier",
}
NEMOTRON_EXCLUDE: dict[str, str] = {
    "age": "generic demographic attribute, not a direct identifier",
    "city": "generic geography, too coarse alone to identify",
    "company_name": "generic organisation name",
    "country": "generic geography, too coarse alone to identify",
    "county": "generic geography, too coarse alone to identify",
    "date": "generic date, not a date of birth",
    "date_time": "generic timestamp",
    "education_level": "generic attribute, not identifying alone",
    "employment_status": "generic attribute, not identifying alone",
    "gender": "sensitive demographic attribute expressed as a bare word; excluded for the same reason as ai4privacy's SEX",
    "language": "generic attribute (spoken language), not identifying",
    "occupation": "generic attribute, not identifying alone",
    "political_view": "sensitive attribute expressed as a bare word; not in airlock's PII scope (identifiers + medical), excluded for consistency with gender",
    "race_ethnicity": "sensitive attribute expressed as a bare word; same reasoning as political_view",
    "religious_belief": "sensitive attribute expressed as a bare word; same reasoning as political_view",
    "sexuality": "sensitive attribute expressed as a bare word; same reasoning as political_view",
    "state": "generic geography, too coarse alone to identify",
    "time": "generic time of day; blocking a bare timestamp would be wrong",
    "url": "generic URL",
    "user_name": "handle/alias, not a real-world direct identifier",
}


def load_nemotron(sample_n: int, seed: int) -> list[Record]:
    from datasets import load_dataset

    ds = load_dataset("nvidia/Nemotron-PII", split="test")
    ds = ds.filter(lambda r: r["locale"] == "us")
    ds = ds.shuffle(seed=seed).select(range(min(sample_n, len(ds))))

    records: list[Record] = []
    seen_labels: set[str] = set()
    for i, row in enumerate(ds):
        spans = ast.literal_eval(row["spans"])
        labels = {s["label"] for s in spans}
        seen_labels |= labels
        blocking = [
            {"label": s["label"], "value": s["text"]}
            for s in spans
            if s["label"] in NEMOTRON_BLOCK
        ]
        records.append(
            Record(
                corpus="nemotron",
                record_id=row.get("uid") or f"nemotron-{i}",
                text=row["text"],
                gold="block" if blocking else "approve",
                blocking=blocking,
                all_labels=labels,
            )
        )
    _check_coverage("nemotron", seen_labels, NEMOTRON_BLOCK, NEMOTRON_EXCLUDE)
    return records


# ---------------------------------------------------------------------------
# gretelai/synthetic_pii_finance_multilingual
#
# field: generated_text   spans: pii_spans, JSON string of [{start,end,label}]
# (no "value"/"text" key in this corpus's span records; the value is sliced
# from generated_text by offset). language field filtered to "English".
# ---------------------------------------------------------------------------

GRETEL_BLOCK: dict[str, str] = {
    "account_pin": "credential",
    "api_key": "credential",
    "bank_routing_number": "account/card number",
    "bban": "account/card number",
    "credit_card_number": "account/card number",
    "credit_card_security_code": "account/card number",
    "customer_id": "direct identifier",
    "date_of_birth": "date of birth, kept unlike generic dates",
    "driver_license_number": "national id",
    "email": "email address, direct identifier",
    "employee_id": "direct identifier",
    "first_name": "person name",
    "iban": "account/card number",
    "ipv4": "network identifier",
    "ipv6": "network identifier",
    "last_name": "person name",
    "local_latlng": "precise geocoordinate, address-equivalent identifier",
    "name": "person name",
    "passport_number": "national id",
    "password": "credential",
    "phone_number": "phone number, direct identifier",
    "ssn": "national id",
    "street_address": "address component",
    "swift_bic_code": "account/card number",
}
GRETEL_EXCLUDE: dict[str, str] = {
    "company": "generic organisation name",
    "date": "generic date, not a date of birth",
    "date_time": "generic timestamp",
    "time": "generic time of day; blocking a bare timestamp would be wrong",
    "user_name": "handle/alias, not a real-world direct identifier",
}


def load_gretel(sample_n: int, seed: int) -> list[Record]:
    from datasets import load_dataset

    ds = load_dataset("gretelai/synthetic_pii_finance_multilingual", split="test")
    ds = ds.filter(lambda r: r["language"] == "English")
    ds = ds.shuffle(seed=seed).select(range(min(sample_n, len(ds))))

    records: list[Record] = []
    seen_labels: set[str] = set()
    for i, row in enumerate(ds):
        text = row["generated_text"]
        spans = json.loads(row["pii_spans"])
        labels = {s["label"] for s in spans}
        seen_labels |= labels
        blocking = [
            {"label": s["label"], "value": text[s["start"] : s["end"]]}
            for s in spans
            if s["label"] in GRETEL_BLOCK
        ]
        records.append(
            Record(
                corpus="gretel",
                record_id=f"gretel-{row.get('index', i)}",
                text=text,
                gold="block" if blocking else "approve",
                blocking=blocking,
                all_labels=labels,
            )
        )
    _check_coverage("gretel", seen_labels, GRETEL_BLOCK, GRETEL_EXCLUDE)
    return records


# ---------------------------------------------------------------------------
# mattmdjaga/text-anonymization-benchmark-val-test (TAB mirror)
#
# field: text   annotations: per-annotator entity_mentions, each with
# identifier_type in {DIRECT, QUASI, NO_MASK} and confidential_status
# ("NOT_CONFIDENTIAL" or a sensitive-attribute tag). quality_checked lists
# which annotator(s) are this document's reference annotation.
#
# Gold uses identifier_type == "DIRECT" only: TAB's own scheme is that a
# DIRECT identifier (a name, an exact case number, a precise address) alone
# singles someone out, while a QUASI identifier only does so in combination
# with others, and NO_MASK is explicitly marked as not needing masking by
# TAB's own annotators. confidential_status's sensitive-attribute tags
# (HEALTH, POLITICS, ETHNIC, BELIEF, SEX) are not folded in as an extra
# blocking axis, for the same reason gender/political_view/race_ethnicity/
# religious_belief/sexuality are excluded for Nemotron: these are bare
# sensitive-category words, not identifiers, and outside airlock's own PII
# scope. Where a document has multiple quality-checked annotators, a span is
# blocking if ANY of them marked it DIRECT (any single reader concluding an
# identifier is present is enough to make the message unsafe to send).
#
# Text is ECHR case judgments and is English in this corpus; no separate
# language field exists and none was needed.
# ---------------------------------------------------------------------------


def load_tab(sample_n: int, seed: int) -> list[Record]:
    from datasets import load_dataset

    ds = load_dataset("mattmdjaga/text-anonymization-benchmark-val-test", split="test")
    ds = ds.shuffle(seed=seed).select(range(min(sample_n, len(ds))))

    records: list[Record] = []
    for row in ds:
        blocking: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        for annotator in row["quality_checked"]:
            for e in row["annotations"][annotator]["entity_mentions"]:
                if e["identifier_type"] != "DIRECT":
                    continue
                if e["entity_mention_id"] in seen_ids:
                    continue
                seen_ids.add(e["entity_mention_id"])
                blocking.append({"label": "direct_identifier", "value": e["span_text"]})
        records.append(
            Record(
                corpus="tab",
                record_id=row["doc_id"],
                text=row["text"],
                gold="block" if blocking else "approve",
                blocking=blocking,
            )
        )
    return records


LOADERS: dict[str, Callable[[int, int], list[Record]]] = {
    "ai4privacy": load_ai4privacy,
    "nemotron": load_nemotron,
    "gretel": load_gretel,
    "tab": load_tab,
}


# ---------------------------------------------------------------------------
# Running the real guard and reporting
# ---------------------------------------------------------------------------


def run_record(record: Record) -> Decision:
    start = time.perf_counter()
    try:
        verdict = evaluate(record.text)
    except Exception as exc:  # noqa: BLE001 - fail closed, same as the guard itself
        latency = (time.perf_counter() - start) * 1000
        return Decision(record=record, predicted="block", layer="error", latency_ms=latency, error=str(exc))
    latency = (time.perf_counter() - start) * 1000
    predicted = "approve" if verdict.decision == "approve" else "block"
    layer = verdict.layers_run[-1] if verdict.layers_run else "none"
    return Decision(record=record, predicted=predicted, layer=layer, latency_ms=latency)


def report_corpus(corpus: str, decisions: list[Decision]) -> dict[str, Any]:
    tp = sum(1 for d in decisions if d.record.gold == "block" and d.predicted == "block")
    fp = sum(1 for d in decisions if d.record.gold == "approve" and d.predicted == "block")
    fn = sum(1 for d in decisions if d.record.gold == "block" and d.predicted == "approve")
    tn = sum(1 for d in decisions if d.record.gold == "approve" and d.predicted == "approve")
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    layer_counts: dict[str, int] = {}
    for d in decisions:
        if d.record.gold == "block" and d.predicted == "block":
            layer_counts[d.layer] = layer_counts.get(d.layer, 0) + 1

    fn_examples = []
    for d in decisions:
        if d.record.gold == "block" and d.predicted == "approve":
            fn_examples.append(
                {
                    "id": d.record.record_id,
                    "labels": sorted({b["label"] for b in d.record.blocking}),
                    "masked_values": [mask(b["value"]) for b in d.record.blocking[:3]],
                }
            )

    n_approve_gold = tn + fp
    return {
        "corpus": corpus,
        "n": len(decisions),
        "n_block_gold": tp + fn,
        "n_approve_gold": n_approve_gold,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "layer_counts": layer_counts,
        "fn_examples": fn_examples[:5],
        "weak_negatives": n_approve_gold < 20,
    }


def print_report(results: list[dict[str, Any]]) -> None:
    table = Table(title="airlock full guard stack vs public corpora")
    table.add_column("corpus")
    table.add_column("n")
    table.add_column("block/approve (gold)")
    table.add_column("precision")
    table.add_column("recall")
    table.add_column("f1")
    table.add_column("false negatives")

    total_tp = total_fp = total_fn = total_tn = 0
    for r in results:
        table.add_row(
            r["corpus"],
            str(r["n"]),
            f"{r['n_block_gold']}/{r['n_approve_gold']}"
            + (" [weak: <20 negatives]" if r["weak_negatives"] else ""),
            f"{r['precision']:.3f}",
            f"{r['recall']:.3f}",
            f"{r['f1']:.3f}",
            str(r["fn"]),
        )
        total_tp += r["tp"]; total_fp += r["fp"]; total_fn += r["fn"]; total_tn += r["tn"]
    console.print(table)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    console.print(
        f"\ncombined across corpora (not a single distribution, read per-corpus rows first): "
        f"precision {precision:.3f}  recall {recall:.3f}  f1 {f1:.3f}  "
        f"false negatives {total_fn}/{total_tp + total_fn}"
    )

    console.print("\nlayer attribution on true positives (which layer actually caught it):")
    combined_layers: dict[str, int] = {}
    for r in results:
        for layer, count in r["layer_counts"].items():
            combined_layers[layer] = combined_layers.get(layer, 0) + count
        if r["layer_counts"]:
            console.print(f"  {r['corpus']}: {r['layer_counts']}")
    console.print(f"  combined: {combined_layers}")

    for r in results:
        if r["fn_examples"]:
            console.print(f"\n{r['corpus']} false negatives (masked):")
            for ex in r["fn_examples"]:
                console.print(f"  {ex['id']}: labels={ex['labels']} values={ex['masked_values']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpora", default=",".join(LOADERS), help="Comma separated corpus names.")
    ap.add_argument("--sample", type=int, default=DEFAULT_SAMPLE, help="Records per corpus (after language filtering).")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--out", type=Path, default=HERE / "results")
    args = ap.parse_args()

    wanted = [c.strip() for c in args.corpora.split(",") if c.strip()]
    args.out.mkdir(parents=True, exist_ok=True)

    all_results = []
    trace_path = args.out / "public_corpora_trace.jsonl"
    with trace_path.open("w") as trace_fh:
        for corpus in wanted:
            loader = LOADERS[corpus]
            console.print(f"\nloading {corpus} (sample={args.sample}, seed={args.seed})...")
            records = loader(args.sample, args.seed)
            console.print(f"  {len(records)} records, {sum(1 for r in records if r.gold == 'block')} block / "
                          f"{sum(1 for r in records if r.gold == 'approve')} approve")

            decisions = []
            for i, record in enumerate(records):
                d = run_record(record)
                decisions.append(d)
                trace_fh.write(json.dumps({
                    "corpus": corpus, "id": record.record_id, "gold": record.gold,
                    "predicted": d.predicted, "layer": d.layer,
                    "latency_ms": round(d.latency_ms, 2), "error": d.error,
                }) + "\n")
                if (i + 1) % 50 == 0:
                    console.print(f"  {i + 1}/{len(records)}")

            all_results.append(report_corpus(corpus, decisions))

    print_report(all_results)
    summary_path = args.out / "public_corpora_summary.json"
    summary_path.write_text(json.dumps({"seed": args.seed, "sample": args.sample, "results": all_results}, indent=2))
    console.print(f"\nwrote {trace_path} and {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
