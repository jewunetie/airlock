#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "torch>=2.2",
#     "transformers>=4.57",
#     "rich>=13.7",
# ]
# ///
"""Bake off three guard configurations against the labelled eval set.

    A  privacy-filter   openai/privacy-filter alone
    B  layered          privacy-filter first, granite on whatever it cleared
    C  granite          granite4.1-guardian alone, via its native scoring
                        protocol (GUARDIAN_CRITERIA + GUARDIAN_BLOCK,
                        reading <score>yes</score>)

Config C is NOT the configuration airlock.py ever shipped. When this bake-off
ran, airlock.py called granite as a general judging model with GUARD_PROMPT
and GUARD_SCHEMA, a different mode in which granite performs differently
(spot-checked: native scoring caught 2 of 4 contextual cases, GUARD_PROMPT
caught 4 of 4). The comparison against granite's shipped configuration was
never run; treat config C's results as evidence about granite's native
scoring mode only. airlock.py no longer uses granite at all, so config C
also no longer reflects "the current architecture" in any sense.

Positive class is "block". Precision, recall and F1 are computed with respect
to blocking, so recall is the fraction of genuinely sensitive messages caught
and a false positive is a block on clean prose.

Usage:

    ./bakeoff.py --configs A                 # sandbox, no Ollama needed
    ./bakeoff.py --configs A,B,C             # Mac, with Ollama running
    ./bakeoff.py --configs A --pf-model /local/path/to/weights

Outputs a report to stdout plus results/trace.jsonl and results/summary.json.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.table import Table

console = Console()

HERE = Path(__file__).parent
OLLAMA_HOST = "http://localhost:11434"


def resolve_device(choice: str = "auto") -> str:
    """Pick a torch device.

    Both encoders default to CPU under `from_pretrained`, which on a Mac leaves
    the GPU completely idle. These are single-forward-pass encoders, not
    generative models, so the win here is simply putting the matmuls on Metal.

    There is no MLX build of either model. Both use custom architectures loaded
    through trust_remote_code (a BIOES token-classification head on a bespoke
    bidirectional LFM2 backbone, and a GLiNER-style rule-matching head), and
    MLX conversion tooling targets standard generative architectures. Porting
    them by hand is possible but is not a speedup you get for free. MPS is.
    """
    import torch

    if choice != "auto":
        return choice
    if torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"

# The eight span labels Privacy Filter emits. Every one is an identifier type.
# There is no health, legal, or financial-context label in this taxonomy, which
# is the structural fact the bake-off is designed to measure.
PF_LABELS = [
    "account_number",
    "private_address",
    "private_email",
    "private_person",
    "private_phone",
    "private_url",
    "private_date",
    "secret",
]


# ---------------------------------------------------------------------------
# Result plumbing
# ---------------------------------------------------------------------------
@dataclass
class Decision:
    record_id: str
    category: str
    gold: str
    predicted: str
    findings: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    stage: str = ""
    error: str = ""

    @property
    def correct(self) -> bool:
        return self.gold == self.predicted


# ---------------------------------------------------------------------------
# Config A: Privacy Filter
# ---------------------------------------------------------------------------
class PrivacyFilterGuard:
    """Token classifier. Blocks when any span of a blocking label is found."""

    name = "privacy-filter"

    def __init__(
        self,
        model_path: str,
        threshold: float = 0.5,
        blocking_labels: set[str] | None = None,
    ) -> None:
        import torch
        from transformers import pipeline

        self.threshold = threshold
        self.blocking_labels = blocking_labels or set(PF_LABELS)
        console.print(f"[dim]loading {model_path} on cpu[/dim]")
        t0 = time.perf_counter()
        # bfloat16 is the storage dtype. Loading as float32 doubles the
        # footprint to roughly 5.6GB, which will not fit in a small container.
        # On a CPU without native bf16 matmul (most aarch64) torch falls back
        # to BLAS gemm, which is correct but slow. Latency measured under that
        # fallback does not transfer to Apple Silicon, which has native bf16.
        self.pipe = pipeline(
            task="token-classification",
            model=model_path,
            aggregation_strategy="simple",
            device=-1,
            dtype=torch.bfloat16,
        )
        console.print(f"[dim]loaded in {time.perf_counter() - t0:.1f}s[/dim]")

    def decide(self, text: str) -> tuple[str, list[str], str]:
        spans = self.pipe(text)
        hits = []
        for span in spans:
            label = str(span.get("entity_group") or span.get("entity") or "")
            label = re.sub(r"^[BIES]-", "", label)
            score = float(span.get("score", 0.0))
            if label in self.blocking_labels and score >= self.threshold:
                hits.append(label)
        # Deduplicate while preserving order, so the trace shows which label
        # types fired rather than one entry per occurrence.
        seen: list[str] = []
        for h in hits:
            if h not in seen:
                seen.append(h)
        return ("block" if seen else "approve"), seen, "pf"


# ---------------------------------------------------------------------------
# Config G: LFM2.5 PII-Detector
# ---------------------------------------------------------------------------
class PIIDetectorGuard:
    """LiquidAI/LFM2.5-Encoder-350M-PII-Detector. 40 entity types, 16 languages.

    Measured to strictly dominate openai/privacy-filter on this eval set:
    better precision, better recall, a quarter of the parameters, five times
    faster. Blocks when any non-O label exceeds the threshold.
    """

    name = "pii-detector"
    DEFAULT = "LiquidAI/LFM2.5-Encoder-350M-PII-Detector"

    def __init__(self, model_path: str = DEFAULT, threshold: float = 0.5,
                 device: str = "auto") -> None:
        import torch
        from transformers import AutoModelForTokenClassification, AutoTokenizer

        self.torch = torch
        self.threshold = threshold
        self.device = resolve_device(device)
        console.print(f"[dim]loading {model_path} on {self.device}[/dim]")
        self.tok = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        self.model = AutoModelForTokenClassification.from_pretrained(
            model_path, trust_remote_code=True
        ).eval().to(self.device)
        raw = self.model.config.id2label
        self.id2label = {int(k): v for k, v in raw.items()} if isinstance(raw, dict) else dict(enumerate(raw))

    def decide(self, text: str) -> tuple[str, list[str], str]:
        enc = self.tok(text, return_tensors="pt", truncation=True, max_length=512)
        enc = {k: v.to(self.device) for k, v in enc.items()}
        with self.torch.no_grad():
            logits = self.model(**enc).logits.float().cpu()
        conf, ids = logits.softmax(-1)[0].max(-1)
        found: list[str] = []
        for c, i in zip(conf.tolist(), ids.tolist()):
            label = self.id2label.get(i, "O")
            if label == "O" or c < self.threshold:
                continue
            entity = re.sub(r"^[BIES]-", "", label)
            if entity not in found:
                found.append(entity)
        return ("block" if found else "approve"), found, "pii-detector"


# ---------------------------------------------------------------------------
# Config E: LFM2.5 Policy Linter
# ---------------------------------------------------------------------------
# Free-text rules, scored per token, zero-shot. These cover contextual
# sensitivity, which no span detector can see because there is no span.
# Identifier rules are deliberately NOT included: the linter is poor at exact
# identifiers (measured recall 0.35 on structured PII) and adding those rules
# only contributes false positives. Identifiers are the detector's job.
CONTEXTUAL_RULES = [
    "Flag disclosure of a medical condition, diagnosis, treatment, or mental health.",
    "Flag disclosure of financial hardship, debt, bankruptcy, or inability to pay.",
    "Flag disclosure of a lawsuit, legal dispute, settlement, or investigation.",
    "Flag disclosure of addiction, recovery, or substance use.",
    "Flag disclosure of immigration or visa status.",
    "Flag confidential business information such as unannounced acquisitions or a customer leaving.",
]


class PolicyLinterGuard:
    """LiquidAI/LFM2.5-Encoder-350M-Policy-Linter, GLiNER-style rule matching.

    Measured recall 1.00 on the contextual category at threshold 0.70, against
    0.05 for openai/privacy-filter. Threshold trades precision for recall and
    should be chosen deliberately: see the operating-point note in PLAN.md.
    """

    name = "policy-linter"
    DEFAULT = "LiquidAI/LFM2.5-Encoder-350M-Policy-Linter"

    def __init__(
        self,
        model_path: str = DEFAULT,
        threshold: float = 0.90,
        rules: list[str] | None = None,
        per_rule: dict[int, float] | None = None,
        device: str = "auto",
    ) -> None:
        import torch
        from transformers import AutoModel, AutoTokenizer

        self.torch = torch
        self.device = resolve_device(device)
        self.threshold = threshold
        self.rules = rules or CONTEXTUAL_RULES
        # Per-rule thresholds. A single global cutoff forces the noisiest rule
        # and the most valuable rule to share one operating point, which is
        # what produced precision 0.62 at a global 0.70. Measured false
        # positives by rule at that setting: financial hardship 40,
        # confidential business 34, immigration 24, lawsuit 12, medical 11,
        # addiction 3. Meanwhile confidential business is the only rule that
        # catches the hardest residual cases, so it needs to stay low while
        # the noisy ones are raised.
        self.per_rule = per_rule or {}
        console.print(f"[dim]loading {model_path} on {self.device}[/dim]")
        self.tok = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        self.model = AutoModel.from_pretrained(model_path, trust_remote_code=True).eval().to(self.device)
        self.prefix = "Policy:\n" + "\n".join(f"- {r}" for r in self.rules) + "\n\nText:\n"

    def decide(self, text: str) -> tuple[str, list[str], str]:
        full = self.prefix + text
        enc = self.tok(full, return_offsets_mapping=True, return_tensors="pt", truncation=True, max_length=2048)
        offsets = enc.pop("offset_mapping")[0].tolist()
        pool = self.torch.zeros(1, len(self.rules), len(offsets))
        pos = len("Policy:\n")
        for ri, rule in enumerate(self.rules):
            start = pos + 2
            end = start + len(rule)
            idx = [i for i, (a, b) in enumerate(offsets) if a < end and b > start and a != b]
            if idx:
                pool[0, ri, idx] = 1 / len(idx)
            pos = end + 1
        enc = {k: v.to(self.device) for k, v in enc.items()}
        pool = pool.to(self.device)
        with self.torch.no_grad():
            probs = self.model(**enc, rule_pool=pool)["logits"].float().sigmoid()[0].cpu()
        text_start = len(self.prefix)
        keep = [i for i, (a, b) in enumerate(offsets) if b > text_start and a != b]
        if not keep:
            return "approve", [], "policy-linter"
        sub = probs[keep]
        found = [
            f"rule{ri}"
            for ri in range(len(self.rules))
            if float(sub[:, ri].max()) > self.per_rule.get(ri, self.threshold)
        ]
        return ("block" if found else "approve"), found, "policy-linter"


class UnionGuard:
    """Config I. Independent detectors, union of their verdicts.

    Union rather than cascade because the two cover disjoint failure modes: the
    detector finds identifier spans, the linter finds sensitivity with no span.
    Cascading would let whichever ran first decide, which throws away the other
    one's coverage on exactly the cases it exists for.
    """

    name = "union"

    def __init__(self, *guards: Any) -> None:
        self.guards = guards

    def decide(self, text: str) -> tuple[str, list[str], str]:
        findings: list[str] = []
        stages: list[str] = []
        for g in self.guards:
            decision, f, _ = g.decide(text)
            if decision == "block":
                findings += f
                stages.append(g.name)
        return ("block" if findings else "approve"), findings, "+".join(stages) or "none"


# ---------------------------------------------------------------------------
# Config C: Granite via Ollama
# ---------------------------------------------------------------------------
GUARDIAN_CRITERIA = (
    "The text reveals private or sensitive information about a specific person "
    "or organisation. This includes personal identifiers, financial details, "
    "health or medical information, legal matters, credentials or secrets, and "
    "situations of personal hardship such as illness, addiction, immigration "
    "status, or financial distress, even when no name is given. "
    "Abstract discussion of policy, process, aggregate metrics, or topics that "
    "contains no specific private detail does NOT meet this criterion."
)

GUARDIAN_BLOCK = """<guardian>/nothink

### Criteria: {criteria}

### Scoring Schema: If the last assistant's text meets the criteria, return 'yes'; otherwise, return 'no'.
"""


class GraniteGuard:
    """IBM Granite Guardian via Ollama, using its native yes/no scoring."""

    name = "granite"

    def __init__(self, model: str = "granite4.1-guardian:8b", timeout: int = 120) -> None:
        self.model = model
        self.timeout = timeout

    def decide(self, text: str) -> tuple[str, list[str], str]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "assistant", "content": text},
                {"role": "user", "content": GUARDIAN_BLOCK.format(criteria=GUARDIAN_CRITERIA)},
            ],
            "stream": False,
            "think": False,
            "options": {"temperature": 0},
        }
        req = urllib.request.Request(
            f"{OLLAMA_HOST}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode())
        raw = (body.get("message") or {}).get("content", "") or ""
        match = re.search(r"<score>\s*(yes|no)\s*</score>", raw, re.I)
        if not match:
            match = re.search(r"\b(yes|no)\b", raw, re.I)
        if not match:
            # Fail closed. An unreadable verdict blocks, matching airlock.
            return "block", ["guard-unparseable"], "granite"
        verdict = match.group(1).lower()
        return ("block" if verdict == "yes" else "approve"), (["granite-flag"] if verdict == "yes" else []), "granite"


# ---------------------------------------------------------------------------
# Config B: layered
# ---------------------------------------------------------------------------
class LayeredGuard:
    """Privacy Filter first. Granite only sees what Privacy Filter cleared.

    This is the interesting configuration: the cheap deterministic-ish detector
    handles identifier spans, and the expensive model is spent only on the
    residual, which is where contextual sensitivity lives.
    """

    name = "layered"

    def __init__(self, first: PrivacyFilterGuard, second: GraniteGuard) -> None:
        self.first = first
        self.second = second

    def decide(self, text: str) -> tuple[str, list[str], str]:
        decision, findings, _ = self.first.decide(text)
        if decision == "block":
            return "block", findings, "pf"
        decision2, findings2, _ = self.second.decide(text)
        return decision2, findings2, "granite"


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def confusion(decisions: list[Decision]) -> dict[str, int]:
    tp = sum(1 for d in decisions if d.gold == "block" and d.predicted == "block")
    fp = sum(1 for d in decisions if d.gold == "approve" and d.predicted == "block")
    fn = sum(1 for d in decisions if d.gold == "block" and d.predicted == "approve")
    tn = sum(1 for d in decisions if d.gold == "approve" and d.predicted == "approve")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def metrics(decisions: list[Decision]) -> dict[str, float]:
    c = confusion(decisions)
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    lat = [d.latency_ms for d in decisions if d.latency_ms]
    return {
        **c,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "fnr": fnr,
        "latency_mean_ms": statistics.mean(lat) if lat else 0.0,
        "latency_median_ms": statistics.median(lat) if lat else 0.0,
        "latency_p95_ms": (sorted(lat)[int(len(lat) * 0.95)] if len(lat) > 1 else (lat[0] if lat else 0.0)),
    }


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
def load_partial(path: Path) -> dict[str, Decision]:
    """Read an existing per-config trace so a run can resume where it stopped.

    Long sweeps get interrupted: a shell timeout, a laptop sleeping, an Ollama
    restart. Without resume, every interruption throws away all completed work,
    which in practice means the eval never finishes.
    """
    done: dict[str, Decision] = {}
    if not path.exists():
        return done
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        done[d["id"]] = Decision(
            record_id=d["id"], category=d["category"], gold=d["gold"],
            predicted=d["predicted"], findings=d.get("findings", []),
            latency_ms=d.get("latency_ms", 0.0), stage=d.get("stage", ""),
            error=d.get("error", ""),
        )
    return done


def run_config(
    label: str,
    guard: Any,
    records: list[dict],
    progress_every: int = 25,
    partial_path: Path | None = None,
    time_budget_s: float = 0.0,
) -> tuple[list[Decision], bool]:
    """Return (decisions, complete). Appends to partial_path as it goes."""
    done = load_partial(partial_path) if partial_path else {}
    todo = [r for r in records if r["id"] not in done]
    decisions: list[Decision] = list(done.values())
    if not todo:
        console.print(f"[green]config {label} already complete[/green] ({len(decisions)} records)")
        return decisions, True

    console.print(
        f"\n[bold]config {label} ({guard.name})[/bold] "
        f"{len(done)} done, {len(todo)} remaining"
    )
    handle = partial_path.open("a") if partial_path else None
    t_start = time.perf_counter()
    for i, rec in enumerate(todo, start=1):
        if time_budget_s and (time.perf_counter() - t_start) > time_budget_s:
            console.print(f"[yellow]time budget reached, {len(todo) - i + 1} left. Re-run to continue.[/yellow]")
            if handle:
                handle.close()
            return decisions, False
        t0 = time.perf_counter()
        try:
            predicted, findings, stage = guard.decide(rec["text"])
            err = ""
        except Exception as exc:  # noqa: BLE001
            # Errors-as-inputs: record and continue rather than aborting the
            # whole sweep. A crashed run produces no numbers at all.
            predicted, findings, stage, err = "block", ["error"], "error", f"{type(exc).__name__}: {exc}"
        dt = (time.perf_counter() - t0) * 1000
        decisions.append(
            Decision(
                record_id=rec["id"],
                category=rec["category"],
                gold=rec["gold_label"],
                predicted=predicted,
                findings=findings,
                latency_ms=dt,
                stage=stage,
                error=err,
            )
        )
        if handle:
            handle.write(json.dumps({
                "config": label, "id": decisions[-1].record_id,
                "category": decisions[-1].category, "gold": decisions[-1].gold,
                "predicted": decisions[-1].predicted, "correct": decisions[-1].correct,
                "findings": decisions[-1].findings, "stage": decisions[-1].stage,
                "latency_ms": round(decisions[-1].latency_ms, 2),
                "error": decisions[-1].error,
            }) + "\n")
            handle.flush()
        if i % progress_every == 0:
            rate = i / (time.perf_counter() - t_start)
            console.print(f"[dim]  {i}/{len(todo)}  {rate:.2f} rec/s[/dim]")
    if handle:
        handle.close()
    return decisions, True


def report(label: str, decisions: list[Decision], categories: list[str]) -> dict:
    overall = metrics(decisions)

    table = Table(title=f"config {label}  per category", header_style="bold")
    table.add_column("category")
    for col in ("TP", "FP", "FN", "TN", "prec", "recall", "F1", "FPR", "FNR"):
        table.add_column(col, justify="right")
    per_cat = {}
    for cat in categories:
        subset = [d for d in decisions if d.category == cat]
        m = metrics(subset)
        per_cat[cat] = m
        table.add_row(
            cat,
            str(m["tp"]), str(m["fp"]), str(m["fn"]), str(m["tn"]),
            f"{m['precision']:.2f}", f"{m['recall']:.2f}", f"{m['f1']:.2f}",
            f"{m['fpr']:.2f}", f"{m['fnr']:.2f}",
        )
    table.add_section()
    table.add_row(
        "OVERALL",
        str(overall["tp"]), str(overall["fp"]), str(overall["fn"]), str(overall["tn"]),
        f"{overall['precision']:.2f}", f"{overall['recall']:.2f}", f"{overall['f1']:.2f}",
        f"{overall['fpr']:.2f}", f"{overall['fnr']:.2f}",
        style="bold",
    )
    console.print(table)

    console.print(
        f"  latency  mean {overall['latency_mean_ms']:.0f}ms  "
        f"median {overall['latency_median_ms']:.0f}ms  p95 {overall['latency_p95_ms']:.0f}ms"
    )

    # Which labels drove the false positives. This is the actionable part: if
    # one label causes most over-blocking it can be dropped from the blocking
    # set without retraining anything.
    fp_labels: dict[str, int] = {}
    for d in decisions:
        if d.gold == "approve" and d.predicted == "block":
            for f in d.findings:
                fp_labels[f] = fp_labels.get(f, 0) + 1
    if fp_labels:
        ranked = sorted(fp_labels.items(), key=lambda kv: -kv[1])
        console.print("  false positives by label: " + ", ".join(f"{k}={v}" for k, v in ranked))

    errors = [d for d in decisions if d.error]
    if errors:
        console.print(f"  [red]{len(errors)} errors[/red], first: {errors[0].error[:120]}")

    return {"overall": overall, "per_category": per_cat, "fp_labels": fp_labels}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--configs", default="A", help="Comma separated: A, B, C.")
    ap.add_argument("--dataset", type=Path, default=HERE / "dataset.jsonl")
    ap.add_argument("--out", type=Path, default=HERE / "results")
    ap.add_argument("--pf-model", default="openai/privacy-filter", help="Path or hub id.")
    ap.add_argument("--pii-model", default=PIIDetectorGuard.DEFAULT)
    ap.add_argument("--pii-threshold", type=float, default=0.5)
    ap.add_argument("--linter-model", default=PolicyLinterGuard.DEFAULT)
    ap.add_argument("--linter-threshold", type=float, default=0.90,
                    help="Global Policy Linter threshold, used for any rule not overridden.")
    ap.add_argument("--device", default="auto",
                    help="torch device: auto, mps, cuda, cpu. auto prefers mps on Apple Silicon.")
    ap.add_argument("--linter-rule-thresholds", default="",
                    help="Per-rule overrides, e.g. '1:0.98,4:0.98,5:0.70'. "
                         "Rule order matches CONTEXTUAL_RULES: 0 medical, 1 financial "
                         "hardship, 2 legal, 3 addiction, 4 immigration, 5 confidential business.")
    ap.add_argument("--ids", default="", help="Comma separated record ids, or @file. Runs only those.")
    ap.add_argument("--pf-threshold", type=float, default=0.5)
    ap.add_argument(
        "--pf-blocking-labels",
        default=",".join(PF_LABELS),
        help="Which Privacy Filter labels count as a block.",
    )
    ap.add_argument("--granite-model", default="granite4.1-guardian:8b")
    ap.add_argument("--limit", type=int, default=0, help="Only run the first N records.")
    ap.add_argument("--time-budget", type=float, default=0.0,
                    help="Stop after N seconds and write partial results. Re-run to resume.")
    ap.add_argument("--report-only", action="store_true",
                    help="Skip inference, just report from existing partial traces.")
    args = ap.parse_args()

    records = [json.loads(l) for l in args.dataset.read_text().splitlines() if l.strip()]
    if args.ids:
        raw = Path(args.ids[1:]).read_text().split() if args.ids.startswith("@") else args.ids.split(",")
        wanted_ids = {x.strip() for x in raw if x.strip()}
        records = [r for r in records if r["id"] in wanted_ids]
        console.print(f"[yellow]filtered to {len(records)} records by --ids[/yellow]")
    if args.limit:
        records = records[: args.limit]
    categories = sorted({r["category"] for r in records})
    console.print(f"loaded {len(records)} records across {len(categories)} categories")

    wanted = [c.strip().upper() for c in args.configs.split(",") if c.strip()]
    args.out.mkdir(parents=True, exist_ok=True)

    pii = (PIIDetectorGuard(args.pii_model, args.pii_threshold, device=args.device)
           if ({"G", "I"} & set(wanted)) else None)
    per_rule = {}
    for part in args.linter_rule_thresholds.split(","):
        if ":" in part:
            k, v = part.split(":", 1)
            per_rule[int(k.strip())] = float(v.strip())
    lint = (PolicyLinterGuard(args.linter_model, args.linter_threshold,
                              per_rule=per_rule, device=args.device)
            if ({"E", "I"} & set(wanted)) else None)
    pf: PrivacyFilterGuard | None = None
    if "A" in wanted or "B" in wanted:
        pf = PrivacyFilterGuard(
            args.pf_model,
            threshold=args.pf_threshold,
            blocking_labels={s.strip() for s in args.pf_blocking_labels.split(",") if s.strip()},
        )

    summary: dict[str, Any] = {}
    all_decisions: list[tuple[str, Decision]] = []

    plans = []
    if "A" in wanted: plans.append(("A", lambda: pf))
    if "C" in wanted: plans.append(("C", lambda: GraniteGuard(args.granite_model)))
    if "B" in wanted: plans.append(("B", lambda: LayeredGuard(pf, GraniteGuard(args.granite_model))))
    if "G" in wanted: plans.append(("G", lambda: pii))
    if "E" in wanted: plans.append(("E", lambda: lint))
    if "I" in wanted: plans.append(("I", lambda: UnionGuard(pii, lint)))

    for label, make in plans:
        partial = args.out / f"partial_{label}.jsonl"
        if args.report_only:
            d = list(load_partial(partial).values())
            complete = len(d) == len(records)
        else:
            d, complete = run_config(label, make(), records,
                                     partial_path=partial, time_budget_s=args.time_budget)
        if not d:
            continue
        if not complete:
            console.print(f"[yellow]config {label}: {len(d)}/{len(records)} done. "
                          f"Numbers below are partial.[/yellow]")
        summary[label] = report(label, d, categories)
        summary[label]["complete"] = complete
        summary[label]["n"] = len(d)
        all_decisions += [(label, x) for x in d]

    trace = args.out / "trace.jsonl"
    with trace.open("w") as fh:
        for cfg, d in all_decisions:
            fh.write(json.dumps({
                "config": cfg, "id": d.record_id, "category": d.category,
                "gold": d.gold, "predicted": d.predicted, "correct": d.correct,
                "findings": d.findings, "stage": d.stage,
                "latency_ms": round(d.latency_ms, 2), "error": d.error,
            }) + "\n")
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2))
    console.print(f"\nwrote {trace} and {args.out / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
