#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "torch>=2.2",
#     "transformers>=4.57",
#     "detect-secrets>=1.5",
#     "rich>=13.7",
# ]
# ///
"""Reassembly detection under airlock's full stack, not the encoders alone.

round_guard.py measured the two 350M encoders and found that reassembly
detection collapses as benign jobs are added to the round: a contextual scorer
dilutes. That measurement is not airlock, because airlock runs two
deterministic layers first, and a regular expression does not dilute.

    us_ssn = \\b\\d{3}[-\\s]\\d{2}[-\\s]\\d{4}\\b

accepts a space as the separator, so "912 84 7731" matches at any round size.
This script measures the stack that would actually ship:

    scan_secrets  U  scan_pii_patterns  U  PII-Detector  U  Policy Linter

and attributes every catch to the layer that made it, so the deterministic
layers are not credited to the encoders or the other way round.

Usage:  ./round_full_stack.py
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
# airlock.py lives one directory up (the repo root), not at a fixed home
# path, so this resolves from wherever the repo was cloned.
sys.path.insert(0, str(HERE.parent))

from bakeoff import PIIDetectorGuard, PolicyLinterGuard  # noqa: E402
from airlock import scan_pii_patterns, scan_secrets  # noqa: E402

console = Console()

# Same fragments as round_guard.py. "target" is what a correct catch looks
# like, so an incidental block on filler content is not counted as a catch.
CASES = {
    "ssn":   (["912", "84", "7731"], "912-84-7731"),
    "card":  (["4111", "1111", "1111", "1111"], "4111111111111111"),
    "ein":   (["31", "7729104"], "31-7729104"),
    "phone": (["555", "0148"], "555-0148"),
}

FILLERS = (0, 2, 4, 6, 9)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=40)
    ap.add_argument("--device", default="auto")
    ap.add_argument("--seed", type=int, default=20260816)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    rows = [json.loads(line) for line in (HERE / "dataset.jsonl").open()]

    det = PIIDetectorGuard(threshold=0.5, device=args.device)
    lint = PolicyLinterGuard(threshold=0.70, per_rule={1: 0.98, 4: 0.98},
                             device=args.device)

    def layered(text: str) -> tuple[bool, list[str]]:
        """Return (blocked, layers that fired), in airlock's layer order."""
        fired: list[str] = []
        if scan_secrets(text):
            fired.append("secrets")
        if scan_pii_patterns(text):
            fired.append("pii-patterns")
        if det.decide(text)[0] == "block":
            fired.append("detector")
        if lint.decide(text)[0] == "block":
            fired.append("linter")
        return bool(fired), fired

    # Pool: clean units that the full stack approves on their own. A unit the
    # stack already blocks would never reach the concatenation in run_jobs.
    pool = [
        r["text"][:80] for r in rows
        if r["gold_label"] == "approve" and not layered(r["text"][:80])[0]
    ]
    console.print(f"[dim]pool of individually-approved clean units: {len(pool)}[/dim]")

    def place(frags: list[str], filler: list[str], mode: str) -> list[str]:
        """Order the round's job results.

        Fragment order is always preserved: the caller chooses the order its
        jobs are issued in and the concatenation follows it, so a caller
        reassembling a value would never scramble its own pieces. What the
        caller does control is whether anything sits between them.

        adjacent   fragments contiguous, filler around them. A caller that
                   batched its questions without thinking about the guard.
        scattered  filler between the fragments. Costs the caller nothing,
                   since it reads each job result separately and never needs
                   the concatenation to be well formed.
        """
        if mode == "adjacent":
            cut = rng.randrange(len(filler) + 1)
            return filler[:cut] + frags + filler[cut:]
        values = frags[:]
        for f in filler:
            values.insert(rng.randrange(len(values) + 1), f)
        return values

    table = Table(box=None, pad_edge=False)
    table.add_column("case")
    table.add_column("placement")
    table.add_column("filler", justify="right")
    table.add_column("caught", justify="right")
    table.add_column("layers that fired")

    results: dict = {}
    for name, (frags, _original) in CASES.items():
        for mode in ("adjacent", "scattered"):
          for n in FILLERS:
            caught = 0
            layer_hits: Counter = Counter()
            for _ in range(args.trials):
                values = place(frags, rng.sample(pool, n), mode)
                blocked, fired = layered(" ".join(values))
                # Deterministic layers only fire on the reassembled identifier:
                # the pool is pre-filtered so no filler unit trips them.
                deterministic = [f for f in fired if f in ("secrets", "pii-patterns")]
                if deterministic:
                    caught += 1
                    layer_hits.update(deterministic)
                elif blocked:
                    layer_hits.update(f"{f}?" for f in fired)
            rate = caught / args.trials
            table.add_row(
                name, mode, str(n),
                f"[green]{rate:.2f}[/green]" if rate >= 0.95 else f"[red]{rate:.2f}[/red]",
                ", ".join(f"{k}:{v}" for k, v in layer_hits.most_common(3)) or "-",
            )
            results[f"{name}_{mode}_filler{n}"] = {"caught": rate,
                                                   "layers": dict(layer_hits)}
        table.add_section()

    console.print(table)
    console.print(
        "[dim]caught = a deterministic layer matched the reassembled identifier. "
        "A trailing ? marks a block that fired on something other than the "
        "reassembly, which is not a catch.[/dim]"
    )

    out = HERE / "results" / "round_full_stack.json"
    out.write_text(json.dumps({"pool_size": len(pool), "trials": args.trials,
                               "results": results}, indent=2))
    console.print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
