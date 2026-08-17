#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "rich>=13.7",
# ]
# ///
"""Measure the two reassembles_identifier claims eval/README.md flagged as
not reproducible: the six-digit-floor residual cited in the function's
docstring, and the worst-case timing cited above MAX_REASSEMBLY_LENGTH.

Both numbers were carried in comments without a script behind them. This
gives them one, using the shipped functions directly rather than
reimplementing their logic.

Section 1: six-digit-floor residual
------------------------------------
reassembles_identifier's raw pass requires a source identifier as a
contiguous substring of some subset of the round's values. Its digits-only
projection (added to close the padding bypass) drops that requirement to
"contiguous in digits only", which widens what can coincidentally match once
a source is short. MIN_REASSEMBLY_LENGTH is 6, so a six-digit source sits
exactly at that floor.

This varies SOURCE LENGTH (six, eight, nine digits) and SOURCE COUNT against
a digit-dense round of ordinary prose, amounts, dates, box numbers and
reference numbers, none of which are meant to be sensitive on their own. A
trial false-blocks if any source in that trial's set is reconstructed from a
round that never contained it. Reported for the shipped function
(reassembles_identifier, raw pass then digits projection) and for the raw
pass alone (_subset_contains on the same candidate filter reassembles_identifier
uses before its own digits projection), so the gap the docstring attributes
to the projection is visible.

Section 2: MAX_REASSEMBLY_LENGTH worst-case cost
-------------------------------------------------
The comment above MAX_REASSEMBLY_LENGTH justifies the bound by citing a
pre-bound worst case. That exact scenario (12 values of FILE_SLICE_CHARS each)
is no longer reachable through reassembles_identifier: the length check
introduced because of it now rejects a round that large in O(1), before the
expensive subset enumeration ever runs. So this times the worst case the
CURRENT, bounded function can still experience: MAX_JOBS_PER_ROUND values
whose total normalised length sits exactly at the MAX_REASSEMBLY_LENGTH
ceiling (so the length check does not short-circuit), against a large source
set built so nothing matches (so neither the raw pass nor the digits
projection exits early on a hit). That is the real cost a caller can still
impose today; whether it matches the comment's pre-bound figure is exactly
the question this answers.

Usage:  ./reassembly_residuals.py [--airlock PATH] [--trials 300]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import statistics
import string
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()
HERE = Path(__file__).parent
DEFAULT_AIRLOCK = HERE.parent / "airlock.py"

DIGITS = string.digits


def load_airlock(path: Path):
    spec = importlib.util.spec_from_file_location("airlock", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["airlock"] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# Section 1: six-digit-floor residual
# --------------------------------------------------------------------------

SOURCE_LENGTHS = (6, 8, 9)
SOURCE_COUNTS = (20, 40, 60)


def digit_dense_round(rng: random.Random, prose_pool: list[str]) -> list[str]:
    """12 values: ordinary prose, amounts, dates, box numbers, reference
    numbers. None of these are sensitive; the round is meant to be one that
    should never block."""
    values = []
    for _ in range(12):
        kind = rng.choice(("prose", "amount", "date", "box", "ref"))
        if kind == "prose":
            values.append(rng.choice(prose_pool))
        elif kind == "amount":
            values.append(f"{rng.randrange(100, 99999)}.{rng.randrange(0, 99):02d}")
        elif kind == "date":
            values.append(f"{rng.randrange(2015, 2027)}-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}")
        elif kind == "box":
            values.append(f"Box {rng.randrange(1, 9999)}")
        else:
            values.append(f"REF-{rng.randrange(100000, 999999)}")
    return values


def random_digit_sources(rng: random.Random, length: int, count: int) -> set[str]:
    sources: set[str] = set()
    while len(sources) < count:
        sources.add("".join(rng.choice(DIGITS) for _ in range(length)))
    return sources


def raw_pass(a, values: list[str], sources: set[str]) -> bool:
    """reassembles_identifier's raw pass in isolation: the same candidate
    filter it applies before its own digits projection, then the real
    _subset_contains. Not a reimplementation of the subset logic, only the
    filtering step that sits around it."""
    normalised = [a.normalise_identifier(v) for v in values]
    candidates = {
        s for s in sources
        if len(s) >= a.MIN_REASSEMBLY_LENGTH and not any(s in v for v in normalised)
    }
    if not candidates:
        return False
    return a._subset_contains(normalised, candidates)


def measure_floor_residual(a, args, prose_pool: list[str]) -> dict:
    console.print("[bold]Six-digit-floor residual: false blocking on a "
                  "digit-dense round that contains none of the sources[/bold]")
    table = Table(box=None, pad_edge=False)
    table.add_column("source length")
    table.add_column("source count", justify="right")
    table.add_column("shipped", justify="right")
    table.add_column("raw pass", justify="right")

    results: dict[str, dict[str, float]] = {}
    rng = random.Random(args.seed)
    for length in SOURCE_LENGTHS:
        for count in SOURCE_COUNTS:
            shipped_blocks = 0
            raw_blocks = 0
            for _ in range(args.trials):
                round_values = digit_dense_round(rng, prose_pool)
                sources = random_digit_sources(rng, length, count)
                if a.reassembles_identifier(round_values, sources):
                    shipped_blocks += 1
                if raw_pass(a, round_values, sources):
                    raw_blocks += 1
            shipped_rate = shipped_blocks / args.trials
            raw_rate = raw_blocks / args.trials
            results[f"{length}d/{count}"] = {"shipped": shipped_rate, "raw": raw_rate}
            table.add_row(
                f"{length} digits", str(count),
                f"[red]{shipped_rate:.4f}[/red]" if shipped_rate > 0.05 else f"{shipped_rate:.4f}",
                f"[red]{raw_rate:.4f}[/red]" if raw_rate > 0.05 else f"{raw_rate:.4f}",
            )
    console.print(table)
    console.print(f"[dim]{args.trials} trials per cell, seed={args.seed}[/dim]\n")
    return results


# --------------------------------------------------------------------------
# Section 2: MAX_REASSEMBLY_LENGTH worst-case cost
# --------------------------------------------------------------------------


def ceiling_round(rng: random.Random, total: int, n: int) -> list[str]:
    """n all-digit values whose lengths sum to exactly `total`, so the round
    sits at the MAX_REASSEMBLY_LENGTH ceiling without tripping it."""
    base, rem = divmod(total, n)
    lengths = [base + 1] * rem + [base] * (n - rem)
    rng.shuffle(lengths)
    return ["".join(rng.choice(DIGITS) for _ in range(length)) for length in lengths]


def non_matching_sources(rng: random.Random, count: int, length: int) -> set[str]:
    sources: set[str] = set()
    while len(sources) < count:
        sources.add("".join(rng.choice(DIGITS) for _ in range(length)))
    return sources


def measure_worst_case_cost(a, args) -> dict:
    console.print("[bold]MAX_REASSEMBLY_LENGTH worst-case cost: real "
                  "reassembles_identifier, values at the ceiling, sources "
                  "that never match[/bold]")
    rng = random.Random(args.seed)
    values = ceiling_round(rng, a.MAX_REASSEMBLY_LENGTH, a.MAX_JOBS_PER_ROUND)
    sources = non_matching_sources(rng, count=400, length=12)
    total_chars = sum(len(a.normalise_identifier(v)) for v in values)
    assert total_chars == a.MAX_REASSEMBLY_LENGTH, (
        f"expected round at the ceiling ({a.MAX_REASSEMBLY_LENGTH}), got {total_chars}"
    )

    times = []
    blocked = None
    for _ in range(args.reps):
        t0 = time.perf_counter()
        blocked = a.reassembles_identifier(values, sources)
        times.append(time.perf_counter() - t0)
    assert blocked is False, (
        "a source matched, so the call exited early and did not pay the "
        "full cost this measurement is trying to time"
    )

    mean_s = statistics.mean(times)
    median_s = statistics.median(times)
    console.print(
        f"values={len(values)} (MAX_JOBS_PER_ROUND), "
        f"total chars={total_chars} (MAX_REASSEMBLY_LENGTH ceiling), "
        f"sources={len(sources)}, reps={args.reps}"
    )
    console.print(f"mean {mean_s:.3f}s, median {median_s:.3f}s")
    console.print("[dim]Machine-specific. Re-run on the machine you care "
                  "about before treating this as a portable figure; see "
                  "eval/README.md's note on sandbox versus Apple Silicon "
                  "timing.[/dim]\n")
    return {"values": len(values), "total_chars": total_chars, "sources": len(sources),
            "reps": args.reps, "mean_s": mean_s, "median_s": median_s,
            "all_s": times}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--airlock", type=Path, default=DEFAULT_AIRLOCK)
    ap.add_argument("--trials", type=int, default=300)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20260817)
    args = ap.parse_args()

    a = load_airlock(args.airlock)

    rows = [json.loads(line) for line in (HERE / "dataset.jsonl").open()]
    prose_pool = [r["text"][:80] for r in rows if r["gold_label"] == "approve"]
    console.print(f"[dim]airlock: {args.airlock}[/dim]")
    console.print(f"[dim]prose filler pool: {len(prose_pool)}[/dim]\n")

    floor_results = measure_floor_residual(a, args, prose_pool)
    cost_results = measure_worst_case_cost(a, args)

    out = HERE / "results" / "reassembly_residuals.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({
        "airlock": str(args.airlock), "trials": args.trials, "seed": args.seed,
        "floor_residual": floor_results, "worst_case_cost": cost_results,
    }, indent=2))
    console.print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
