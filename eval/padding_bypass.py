#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "rich>=13.7",
#     "detect-secrets>=1.5",
# ]
# ///
"""Measure candidate fixes for the suffix-padding bypass in reassembles_identifier.

The shipped check tests substring containment of a source identifier against
the concatenation of some subset of the round's values, taken in job order.
That tolerates a PREFIX on each fragment but not a SUFFIX:

    ["912", "84", "7731"]           -> caught
    ["912 ok", "84 ok", "7731 ok"]  -> missed

because trailing padding inserts characters between the fragments and breaks
the contiguous run the identifier needs. A caller writes the `extract`
instruction, so asking for the digits followed by a word costs it nothing.

The bypass is bounded: a shaped job cannot carry the padding, since
`as: "digits"` is anchored to ^[0-9-]{1,20}$ and `as: "number"` is a JSON
number. It is reachable only through unshaped free-text jobs.

Closing it changes the detection model, which is why this is a measurement and
not a patch. The last time a detection model was changed on intuition
(character subsequence) it measured 38% false blocks. Two candidates:

  digits   additionally project every value to digits only, then run the same
           subset test. Cheap, targets numeric identifiers specifically.
  substr   dynamic programme where each value may contribute ANY contiguous
           substring of itself, values consumed in job order. Complete against
           padding on either side, and O(n * |source|^2) rather than 2**n.

Both are scored on detection against padded attacks AND false blocking on
legitimate rounds. A candidate that catches everything and blocks everything
is worthless, so the false-block column decides.

Usage:  ./padding_bypass.py [--airlock PATH] [--trials 200]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import statistics
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()
HERE = Path(__file__).parent
# Default to the airlock.py this eval/ ships alongside, so the default works
# from any clone location; --airlock still overrides it.
DEFAULT_AIRLOCK = HERE.parent / "airlock.py"


def load_airlock(path: Path):
    spec = importlib.util.spec_from_file_location("airlock", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["airlock"] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# Candidate detectors
# --------------------------------------------------------------------------
# Each takes already-normalised values and a candidate source set, and returns
# True to block. "shipped" is the current behaviour, reimplemented here so all
# three are scored through one code path and a difference cannot come from
# calling conventions.


def shipped(normalised: list[str], sources: set[str]) -> bool:
    """Substring of the concatenation of some subset, in job order."""
    n = len(normalised)
    for mask in range(1, 1 << n):
        joined = "".join(normalised[i] for i in range(n) if mask >> i & 1)
        if any(s in joined for s in sources):
            return True
    return False


def digits_projection(normalised: list[str], sources: set[str]) -> bool:
    """Shipped, plus the same test over each value's digits-only projection.

    Aimed at the common case: the identifiers worth reassembling are mostly
    numeric, and non-digit padding vanishes under the projection while prose
    filler contributes almost nothing.
    """
    if shipped(normalised, sources):
        return True
    projected = ["".join(c for c in v if c.isdigit()) for v in normalised]
    numeric_sources = {s for s in sources if s.isdigit()}
    if not numeric_sources or not any(projected):
        return False
    return shipped(projected, numeric_sources)


def substring_dp(normalised: list[str], sources: set[str]) -> bool:
    """Each value may contribute ANY contiguous substring, values in job order.

    Complete against padding on either side of every fragment. Values are
    consumed in order and at most once, so the order-preserving threat model
    is unchanged; only the per-value tolerance widens.
    """
    for source in sources:
        length = len(source)
        # reachable[p] is True when source[:p] can be built from the values
        # seen so far. Position 0 is reachable before any value is consumed.
        reachable = [False] * (length + 1)
        reachable[0] = True
        for value in normalised:
            if not value:
                continue
            nxt = reachable[:]          # skipping this value is always allowed
            for p in range(length):
                if not reachable[p]:
                    continue
                for end in range(p + 1, length + 1):
                    if source[p:end] in value:
                        nxt[end] = True
                    else:
                        # Substrings are prefix-closed: once source[p:end] is
                        # absent from value, every longer one is too.
                        break
            reachable = nxt
            if reachable[length]:
                return True
    return False


CANDIDATES = {
    "shipped": shipped,
    "digits": digits_projection,
    "substr": substring_dp,
}


# --------------------------------------------------------------------------
# Corpora
# --------------------------------------------------------------------------

IDENTIFIERS = {
    "ssn": ("912847731", ["912", "84", "7731"]),
    "card": ("4111111111111111", ["4111", "1111", "1111", "1111"]),
    "ein": ("317729104", ["31", "7729104"]),
    "acct": ("8829930041", ["8829", "9300", "41"]),
}

# How a caller could dress each fragment. Every variant still passes the
# per-job guard, because each fragment is individually harmless.
PADDINGS = {
    "none": lambda f: f,
    "suffix": lambda f: f"{f} ok",
    "prefix": lambda f: f"value {f}",
    "both": lambda f: f"the {f} confirmed",
    "prose": lambda f: f"The figure recorded here is {f}",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--airlock", type=Path, default=DEFAULT_AIRLOCK)
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--seed", type=int, default=20260817)
    args = ap.parse_args()

    a = load_airlock(args.airlock)
    rng = random.Random(args.seed)
    norm = a.normalise_identifier

    rows = [json.loads(line) for line in (HERE / "dataset.jsonl").open()]
    prose_pool = [r["text"][:80] for r in rows if r["gold_label"] == "approve"]
    console.print(f"[dim]airlock: {args.airlock}[/dim]")
    console.print(f"[dim]prose filler pool: {len(prose_pool)}[/dim]\n")

    all_sources = {v[0] for v in IDENTIFIERS.values()}

    # ---------------- detection ----------------
    console.print("[bold]Detection: fragments dressed by the caller, "
                  "6 benign prose jobs interleaved[/bold]")
    det = Table(box=None, pad_edge=False)
    det.add_column("padding")
    for name in CANDIDATES:
        det.add_column(name, justify="right")

    detection: dict = {}
    for pad_name, pad in PADDINGS.items():
        cells = []
        for cand_name, cand in CANDIDATES.items():
            hits = 0
            for _ in range(args.trials):
                ident = rng.choice(list(IDENTIFIERS))
                _source, frags = IDENTIFIERS[ident]
                values = [pad(f) for f in frags]
                for filler in rng.sample(prose_pool, 6):
                    values.insert(rng.randrange(len(values) + 1), filler)
                normalised = [norm(v) for v in values]
                live = {s for s in all_sources if not any(s in v for v in normalised)}
                if live and cand(normalised, live):
                    hits += 1
            rate = hits / args.trials
            cells.append(rate)
            detection[f"{pad_name}/{cand_name}"] = rate
        det.add_row(pad_name, *[
            f"[green]{r:.2f}[/green]" if r >= 0.95 else
            (f"[red]{r:.2f}[/red]" if r < 0.5 else f"[yellow]{r:.2f}[/yellow]")
            for r in cells
        ])
    console.print(det)

    # ---------------- false blocking ----------------
    # Three legitimate round shapes. The numeric one is where the shipped
    # check was tuned; prose and mixed are the shapes it was never measured on.
    def numeric_round() -> list[str]:
        out = []
        for _ in range(12):
            k = rng.choice("wcya")
            out.append(str(rng.randrange(20000, 150000)) if k == "w" else
                       str(rng.randrange(1, 500)) if k == "c" else
                       str(rng.randrange(2015, 2027)) if k == "y" else
                       f"{rng.randrange(100, 99999)}.{rng.randrange(0, 99):02d}")
        return out

    def prose_round() -> list[str]:
        return rng.sample(prose_pool, 12)

    def mixed_round() -> list[str]:
        out = numeric_round()[:6] + rng.sample(prose_pool, 6)
        rng.shuffle(out)
        return out

    console.print("\n[bold]False blocking: legitimate rounds over a workspace "
                  "holding all four identifiers[/bold]")
    fp = Table(box=None, pad_edge=False)
    fp.add_column("round shape")
    for name in CANDIDATES:
        fp.add_column(name, justify="right")

    false_blocks: dict = {}
    for shape_name, shape in (("numeric", numeric_round),
                              ("prose", prose_round),
                              ("mixed", mixed_round)):
        cells = []
        for cand_name, cand in CANDIDATES.items():
            blocked = 0
            for _ in range(args.trials):
                normalised = [norm(v) for v in shape()]
                live = {s for s in all_sources if not any(s in v for v in normalised)}
                if live and cand(normalised, live):
                    blocked += 1
            rate = blocked / args.trials
            cells.append(rate)
            false_blocks[f"{shape_name}/{cand_name}"] = rate
        fp.add_row(shape_name, *[
            f"[green]{r:.2f}[/green]" if r <= 0.02 else
            (f"[red]{r:.2f}[/red]" if r > 0.10 else f"[yellow]{r:.2f}[/yellow]")
            for r in cells
        ])
    console.print(fp)

    # ---------------- cost ----------------
    console.print("\n[bold]Cost per round, 12 values[/bold]")
    cost = Table(box=None, pad_edge=False)
    cost.add_column("candidate")
    cost.add_column("short values", justify="right")
    cost.add_column("long values (800 chars each)", justify="right")

    long_round = [norm("x" * 800 + str(i)) for i in range(12)]
    for cand_name, cand in CANDIDATES.items():
        short = [norm(v) for v in numeric_round()]
        t0 = time.perf_counter()
        for _ in range(50):
            cand(short, all_sources)
        short_ms = (time.perf_counter() - t0) / 50 * 1000
        t0 = time.perf_counter()
        for _ in range(5):
            cand(long_round, all_sources)
        long_ms = (time.perf_counter() - t0) / 5 * 1000
        cost.add_row(cand_name, f"{short_ms:.1f}ms",
                     f"[red]{long_ms:.0f}ms[/red]" if long_ms > 200 else f"{long_ms:.0f}ms")
    console.print(cost)

    out = HERE / "results" / "padding_bypass.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({
        "airlock": str(args.airlock), "trials": args.trials, "seed": args.seed,
        "detection": detection, "false_blocks": false_blocks,
    }, indent=2))
    console.print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
