#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp[cli]>=2.0.0,<2.1.0",
#     "rich>=13.7",
#     "presidio-analyzer>=2.2",
#     "spacy>=3.7",
#     "detect-secrets>=1.5",
#     "pypdf>=5.0",
#     "reportlab>=4.0",
# ]
# ///
"""End to end: complete a Form 1040 through airlock without seeing the taxpayer.

    uv run --script tests/test_tax_e2e.py
    uv run --script tests/test_tax_e2e.py --keep          leave the files behind
    uv run --script tests/test_tax_e2e.py --no-presidio   for a machine without it

The cloud model is a tax preparer on a phone call: it knows the form and which
figure belongs on which line, and it never learns who the taxpayer is.

It decomposes rather than delegates. Each job is one fact from one document,
which is what a small local model can actually do. Figures come back so the
preparer can add them up; identifiers are filled straight into the form and
never returned at all.

Correctness is checked locally against the file on disk. Containment is checked
against the transcript. Neither check needs the other's data.

SSNs use the 900-999 area, which SSA has never issued.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
AIRLOCK = HERE.parent / "airlock.py"
spec = importlib.util.spec_from_file_location("airlock", AIRLOCK)
airlock = importlib.util.module_from_spec(spec)
sys.modules["airlock"] = airlock
spec.loader.exec_module(airlock)

SSN = "912-84-7731"
IDENTIFIERS = {
    "SSN": SSN,
    "SSN unformatted": "912847731",
    "taxpayer surname": "Whitfield",
    "home address": "1820 Larkspur Lane",
    "employer EIN": "47-6183920",
    "payer TIN": "31-0854434",
    "bank account": "4419-882301",
}

WAGES = 94_250.00 + 8_400.00
INTEREST = 317.42
TOTAL_INCOME = WAGES + INTEREST
WITHHELD = 11_910.00 + 612.00

PASS, FAIL, DIAG = [], [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'pass' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))


def build_docs(root: Path) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    def page(path: Path, title: str, rows: list[tuple[str, str]]) -> None:
        c = canvas.Canvas(str(path), pagesize=letter)
        c.setFont("Helvetica-Bold", 13)
        c.drawString(72, 720, title)
        c.setFont("Helvetica", 10)
        y = 694
        for label, value in rows:
            c.drawString(72, y, label)
            c.drawString(320, y, value)
            y -= 17
        c.showPage()
        c.save()

    root.mkdir(parents=True, exist_ok=True)
    # Named so that sorting puts the form at index 0 and the sources after it.
    (root / "0_1040.md").write_text(
        "# Form 1040 (2025)\n\n"
        "Name: \nSSN: \nAddress: \n\n"
        "1a: \n2b: \n9: \n25a: \n"
    )
    page(root / "1_W2_Acme.pdf", "Form W-2  2025", [
        ("a Employee SSN", SSN),
        ("b Employer EIN", "47-6183920"),
        ("e Employee name", "Dana R. Whitfield"),
        ("f Employee address", "1820 Larkspur Lane, Apt 6C, Dayton OH 45409"),
        ("1 Wages, tips, other compensation", "94250.00"),
        ("2 Federal income tax withheld", "11910.00"),
    ])
    page(root / "2_W2_Northwind.pdf", "Form W-2  2025", [
        ("a Employee SSN", SSN),
        ("e Employee name", "Dana R. Whitfield"),
        ("1 Wages, tips, other compensation", "8400.00"),
        ("2 Federal income tax withheld", "612.00"),
    ])
    page(root / "3_1099-INT.pdf", "Form 1099-INT  2025", [
        ("Recipient SSN", SSN),
        ("Payer TIN", "31-0854434"),
        ("Account number", "4419-882301"),
        ("1 Interest income", "317.42"),
    ])


def make_args(root: Path) -> argparse.Namespace:
    values = dict(airlock.CLI_DEFAULTS)
    values.update(
        root=root,
        approve="none",
        allow_writes=True,
        no_presidio="--no-presidio" in sys.argv,
    )
    return argparse.Namespace(**values)


def num(text: str) -> float | None:
    """The money value in a string.

    A model that replies "Box 1: 94250.00" answered the question, so a bare
    literal must not be required. But taking the first number returns 1 from
    that same string, so prefer a decimal amount and fall back to the last
    number rather than the first.
    """
    import re as _re
    candidates = _re.findall(r"-?[\d,]*\.\d+|-?[\d,]*\d", str(text).replace("$", ""))
    if not candidates:
        return None
    decimals = [c for c in candidates if "." in c]
    pick = (decimals or candidates)[-1]
    try:
        return float(pick.replace(",", ""))
    except ValueError:
        return None


async def run(root: Path) -> None:
    from mcp import Client

    server = airlock.build_server(make_args(root))
    transcript: list[str] = []
    raw: list[tuple[str, str]] = []

    def record(result) -> dict:
        body = result.structured_content or {}
        transcript.append(json.dumps(body))
        return body

    async with Client(server) as client:
        async def extract(label: str, jobs: list[dict]) -> dict:
            started = time.monotonic()
            body = record(await client.call_tool(
                "airlock_extract", {"session": session, "jobs": jobs}))
            print(f"    [{time.monotonic() - started:5.1f}s] {label}", flush=True)
            for r in body.get("results", []):
                shown = r.get("value", r.get("field", r.get("detail", "")))
                raw.append((f"{label[:22]} job {r.get('job')}",
                            f"{r.get('status')}: {str(shown)[:60]}"))
                mark = "  <-- not found" if r.get("status") == "not_found" else ""
                print(f"              job {r.get('job')}: {r.get('status')} "
                      f"{str(shown)[:52]}{mark}")
            return body

        print("\n  1. open")
        opened = record(await client.call_tool("airlock_open", {
            "objective": "Complete a 2025 Form 1040 from these documents."}))
        session = opened.get("session")
        docs = opened.get("documents", [])
        print(f"    {len(docs)} documents: {json.dumps(docs)}")
        check("airlock_open discloses no filename",
              not any(n in json.dumps(opened) for n in ("W2", "1099", "1040")),
              "names leaked" if any(n in json.dumps(opened) for n in ("W2", "1099")) else "clean")

        # Figures only. These are not identifying, so they come back and the
        # preparer adds them up rather than trusting a 0.8B model to.
        print("\n  2. collect the figures, one fact per job")
        got = await extract("wages, withholding and interest", [
            {"document": 1, "extract": "wages in box 1", "as": "number"},
            {"document": 2, "extract": "wages in box 1", "as": "number"},
            {"document": 1, "extract": "federal income tax withheld in box 2",
             "as": "number"},
            {"document": 2, "extract": "federal income tax withheld in box 2",
             "as": "number"},
            {"document": 3, "extract": "the interest income amount", "as": "number"},
        ])
        values = {r["job"]: num(r.get("value")) for r in got.get("results", [])
                  if r.get("status") == "ok"}
        wages = sum(v for j, v in values.items() if j in (0, 1) and v is not None)
        withheld = sum(v for j, v in values.items() if j in (2, 3) and v is not None)
        interest = values.get(4) or 0.0
        print(f"    computed by the caller: wages={wages} withheld={withheld} "
              f"interest={interest}")

        # Identifiers never come back. They move document to document locally.
        print("\n  3. fill the form: identifiers locally, figures from my arithmetic")
        await extract("identifying fields, values never returned", [
            {"document": 1, "extract": "the employee name", "as": "line",
             "into": 0, "field": "Name"},
            {"document": 1, "extract": "the nine digit employee social security "
             "number, digits and hyphens only", "as": "digits",
             "into": 0, "field": "SSN"},
            {"document": 1, "extract": "the employee street address", "as": "line",
             "into": 0, "field": "Address"},
        ])
        await extract("computed lines", [
            {"into": 0, "field": "1a", "value": f"{wages:.2f}"},
            {"into": 0, "field": "2b", "value": f"{interest:.2f}"},
            {"into": 0, "field": "9", "value": f"{wages + interest:.2f}"},
            {"into": 0, "field": "25a", "value": f"{withheld:.2f}"},
        ])

    print("\n  local verification, on disk")
    filled = (root / "0_1040.md").read_text()
    for label, want in [("1a", WAGES), ("2b", INTEREST),
                        ("9", TOTAL_INCOME), ("25a", WITHHELD)]:
        line = next((ln for ln in filled.splitlines()
                     if ln.strip().startswith(f"{label}:")), "")
        check(f"line {label} = {want:,.2f}", num(line.split(":", 1)[-1]) == want,
              line.strip() or "missing")
    check("the form carries the taxpayer SSN", SSN in filled,
          "a return without it is useless")
    check("the form carries the taxpayer name", "Whitfield" in filled)

    DIAG.append("what the worker actually returned:")
    for name, value in raw:
        DIAG.append(f"    {name:34} {value}")
    DIAG.append("the form as written:")
    for line in filled.splitlines():
        if line.strip():
            DIAG.append(f"    {line}")

    print("\n  containment, on what reached the caller")
    blob = " ".join(transcript)
    leaked = [k for k, v in IDENTIFIERS.items() if v in blob]
    filled_any = SSN in filled
    if not filled_any:
        print("  INCONCLUSIVE  the form was never filled, so this proves nothing")
        DIAG.append("the worker never filled the form; containment is unproven")
    else:
        check("no identifier reached the caller", not leaked,
              ", ".join(leaked) or "clean")
    (root.parent / "transcript.json").write_text(blob)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="airlock-1040-"))
    root = tmp / "tax"
    try:
        build_docs(root)
        mode = "presidio OFF" if "--no-presidio" in sys.argv else "presidio ON"
        print(f"workspace: {root}   guard: {mode}")
        try:
            asyncio.run(run(root))
        except BaseException as exc:  # noqa: BLE001
            FAIL.append("run crashed")
            print(f"  FAIL  run crashed [{type(exc).__name__}: {str(exc)[:120]}]")
        else:
            print(f"\n  1040 left at: {root / '0_1040.md'}")
    finally:
        print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
        for n in FAIL:
            print(f"  - {n}")
        for line in DIAG:
            print(f"  {line}")
        if "--keep" not in sys.argv:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
