#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Tests for the packaging metadata, not the guard.

    uv run --script tests/test_packaging.py

airlock.py's PEP 723 header and pyproject.toml's [project] table both
declare the same runtime dependencies, because the script must stay runnable
with `uv run --script airlock.py` directly while also being installable with
`uv tool install .`. Nothing keeps those two declarations in sync
automatically: no native mechanism ties a PEP 723 inline block to a sibling
pyproject.toml's [project.dependencies] (checked; uv and hatchling read
each independently), and a custom hatchling metadata hook that parsed one
into the other was rejected on purpose, since it would make
pyproject.toml's dependency list dynamic and unreadable at a glance, which
cuts against the auditability CLAUDE.md names as the reason this project
stays one file. This test is the safety net instead: it fails loudly the
moment the two lists disagree, on names or version bounds, rather than
letting a `uv tool install .` pull different versions than
`uv run --script airlock.py` would.

requires-python is checked too, for the same reason and at no extra cost:
it is right next to dependencies in both files and just as easy to let
drift.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
AIRLOCK = REPO / "airlock.py"
PYPROJECT = REPO / "pyproject.toml"

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    mark = "  pass" if ok else "  FAIL"
    print(f"{mark}  {name}" + (f"  [{detail}]" if detail else ""))


def read_pep723_metadata(script: Path) -> dict:
    """Extract the PEP 723 `# /// script ... # ///` block as parsed TOML.

    Each metadata line is `# ` followed by TOML, or a bare `#` for a blank
    TOML line (both forms appear in this project's headers). Reconstructing
    plain TOML from that and calling tomllib is simpler and more honest than
    trusting our own regex against real TOML syntax like inline lists.
    """
    text = script.read_text()
    match = re.search(r"(?m)^# /// script\s*$\n(?P<body>(?:^#.*\n)*?)^# ///\s*$", text)
    if not match:
        raise ValueError(f"no PEP 723 script block found in {script}")
    lines = []
    for line in match.group("body").splitlines():
        if line == "#":
            lines.append("")
        elif line.startswith("# "):
            lines.append(line[2:])
        else:
            raise ValueError(f"malformed PEP 723 metadata line: {line!r}")
    return tomllib.loads("\n".join(lines))


def main() -> int:
    pep723 = read_pep723_metadata(AIRLOCK)
    pyproject = tomllib.loads(PYPROJECT.read_text())
    project = pyproject["project"]

    script_deps = pep723.get("dependencies", [])
    project_deps = project.get("dependencies", [])
    check(
        "dependency lists agree exactly",
        sorted(script_deps) == sorted(project_deps),
        f"script={sorted(script_deps)} pyproject={sorted(project_deps)}",
    )
    check(
        "no duplicate dependency entries in either list",
        len(script_deps) == len(set(script_deps))
        and len(project_deps) == len(set(project_deps)),
    )
    check(
        "requires-python agrees",
        pep723.get("requires-python") == project.get("requires-python"),
        f"script={pep723.get('requires-python')!r} "
        f"pyproject={project.get('requires-python')!r}",
    )
    check(
        "console script points at airlock:main",
        project.get("scripts", {}).get("airlock") == "airlock:main",
    )

    total = len(PASS) + len(FAIL)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed ({total} checks)")
    if FAIL:
        print("failed:")
        for name in FAIL:
            print(f"  - {name}")
    if total < 4:
        print(f"\nWARNING: only {total} checks ran. Expected 4.")
        print("Something did not collect. Treat this as a failure, not a pass.")
        return 1
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
