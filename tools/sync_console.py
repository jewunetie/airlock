#!/usr/bin/env python3
"""Copy ui/index.html into airlock.py's CONSOLE_HTML literal.

ui/index.html is the editing copy; the literal is what ships, so that
`uv run --script airlock.py` works from any directory. tests/test_console.py
fails when they differ, and this is the one-line way to make them agree.
"""

import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
html = (root / "ui" / "index.html").read_text()
if '"""' in html:
    sys.exit("ui/index.html contains a triple quote, which would end the literal")
if html.rstrip("\n").endswith("\\"):
    sys.exit("ui/index.html ends in a backslash, which a raw string cannot hold")

source = (root / "airlock.py").read_text()
pattern = re.compile(r'CONSOLE_HTML = r""".*?"""', re.DOTALL)
if not pattern.search(source):
    sys.exit("CONSOLE_HTML literal not found in airlock.py")
updated = pattern.sub(lambda _: 'CONSOLE_HTML = r"""' + html + '"""', source, count=1)
if updated == source:
    print("already in sync")
else:
    (root / "airlock.py").write_text(updated)
    print(f"synced {len(html)} chars into airlock.py")
