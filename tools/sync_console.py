#!/usr/bin/env python3
"""Historical, unsupported helper for the retired web console.

The former ui/index.html editing copy, CONSOLE_HTML literal and test_console
check no longer describe shipped Airlock. The active interface is native Textual
in root airlock.py. This retained illustration cannot sync the current product.
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
