#!/usr/bin/env python3
"""Print test counts and failures from .trx files as GitHub annotations (so results can be read without downloading logs)."""
import glob, sys, xml.etree.ElementTree as ET
ns = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}
total = failed = skipped = 0
for f in glob.glob(sys.argv[1] + "/**/*.trx", recursive=True):
    root = ET.parse(f).getroot()
    for r in root.iterfind(".//t:UnitTestResult", ns):
        total += 1; o = r.get("outcome")
        if o == "Failed":
            failed += 1
            msg = r.find(".//t:Message", ns)
            print(f"::error title=test failed::{r.get('testName')}: {(msg.text if msg is not None else '')[:600]!r}")
        elif o in ("NotExecuted", "Skipped"):
            skipped += 1
            print(f"::notice title=test skipped::{r.get('testName')}")
print(f"::notice title=summary::tests={total} failures={failed} skipped={skipped}")
sys.exit(1 if failed or total == 0 else 0)
