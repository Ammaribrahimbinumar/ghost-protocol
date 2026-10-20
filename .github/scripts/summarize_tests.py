import sys, glob, xml.etree.ElementTree as ET
root = sys.argv[1]
tot = fail = err = skip = 0
bad = []
for f in glob.glob(f"{root}/**/build/test-results/**/*.xml", recursive=True):
    t = ET.parse(f).getroot()
    tot += int(t.get("tests", 0)); fail += int(t.get("failures", 0)); err += int(t.get("errors", 0)); skip += int(t.get("skipped", 0))
    for c in t.iter("testcase"):
        for k in ("failure", "error"):
            e = c.find(k)
            if e is not None:
                bad.append(f"{c.get('classname')}.{c.get('name')}: {(e.get('message') or '')[:300]}")
print(f"::notice title=Test summary::tests={tot} failures={fail} errors={err} skipped={skip}")
if bad:
    print("::error title=Failed tests::" + "%0A".join(bad)[:12000])
