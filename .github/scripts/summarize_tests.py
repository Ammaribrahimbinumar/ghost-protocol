import sys, glob, xml.etree.ElementTree as ET
root = sys.argv[1]
tot = fail = err = skip = 0
bad = []
names = []
for f in glob.glob(f"{root}/**/build/test-results/**/*.xml", recursive=True) + glob.glob(f"{root}/**/build/outputs/androidTest-results/**/*.xml", recursive=True):
    t = ET.parse(f).getroot()
    tot += int(t.get("tests", 0)); fail += int(t.get("failures", 0)); err += int(t.get("errors", 0)); skip += int(t.get("skipped", 0))
    for c in t.iter("testcase"):
        for k in ("failure", "error"):
            e = c.find(k)
            names.append(f"{c.get('classname').split('.')[-1]}.{c.get('name')}")
            if e is not None:
                bad.append(f"{c.get('classname')}.{c.get('name')}: {(e.get('message') or '')[:300]} {(e.text or '')[:900].replace(chr(10), ' | ')}")
print(f"::notice title=Test summary::tests={tot} failures={fail} errors={err} skipped={skip}")
if bad:
    print("::error title=Failed tests::" + "%0A".join(bad)[:12000])
print("::notice title=Test names::" + "%0A".join(sorted(names))[:12000])
