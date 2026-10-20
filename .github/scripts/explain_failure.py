import sys, re
lines = open(sys.argv[1], errors="replace").read().splitlines()
keep = [l.strip() for l in lines if re.search(r"^e: |error:|FAILED|Could not|Unresolved|AssertionError|Exception:|tampering byte|accepted|case \d", l)]
wrong = []
for i, l in enumerate(lines):
    if "What went wrong" in l:
        wrong = [x.strip() for x in lines[i:i + 14]]
        break
print("::error title=Gradle failure::" + "%0A".join(wrong + ["---"] + keep[:50])[:14000])
print("::error title=Gradle log tail::" + "%0A".join(l for l in lines[-40:] if not l.lstrip().startswith("at "))[:6000])
