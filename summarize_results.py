import json

with open("data/autopilot/latest_findings.json", "r", encoding="utf-8") as f:
    data = json.load(f)

print(f"Total findings: {len(data)}")

sev = {}
types = {}
programs = {}
for finding in data:
    s = finding.get("severity", "?")
    sev[s] = sev.get(s, 0) + 1
    t = finding.get("type", "?")
    types[t] = types.get(t, 0) + 1
    p = finding.get("program", "?")
    programs[p] = programs.get(p, 0) + 1

print("\nBy Severity:")
for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
    if s in sev:
        print(f"  {s}: {sev[s]}")

print("\nBy Type:")
for t, c in sorted(types.items(), key=lambda x: -x[1]):
    print(f"  {t}: {c}")

print("\nBy Program:")
for p, c in sorted(programs.items(), key=lambda x: -x[1]):
    print(f"  {p}: {c}")

# Print HIGH and CRITICAL findings
print("\n" + "="*60)
print(" TOP FINDINGS (CRITICAL + HIGH)")
print("="*60)
for finding in data:
    if finding.get("severity") in ("CRITICAL", "HIGH"):
        print(f"\n  [{finding['severity']}] {finding['type']}")
        print(f"  Program: {finding.get('program')}")
        print(f"  URL: {finding.get('url')}")
        if finding.get("detail"):
            print(f"  Detail: {finding['detail']}")
        if finding.get("origin_sent"):
            print(f"  Origin: {finding['origin_sent']} -> Reflected: {finding['origin_reflected']}")
        if finding.get("credentials"):
            print(f"  Credentials: {finding['credentials']}")
