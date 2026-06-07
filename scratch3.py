import json

sarif_path = r'c:\Users\prajw\.openclaw\workspace\h1-workflow\scanners\mantishack_features\out\scan_20260607_203027_pid29472_0000\combined.sarif'

with open(sarif_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

findings = []
for run in data.get('runs', []):
    rules = {r['id']: r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
    for result in run.get('results', []):
        rule_id = result.get('ruleId')
        rule = rules.get(rule_id, {})
        props = rule.get('properties', {})
        severity = props.get('precision', props.get('security-severity', result.get('level', 'none')))
        
        message = result.get('message', {}).get('text', '')
        
        loc = result.get('locations', [{}])[0].get('physicalLocation', {})
        uri = loc.get('artifactLocation', {}).get('uri', '')
        line = loc.get('region', {}).get('startLine', 0)
        
        findings.append({
            'rule_id': rule_id,
            'severity': severity,
            'message': message[:200].replace('\n', ' '),
            'file': f"{uri}:{line}"
        })

# Filter out low/info and noise
filtered = [f for f in findings if f['severity'] in ['high', 'critical', 'error'] or (isinstance(f['severity'], str) and f['severity'].replace('.','',1).isdigit() and float(f['severity']) > 7.0)]

# Print summary
grouped = {}
for f in findings:
    if f['rule_id'] not in grouped:
        grouped[f['rule_id']] = []
    grouped[f['rule_id']].append(f)

print(f"Total findings: {len(findings)}")
print("Rule Summary:")
for k, v in grouped.items():
    print(f" - {k}: {len(v)} findings")

print("\nImportant Findings:")
for f in sorted(findings, key=lambda x: str(x['severity']), reverse=True):
    if 'high' in str(f['severity']).lower() or 'error' in str(f['severity']).lower() or 'critical' in str(f['severity']).lower():
        print(f"[{f['severity']}] {f['rule_id']} in {f['file']}")
