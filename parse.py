import json
with open('data/recon/priceline_probe_results.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
live = [x for x in data if x['status'] == 200]
print(f"Live Targets: {len(live)}")
print("\nTop Interesting Targets:")
# List of known noise or false positives from tools like Wapiti
NOISE_FILTERS = [
    "CSP is not set",
    "X-Frame-Options is not set",
    "Strict-Transport-Security",
    "X-Content-Type-Options is not set",
    "OCSP Must-Staple",
    "OpenSSL CCS (CVE-2014-0224)",
    "secure renegotiations",
    "TLS/SSL misconfigurations"
]

for i, d in enumerate(data[:10]):
    # Filter out noisy issues
    filtered_issues = [
        issue for issue in d.get('issues', [])
        if not any(noise.lower() in issue.lower() for noise in NOISE_FILTERS)
    ]
    
    print(f"[{d['status']}] {d['url']} - {len(filtered_issues)} actionable issues")
    for issue in filtered_issues:
        print(f"   - {issue}")
        
    if d.get('cors') == '*':
        print("   - 🚨 High: Wildcard CORS found!")
print("\nTakeover Candidates (404/503/Timeout/Conn_err):")
for d in data:
    if d['status'] in (404, 503, "TIMEOUT", "CONN_ERR"):
        print(f"   - {d['url']} ({d['status']})")
