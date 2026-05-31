"""
Quick Stripchat Recon — Uses Python requests to probe scope targets directly.
Checks for common vulns, missing security headers, and live assets.
"""
import json
import sys
import os
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, ".")
from modules import config

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Load Stripchat scope
scope_file = config.TARGETS_DIR / "stripchat.json"
scope_data = json.loads(scope_file.read_text())

# Extract targets, expanding simple wildcards
targets = set()
targets.add("https://stripchat.com")
targets.add("https://www.stripchat.com")

for s in scope_data["scope"]["all"]:
    asset = s.get("asset_identifier", "")
    if not asset or len(asset) < 4:
        continue
    
    if asset.startswith("*."):
        # Wildcard - we'll just add the base domain
        base = asset[2:]
        targets.add(f"https://{base}")
        continue
    elif "*" in asset:
        continue # Skip complex wildcards for now
        
    if not asset.startswith("http"):
        asset = f"https://{asset}"
        
    targets.add(asset.split(",")[0].strip())

print(f"[*] Probing {len(targets)} targets from Stripchat scope...\n")

def probe_target(url):
    result = {
        "url": url,
        "status": None,
        "title": "",
        "server": "",
        "headers": {},
        "redirect": "",
        "issues": [],
    }
    
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True, verify=True)
        result["status"] = resp.status_code
        result["server"] = resp.headers.get("Server", "")
        result["redirect"] = resp.url if resp.url != url else ""
        
        # Extract title
        if "<title>" in resp.text.lower():
            start = resp.text.lower().find("<title>") + 7
            end = resp.text.lower().find("</title>")
            if end > start:
                result["title"] = resp.text[start:end].strip()[:80]
        
        # Security header checks
        h = resp.headers
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS",
            "X-Content-Type-Options": "Missing X-Content-Type-Options",
            "X-Frame-Options": "Missing X-Frame-Options",
            "Content-Security-Policy": "Missing CSP",
            "X-XSS-Protection": "Missing X-XSS-Protection",
        }
        
        for header, issue in security_headers.items():
            if header not in h:
                result["issues"].append(issue)
        
        # Check for interesting headers
        interesting = {}
        for key in h:
            kl = key.lower()
            if any(x in kl for x in ["x-powered-by", "via", "x-cache", "x-amz", "x-request"]):
                interesting[key] = h[key]
        result["headers"] = interesting
        
        # Check CORS
        result["cors"] = h.get("Access-Control-Allow-Origin", "")
        if result["cors"] == "*":
            result["issues"].append("CORS: Wildcard (*) Access-Control-Allow-Origin!")
            
    except Exception as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            result["status"] = "SSL_ERR"
            result["issues"].append("SSL Certificate Validation Failed")
        else:
            result["status"] = f"ERR: {str(e)[:40]}"
    
    return result

results = []
with ThreadPoolExecutor(max_workers=5) as executor:
    futures = {executor.submit(probe_target, url): url for url in sorted(targets)}
    for future in as_completed(futures):
        result = future.result()
        results.append(result)
        status = result["status"]
        icon = "+" if status == 200 else "-"
        print(f"  [{icon}] {result['url']:<40s} {status:>8}  {result.get('title', '')[:30]}")

print(f"\n{'='*80}")
print(f"  STRIPCHAT RECON SUMMARY")
print(f"{'='*80}")

for r in sorted(results, key=lambda x: str(x['status'])):
    print(f"\n[{r['status']}] {r['url']}")
    if r['redirect']: print(f"    -> Redirects to: {r['redirect']}")
    if r['server']: print(f"    Server: {r['server']}")
    if r['headers']:
        for k, v in r['headers'].items():
            print(f"    {k}: {v}")
    
    # Filter issues to only show high priority ones
    high_pri = [i for i in r['issues'] if any(x in i.lower() for x in ['cors', 'csp', 'ssl'])]
    for issue in high_pri:
        print(f"    ⚠️ {issue}")

# Check for subdomains we should enumerate
print(f"\n{'='*80}")
print(f"  NEXT STEPS FOR STRIPCHAT")
print(f"{'='*80}")
print("1. Subdomain Enumeration needed on: *.stripchat.com")
print("   Run: subfinder -d stripchat.com")
print("2. Test WebSocket API: websocket-apps.sc-apps.com")
print("   WebSocket vulnerabilities (CSWSH, missing auth) are common here.")
print("3. Check extensions: extensions.stripchat.com")
print("   Look for exposed config files, source code leaks.")
