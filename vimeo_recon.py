"""
Quick Vimeo Recon — Uses Python requests to probe scope targets directly.
No external tools needed. Checks for common vulns.
"""
import json
import sys
import os
import time
import requests
from urllib.parse import urlparse
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

# Load Vimeo scope
scope_file = config.TARGETS_DIR / "vimeo.json"
scope_data = json.loads(scope_file.read_text())

# Extract all probbable URLs/domains
targets = set()
for s in scope_data["scope"]["all"]:
    asset = s.get("asset_identifier", "")
    if not asset or asset.startswith("*.") or len(asset) < 4:
        continue
    # Skip non-web assets
    atype = s.get("asset_type", "").upper()
    if atype in ("APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID", "HARDWARE", "WINDOWS_APP", "OTHER_APK"):
        continue
    if asset.isdigit():
        continue
    
    # Normalize
    if not asset.startswith("http"):
        asset = f"https://{asset}"
    # Remove trailing paths for base domain check
    targets.add(asset.split(",")[0].strip())

print(f"[*] Probing {len(targets)} targets from Vimeo scope...\n")

def probe_target(url):
    """Probe a target and collect info."""
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
            "X-Frame-Options": "Missing X-Frame-Options (potential clickjacking)",
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
            if any(x in kl for x in ["x-powered-by", "x-aspnet", "x-debug", "x-backend",
                                      "x-request-id", "x-served", "via", "x-cache"]):
                interesting[key] = h[key]
        result["headers"] = interesting
        
        # Check CORS
        result["cors"] = h.get("Access-Control-Allow-Origin", "")
        if result["cors"] == "*":
            result["issues"].append("CORS: Wildcard (*) Access-Control-Allow-Origin!")
        
        # Check cookies
        cookies = resp.headers.get("Set-Cookie", "")
        if cookies:
            if "secure" not in cookies.lower():
                result["issues"].append("Cookie missing Secure flag")
            if "httponly" not in cookies.lower():
                result["issues"].append("Cookie missing HttpOnly flag")
            if "samesite" not in cookies.lower():
                result["issues"].append("Cookie missing SameSite attribute")
        
    except requests.exceptions.SSLError:
        result["issues"].append("SSL/TLS Error!")
        result["status"] = "SSL_ERR"
    except requests.exceptions.ConnectionError:
        result["status"] = "CONN_ERR"
    except requests.exceptions.Timeout:
        result["status"] = "TIMEOUT"
    except Exception as e:
        result["status"] = f"ERR: {str(e)[:50]}"
    
    return result

# Probe all targets concurrently
results = []
with ThreadPoolExecutor(max_workers=5) as executor:
    futures = {executor.submit(probe_target, url): url for url in sorted(targets)}
    for future in as_completed(futures):
        result = future.result()
        results.append(result)
        status = result["status"]
        issues = len(result["issues"])
        icon = "!" if issues > 2 else "+" if status == 200 else "-"
        print(f"  [{icon}] {result['url']:<50s} {status:>8}  {result.get('title', '')[:40]}")

# Sort by interest level (more issues = more interesting)
results.sort(key=lambda x: len(x.get("issues", [])), reverse=True)

print(f"\n{'='*80}")
print(f"  VIMEO RECON RESULTS SUMMARY")
print(f"{'='*80}")

live = [r for r in results if r["status"] == 200]
redirects = [r for r in results if isinstance(r["status"], int) and 300 <= r["status"] < 400]
errors = [r for r in results if not isinstance(r["status"], int) or r["status"] >= 400]

print(f"\n  Live (200):     {len(live)}")
print(f"  Redirects:      {len(redirects)}")
print(f"  Errors:         {len(errors)}")

# Show interesting findings
print(f"\n{'='*80}")
print(f"  SECURITY FINDINGS")
print(f"{'='*80}")

for r in results:
    issues = r.get("issues", [])
    if not issues:
        continue
    print(f"\n  [{r['status']}] {r['url']}")
    if r.get("server"):
        print(f"      Server: {r['server']}")
    if r.get("cors"):
        print(f"      CORS: {r['cors']}")
    if r.get("headers"):
        for k, v in r["headers"].items():
            print(f"      {k}: {v}")
    for issue in issues:
        severity = "HIGH" if any(x in issue.lower() for x in ["cors", "ssl", "clickjack"]) else "INFO"
        print(f"      [{severity}] {issue}")

# Check for subdomain takeover candidates
print(f"\n{'='*80}")
print(f"  SUBDOMAIN TAKEOVER CANDIDATES")
print(f"{'='*80}")

takeover_candidates = [r for r in results if r["status"] in ("CONN_ERR", "TIMEOUT", 404, 503)]
if takeover_candidates:
    for r in takeover_candidates:
        print(f"  [CHECK] {r['url']} -> {r['status']}")
else:
    print("  None found (all targets responding)")

# Check for open redirects potential
print(f"\n{'='*80}")
print(f"  REDIRECT CHAIN ANALYSIS")
print(f"{'='*80}")
for r in results:
    if r.get("redirect") and r["redirect"] != r["url"]:
        print(f"  {r['url']}")
        print(f"    -> {r['redirect']}")

# Save all results
output_file = config.RECON_DIR / "vimeo_probe_results.json"
output_file.write_text(json.dumps(results, indent=2, default=str))
print(f"\n  Results saved to: {output_file}")

# Summary of most interesting targets
print(f"\n{'='*80}")
print(f"  TOP TARGETS FOR MANUAL TESTING")
print(f"{'='*80}")
print("""
  Priority targets (bounty-eligible + most attack surface):
  
  1. www.vimeo.com          - Main web app (auth flows, uploads, settings)
  2. api.vimeo.com          - REST API (IDOR, broken auth, rate limiting)
  3. player.vimeo.com       - Video player (XSS, embed injection)
  4. checkout.vimeo.com     - Payment flow (logic bugs, IDOR)
  5. *.livestream.com       - Livestreaming platform (wide wildcard)
  6. *.magisto.com           - Video editor (file upload vulns)
  7. vhx.tv / *.vhx.tv     - OTT platform (auth, IDOR)
  8. vimeo.atlassian.net    - Jira instance (info disclosure)
  
  Common bug types that pay well on Vimeo:
  - IDOR (access other users' private videos/settings)
  - Authentication bypass
  - SSRF via video URL import
  - XSS in video titles/descriptions/embeds
  - Business logic bugs in subscription/payment flows
  - API rate limiting bypass
  - File upload vulnerabilities
""")
