#!/usr/bin/env python3
"""
OSL Deep Unauthenticated Probe
- Find the actual login/signup URLs
- Probe API structure
- Check for info disclosure on unauthenticated endpoints
- Look for hidden endpoints via sitemap, robots.txt, etc.
"""
import requests
import re
import json
import sys
import os

os.environ["PYTHONIOENCODING"] = "utf-8"
try: sys.stdout.reconfigure(encoding="utf-8")
except: pass

BASE = "https://www.osl.com"
RESULTS = []

COOKIES = {
    "glb_locale": "en_US",
    "gt_local_id": "Ne+ULAGWDYZDSo1stCOnowH1dJFouuPHejnTvTG82frd2a1UuNMIwA==",
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/html",
}

def sep(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")

def log_finding(sev, typ, url, detail):
    RESULTS.append({"severity": sev, "type": typ, "url": url, "detail": detail})
    emoji = {"CRITICAL":"[!!!]", "HIGH":"[!!]", "MEDIUM":"[!]", "LOW":"[.]", "INFO":"[i]"}.get(sev, "[?]")
    print(f"  {emoji} [{sev}] {typ}")
    print(f"      URL: {url}")
    print(f"      Detail: {detail[:200]}")

# ── Phase 1: Find login/signup/API URLs ──
sep("PHASE 1: DISCOVER LOGIN & API ENDPOINTS")

discovery_paths = [
    "/robots.txt",
    "/sitemap.xml",
    "/en/login",
    "/en/login/",
    "/en/register",
    "/en/register/",
    "/en/signup",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    "/graphql",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/health",
    "/status",
    "/version",
    "/en/institutional",
    "/en/otc",
    "/en/custody",
]

for path in discovery_paths:
    try:
        url = BASE + path
        r = requests.get(url, headers=HEADERS, cookies=COOKIES, timeout=5, allow_redirects=True)
        status = r.status_code
        final_url = r.url
        ct = r.headers.get("Content-Type", "")
        
        if status == 200:
            snippet = r.text[:200].replace("\n", " ").strip()
            print(f"  [200] {path} -> {final_url}")
            print(f"         Type: {ct[:50]}")
            
            if "json" in ct:
                try:
                    data = r.json()
                    print(f"         JSON keys: {list(data.keys())[:10]}")
                except:
                    pass
            
            # Check for login/register forms
            if "login" in path or "register" in path or "signup" in path:
                log_finding("INFO", "AUTH_ENDPOINT_FOUND", final_url, 
                    f"Authentication endpoint accessible. Use this to create your test account.")
                    
        elif status in [301, 302]:
            loc = r.headers.get("Location", "N/A")
            print(f"  [{status}] {path} -> Redirects to: {loc}")
        elif status == 403:
            print(f"  [403] {path} -> Forbidden (WAF/Auth)")
        elif status == 404:
            pass  # skip 404s
        else:
            print(f"  [{status}] {path}")
    except Exception as e:
        pass

# ── Phase 2: Check trade.osl.com subdomains ──
sep("PHASE 2: SUBDOMAIN PROBING")

subdomains = [
    "trade.osl.com",
    "api.osl.com",
    "sg.osl.com",
    "hk.osl.com",
    "auth.osl.com",
    "login.osl.com",
    "sso.osl.com",
    "admin.osl.com",
    "staging.osl.com",
    "dev.osl.com",
    "test.osl.com",
    "sandbox.osl.com",
    "uat.osl.com",
    "internal.osl.com",
    "portal.osl.com",
    "dashboard.osl.com",
    "app.osl.com",
    "exchange.osl.com",
    "custody.osl.com",
    "otc.osl.com",
    "sentry.osl.com",
    "cdn.osl.com",
    "static.osl.com",
    "mail.osl.com",
    "vpn.osl.com",
    "jira.osl.com",
    "confluence.osl.com",
    "gitlab.osl.com",
    "jenkins.osl.com",
]

live_subs = []
for sub in subdomains:
    try:
        r = requests.get(f"https://{sub}/", headers=HEADERS, timeout=3, allow_redirects=True)
        status = r.status_code
        final = r.url
        server = r.headers.get("Server", "N/A")
        ct = r.headers.get("Content-Type", "")[:40]
        print(f"  [{status}] {sub} -> {final} (Server: {server})")
        live_subs.append(sub)
        
        if sub in ["admin.osl.com", "staging.osl.com", "dev.osl.com", 
                    "uat.osl.com", "internal.osl.com", "jira.osl.com",
                    "confluence.osl.com", "gitlab.osl.com", "jenkins.osl.com"]:
            log_finding("HIGH", "SENSITIVE_SUBDOMAIN_ACCESSIBLE", 
                f"https://{sub}/", f"Internal/sensitive subdomain is live. Server: {server}")
            
    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass

# ── Phase 3: Check sentry.osl.com for info disclosure ──
sep("PHASE 3: SENTRY INSTANCE PROBE")
print("  Checking sentry.osl.com for public project info disclosure...")

sentry_paths = [
    "/api/0/",
    "/api/0/organizations/",
    "/api/0/projects/",
    "/api/0/teams/",
    "/_health/",
    "/debug/",
]

for path in sentry_paths:
    try:
        url = f"https://sentry.osl.com{path}"
        r = requests.get(url, headers=HEADERS, timeout=5)
        if r.status_code == 200:
            ct = r.headers.get("Content-Type", "")
            print(f"  [200] sentry.osl.com{path} ({ct[:30]})")
            if "json" in ct:
                try:
                    data = r.json()
                    detail = json.dumps(data)[:300]
                    log_finding("MEDIUM", "SENTRY_INFO_DISCLOSURE", url, 
                        f"Sentry API endpoint accessible without auth: {detail}")
                except:
                    pass
        else:
            print(f"  [{r.status_code}] sentry.osl.com{path}")
    except:
        pass

# ── Phase 4: Deep JS bundle analysis ──
sep("PHASE 4: DEEP JS BUNDLE ANALYSIS")
print("  Analyzing main page JS for internal URLs, API keys, tokens...")

try:
    r = requests.get(BASE + "/en", headers=HEADERS, timeout=10)
    js_links = re.findall(r'src="([^"]*\.js[^"]*)"', r.text)
    
    all_secrets = []
    for link in js_links[:15]:  # limit to first 15 JS files
        if not link.startswith("http"):
            link = "https://osl.com" + link if link.startswith("/") else "https://osl.com/" + link
        
        try:
            js_r = requests.get(link, timeout=5)
            text = js_r.text
            
            # Look for various secrets/internal info
            patterns = {
                "Slack Webhook": r'hooks\.slack\.com/services/[A-Za-z0-9/]+',
                "Internal URL": r'https?://[a-z0-9\-]+\.internal\.osl\.com[^"\'\\s]*',
                "PagerDuty": r'pagerduty\.com/[^"\'\\s]+',
                "Datadog Key": r'DD_[A-Z_]+=["\']\w+["\']',
                "Sentry DSN": r'https://[a-f0-9]+@[a-z0-9.]+\.sentry\.io/\d+',
                "Firebase Config": r'firebaseConfig\s*=\s*\{[^}]+\}',
                "GCP Project": r'project[_-]?id["\':\s]+["\']([\w-]+)["\']',
                "Private Key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            }
            
            for name, pattern in patterns.items():
                matches = re.findall(pattern, text)
                if matches:
                    for m in matches[:3]:
                        detail = m if isinstance(m, str) else str(m)
                        log_finding("HIGH", f"JS_SECRET_{name.upper().replace(' ','_')}", 
                            link, detail[:200])
                            
        except:
            pass
            
    print(f"  Analyzed {min(len(js_links), 15)} JS bundles.")
except Exception as e:
    print(f"  Error: {e}")

# ── Phase 5: Check for exposed API documentation ──
sep("PHASE 5: API DOCUMENTATION EXPOSURE")

api_doc_urls = [
    "https://www.osl.com/api/",
    "https://www.osl.com/docs/api/",
    "https://www.osl.com/swagger/",
    "https://www.osl.com/redoc/",
    "https://api.osl.com/swagger.json",
    "https://api.osl.com/openapi.json",
    "https://api.osl.com/api-docs",
    "https://api.osl.com/docs",
    "https://api.osl.com/v1/docs",
    "https://api.osl.com/health",
    "https://api.osl.com/status",
    "https://api.osl.com/version",
]

for url in api_doc_urls:
    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
        if r.status_code == 200:
            ct = r.headers.get("Content-Type", "")
            snippet = r.text[:200].replace("\n", " ")
            print(f"  [200] {url}")
            print(f"         Content-Type: {ct[:40]}")
            log_finding("MEDIUM", "API_DOCS_EXPOSED", url, 
                f"API documentation accessible. Snippet: {snippet[:100]}")
    except:
        pass

# ── Summary ──
sep("SUMMARY")
print(f"  Total findings: {len(RESULTS)}")
for r in RESULTS:
    emoji = {"CRITICAL":"!!!","HIGH":"!!","MEDIUM":"!","LOW":".","INFO":"i"}.get(r["severity"],"?")
    print(f"  [{emoji}] {r['severity']}: {r['type']} @ {r['url'][:60]}")

# Save
from pathlib import Path
out = Path("data/autopilot/osl_deep_probe.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(RESULTS, indent=2), encoding="utf-8")
print(f"\n  Results saved to: {out}")
