#!/usr/bin/env python3
"""Probe /internal/ with JSON Accept headers + deeper sub-endpoints."""
import requests, json, sys, os
os.environ["PYTHONIOENCODING"] = "utf-8"
try: sys.stdout.reconfigure(encoding="utf-8")
except: pass

BASE = "https://app.launchdarkly.com"
S = requests.Session()

def probe(path, accept="application/json"):
    url = f"{BASE}{path}"
    headers = {"User-Agent": "Mozilla/5.0", "Accept": accept}
    try:
        r = S.get(url, timeout=10, headers=headers, allow_redirects=False)
        ct = r.headers.get("Content-Type", "")
        print(f"\n  [{r.status_code}] {path}")
        print(f"  Content-Type: {ct}")
        if "json" in ct:
            try:
                data = r.json()
                pretty = json.dumps(data, indent=2)[:800]
                print(f"  JSON Response:\n{pretty}")
                return data
            except:
                print(f"  Body: {r.text[:500]}")
        elif r.status_code == 200 and "html" in ct:
            # Check if it's a sign-in page or actual content
            if "Sign in" in r.text:
                print(f"  -> Sign-in page (SPA shell, client-side auth)")
            elif "data-is-unauthenticated" in r.text:
                print(f"  -> Unauthenticated SPA shell")
            else:
                print(f"  -> HTML content (first 200 chars): {r.text[:200]}")
        else:
            print(f"  Body: {r.text[:300]}")
        return None
    except Exception as e:
        print(f"  ERROR: {e}")
        return None

print("=" * 60)
print("INTERNAL API DEEP PROBE")
print("=" * 60)

# Phase 1: /internal/ root with JSON
print("\n--- Phase 1: /internal/ root ---")
data = probe("/internal/")

# Phase 2: Follow all _links
if data and "_links" in data:
    print("\n--- Phase 2: Following _links from /internal/ ---")
    for name, info in data["_links"].items():
        href = info.get("href", "")
        if href and href != "/internal/":
            sub_data = probe(href)
            # If sub_data has more _links, follow those too
            if sub_data and "_links" in sub_data:
                print(f"\n  --- Sub-links from {href} ---")
                for sub_name, sub_info in sub_data["_links"].items():
                    sub_href = sub_info.get("href", "")
                    if sub_href and sub_href != href:
                        probe(sub_href)

# Phase 3: Try alternate content types
print("\n--- Phase 3: /internal/ with different Accept headers ---")
for accept in ["text/plain", "*/*", "application/xml", "text/xml"]:
    probe("/internal/", accept=accept)

# Phase 4: Try POST to /internal/ endpoints
print("\n--- Phase 4: POST to /internal/ ---")
for path in ["/internal/", "/internal/account", "/internal/actions"]:
    url = f"{BASE}{path}"
    try:
        r = S.post(url, json={"test": True}, timeout=5, 
                   headers={"Content-Type": "application/json", "Accept": "application/json"})
        print(f"  POST {path}: {r.status_code} - {r.text[:200]}")
    except Exception as e:
        print(f"  POST {path}: ERROR - {e}")

# Phase 5: Try to access /api/ root (saw redirect earlier)
print("\n--- Phase 5: /api/ root ---")
probe("/api/")
probe("/api/v2")
probe("/api/v2/")

# Phase 6: docs.launchdarkly.com security headers (0/8 missing = reportable)
print("\n--- Phase 6: docs.launchdarkly.com full header dump ---")
try:
    r = S.get("https://docs.launchdarkly.com", timeout=10)
    print(f"  Status: {r.status_code}")
    for h, v in r.headers.items():
        print(f"  {h}: {v[:100]}")
except Exception as e:
    print(f"  ERROR: {e}")

print("\nDONE.")
