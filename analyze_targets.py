"""Deep analysis - fetch scope for top programs and rank by attack surface."""
import json
import sys
import os
import time

# Fix Windows encoding
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, ".")

import requests
from modules import config

# ---- Fetch scope from public data (no Rich dependency) ----
print("[*] Loading cached programs...")
cache = json.loads(config.CACHE_FILE.read_text())
programs = cache["programs"]

# Build a lookup from public data
public_scope = {}
for p in programs:
    handle = p.get("handle", "")
    in_scope = p.get("in_scope", [])
    if in_scope:
        public_scope[handle] = in_scope

# Candidates to analyze
candidates = [
    "cloudflare", "slack", "coinbase", "uber", "gitlab",
    "bookingcom", "att", "adobe", "snapchat", "yelp",
    "tinder", "vimeo", "linkedin", "automattic", "airtable",
    "x", "priceline", "ui", "greenhouse", "doordash",
    "robinhood", "twilio", "wordpress", "security",
    "basecamp", "coinmate", "1win_com", "meesho_bbp",
    "coupang_tw", "anduril_industries"
]

# Also try to fetch scope via API for programs without public scope data
auth = config.get_auth()

results = []

for handle in candidates:
    scopes = []

    # Check cached file first
    filepath = config.TARGETS_DIR / f"{handle}.json"
    if filepath.exists():
        data = json.loads(filepath.read_text())
        scopes = data.get("scope", {}).get("all", [])
    elif handle in public_scope:
        scopes = public_scope[handle]
    elif auth:
        # Quick API fetch (no Rich progress bar)
        url = f"{config.H1_PROGRAMS_URL}/{handle}/structured_scopes"
        try:
            resp = requests.get(url, auth=auth, headers={"Accept": "application/json"},
                                params={"page[size]": 100}, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for s in data.get("data", []):
                    attrs = s.get("attributes", {})
                    scopes.append({
                        "asset_identifier": attrs.get("asset_identifier", ""),
                        "asset_type": attrs.get("asset_type", ""),
                        "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
                    })
            time.sleep(0.15)
        except Exception:
            pass

    if not scopes:
        continue

    # Categorize
    wildcards = []
    domains = []
    urls = []
    apis = []
    for s in scopes:
        asset = s.get("asset_identifier", "")
        atype = s.get("asset_type", "").upper()
        if asset.startswith("*.") or atype == "WILDCARD":
            wildcards.append(asset)
        elif atype in ("API",):
            apis.append(asset)
        elif atype in ("URL",) or "://" in asset:
            urls.append(asset)
        elif "." in asset:
            domains.append(asset)

    total = len(scopes)
    score = len(wildcards) * 10 + len(domains) * 3 + len(urls) * 2 + len(apis) * 2 + total

    results.append({
        "handle": handle,
        "wildcards": len(wildcards),
        "wc_list": wildcards[:5],
        "domains": len(domains),
        "urls": len(urls),
        "apis": len(apis),
        "total": total,
        "score": score,
    })

results.sort(key=lambda x: x["score"], reverse=True)

print(f"\n{'='*80}")
print(f"  BEST TARGETS RANKED BY ATTACK SURFACE (analyzed {len(results)} programs)")
print(f"{'='*80}")

for i, r in enumerate(results, 1):
    bar = "#" * min(r["score"] // 3, 35)
    print(f"\n  {i:2d}. {r['handle']:<22s} Score: {r['score']:3d}  |{bar}")
    print(f"      WC: {r['wildcards']}  Domains: {r['domains']}  URLs: {r['urls']}  APIs: {r['apis']}  Total: {r['total']}")
    if r["wc_list"]:
        for w in r["wc_list"][:3]:
            print(f"        -> {w}")

# Recommendations
top_wc = [r for r in results if r["wildcards"] >= 2][:5]
top_focused = [r for r in results if r["wildcards"] == 0 and r["total"] >= 5][:5]
medium = [r for r in results if 0 < r["wildcards"] < 3 and r["total"] >= 3][:5]

print(f"\n{'='*80}")
print(f"  RECOMMENDATIONS")
print(f"{'='*80}")

print("\n  TIER 1 - Wide wildcard scope (best for overnight recon):")
for r in top_wc:
    print(f"    >>> {r['handle']:<22s} {r['wildcards']} wildcards, {r['total']} total assets")

if medium:
    print("\n  TIER 2 - Medium scope (good balance of recon + manual):")
    for r in medium:
        print(f"    >>> {r['handle']:<22s} {r['wildcards']} wildcards, {r['total']} total assets")

if top_focused:
    print("\n  TIER 3 - Focused scope (deep manual testing):")
    for r in top_focused:
        print(f"    >>> {r['handle']:<22s} {r['total']} total assets")

if top_wc:
    pick = top_wc[0]
    print(f"\n  SUGGESTED FIRST TARGET: >>> {pick['handle']} <<<")
    print(f"  Why: {pick['wildcards']} wildcards = massive subdomain discovery potential")
    print(f"  Run: python h1_workflow.py pipeline {pick['handle']}")

print()
