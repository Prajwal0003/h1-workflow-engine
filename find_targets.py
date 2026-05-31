"""Quick script to analyze cached programs and find best targets."""
import json
import sys
sys.path.insert(0, ".")
from modules import config

# Load cached programs
cache = json.loads(config.CACHE_FILE.read_text())
programs = cache["programs"]

print(f"\nTotal programs cached: {len(programs)}")
print(f"With bounties: {len([p for p in programs if p.get('offers_bounties')])}")

# Filter: bounty + open + has scope data
good_targets = []
for p in programs:
    if not p.get("offers_bounties"):
        continue
    if p.get("submission_state", "").lower() != "open":
        continue
    
    in_scope = p.get("in_scope", [])
    scope_count = len(in_scope) if in_scope else p.get("in_scope_count", 0)
    
    # Count wildcards (wide attack surface = good for hunters)
    wildcards = []
    domains = []
    urls = []
    if in_scope:
        for s in in_scope:
            asset = s.get("asset_identifier", "")
            atype = s.get("asset_type", "").upper()
            if asset.startswith("*.") or atype == "WILDCARD":
                wildcards.append(asset)
            elif atype in ("URL", "DOMAIN") or "." in asset:
                domains.append(asset)
    
    good_targets.append({
        "handle": p["handle"],
        "name": p["name"],
        "url": p.get("url", ""),
        "source": p.get("source", ""),
        "scope_count": scope_count if isinstance(scope_count, int) else 0,
        "wildcards": len(wildcards),
        "wildcard_list": wildcards[:5],
        "domains": len(domains),
    })

# Sort by: wildcards first (wide scope), then total scope count
good_targets.sort(key=lambda x: (x["wildcards"], x["scope_count"]), reverse=True)

print("\n" + "="*80)
print("TOP TARGETS - WIDE SCOPE (Wildcards = more attack surface)")
print("="*80)

for i, t in enumerate(good_targets[:25], 1):
    wc = f"[{t['wildcards']} wildcards]" if t['wildcards'] > 0 else ""
    scope = f"scope:{t['scope_count']}" if t['scope_count'] > 0 else ""
    print(f"\n  {i:2d}. {t['name']:<35s} ({t['handle']})")
    print(f"      {scope} {wc}")
    if t["wildcard_list"]:
        for w in t["wildcard_list"][:3]:
            print(f"        -> {w}")

print("\n" + "="*80)
print("HIDDEN GEMS - Less known programs (fewer hunters = less competition)")
print("="*80)

# Programs from API that aren't in public data (private/invite-only)
api_only = [t for t in good_targets if t["source"] == "api"]
print(f"\nYou have access to {len(api_only)} API-only programs (private/invite):")
for i, t in enumerate(api_only[:15], 1):
    wc = f"[{t['wildcards']} WC]" if t['wildcards'] > 0 else ""
    print(f"  {i:2d}. {t['name']:<35s} ({t['handle']}) {wc}")

print("\n" + "="*80)
print("RECOMMENDED STRATEGY")
print("="*80)
print("""
  1. START with wildcard programs (more subdomains to find)
  2. PRIORITIZE private/invite programs (less competition)
  3. FOCUS on web apps over mobile (easier attack surface)
  4. CHECK disclosed bugs first to learn what they pay for
""")
