import sys
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
"""
Find low-competition bug bounty programs that pay bounties.
Fetches from HackerOne and Bugcrowd, filters for:
- Programs that pay bounties
- Programs with web app scope (URLs, not mobile/hardware)
- Programs that are less popular (fewer reports = less competition)
- Validates that target URLs are actually live
"""

import requests
import urllib3
import json
import time
import random
from urllib.parse import urlparse

urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def fetch_h1_programs():
    """Fetch HackerOne programs from bounty-targets-data."""
    print("[*] Fetching HackerOne programs...", flush=True)
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/hackerone_data.json",
            timeout=30
        )
        programs = r.json()
        print(f"  [+] Loaded {len(programs)} H1 programs", flush=True)
        return programs
    except Exception as e:
        print(f"  [-] Failed: {e}")
        return []

def fetch_bc_programs():
    """Fetch Bugcrowd programs."""
    print("[*] Fetching Bugcrowd programs...", flush=True)
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/bugcrowd_data.json",
            timeout=30
        )
        programs = r.json()
        print(f"  [+] Loaded {len(programs)} Bugcrowd programs", flush=True)
        return programs
    except Exception as e:
        print(f"  [-] Failed: {e}")
        return []

def check_url_live(url, timeout=5):
    """Check if a URL is live and returns a meaningful response."""
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout, verify=False, allow_redirects=True)
        # Must be a real page, not a parking page or Cloudflare error
        if r.status_code in [200, 301, 302, 403]:
            body = r.text.lower()
            # Filter out parked domains, for-sale pages, etc.
            parking_indicators = ["domain is for sale", "buy this domain", "parked", "godaddy", "sedoparking"]
            if any(p in body for p in parking_indicators):
                return False, r.status_code, len(r.text)
            return True, r.status_code, len(r.text)
        return False, r.status_code, 0
    except:
        return False, 0, 0

def analyze_h1(programs):
    """Filter and rank H1 programs for low competition."""
    candidates = []
    for p in programs:
        if not p.get("offers_bounties", False):
            continue
        
        handle = p.get("handle", "")
        name = p.get("name", handle)
        
        # Extract web URLs from scope
        urls = []
        for t in p.get("targets", {}).get("in_scope", []):
            asset = t.get("asset_identifier", "")
            atype = t.get("asset_type", "").upper()
            if atype in ("URL", "WILDCARD") and "." in asset and "*" not in asset:
                clean = asset.strip().rstrip("/")
                if not clean.startswith("http"):
                    clean = f"https://{clean}"
                urls.append(clean)
        
        if not urls:
            continue
        
        # Estimate competition level based on available metrics
        # Programs with fewer scope items tend to be smaller/newer
        scope_size = len(p.get("targets", {}).get("in_scope", []))
        
        candidates.append({
            "source": "HackerOne",
            "handle": handle,
            "name": name,
            "urls": urls[:10],
            "scope_size": scope_size,
            "url_count": len(urls),
        })
    
    return candidates

def analyze_bc(programs):
    """Filter and rank Bugcrowd programs."""
    candidates = []
    for p in programs:
        if not p.get("has_bounty", False):
            continue
        
        code = p.get("code", "")
        name = p.get("name", code)
        
        urls = []
        for t in p.get("targets", {}).get("in_scope", []):
            asset = t.get("target", "")
            if asset and "." in asset and " " not in asset and "*" not in asset:
                clean = asset.strip().rstrip("/")
                if not clean.startswith("http"):
                    clean = f"https://{clean}"
                urls.append(clean)
        
        if not urls:
            continue
        
        scope_size = len(p.get("targets", {}).get("in_scope", []))
        
        candidates.append({
            "source": "Bugcrowd",
            "handle": code,
            "name": name,
            "urls": urls[:10],
            "scope_size": scope_size,
            "url_count": len(urls),
        })
    
    return candidates

def main():
    h1 = fetch_h1_programs()
    bc = fetch_bc_programs()
    
    h1_candidates = analyze_h1(h1)
    bc_candidates = analyze_bc(bc)
    
    all_candidates = h1_candidates + bc_candidates
    print(f"\n[*] Total bounty programs with web scope: {len(all_candidates)}")
    
    # Sort by scope size (smaller scope = likely less hunted)
    # But filter out programs with only 1 URL (too small)
    filtered = [c for c in all_candidates if 2 <= c["url_count"] <= 15]
    filtered.sort(key=lambda x: x["scope_size"])
    
    print(f"[*] Filtered to {len(filtered)} programs with 2-15 URLs in scope")
    
    # Take a random sample from the lower half (less popular)
    lower_half = filtered[:len(filtered)//2]
    sample = random.sample(lower_half, min(20, len(lower_half)))
    
    print(f"\n[*] Checking {len(sample)} random low-competition programs for live targets...\n")
    
    live_programs = []
    for prog in sample:
        name = prog["name"]
        handle = prog["handle"]
        source = prog["source"]
        urls = prog["urls"]
        
        # Check if at least one URL is live
        live_urls = []
        for url in urls[:5]:
            is_live, status, size = check_url_live(url)
            if is_live and size > 500:
                live_urls.append({"url": url, "status": status, "size": size})
        
        if live_urls:
            prog["live_urls"] = live_urls
            live_programs.append(prog)
            print(f"  [OK] {source} | {name} ({handle}) -- {len(live_urls)}/{len(urls[:5])} URLs live", flush=True)
        else:
            print(f"  [--] {source} | {name} ({handle}) -- no live URLs", flush=True)
        
        time.sleep(0.3)
    
    print(f"\n{'='*60}")
    print(f"RESULTS: {len(live_programs)} live, low-competition programs found")
    print(f"{'='*60}\n")
    
    for i, prog in enumerate(live_programs, 1):
        print(f"{i}. [{prog['source']}] {prog['name']} ({prog['handle']})")
        print(f"   Scope: {prog['url_count']} URLs | Live: {len(prog['live_urls'])}")
        for lu in prog["live_urls"]:
            print(f"     -> {lu['url']} (HTTP {lu['status']}, {lu['size']} bytes)")
        print()
    
    # Save results
    output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_programs_analyzed": len(all_candidates),
        "live_programs": live_programs,
    }
    with open("data/low_competition_targets.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Saved to data/low_competition_targets.json")

if __name__ == "__main__":
    main()
