import sys
import os
import json
import time
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, ".")
from modules import config

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGETS = ["vimeo", "bookingcom", "robinhood", "automattic"]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

def probe_target(url):
    result = {"url": url, "status": None, "issues": [], "cors": ""}
    try:
        resp = requests.get(url, headers=HEADERS, timeout=7, allow_redirects=True, verify=False)
        result["status"] = resp.status_code
        h = resp.headers
        
        # Check CORS
        cors = h.get("Access-Control-Allow-Origin", "")
        result["cors"] = cors
        if cors == "*":
            result["issues"].append("Wildcard CORS")
            
    except requests.exceptions.RequestException as e:
        if "SSLError" in str(type(e)):
            result["status"] = "SSL_ERR"
        elif "Timeout" in str(type(e)):
            result["status"] = "TIMEOUT"
        else:
            result["status"] = "CONN_ERR"
    return result

print("="*60)
print(" MASS RECON: TOP 4 TARGETS ")
print("="*60)

for handle in TARGETS:
    print(f"\n[*] Processing {handle}...")
    
    scope_file = config.TARGETS_DIR / f"{handle}.json"
    
    if not scope_file.exists():
        print(f"[-] No scope file found for {handle}. Skipping.")
        continue
        
    try:
        scope_data = json.loads(scope_file.read_text(encoding="utf-8"))
    except Exception:
        print(f"[-] Invalid JSON in scope file for {handle}")
        continue
        
    # Extract URLs
    urls = set()
    for s in scope_data.get("scope", {}).get("all", []):
        asset = s.get("asset_identifier", "")
        if not asset or asset.startswith("*.") or len(asset) < 4:
            continue
        atype = s.get("asset_type", "").upper()
        if atype in ("APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID", "HARDWARE", "WINDOWS_APP", "OTHER_APK", "CIDR"):
            continue
        if asset.isdigit():
            continue
        if not asset.startswith("http"):
            asset = f"https://{asset}"
        urls.add(asset.split(",")[0].strip())
        
    print(f"    Found {len(urls)} target URLs to probe.")
    
    if not urls:
        continue
        
    # 2. Probe URLs
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(probe_target, url): url for url in sorted(urls)}
        for future in as_completed(futures):
            results.append(future.result())
            
    # 3. Analyze Results
    live = [r for r in results if type(r["status"]) is int and r["status"] < 400]
    takeovers = [r for r in results if r["status"] in (404, 503, "TIMEOUT", "CONN_ERR")]
    cors_vulns = [r for r in results if "Wildcard CORS" in r.get("issues", [])]
    
    print(f"    -> Live targets (2xx/3xx): {len(live)}")
    
    # -- State Tracking / Diffing Logic --
    state_file = config.TARGETS_DIR / f"{handle}_known_live.json"
    known_live_urls = set()
    if state_file.exists():
        try:
            known_live_urls = set(json.loads(state_file.read_text(encoding="utf-8")))
        except Exception:
            pass
            
    current_live_urls = set(r["url"] for r in live)
    new_assets = current_live_urls - known_live_urls
    
    if new_assets:
        print(f"    [***] FOUND {len(new_assets)} NEW ASSETS SINCE LAST RUN! [***]")
        for na in new_assets:
            print(f"        - {na}")
            # You can trigger your deep scans (Nuclei, Fuzzing) here for 'na'
        
        # Update the state file with the new complete list
        state_file.write_text(json.dumps(list(current_live_urls), indent=2), encoding="utf-8")
    else:
        print("    [-] No new live assets discovered. Skipping deep scans.")
    # ------------------------------------

    print(f"    -> Potential Takeovers (404/503/Timeout/Conn_err): {len(takeovers)}")
    
    if cors_vulns:
        print("    [!] Vulnerable CORS found:")
        for r in cors_vulns:
            print(f"        - {r['url']}")
            
    if takeovers:
        print("    [!] Top Takeover Candidates:")
        for r in takeovers[:5]: # show top 5
            print(f"        - {r['url']} ({r['status']})")
            
    print("-"*60)
