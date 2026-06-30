#!/usr/bin/env python3
"""Verify all mega scanner findings — kill false positives, confirm real ones."""
import requests, json, sys, os
os.environ["PYTHONIOENCODING"] = "utf-8"
try: sys.stdout.reconfigure(encoding="utf-8")
except: pass

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
findings = []
with open("data/autopilot/mega/findings.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            findings.append(json.loads(line))

print(f"Total raw findings: {len(findings)}")
print(f"{'='*70}\n")

verified = []
false_positives = []
duplicates = []

seen_types = {}

for i, f in enumerate(findings, 1):
    typ = f["type"]
    url = f["url"]
    sev = f["severity"]
    key = f"{typ}|{url}"
    
    # Dedup check
    if key in seen_types:
        duplicates.append(f)
        print(f"[{i}] DUPLICATE: {typ} @ {url[:50]}")
        continue
    seen_types[key] = True
    
    print(f"[{i}] Verifying: [{sev}] {typ}")
    print(f"    URL: {url}")
    
    # ── Verify security.txt files ──
    if "security.txt" in url:
        try:
            r = requests.get(url, headers=H, timeout=5)
            if r.status_code == 200 and "Contact:" in r.text:
                print(f"    VERDICT: FALSE POSITIVE — This is a STANDARD security.txt disclosure file.")
                print(f"    REASON: security.txt is intentionally public per RFC 9116. Not a vulnerability.")
                print(f"    Content: {r.text[:120]}")
                false_positives.append({**f, "verdict": "FALSE_POSITIVE", "reason": "security.txt is intentional per RFC 9116"})
            else:
                print(f"    VERDICT: Checking further...")
        except Exception as e:
            print(f"    ERROR: {e}")
        print()
        continue
    
    # ── Verify missing security headers ──
    if typ.startswith("MISSING_"):
        header_name = typ.replace("MISSING_", "").replace("_", "-")
        try:
            r = requests.get(url, headers=H, timeout=5)
            
            # Check if the header is truly missing
            found = False
            for k in r.headers:
                if k.lower().replace("-","_") == header_name.lower().replace("-","_"):
                    found = True
                    break
            
            if found:
                print(f"    VERDICT: FALSE POSITIVE — Header IS present now")
                false_positives.append({**f, "verdict": "FALSE_POSITIVE", "reason": "Header present on re-check"})
            else:
                # Missing headers are real but low-severity
                print(f"    VERDICT: REAL but LOW impact — missing {header_name}")
                print(f"    NOTE: Most programs do NOT pay for missing headers alone")
                verified.append({**f, "verdict": "REAL_LOW_IMPACT", "reason": f"Missing {header_name} confirmed, but P4 at best"})
        except Exception as e:
            print(f"    ERROR: {e}")
        print()
        continue
    
    # ── Verify SERVER_INFO_LEAK ──
    if typ == "SERVER_INFO_LEAK":
        try:
            r = requests.get(url, headers=H, timeout=5)
            xpb = r.headers.get("x-powered-by", "")
            if xpb:
                print(f"    CONFIRMED: x-powered-by: {xpb}")
                print(f"    VERDICT: REAL but usually NOT bounty-worthy (P4/informational)")
                verified.append({**f, "verdict": "REAL_LOW_IMPACT", "reason": f"x-powered-by: {xpb} confirmed. Informational."})
            else:
                print(f"    VERDICT: FALSE POSITIVE — header gone on recheck")
                false_positives.append({**f, "verdict": "FALSE_POSITIVE", "reason": "Header not present on re-check"})
        except Exception as e:
            print(f"    ERROR: {e}")
        print()
        continue
    
    # ── Verify INTERNAL_INFO_HEADER ──
    if typ == "INTERNAL_INFO_HEADER":
        detail = f["detail"]
        if "content-security-policy" in detail.lower():
            print(f"    VERDICT: FALSE POSITIVE — CSP header containing googleapis.com domains is normal")
            print(f"    REASON: CSP lists allowed sources; Google APIs are third-party services, not internal infrastructure")
            false_positives.append({**f, "verdict": "FALSE_POSITIVE", "reason": "CSP header with Google APIs is standard config, not internal info leak"})
        else:
            print(f"    NEEDS REVIEW: {detail[:100]}")
        print()
        continue
    
    # ── Verify API_DOCS_EXPOSED ──
    if typ == "API_DOCS_EXPOSED":
        try:
            r = requests.get(url, headers=H, timeout=5)
            if r.status_code == 200:
                is_swagger = "swagger" in r.text.lower() or "openapi" in r.text.lower()
                # Check if it requires auth
                has_auth_required = "authorize" in r.text.lower() or "login" in r.text.lower()
                
                if is_swagger:
                    print(f"    CONFIRMED: Swagger UI is publicly accessible!")
                    print(f"    Status: {r.status_code}, Size: {len(r.text)} bytes")
                    
                    # Try to fetch the spec
                    spec_urls = [
                        url.replace("/swagger-ui/", "/swagger.json"),
                        url.replace("/swagger-ui/", "/v2/api-docs"),
                        url.replace("/swagger-ui/", "/openapi.json"),
                    ]
                    for spec_url in spec_urls:
                        sr = requests.get(spec_url, headers=H, timeout=5)
                        if sr.status_code == 200 and "json" in sr.headers.get("Content-Type",""):
                            try:
                                spec = sr.json()
                                paths = list(spec.get("paths", {}).keys())[:10]
                                print(f"    SPEC FOUND: {spec_url}")
                                print(f"    API PATHS: {paths}")
                                print(f"    VERDICT: REAL — P3/Medium. Public API docs with endpoint details.")
                                verified.append({**f, "verdict": "REAL_SUBMITTABLE", 
                                    "reason": f"Swagger UI + spec accessible. {len(spec.get('paths',{}))} endpoints exposed.",
                                    "api_paths": paths})
                                break
                            except:
                                pass
                    else:
                        print(f"    VERDICT: REAL but lower impact — Swagger UI without downloadable spec")
                        verified.append({**f, "verdict": "REAL_LOW_IMPACT", "reason": "Swagger UI accessible but spec not directly downloadable"})
                else:
                    print(f"    VERDICT: FALSE POSITIVE — page doesn't contain actual Swagger/OpenAPI content")
                    false_positives.append({**f, "verdict": "FALSE_POSITIVE", "reason": "No actual API docs content"})
            else:
                print(f"    VERDICT: FALSE POSITIVE — returns {r.status_code}")
                false_positives.append({**f, "verdict": "FALSE_POSITIVE", "reason": f"Returns {r.status_code}"})
        except Exception as e:
            print(f"    ERROR: {e}")
        print()
        continue
    
    # ── Verify OAUTH_ENDPOINT_FOUND ──
    if typ == "OAUTH_ENDPOINT_FOUND":
        try:
            r = requests.get(url, headers=H, timeout=5)
            if r.status_code == 200:
                data = r.json()
                print(f"    CONFIRMED: OpenID Connect config is public")
                print(f"    Issuer: {data.get('issuer','N/A')}")
                print(f"    VERDICT: FALSE POSITIVE — OIDC discovery is INTENTIONALLY public per spec (RFC 8414)")
                false_positives.append({**f, "verdict": "FALSE_POSITIVE", "reason": "OIDC discovery endpoint is intentionally public per RFC 8414"})
        except Exception as e:
            print(f"    ERROR: {e}")
        print()
        continue
    
    # Default
    print(f"    VERDICT: NEEDS MANUAL REVIEW")
    verified.append({**f, "verdict": "NEEDS_REVIEW"})
    print()

# ── Summary ──
print(f"\n{'='*70}")
print(f"  TRIAGE SUMMARY")
print(f"{'='*70}")
print(f"  Total Raw:        {len(findings)}")
print(f"  Duplicates:       {len(duplicates)}")
print(f"  False Positives:  {len(false_positives)}")
print(f"  Verified Real:    {len(verified)}")
print()

print(f"--- FALSE POSITIVES ({len(false_positives)}) ---")
for fp in false_positives:
    print(f"  [x] {fp['type']}: {fp['reason']}")

print(f"\n--- VERIFIED FINDINGS ({len(verified)}) ---")
for v in verified:
    verdict = v.get("verdict","?")
    emoji = {"REAL_SUBMITTABLE":"$$$","REAL_LOW_IMPACT":"..","NEEDS_REVIEW":"??"}.get(verdict,"??")
    print(f"  [{emoji}] [{v['severity']}] {v['type']} @ {v['url'][:50]}")
    print(f"       {v.get('reason','')}")

# Save
out = {"verified": verified, "false_positives": false_positives, "duplicates": duplicates}
with open("data/autopilot/mega/triage_results.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\nTriage saved to: data/autopilot/mega/triage_results.json")
