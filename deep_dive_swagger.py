#!/usr/bin/env python3
"""Deep dive into the Swagger UI finding on api.recordedfuture.com"""
import requests, json, sys, os
os.environ["PYTHONIOENCODING"] = "utf-8"
try: sys.stdout.reconfigure(encoding="utf-8")
except: pass

H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
base = "https://api.recordedfuture.com"

print("=== DEEP DIVE: api.recordedfuture.com Swagger UI ===\n")

# 1. Confirm Swagger UI
r = requests.get(f"{base}/swagger-ui/", headers=H, timeout=10)
print(f"[1] Swagger UI: {r.status_code} ({len(r.text)} bytes)")
print(f"    Content snippet: {r.text[:200]}")
print()

# 2. Try all common spec locations
spec_paths = [
    "/swagger.json", "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api/swagger.json", "/swagger-resources", "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
]

print("[2] Probing for API spec files...")
for path in spec_paths:
    url = f"{base}{path}"
    try:
        r = requests.get(url, headers=H, timeout=5)
        ct = r.headers.get("Content-Type", "")
        if r.status_code == 200:
            print(f"    [200] {path} ({ct[:30]}, {len(r.text)}B)")
            if "json" in ct or r.text.strip().startswith("{"):
                try:
                    data = r.json()
                    if "paths" in data or "swagger" in data or "openapi" in data:
                        print(f"         !!! FULL API SPEC FOUND !!!")
                        paths = list(data.get("paths", {}).keys())
                        print(f"         Endpoints: {len(paths)}")
                        for p in paths[:20]:
                            methods = list(data["paths"][p].keys())
                            print(f"           {', '.join(m.upper() for m in methods)} {p}")
                        # Save it
                        with open("data/autopilot/mega/rf_api_spec.json", "w") as f:
                            json.dump(data, f, indent=2)
                        print(f"         Saved to: data/autopilot/mega/rf_api_spec.json")
                    elif "apis" in data or "url" in str(data):
                        print(f"         Resource listing: {json.dumps(data)[:300]}")
                except:
                    pass
        elif r.status_code == 401:
            print(f"    [401] {path} — Auth required (exists!)")
        elif r.status_code == 403:
            print(f"    [403] {path} — Forbidden (exists!)")
    except Exception as e:
        pass

# 3. Check for version/info endpoints
print("\n[3] Probing for info disclosure endpoints...")
info_paths = ["/health", "/healthz", "/status", "/version", "/info", "/actuator",
    "/actuator/health", "/actuator/info", "/actuator/env", "/metrics",
    "/api/v1/status", "/api/v2/status", "/debug", "/ping"]

for path in info_paths:
    url = f"{base}{path}"
    try:
        r = requests.get(url, headers=H, timeout=5)
        if r.status_code == 200:
            ct = r.headers.get("Content-Type", "")
            print(f"    [200] {path} ({ct[:30]})")
            if "json" in ct:
                try:
                    print(f"         {json.dumps(r.json())[:200]}")
                except:
                    print(f"         {r.text[:200]}")
    except:
        pass

# 4. Check all subdomains for Swagger
print("\n[4] Checking other subdomains for Swagger/API docs...")
other_targets = [
    "https://app.recordedfuture.com",
    "https://id.recordedfuture.com",
    "https://tria.ge",
    "https://hatching.io",
    "https://geminiadvisory.io",
]
for target in other_targets:
    for path in ["/swagger-ui/", "/swagger.json", "/api-docs", "/graphql", "/graphiql"]:
        url = f"{target}{path}"
        try:
            r = requests.get(url, headers=H, timeout=5)
            if r.status_code == 200 and len(r.text) > 50:
                ct = r.headers.get("Content-Type", "")
                print(f"    [200] {url} ({ct[:30]}, {len(r.text)}B)")
        except:
            pass

# 5. Header analysis on all verified findings
print("\n[5] Full header dump for api.recordedfuture.com...")
r = requests.get(base, headers=H, timeout=10)
for k, v in r.headers.items():
    print(f"    {k}: {v[:100]}")
