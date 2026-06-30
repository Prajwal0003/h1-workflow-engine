import requests, json, re

headers = {"User-Agent": "Mozilla/5.0"}

print("=== SENTRY DEEP DIVE: sentry.osl.com ===")

# 1. Root API info
r = requests.get("https://sentry.osl.com/api/0/", headers=headers, timeout=5)
print(f"Root API: {r.status_code}")
print(f"  Response: {r.text[:300]}")

# 2. Try to enumerate organizations
paths = [
    "/api/0/organizations/?limit=100",
    "/api/0/internal/stats/",
    "/api/0/internal/health/",
    "/api/0/relay/projectconfigs/",
    "/api/0/relay/publickeys/",
    "/api/0/broadcast/",
    "/api/0/assistant/",
]
for path in paths:
    try:
        r2 = requests.get(f"https://sentry.osl.com{path}", headers=headers, timeout=5)
        ct = r2.headers.get("Content-Type", "")
        print(f"  {path} -> {r2.status_code} ({ct[:30]})")
        if r2.status_code == 200 and "json" in ct:
            print(f"    Data: {r2.text[:300]}")
    except Exception as e:
        print(f"  {path} -> Error")

# 3. Check for Sentry DSN in main page source
print()
print("=== Checking for Sentry DSN in JS bundles ===")
r3 = requests.get("https://www.osl.com/en", headers=headers, timeout=10)
js_links = re.findall(r'src="([^"]*\.js[^"]*)"', r3.text)

found_dsns = set()
for link in js_links[:15]:
    if not link.startswith("http"):
        link = "https://osl.com" + link if link.startswith("/") else "https://osl.com/" + link
    try:
        jr = requests.get(link, timeout=5)
        dsns = re.findall(r'https://[a-f0-9]+@[a-z0-9.]*sentry[a-z0-9.]*/\d+', jr.text)
        for d in dsns:
            if d not in found_dsns:
                found_dsns.add(d)
                short_link = link.split("/")[-1][:40]
                print(f"  Found DSN: {d}")
                print(f"    Source: {short_link}")
    except:
        pass

if not found_dsns:
    print("  No Sentry DSNs found in JS bundles.")

# 4. Check response headers for info leaks
print()
print("=== RESPONSE HEADER ANALYSIS ===")
for url in ["https://www.osl.com/en", "https://sentry.osl.com/", "https://api.osl.com/"]:
    try:
        r4 = requests.get(url, headers=headers, timeout=5)
        interesting = {}
        for k, v in r4.headers.items():
            kl = k.lower()
            if any(x in kl for x in ["server", "x-", "via", "powered", "version", "cf-"]):
                interesting[k] = v
        if interesting:
            print(f"  {url}:")
            for k, v in interesting.items():
                print(f"    {k}: {v}")
    except:
        pass
