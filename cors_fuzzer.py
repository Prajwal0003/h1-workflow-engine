import os
import requests


BASE_URL = os.environ.get("H1_AUTHORIZED_BASE_URL", "").rstrip("/")
if not BASE_URL.startswith("https://"):
    raise SystemExit("Set H1_AUTHORIZED_BASE_URL to an HTTPS origin you are authorized to test.")

COOKIE_STRING = os.environ.get("H1_SCAN_COOKIE", "")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Origin": "https://evil.com",
    "Cookie": COOKIE_STRING,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Priority": "u=0, i",
    "TE": "trailers"
}

# Common sensitive endpoints
WORDLIST = [
    "", "/", "/api/v1/user", "/api/user", "/api/me", "/api/profile",
    "/v1/users/me", "/user/details", "/account", "/profile",
    "/api/bookings", "/api/reservations", "/api/trips",
    "/graphql", "/api/graphql", "/swagger-ui.html"
]

print(f"[*] Fuzzing {BASE_URL} for sensitive endpoints...")
print(f"[*] Sending 'Origin: https://evil.com' to test CORS reflection.\n")

for path in WORDLIST:
    target = f"{BASE_URL}{path}"
    try:
        resp = requests.get(target, headers=HEADERS, allow_redirects=False, timeout=5)
        
        if resp.status_code != 404: # Ignore 404s
            print(f"[+] Found Endpoint: {target} (Status: {resp.status_code})")
            
            # Check for CORS vulnerability
            allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if allow_origin == "https://evil.com" and allow_creds == "true":
                print(f"    [!!!] VULNERABLE TO CORS: {target}")
                print(f"    [!!!] Response size: {len(resp.text)} bytes")

    except requests.exceptions.RequestException as e:
        print(f"[-] Error on {target}: {e}")

print("\n[*] Fuzzing complete.")
