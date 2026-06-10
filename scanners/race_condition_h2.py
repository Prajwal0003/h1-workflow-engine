import requests
import json
import threading
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_h2_race_condition(url):
    """
    HTTP/2 Single-Packet Race Condition Fuzzer (Simplified for Python).
    Fires concurrent requests targeting common state-changing endpoints.
    """
    findings = []
    if not GLOBAL_COOKIE and not GLOBAL_BEARER:
        return findings
    
    # Only test endpoints that might be vulnerable to race conditions
    targets = ["/api/v1/redeem", "/api/v1/transfer", "/api/v1/coupon", "/api/coupon", "/api/transfer"]
    
    is_target = False
    for t in targets:
        if t in url.lower():
            is_target = True
            break
            
    if not is_target:
        return findings

    headers = {}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"

    success_count = 0
    lock = threading.Lock()
    
    def send_req():
        nonlocal success_count
        try:
            r = requests.post(url, headers=headers, json={"code": "FREE100", "amount": 10}, timeout=5, verify=False)
            if r.status_code in [200, 201]:
                with lock:
                    success_count += 1
        except:
            pass

    threads = []
    for _ in range(15):
        t = threading.Thread(target=send_req)
        threads.append(t)
        
    for t in threads: t.start()
    for t in threads: t.join()
    
    if success_count > 1:
        findings.append({
            "type": "RACE_CONDITION",
            "url": url,
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "verified": True,
            "detail": f"Race Condition Exploited! Endpoint processed {success_count} concurrent requests successfully instead of 1."
        })
        
    return findings
