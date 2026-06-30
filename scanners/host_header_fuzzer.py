import requests
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_host_header_fuzzer(url):
    """
    Tests for Host Header Injection which can lead to Password Reset Poisoning 
    or Web Cache Poisoning.
    """
    findings = []
    
    headers_to_test = [
        {"Host": "evil.com"},
        {"X-Forwarded-Host": "evil.com"},
        {"X-Forwarded-Server": "evil.com"},
        {"X-Host": "evil.com"}
    ]
    
    for h in headers_to_test:
        test_headers = h.copy()
        if GLOBAL_COOKIE: test_headers["Cookie"] = GLOBAL_COOKIE
        if GLOBAL_BEARER: test_headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"
        
        try:
            r = requests.get(url, headers=test_headers, timeout=5, verify=False, allow_redirects=False)
            
            # Check if the server redirects us to evil.com
            location = r.headers.get("Location", "")
            if "evil.com" in location and r.status_code in [301, 302, 307, 308]:
                findings.append({
                    "type": "HOST_HEADER_INJECTION",
                    "url": url,
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "verified": True,
                    "detail": f"Host Header Injection! Injecting `{list(h.keys())[0]}: evil.com` caused the server to redirect to {location}."
                })
                break
                
            # Check if evil.com is reflected in the body (e.g. absolute URLs for password resets)
            if "evil.com" in r.text and "<html" in r.text.lower():
                findings.append({
                    "type": "HOST_HEADER_REFLECTION",
                    "url": url,
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "verified": True,
                    "detail": f"Host Header Reflection! Injecting `{list(h.keys())[0]}: evil.com` caused the domain to be reflected in the HTML. Could be used for Cache Poisoning."
                })
                break
        except Exception: 
            pass
            
    return findings
