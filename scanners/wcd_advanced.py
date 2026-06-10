import requests
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_wcd_scan(url):
    """
    Web Cache Deception Scanner.
    Finds P1 vulnerabilities where a CDN caches authenticated profile data 
    because we appended a static extension (like .css).
    """
    findings = []
    headers = {}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"
    
    # Must have auth to test WCD properly
    if not headers:
        return findings

    test_url = f"{url.rstrip('/')}/.css"
    
    try:
        # First request to populate cache (Authenticated)
        requests.get(test_url, headers=headers, timeout=5, verify=False)
        
        # Second request WITHOUT auth to check if it's cached publicly
        r_unauth = requests.get(test_url, timeout=5, verify=False)
        
        cache_status = r_unauth.headers.get("X-Cache", "").upper()
        cf_cache = r_unauth.headers.get("CF-Cache-Status", "").upper()
        
        if "HIT" in cache_status or "HIT" in cf_cache:
            if r_unauth.status_code == 200:
                content_type = r_unauth.headers.get("Content-Type", "")
                # If the CDN served JSON or HTML (user data) from cache instead of actual CSS, it's vulnerable!
                if "application/json" in content_type or "text/html" in content_type:
                    findings.append({
                        "type": "WEB_CACHE_DECEPTION",
                        "url": test_url,
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "verified": True,
                        "detail": f"Web Cache Deception (WCD) confirmed! Appending '.css' caused the CDN to publicly cache the authenticated response. Header 'X-Cache: HIT' observed returning {content_type}."
                    })
    except Exception: 
        pass
    return findings
