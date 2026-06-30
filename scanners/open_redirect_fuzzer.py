import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_open_redirect_fuzzer(url):
    """
    Automatically detects and exploits Open Redirect vulnerabilities 
    with zero false positives.
    """
    findings = []
    if "?" not in url: return findings
    
    headers = {}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"

    parsed = urlparse(url)
    params = parse_qsl(parsed.query)
    
    evil_url = "https://evil.com"
    
    for i, (k, v) in enumerate(params):
        test_params = params.copy()
        test_params[i] = (k, evil_url)
        
        test_query = urlencode(test_params)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
        
        try:
            # We must NOT allow redirects, we want to catch the Location header
            r = requests.get(test_url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            
            location = r.headers.get("Location", "")
            # Strict Zero-FP Check: The location must exactly equal or start with our evil URL
            if location.startswith("https://evil.com") or location.startswith("//evil.com"):
                findings.append({
                    "type": "OPEN_REDIRECT",
                    "url": test_url,
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "verified": True,
                    "detail": f"Verified Open Redirect on parameter `{k}`. Server responded with Location: {location}"
                })
                break
        except Exception: 
            pass
            
    return findings
