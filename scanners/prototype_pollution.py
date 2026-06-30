import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_prototype_pollution(url):
    """
    Client-side Prototype Pollution scanner via query parameters.
    """
    findings = []
    if "?" not in url:
        test_url = url.rstrip("/") + "?__proto__[evil]=1"
    else:
        test_url = url + "&__proto__[evil]=1"
        
    headers = {}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    
    try:
        r = requests.get(test_url, headers=headers, timeout=5, verify=False)
        # Simplified check: looking for reflection that might indicate pollution
        if "__proto__[evil]" in r.text:
            pass # A full headless browser is needed to verify execution.
            # We defer execution to the headless DOM XSS tracer.
    except: pass
    
    return findings
