import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_oauth_hijack(url):
    """
    Automated OAuth 2.0 & SSO Hijacker.
    Looks for redirect_uri in the URL and attempts to hijack the flow.
    """
    findings = []
    if "redirect_uri" not in url and "redirect_url" not in url and "return_to" not in url:
        return findings
        
    parsed = urlparse(url)
    params = parse_qsl(parsed.query)
    
    for i, (k, v) in enumerate(params):
        if k in ["redirect_uri", "redirect_url", "return_to"]:
            test_params = params.copy()
            test_params[i] = (k, "https://evil.com")
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_params), parsed.fragment))
            try:
                r = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                if r.headers.get("Location", "").startswith("https://evil.com"):
                    findings.append({
                        "type": "OAUTH_REDIRECT_HIJACK",
                        "url": test_url,
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "verified": True,
                        "detail": f"OAuth/SSO Hijack verified! Parameter {k} successfully redirected to evil.com during the OAuth flow."
                    })
            except: pass
            
    return findings
