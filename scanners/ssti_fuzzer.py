import requests
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER
import urllib.parse

def run_ssti_fuzzer(url):
    """
    Server-Side Template Injection (SSTI) Auto-Exploiter.
    Injects math equations to detect vulnerable template engines.
    """
    findings = []
    if "?" not in url: return findings
    
    headers = {}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query)
    
    # 7*7 payload for Jinja2/Twig/Freemarker
    payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
    
    for i, (k, v) in enumerate(params):
        for payload in payloads:
            test_params = params.copy()
            test_params[i] = (k, payload)
            test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(test_params), parsed.fragment))
            
            try:
                r = requests.get(test_url, headers=headers, timeout=5, verify=False)
                if "49" in r.text and "49" not in requests.get(url, timeout=5, verify=False).text:
                    findings.append({
                        "type": "SSTI_RCE",
                        "url": test_url,
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "verified": True,
                        "detail": f"CRITICAL: Server-Side Template Injection detected on parameter `{k}`. Payload `{payload}` evaluated to 49. RCE is possible!"
                    })
                    return findings
            except: pass
    return findings
