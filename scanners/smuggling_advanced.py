import requests
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_smuggling_advanced(url):
    """
    HTTP Request Smuggling (CL.TE / TE.CL) basic detection.
    """
    findings = []
    headers = {
        "Transfer-Encoding": "chunked",
        "Content-Length": "4"
    }
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    
    body = "1\r\nZ\r\n0\r\n\r\n"
    try:
        r = requests.post(url, headers=headers, data=body, timeout=5, verify=False)
        if r.status_code == 500 or r.status_code == 400:
            # Often indicates a smuggling desync if the server errors out
            pass
    except requests.exceptions.Timeout:
        # Timeouts often indicate a TE.CL desync hanging the socket
        findings.append({
            "type": "HTTP_REQUEST_SMUGGLING_TIMEOUT",
            "url": url,
            "severity": "HIGH",
            "confidence": "LOW",
            "verified": False,
            "detail": "Possible HTTP Request Smuggling (TE.CL) detected via timeout."
        })
    except: pass
    return findings
