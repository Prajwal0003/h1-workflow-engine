"""
HTTP Request Smuggling Scanner.
Ref: awesome-bugbounty-tools (smuggler, h2csmuggler).
"""
import socket
from urllib.parse import urlparse
from .utils import stealth_headers, safe_get


def check_request_smuggling(url):
    """Test for CL.TE and TE.CL request smuggling via timing analysis."""
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname
    port = 443 if parsed.scheme == "https" else 80

    # Test 1: CL.TE detection via differential response
    try:
        import time

        # Normal request baseline
        start = time.time()
        r1 = safe_get(url, timeout=10)
        baseline = time.time() - start

        if not r1:
            return None

        # Send ambiguous Content-Length + Transfer-Encoding
        headers = {
            **stealth_headers(),
            "Transfer-Encoding": "chunked",
            "Content-Length": "4",
        }
        import requests
        try:
            start = time.time()
            r2 = requests.post(url, headers=headers, data="0\r\n\r\n", timeout=10, verify=False)
            elapsed = time.time() - start

            # If the server takes significantly longer, it may be processing the smuggled request
            if elapsed > baseline + 5:
                findings.append({
                    "type": "REQUEST_SMUGGLING_CANDIDATE",
                    "url": url,
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "detail": f"Potential CL.TE smuggling: baseline {baseline:.1f}s vs test {elapsed:.1f}s"
                })
        except requests.exceptions.ReadTimeout:
            findings.append({
                "type": "REQUEST_SMUGGLING_CANDIDATE",
                "url": url,
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "detail": "Timeout on CL.TE probe — possible desync"
            })
    except Exception:
        pass

    # Test 2: Check for HTTP/2 downgrade (h2c smuggling)
    try:
        headers = {**stealth_headers(), "Upgrade": "h2c", "Connection": "Upgrade, HTTP2-Settings"}
        r = safe_get(url, timeout=5)
        if r and r.status_code == 101:
            findings.append({
                "type": "H2C_SMUGGLING",
                "url": url,
                "severity": "HIGH",
                "confidence": "HIGH",
                "detail": "Server accepts h2c upgrade — potential smuggling vector"
            })
    except Exception:
        pass

    return findings if findings else None
