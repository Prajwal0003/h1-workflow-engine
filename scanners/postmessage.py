"""
postMessage Scanner — Detect insecure postMessage usage.
Ref: awesome-bugbounty-tools (postMessage-tracker, PostMessage_Fuzz_Tool).
"""
import re
from .utils import stealth_headers, safe_get


def check_postmessage(url):
    """Scan for insecure postMessage implementations (missing origin checks)."""
    findings = []

    r = safe_get(url)
    if not r:
        return None

    html = r.text

    # Check for addEventListener("message", ...) without origin validation
    message_handlers = re.findall(
        r'addEventListener\s*\(\s*["\']message["\']\s*,\s*function\s*\(([^)]*)\)\s*\{([^}]{0,500})\}',
        html, re.DOTALL
    )

    for event_var, handler_body in message_handlers:
        event_name = event_var.strip() or "e"
        # Check if origin is validated
        has_origin_check = bool(re.search(
            rf'{event_name}\.origin|event\.origin|\.origin\s*[!=]==', handler_body
        ))

        if not has_origin_check:
            # Check what the handler does with the data
            is_dangerous = any(pattern in handler_body for pattern in [
                "innerHTML", "document.write", "eval(", "location",
                ".src", "$.html(", "dangerouslySetInnerHTML",
            ])

            severity = "HIGH" if is_dangerous else "MEDIUM"
            detail = "postMessage handler without origin check"
            if is_dangerous:
                detail += " — uses dangerous sink (innerHTML/eval/location)"

            findings.append({
                "type": "POSTMESSAGE_NO_ORIGIN_CHECK",
                "url": url,
                "severity": severity,
                "confidence": "MEDIUM",
                "detail": detail
            })

    # Check for window.postMessage usage (potential data leakage)
    postmessage_calls = re.findall(
        r'\.postMessage\s*\([^,]+,\s*["\'](\*)["\']', html
    )
    if postmessage_calls:
        findings.append({
            "type": "POSTMESSAGE_WILDCARD_ORIGIN",
            "url": url,
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "detail": "postMessage sent with targetOrigin='*' — data leakage risk"
        })

    return findings if findings else None
