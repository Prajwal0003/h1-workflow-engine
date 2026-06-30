"""
CSRF Scanner — Cross-Site Request Forgery detection.
Ref: awesome-bugbounty-tools (XSRFProbe).
"""
import re
from urllib.parse import urlparse
from .utils import stealth_headers, safe_get


def check_csrf(url):
    """Check forms for missing CSRF tokens and proper cookie flags."""
    findings = []
    r = safe_get(url)
    if not r:
        return None

    html = r.text
    # Find all forms
    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)

    for form_html in forms:
        form_tag = re.search(r'<form[^>]*>', html, re.IGNORECASE)
        method = "GET"
        if form_tag:
            method_match = re.search(r'method=["\'](\w+)["\']', form_tag.group(), re.IGNORECASE)
            if method_match:
                method = method_match.group(1).upper()

        if method != "POST":
            continue

        # Check for CSRF token indicators
        csrf_indicators = [
            r'name=["\']_?csrf',
            r'name=["\']_token',
            r'name=["\']authenticity_token',
            r'name=["\']__RequestVerificationToken',
            r'name=["\']_xsrf',
            r'name=["\']csrfmiddlewaretoken',
            r'type=["\']hidden["\'][^>]*name=["\']token',
        ]

        has_csrf = any(re.search(p, form_html, re.IGNORECASE) for p in csrf_indicators)

        if not has_csrf:
            # Check for SameSite cookie
            cookies = r.headers.get("Set-Cookie", "")
            has_samesite = "SameSite" in cookies

            if not has_samesite:
                findings.append({
                    "type": "CSRF_MISSING_TOKEN",
                    "url": url,
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "detail": "POST form without CSRF token or SameSite cookie"
                })

    return findings if findings else None
