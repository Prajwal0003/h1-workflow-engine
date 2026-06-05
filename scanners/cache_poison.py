"""
Web Cache Poisoning Scanner.
Ref: awesome-bugbounty-tools (toxicache).
"""
import random
from .utils import stealth_headers, safe_get


POISON_HEADERS = {
    "X-Forwarded-Host": "evil-cache-poison.com",
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin",
    "X-Forwarded-Scheme": "nothttps",
    "X-Forwarded-Port": "1337",
    "X-Host": "evil-cache-poison.com",
    "X-Forwarded-Server": "evil-cache-poison.com",
}


def check_cache_poisoning(url):
    """Test for web cache poisoning via unkeyed header injection."""
    findings = []

    # Baseline request
    r1 = safe_get(url)
    if not r1:
        return None

    baseline_text = r1.text
    cache_headers = {
        k: v for k, v in r1.headers.items()
        if k.lower() in ["x-cache", "cf-cache-status", "age", "x-varnish", "via", "x-cache-hits"]
    }

    # If no caching detected, skip
    if not cache_headers:
        return None

    # Test each poison header
    for header_name, header_value in POISON_HEADERS.items():
        headers = stealth_headers()
        headers[header_name] = header_value
        # Add cache buster to avoid affecting cached version
        cache_buster = f"?cb={random.randint(100000, 999999)}"
        test_url = f"{url.rstrip('/')}{cache_buster}"

        r = safe_get(test_url)
        if not r:
            continue

        # Check if the poison value appears in the response
        if header_value in r.text and header_value not in baseline_text:
            findings.append({
                "type": "CACHE_POISONING",
                "url": url,
                "severity": "HIGH",
                "confidence": "HIGH",
                "detail": f"Unkeyed header {header_name} reflected in cached response"
            })
            break

        # Check for different response due to cache state
        if "evil-cache-poison.com" in r.text:
            findings.append({
                "type": "CACHE_POISONING",
                "url": url,
                "severity": "HIGH",
                "confidence": "HIGH",
                "detail": f"Cache poisoned via {header_name} header injection"
            })
            break

    return findings if findings else None
