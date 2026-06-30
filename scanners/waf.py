"""
WAF Detection Scanner.
Ref: awesome-bugbounty-tools (wafw00f, nomore403, XFFenum, Forbidden Buster).
"""
from .utils import stealth_headers, safe_get, run_bin

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["x-amzn-requestid", "awselb", "x-amz-cf-id"],
    "Akamai": ["akamai", "x-akamai-transformed", "akamai-origin-hop"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo", "x-cdn: imperva"],
    "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "F5 BIG-IP": ["bigipserver", "x-cnection", "f5-"],
    "ModSecurity": ["mod_security", "modsecurity", "nyob"],
    "Barracuda": ["barra_counter_session", "barracuda"],
    "Fastly": ["x-fastly-request-id", "fastly"],
    "Varnish": ["x-varnish", "via: varnish"],
    "StackPath": ["x-sp-", "stackpath"],
    "DDoS-Guard": ["ddos-guard"],
    "Wordfence": ["wordfence"],
}

BYPASS_HEADERS_403 = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
]


def detect_waf(url):
    """Detect WAF/CDN and attempt 403 bypass techniques."""
    findings = []

    # Step 1: Detect WAF
    r = safe_get(url)
    if not r:
        return None

    detected_waf = None
    all_headers = str(r.headers).lower()
    all_cookies = str(r.cookies).lower()
    combined = all_headers + " " + all_cookies

    for waf_name, signatures in WAF_SIGNATURES.items():
        if any(sig.lower() in combined for sig in signatures):
            detected_waf = waf_name
            break

    if detected_waf:
        findings.append({
            "type": "WAF_DETECTED",
            "url": url,
            "severity": "INFO",
            "confidence": "HIGH",
            "detail": f"WAF/CDN detected: {detected_waf}"
        })

    # Step 2: If we get 403, try bypass techniques
    if r.status_code == 403:
        for bypass_header in BYPASS_HEADERS_403:
            headers = {**stealth_headers(), **bypass_header}
            r2 = safe_get(url)
            if r2 and r2.status_code == 200:
                header_name = list(bypass_header.keys())[0]
                findings.append({
                    "type": "WAF_403_BYPASS",
                    "url": url,
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": f"403 bypassed using {header_name}: {bypass_header[header_name]}"
                })
                break

        # Path-based bypass attempts
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path or "/"
        bypass_paths = [
            f"{path}/.",
            f"{path}//",
            f"{path}/./",
            f"/{path.lstrip('/')}..;/",
            f"{path}%20",
            f"{path}%09",
            f"{path}?",
            f"{path}.html",
            f"{path};",
        ]

        base = f"{parsed.scheme}://{parsed.netloc}"
        for bp in bypass_paths:
            r3 = safe_get(f"{base}{bp}")
            if r3 and r3.status_code == 200 and len(r3.text) > 100:
                findings.append({
                    "type": "WAF_PATH_BYPASS",
                    "url": f"{base}{bp}",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": f"403 bypassed via path manipulation: {bp}"
                })
                break

    return findings if findings else None
