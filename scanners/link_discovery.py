"""
Link & JS Endpoint Discovery Scanner.
Ref: awesome-bugbounty-tools (LinkFinder, waybackurls, gau, getJS, waymore, katana, jsluice).
"""
import re
import json
from urllib.parse import urlparse
from .utils import stealth_headers, safe_get, run_bin


def discover_links_and_js(url):
    """Crawl and extract endpoints from HTML, JS files, and Wayback Machine."""
    findings = []
    discovered_endpoints = set()
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # 1. Katana crawl (best)
    katana_out = run_bin("katana", ["-u", url, "-silent", "-d", "2", "-jc"], timeout=30)
    if katana_out:
        for line in katana_out.strip().split('\n'):
            line = line.strip()
            if line and line.startswith("http"):
                discovered_endpoints.add(line)

    # 2. GAU historical URLs
    hostname = urlparse(url).hostname
    gau_out = run_bin("gau", [hostname, "--threads", "2"], timeout=20)
    if gau_out:
        for line in gau_out.strip().split('\n'):
            line = line.strip()
            if line and line.startswith("http"):
                discovered_endpoints.add(line)

    # 3. Manual JS extraction (LinkFinder-style)
    r = safe_get(url)
    if r:
        # Extract JS file URLs
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text)
        for js_url in js_urls[:10]:
            if not js_url.startswith("http"):
                js_url = base + ("/" + js_url if not js_url.startswith("/") else js_url)
            jr = safe_get(js_url)
            if jr:
                # Extract paths/endpoints from JS
                paths = re.findall(r'["\']/(api|v[0-9]|graphql|admin|auth|login|user|account)[^\s"\']*["\']', jr.text, re.IGNORECASE)
                for p in paths:
                    discovered_endpoints.add(f"{base}/{p}")

                # Extract full URLs from JS
                urls_in_js = re.findall(r'https?://[^\s"\'<>]+', jr.text)
                for u in urls_in_js:
                    if urlparse(url).hostname in u:
                        discovered_endpoints.add(u.rstrip("'\";,)"))

    # Filter and categorize interesting endpoints
    api_endpoints = [e for e in discovered_endpoints if any(
        k in e.lower() for k in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/internal/"]
    )]
    auth_endpoints = [e for e in discovered_endpoints if any(
        k in e.lower() for k in ["/login", "/auth", "/oauth", "/token", "/signup", "/register"]
    )]
    admin_endpoints = [e for e in discovered_endpoints if any(
        k in e.lower() for k in ["/admin", "/dashboard", "/panel", "/console", "/manage"]
    )]

    if api_endpoints:
        findings.append({
            "type": "API_ENDPOINTS_DISCOVERED",
            "url": url,
            "severity": "INFO",
            "confidence": "HIGH",
            "detail": f"Found {len(api_endpoints)} API endpoints: {', '.join(api_endpoints[:5])}"
        })
    if admin_endpoints:
        findings.append({
            "type": "ADMIN_ENDPOINTS_DISCOVERED",
            "url": url,
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "detail": f"Found {len(admin_endpoints)} admin endpoints: {', '.join(admin_endpoints[:5])}"
        })

    if discovered_endpoints:
        findings.append({
            "type": "ENDPOINTS_DISCOVERED",
            "url": url,
            "severity": "INFO",
            "confidence": "HIGH",
            "detail": f"Total {len(discovered_endpoints)} unique endpoints discovered (katana+gau+JS)"
        })

    return findings if findings else None
