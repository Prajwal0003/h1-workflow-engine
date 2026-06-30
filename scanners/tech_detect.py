"""
Technology Detection Scanner.
Ref: awesome-bugbounty-tools (wappalyzer, httpx, fingerprintx, wafw00f, cdncheck, tlsx).
"""
import re
import json
from .utils import stealth_headers, safe_get, run_bin


TECH_SIGNATURES = {
    "jQuery": [r'jquery[.-](\d+\.\d+\.\d+)', r'jquery\.min\.js'],
    "React": [r'react[.-](\d+\.\d+)', r'_reactRootContainer', r'__NEXT_DATA__'],
    "Angular": [r'angular[.-](\d+\.\d+)', r'ng-app', r'ng-version'],
    "Vue.js": [r'vue[.-](\d+\.\d+)', r'__vue__', r'v-app'],
    "Bootstrap": [r'bootstrap[.-](\d+\.\d+)', r'bootstrap\.min\.css'],
    "Laravel": [r'laravel_session', r'XSRF-TOKEN'],
    "Django": [r'csrfmiddlewaretoken', r'django'],
    "Rails": [r'X-Runtime', r'X-Request-Id'],
    "Express": [r'X-Powered-By:\s*Express'],
    "ASP.NET": [r'X-AspNet-Version', r'X-Powered-By:\s*ASP\.NET', r'__VIEWSTATE'],
    "PHP": [r'X-Powered-By:\s*PHP', r'PHPSESSID'],
    "Nginx": [r'Server:\s*nginx'],
    "Apache": [r'Server:\s*Apache'],
    "IIS": [r'Server:\s*Microsoft-IIS'],
    "Cloudflare": [r'cf-ray', r'Server:\s*cloudflare'],
    "WordPress": [r'wp-content', r'wp-includes', r'wp-json'],
    "Shopify": [r'cdn\.shopify\.com', r'Shopify\.theme'],
    "Next.js": [r'__NEXT_DATA__', r'_next/static'],
}


def check_technologies(url):
    """Detect web technologies, frameworks, and server info."""
    findings = []

    # Try httpx binary first for comprehensive detection
    httpx_out = run_bin("httpx", ["-u", url, "-tech-detect", "-json", "-silent"], timeout=15)
    if httpx_out:
        try:
            for line in httpx_out.strip().split('\n'):
                data = json.loads(line)
                techs = data.get("tech", [])
                if techs:
                    findings.append({
                        "type": "TECH_STACK",
                        "url": url,
                        "severity": "INFO",
                        "confidence": "HIGH",
                        "detail": f"Technologies: {', '.join(techs)}"
                    })
                # Check for outdated server versions
                server = data.get("webserver", "")
                if server:
                    version_match = re.search(r'(\d+\.\d+)', server)
                    if version_match:
                        findings.append({
                            "type": "SERVER_VERSION",
                            "url": url,
                            "severity": "LOW",
                            "confidence": "HIGH",
                            "detail": f"Server: {server}"
                        })
        except (json.JSONDecodeError, KeyError):
            pass

    if findings:
        return findings

    # Fallback: manual detection
    r = safe_get(url)
    if not r:
        return None

    detected = []
    headers_str = str(r.headers)
    full_text = headers_str + r.text

    for tech_name, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                detected.append(tech_name)
                break

    if detected:
        findings.append({
            "type": "TECH_STACK",
            "url": url,
            "severity": "INFO",
            "confidence": "MEDIUM",
            "detail": f"Technologies: {', '.join(detected)}"
        })

    # Check for version disclosure in Server header
    server = r.headers.get("Server", "")
    powered_by = r.headers.get("X-Powered-By", "")
    if server and any(c.isdigit() for c in server):
        findings.append({
            "type": "SERVER_VERSION_DISCLOSURE",
            "url": url,
            "severity": "LOW",
            "confidence": "HIGH",
            "detail": f"Server header: {server}"
        })
    if powered_by:
        findings.append({
            "type": "POWERED_BY_DISCLOSURE",
            "url": url,
            "severity": "LOW",
            "confidence": "HIGH",
            "detail": f"X-Powered-By: {powered_by}"
        })

    return findings if findings else None
