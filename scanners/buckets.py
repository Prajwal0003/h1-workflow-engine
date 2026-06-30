"""
S3 Bucket Scanner — Open bucket detection and misconfiguration testing.
Ref: awesome-bugbounty-tools (S3Scanner, CloudBrute, kicks3).
"""
import re
from urllib.parse import urlparse
from .utils import stealth_headers, safe_get

BUCKET_PATTERNS = [
    r'([a-zA-Z0-9._-]+)\.s3\.amazonaws\.com',
    r's3\.amazonaws\.com/([a-zA-Z0-9._-]+)',
    r'([a-zA-Z0-9._-]+)\.s3-[a-z0-9-]+\.amazonaws\.com',
    r'([a-zA-Z0-9._-]+)\.storage\.googleapis\.com',
    r'storage\.googleapis\.com/([a-zA-Z0-9._-]+)',
    r'([a-zA-Z0-9._-]+)\.blob\.core\.windows\.net',
    r'([a-zA-Z0-9._-]+)\.s3\.us-east-1\.amazonaws\.com',
]


def check_s3_buckets(url):
    """Discover and test cloud storage buckets referenced in the target."""
    findings = []

    r = safe_get(url)
    if not r:
        return None

    # Extract bucket names from HTML/JS
    discovered_buckets = set()
    for pattern in BUCKET_PATTERNS:
        matches = re.findall(pattern, r.text)
        discovered_buckets.update(matches)

    # Also check JS files
    js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text)
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for js_url in js_urls[:5]:
        if not js_url.startswith("http"):
            js_url = base + ("/" + js_url if not js_url.startswith("/") else js_url)
        jr = safe_get(js_url)
        if jr:
            for pattern in BUCKET_PATTERNS:
                matches = re.findall(pattern, jr.text)
                discovered_buckets.update(matches)

    # Test each discovered bucket
    for bucket in discovered_buckets:
        # Test S3
        bucket_url = f"https://{bucket}.s3.amazonaws.com/"
        r = safe_get(bucket_url, timeout=5)
        if not r:
            continue

        if r.status_code == 200:
            if "<ListBucketResult" in r.text:
                findings.append({
                    "type": "S3_BUCKET_LISTING",
                    "url": bucket_url,
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": f"S3 bucket '{bucket}' has directory listing enabled"
                })
            elif "AccessDenied" not in r.text:
                findings.append({
                    "type": "S3_BUCKET_PUBLIC",
                    "url": bucket_url,
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "detail": f"S3 bucket '{bucket}' is publicly accessible"
                })

        # Test for upload permissions
        if r.status_code != 404:
            try:
                import requests
                put_r = requests.put(
                    f"{bucket_url}aegis-test-{hash(bucket) % 10000}.txt",
                    data="test", timeout=5, verify=False
                )
                if put_r.status_code in [200, 204]:
                    findings.append({
                        "type": "S3_BUCKET_WRITABLE",
                        "url": bucket_url,
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "detail": f"S3 bucket '{bucket}' allows public writes!"
                    })
            except Exception:
                pass

    return findings if findings else None
