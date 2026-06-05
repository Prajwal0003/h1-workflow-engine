"""
Git Exposure Scanner — Exposed .git repos and sensitive SCM files.
Ref: awesome-bugbounty-tools (GitTools, git-dumper, gitjacker).
"""
from .utils import stealth_headers, safe_get
from urllib.parse import urlparse


GIT_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.gitignore",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/hgrc",
    "/.DS_Store",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.dockerenv",
    "/composer.json",
    "/package.json",
    "/Gemfile",
    "/Makefile",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/server-info",
    "/web.config",
    "/crossdomain.xml",
]


def check_git_exposure(url):
    """Check for exposed version control files and sensitive configuration."""
    findings = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # Get baseline 404 response for comparison
    baseline = safe_get(f"{base}/this-path-definitely-does-not-exist-{hash(url) % 99999}")
    baseline_len = len(baseline.text) if baseline else 0

    for path in GIT_PATHS:
        r = safe_get(f"{base}{path}")
        if not r or r.status_code != 200:
            continue

        # Skip if same as 404 page (soft 404)
        if baseline and abs(len(r.text) - baseline_len) < 100:
            continue

        if len(r.text) < 10:
            continue

        severity = "LOW"
        detail = f"Exposed file: {path}"

        if ".git/config" in path and ("[core]" in r.text or "[remote" in r.text):
            severity = "HIGH"
            detail = "Git repository config exposed — source code leak possible"
        elif ".git/HEAD" in path and "ref:" in r.text:
            severity = "HIGH"
            detail = f"Git HEAD exposed: {r.text.strip()[:60]}"
        elif ".env" in path and ("=" in r.text and any(k in r.text.upper() for k in ["KEY", "SECRET", "PASSWORD", "TOKEN"])):
            severity = "CRITICAL"
            detail = "Environment file with credentials exposed"
        elif ".htpasswd" in path and ":" in r.text:
            severity = "HIGH"
            detail = "htpasswd file with password hashes exposed"
        elif "server-status" in path and "Apache" in r.text:
            severity = "MEDIUM"
            detail = "Apache server-status page exposed"
        elif path in ["/.svn/entries", "/.svn/wc.db"] and len(r.text) > 20:
            severity = "HIGH"
            detail = "SVN repository metadata exposed"
        elif "package.json" in path:
            severity = "LOW"
            detail = "package.json exposed — dependency info leak"
        elif "Dockerfile" in path:
            severity = "MEDIUM"
            detail = "Dockerfile exposed — infrastructure details leak"

        findings.append({
            "type": "GIT_EXPOSURE",
            "url": f"{base}{path}",
            "severity": severity,
            "confidence": "HIGH",
            "detail": detail
        })

    return findings if findings else None
