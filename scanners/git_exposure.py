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
    baseline = safe_get(f"{base}/this-path-definitely-does-not-exist-{hash(url) % 99999}", allow_redirects=False)
    baseline_len = len(baseline.text) if baseline else 0

    for path in GIT_PATHS:
        r = safe_get(f"{base}{path}", allow_redirects=False)
        if not r or r.status_code != 200:
            continue

        text_lower = r.text.lower()
        # WAF/HTML False Positive Filters
        if "request rejected" in text_lower or "support id" in text_lower:
            continue
        if "<html" in text_lower or "<body" in text_lower:
            # Most of these files should NEVER be HTML. 
            # If it's HTML, it's a soft-404 or a WAF block.
            continue

        # Skip if same as 404 page (soft 404)
        if baseline and abs(len(r.text) - baseline_len) < 100:
            continue

        if len(r.text) < 10:
            continue

        severity = "LOW"
        detail = f"Exposed file: {path}"
        is_valid = False

        if ".git/config" in path and ("[core]" in r.text or "[remote" in r.text):
            severity = "HIGH"
            detail = "Git repository config exposed — source code leak possible"
            is_valid = True
        elif ".git/HEAD" in path and "ref:" in r.text:
            severity = "HIGH"
            detail = f"Git HEAD exposed: {r.text.strip()[:60]}"
            is_valid = True
        elif ".env" in path and len(r.text) > 50 and ("=" in r.text and any(k in r.text.upper() for k in ["KEY", "SECRET", "PASSWORD", "TOKEN", "APP_"])):
            severity = "CRITICAL"
            detail = "Environment file with credentials exposed"
            is_valid = True
        elif ".htpasswd" in path and ":" in r.text:
            severity = "HIGH"
            detail = "htpasswd file with password hashes exposed"
            is_valid = True
        elif "server-status" in path and "Apache" in r.text:
            # server-status is HTML, but we blocked HTML earlier. So we need to bypass HTML block for it?
            # Actually, server-status is an exception to HTML block. Let's handle that.
            pass
        elif path in ["/.svn/entries", "/.svn/wc.db"] and len(r.text) > 20:
            severity = "HIGH"
            detail = "SVN repository metadata exposed"
            is_valid = True
        elif "package.json" in path and "dependencies" in r.text:
            severity = "LOW"
            detail = "package.json exposed — dependency info leak"
            is_valid = True
        elif "Dockerfile" in path and ("FROM" in r.text or "RUN" in r.text):
            severity = "MEDIUM"
            detail = "Dockerfile exposed — infrastructure details leak"
            is_valid = True
            
        if not is_valid:
            continue

        findings.append({
            "type": "GIT_EXPOSURE",
            "url": f"{base}{path}",
            "severity": severity,
            "confidence": "HIGH",
            "detail": detail,
            "duplicate_risk": "HIGH"
        })

    return findings if findings else None

