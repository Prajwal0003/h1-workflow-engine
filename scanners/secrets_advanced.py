"""
Advanced Secrets Scanner — Extended secret detection beyond basic regex.
Ref: awesome-bugbounty-tools (trufflehog, gitleaks, noseyparker, SecretFinder, cariddi, keyhacks).
"""
import re
from .utils import stealth_headers, safe_get, run_bin

SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": r"(AKIA[0-9A-Z]{16})",
    "AWS_SECRET_KEY": r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})",
    "STRIPE_SECRET": r"(sk_live_[0-9a-zA-Z]{24,})",
    "STRIPE_PUBLISHABLE": r"(pk_live_[0-9a-zA-Z]{24,})",
    "GOOGLE_API_KEY": r"(AIza[0-9A-Za-z\-_]{35})",
    "GOOGLE_OAUTH_TOKEN": r"(ya29\.[0-9A-Za-z\-_]+)",
    "GITHUB_TOKEN": r"(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})",
    "SLACK_TOKEN": r"(xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})",
    "SLACK_WEBHOOK": r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)",
    "TWILIO_SID": r"(AC[a-z0-9]{32})",
    "TWILIO_TOKEN": r"(?i)(twilio[_-]?auth[_-]?token)\s*[=:]\s*['\"]?([a-f0-9]{32})",
    "MAILGUN_KEY": r"(key-[0-9a-zA-Z]{32})",
    "SENDGRID_KEY": r"(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})",
    "FIREBASE_KEY": r"(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})",
    "HEROKU_API_KEY": r"(?i)(heroku[_-]?api[_-]?key)\s*[=:]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
    "SHOPIFY_TOKEN": r"(shpat_[a-fA-F0-9]{32})",
    "SHOPIFY_SECRET": r"(shpss_[a-fA-F0-9]{32})",
    "SQUARE_TOKEN": r"(sq0atp-[0-9A-Za-z\-_]{22})",
    "PAYPAL_TOKEN": r"(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})",
    "PRIVATE_KEY": r"(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)",
    "JWT_TOKEN": r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
    "GENERIC_SECRET": r"(?i)(?:password|secret|token|key|api_key|apikey|auth)\s*[=:]\s*['\"]([^\s'\"]{8,})['\"]",
    "DATABASE_URL": r"(?i)((?:mysql|postgres|mongodb|redis)://[^\s'\"<>]+)",
}


def check_advanced_secrets(url):
    """Deep scan for leaked secrets in HTML, JS, and response headers."""
    findings = []

    r = safe_get(url)
    if not r:
        return None

    html = r.text
    from urllib.parse import urlparse
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # Collect all text to scan: HTML + JS files
    all_text = [(url, html)]

    # Extract and fetch JS files
    js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
    for js_url in js_urls[:8]:
        if not js_url.startswith("http"):
            js_url = base + ("/" + js_url if not js_url.startswith("/") else js_url)
        jr = safe_get(js_url)
        if jr:
            all_text.append((js_url, jr.text))

    for source_url, text in all_text:
        for secret_name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, text)
            if not matches:
                continue

            for match in set(matches) if isinstance(matches[0], str) else set(str(m) for m in matches):
                # Skip false positives
                if len(str(match)) < 8:
                    continue
                if str(match).count("*") > 3:
                    continue  # Masked values

                severity = "CRITICAL"
                if secret_name in ["GENERIC_SECRET", "JWT_TOKEN"]:
                    severity = "HIGH"
                elif secret_name in ["STRIPE_PUBLISHABLE"]:
                    severity = "MEDIUM"

                findings.append({
                    "type": f"SECRET_{secret_name}",
                    "url": source_url,
                    "severity": severity,
                    "confidence": "HIGH",
                    "detail": f"Found {secret_name}: {str(match)[:20]}..."
                })

    # Deduplicate by type+url
    seen = set()
    unique_findings = []
    for f in findings:
        key = f"{f['type']}_{f['url']}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings[:20] if unique_findings else None
