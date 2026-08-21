import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from . import utils


SECRET_REGEXES = {
    "AWS Access Key": r"(?i)AKIA[0-9A-Z]{16}",
    "Stripe Standard API": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API": r"rk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Generic Secret": r"(?i)(api_key|secret|password|token)[\s=:]+[\"']([a-zA-Z0-9\-_]{16,})[\"']",
}
PLACEHOLDERS = {"example", "changeme", "your_api_key", "your-key", "replace_me",
                "undefined", "null", "test", "dummy"}
THIRD_PARTY_MARKERS = ("jquery", "bootstrap", "google-analytics", "recaptcha", "cloudflare")


def _same_organization(host, base_host):
    return bool(host and base_host and (host == base_host or host.endswith(f".{base_host}")))


def hunt_js_secrets(url):
    """Find unique secret-pattern candidates in first-party JavaScript assets."""
    findings = []
    seen = set()
    parsed = urlparse(url)
    base_host = (parsed.hostname or "").lower()
    headers = {"User-Agent": "Aegis-Auto/JS-Hunter"}
    if utils.GLOBAL_COOKIE:
        headers["Cookie"] = utils.GLOBAL_COOKIE
    if utils.GLOBAL_BEARER:
        headers["Authorization"] = f"Bearer {utils.GLOBAL_BEARER}"

    try:
        page = requests.get(url, headers=headers, timeout=10, verify=False,
                            allow_redirects=False)
        if page.status_code >= 400:
            return findings
        soup = BeautifulSoup(page.text, "html.parser")
        js_links = {urljoin(url, script["src"])
                    for script in soup.find_all("script", src=True)}

        for js_url in js_links:
            js_host = (urlparse(js_url).hostname or "").lower()
            if not _same_organization(js_host, base_host):
                continue
            if any(marker in js_url.lower() for marker in THIRD_PARTY_MARKERS):
                continue
            try:
                js_response = requests.get(js_url, headers=headers, timeout=10,
                                           verify=False, allow_redirects=False)
                if js_response.status_code >= 400:
                    continue
                content = js_response.text
                for name, regex in SECRET_REGEXES.items():
                    for match in set(re.findall(regex, content)):
                        value = match[1] if isinstance(match, tuple) else match
                        value = str(value).strip()
                        if (not value or len(value) > 150
                                or value.lower() in PLACEHOLDERS
                                or value.lower().startswith("your_")):
                            continue
                        identity = (name, value)
                        if identity in seen:
                            continue
                        seen.add(identity)
                        severity = "HIGH" if name in {"AWS Access Key", "Stripe Standard API", "Stripe Restricted API", "RSA Private Key"} else "MEDIUM"
                        findings.append({
                            "type": "HARDCODED_SECRET_LEAK",
                            "url": js_url,
                            "severity": severity,
                            "confidence": "MEDIUM",
                            "verified": False,
                            "verification_method": "source-secret-pattern",
                            "verification_evidence": {
                                "deterministic": False,
                                "secret_type": name,
                                "source_url": js_url,
                                "secret_value_redacted": f"{value[:4]}***{value[-3:]}",
                            },
                            "detail": (f"Potential {name} found in first-party JavaScript; "
                                       "validate ownership, scope, and activity before reporting."),
                        })
            except requests.RequestException:
                continue
    except requests.RequestException:
        pass
    return findings
