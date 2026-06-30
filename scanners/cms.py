"""
CMS Scanner — WordPress, Joomla, Drupal, AEM detection and vuln scanning.
Ref: awesome-bugbounty-tools (wpscan, CMSmap, joomscan, aemhacker).
"""
import re
from .utils import stealth_headers, safe_get

CMS_FINGERPRINTS = {
    "WordPress": [
        "/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/",
        "/xmlrpc.php", "/wp-json/wp/v2/users",
    ],
    "Joomla": [
        "/administrator/", "/components/", "/modules/",
        "/plugins/", "/templates/", "/media/jui/",
    ],
    "Drupal": [
        "/core/misc/drupal.js", "/sites/default/",
        "/user/login", "/node/1",
    ],
    "AEM": [
        "/crx/de/index.jsp", "/system/console",
        "/bin/querybuilder.json", "/etc/designs/",
    ],
}

WP_VULNS = [
    ("/wp-json/wp/v2/users", "WordPress user enumeration via REST API"),
    ("/xmlrpc.php", "WordPress XML-RPC enabled (brute-force / DDoS vector)"),
    ("/?rest_route=/wp/v2/users", "WordPress user enum via rest_route"),
    ("/wp-content/debug.log", "WordPress debug log exposed"),
    ("/wp-config.php.bak", "WordPress config backup exposed"),
    ("/.wp-config.php.swp", "WordPress config swap file"),
]


def check_cms_vulnerabilities(url):
    """Detect CMS type and scan for known CMS-specific vulnerabilities."""
    findings = []
    from urllib.parse import urlparse
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    detected_cms = None

    # Step 1: Fingerprint CMS
    for cms_name, paths in CMS_FINGERPRINTS.items():
        for path in paths[:3]:
            r = safe_get(f"{base}{path}")
            if r and r.status_code in [200, 301, 302, 403]:
                detected_cms = cms_name
                break
        if detected_cms:
            break

    # Also check meta generator tag
    r = safe_get(base)
    if r:
        gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text, re.IGNORECASE)
        if gen_match:
            gen = gen_match.group(1).lower()
            if "wordpress" in gen:
                detected_cms = "WordPress"
            elif "joomla" in gen:
                detected_cms = "Joomla"
            elif "drupal" in gen:
                detected_cms = "Drupal"

    if not detected_cms:
        return None

    # Step 2: CMS-specific vulnerability checks
    if detected_cms == "WordPress":
        for path, desc in WP_VULNS:
            r = safe_get(f"{base}{path}")
            if not r:
                continue

            if path == "/wp-json/wp/v2/users" and r.status_code == 200:
                try:
                    users = r.json()
                    if isinstance(users, list) and users:
                        usernames = [u.get("slug", "") for u in users[:5]]
                        findings.append({
                            "type": "WP_USER_ENUM",
                            "url": f"{base}{path}",
                            "severity": "MEDIUM",
                            "confidence": "HIGH",
                            "detail": f"Exposed users: {', '.join(usernames)}"
                        })
                except Exception:
                    pass

            elif path == "/xmlrpc.php" and r.status_code == 200 and "XML-RPC" in r.text:
                findings.append({
                    "type": "WP_XMLRPC_ENABLED",
                    "url": f"{base}{path}",
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "detail": desc
                })

            elif "debug.log" in path and r.status_code == 200 and len(r.text) > 100:
                findings.append({
                    "type": "WP_DEBUG_LOG",
                    "url": f"{base}{path}",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": desc
                })

            elif ("bak" in path or "swp" in path) and r.status_code == 200 and len(r.text) > 50:
                findings.append({
                    "type": "WP_CONFIG_BACKUP",
                    "url": f"{base}{path}",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "detail": desc
                })

    elif detected_cms == "AEM":
        aem_paths = [
            ("/crx/de/index.jsp", "AEM CRX DE console exposed"),
            ("/system/console", "AEM Felix console exposed"),
            ("/bin/querybuilder.json?path=/home/users&p.limit=-1", "AEM user enumeration"),
        ]
        for path, desc in aem_paths:
            r = safe_get(f"{base}{path}")
            if r and r.status_code == 200:
                findings.append({
                    "type": "AEM_EXPOSURE",
                    "url": f"{base}{path}",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": desc
                })

    return findings if findings else None
