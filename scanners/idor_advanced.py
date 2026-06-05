"""
Advanced IDOR Scanner.
Ref: awesome-bugbounty-tools (Autorize).
"""
import re
import random
from urllib.parse import urlparse
from .utils import stealth_headers, safe_get

IDOR_ENDPOINTS = [
    "/api/v1/user/{id}", "/api/v1/users/{id}", "/api/user/{id}",
    "/api/v1/account/{id}", "/api/v1/profile/{id}",
    "/api/v1/order/{id}", "/api/v1/orders/{id}",
    "/api/v1/invoice/{id}", "/api/v1/document/{id}",
    "/api/v1/file/{id}", "/api/v1/download/{id}",
    "/api/v1/message/{id}", "/api/v1/notification/{id}",
    "/user/{id}", "/profile/{id}", "/account/{id}",
    "/order/{id}", "/invoice/{id}", "/ticket/{id}",
]

SENSITIVE_DATA_MARKERS = [
    '"email"', '"username"', '"user_id"', '"name"', '"address"',
    '"phone"', '"balance"', '"account"', '"token"', '"password"',
    '"ssn"', '"credit_card"', '"dob"', '"salary"',
]


def check_idor_advanced(url):
    """Test API endpoints for IDOR by comparing responses across different IDs."""
    findings = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    for ep_template in IDOR_ENDPOINTS:
        # Test with sequential IDs
        for test_id in ["1", "2", "100", "admin"]:
            ep = ep_template.replace("{id}", test_id)
            target = f"{base}{ep}"

            r = safe_get(target)
            if not r or r.status_code != 200:
                continue

            ct = r.headers.get("Content-Type", "")
            is_json = "application/json" in ct

            if not is_json and len(r.text) < 50:
                continue

            # Check for sensitive data in response
            has_sensitive = any(marker in r.text.lower() for marker in SENSITIVE_DATA_MARKERS)
            if not has_sensitive:
                continue

            # Verify with a random ID to ensure it's not a static response
            random_id = str(random.randint(99990, 99999))
            ep_random = ep_template.replace("{id}", random_id)
            r_random = safe_get(f"{base}{ep_random}")

            if r_random and abs(len(r.text) - len(r_random.text)) > 100:
                findings.append({
                    "type": "IDOR",
                    "url": target,
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": f"IDOR: different user data returned for ID={test_id} vs ID={random_id} ({abs(len(r.text) - len(r_random.text))} byte diff)"
                })
                break  # One IDOR per endpoint template is enough

    return findings if findings else None
