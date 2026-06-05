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
        for test_id in [1, 2, 100]:
            ep1 = ep_template.replace("{id}", str(test_id))
            target1 = f"{base}{ep1}"

            r1 = safe_get(target1, allow_redirects=False)
            if not r1 or r1.status_code != 200:
                continue

            ct1 = r1.headers.get("Content-Type", "")
            is_json = "application/json" in ct1

            if not is_json and len(r1.text) < 50:
                continue

            # Check for sensitive data in response
            if not any(marker in r1.text.lower() for marker in SENSITIVE_DATA_MARKERS):
                continue

            # Test ID+1
            ep2 = ep_template.replace("{id}", str(test_id + 1))
            target2 = f"{base}{ep2}"
            r2 = safe_get(target2, allow_redirects=False)
            
            # If ID+1 doesn't exist or redirects, it's not a reliable comparison
            if not r2 or r2.status_code != 200:
                continue
                
            if not any(marker in r2.text.lower() for marker in SENSITIVE_DATA_MARKERS):
                continue

            # Both returned 200 OK with sensitive data. Compare sizes.
            diff_bytes = abs(len(r1.text) - len(r2.text))
            
            if diff_bytes > 20: # Meaning they are two DIFFERENT valid user objects
                findings.append({
                    "type": "IDOR",
                    "url": target1,
                    "severity": "MEDIUM",  # Start medium, flag for review
                    "confidence": "MEDIUM",
                    "duplicate_risk": "LOW",
                    "requires_manual_verification": True,
                    "detail": f"Potential IDOR: Valid distinct responses for ID={test_id} and ID={test_id+1} ({diff_bytes} byte diff). Needs manual review!"
                })
                break  # One IDOR per endpoint template is enough

    return findings if findings else None
