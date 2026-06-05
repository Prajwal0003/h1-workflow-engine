"""
JWT Scanner — JSON Web Token vulnerability detection.
Ref: awesome-bugbounty-tools (jwt_tool, jwt-hack, jwt-cracker).
"""
import re
import json
import base64
from .utils import stealth_headers, safe_get


def decode_jwt_part(part):
    """Decode a JWT base64url-encoded part."""
    try:
        padding = 4 - len(part) % 4
        part += "=" * padding
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return None


def check_jwt_vulnerabilities(url):
    """Scan for JWT misconfigurations: alg=none, weak secrets, exposed tokens."""
    findings = []

    r = safe_get(url)
    if not r:
        return None

    # 1. Search for JWTs in response body, headers, cookies
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    jwt_locations = []

    # Check response body
    body_tokens = re.findall(jwt_pattern, r.text)
    jwt_locations.extend(("body", t) for t in body_tokens)

    # Check cookies
    for cookie_name, cookie_val in r.cookies.items():
        cookie_tokens = re.findall(jwt_pattern, cookie_val)
        jwt_locations.extend((f"cookie:{cookie_name}", t) for t in cookie_tokens)

    # Check headers
    for h_name, h_val in r.headers.items():
        header_tokens = re.findall(jwt_pattern, h_val)
        jwt_locations.extend((f"header:{h_name}", t) for t in header_tokens)

    for location, token in jwt_locations[:5]:
        parts = token.split(".")
        if len(parts) != 3:
            continue

        header = decode_jwt_part(parts[0])
        payload = decode_jwt_part(parts[1])

        if not header or not payload:
            continue

        alg = header.get("alg", "")

        # Check 1: alg=none vulnerability
        if alg.lower() == "none":
            findings.append({
                "type": "JWT_ALG_NONE",
                "url": url,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "detail": f"JWT with alg=none found in {location}"
            })

        # Check 2: Weak algorithm (HS256 with potentially guessable key)
        if alg == "HS256":
            findings.append({
                "type": "JWT_WEAK_ALG",
                "url": url,
                "severity": "MEDIUM",
                "confidence": "LOW",
                "detail": f"JWT using HS256 in {location} — brute-forceable secret"
            })

        # Check 3: Sensitive data in payload
        sensitive_keys = ["password", "secret", "ssn", "credit_card", "api_key", "private_key"]
        for key in sensitive_keys:
            if key in str(payload).lower():
                findings.append({
                    "type": "JWT_SENSITIVE_DATA",
                    "url": url,
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": f"JWT payload contains '{key}' in {location}"
                })
                break

        # Check 4: No expiration
        if "exp" not in payload:
            findings.append({
                "type": "JWT_NO_EXPIRY",
                "url": url,
                "severity": "LOW",
                "confidence": "HIGH",
                "detail": f"JWT without expiration in {location}"
            })

    return findings if findings else None
