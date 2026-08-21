import secrets
from urllib.parse import urlparse

import requests

from . import utils


REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _exact_host(location, expected_host):
    if not location:
        return False
    candidate = location if not location.startswith("//") else f"https:{location}"
    return urlparse(candidate).hostname == expected_host


def run_host_header_fuzzer(url):
    """Test host-header poisoning without treating ordinary reflection as proof."""
    findings = []
    attacker_host = f"h1-{secrets.token_hex(5)}.evil.com"
    headers_to_test = [
        "Host",
        "X-Forwarded-Host",
        "X-Forwarded-Server",
        "X-Host",
    ]

    base_headers = {"User-Agent": "Aegis-Auto/HostHeader"}
    if utils.GLOBAL_COOKIE:
        base_headers["Cookie"] = utils.GLOBAL_COOKIE
    if utils.GLOBAL_BEARER:
        base_headers["Authorization"] = f"Bearer {utils.GLOBAL_BEARER}"

    try:
        baseline = requests.get(url, headers=base_headers, timeout=5, verify=False,
                                allow_redirects=False)
    except requests.RequestException:
        baseline = None

    for header_name in headers_to_test:
        test_headers = dict(base_headers)
        test_headers[header_name] = attacker_host
        try:
            response = requests.get(url, headers=test_headers, timeout=5,
                                    verify=False, allow_redirects=False)
        except requests.RequestException:
            continue

        location = response.headers.get("Location", "")
        baseline_location = baseline.headers.get("Location", "") if baseline is not None else ""
        if (response.status_code in REDIRECT_STATUSES
                and _exact_host(location, attacker_host)
                and not _exact_host(baseline_location, attacker_host)):
            findings.append({
                "type": "HOST_HEADER_INJECTION",
                "url": url,
                "severity": "HIGH",
                "confidence": "HIGH",
                "verified": True,
                "verification_method": "host-header-redirect",
                "verification_evidence": {
                    "deterministic": True,
                    "header": header_name,
                    "attacker_host": attacker_host,
                    "status": response.status_code,
                    "location": location,
                    "baseline_status": baseline.status_code if baseline is not None else None,
                    "baseline_location": baseline_location,
                },
                "detail": (f"Injecting `{header_name}: {attacker_host}` caused a no-follow redirect "
                           f"to the exact attacker host: {location}"),
            })
            return findings

        # A unique body reflection is useful reconnaissance, but it does not
        # establish password-reset poisoning, cache poisoning, or impact.
        content_type = response.headers.get("Content-Type", "").lower()
        if attacker_host in response.text and "html" in content_type:
            findings.append({
                "type": "HOST_HEADER_REFLECTION",
                "url": url,
                "severity": "LOW",
                "confidence": "MEDIUM",
                "verified": False,
                "verification_method": "host-header-body-reflection",
                "verification_evidence": {
                    "deterministic": False,
                    "header": header_name,
                    "attacker_host": attacker_host,
                    "status": response.status_code,
                },
                "detail": (f"Unique host marker `{attacker_host}` reflected in HTML after "
                           f"injecting `{header_name}`; impact requires manual cache or workflow validation."),
            })
            # Continue testing other headers in case one yields a stronger
            # redirect-based result.

    return findings
