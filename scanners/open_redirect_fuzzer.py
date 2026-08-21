from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from . import utils


REDIRECT_STATUSES = {301, 302, 303, 307, 308}
ATTACKER_HOST = "evil.com"


def _is_attacker_destination(location):
    """Accept only a parsed exact attacker-controlled hostname."""
    if not location:
        return False
    candidate = location if not location.startswith("//") else f"https:{location}"
    parsed = urlparse(candidate)
    return parsed.hostname == ATTACKER_HOST


def run_open_redirect_fuzzer(url):
    """Detect direct open redirects with a baseline and exact-host proof."""
    findings = []
    if "?" not in url:
        return findings

    headers = {"User-Agent": "Aegis-Auto/OpenRedirect"}
    if utils.GLOBAL_COOKIE:
        headers["Cookie"] = utils.GLOBAL_COOKIE
    if utils.GLOBAL_BEARER:
        headers["Authorization"] = f"Bearer {utils.GLOBAL_BEARER}"

    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    try:
        baseline = requests.get(url, headers=headers, timeout=5, verify=False,
                                allow_redirects=False)
        baseline_location = baseline.headers.get("Location", "")
        # If the clean URL already redirects to the attacker destination, the
        # parameter mutation did not demonstrate the vulnerability.
        if baseline.status_code in REDIRECT_STATUSES and _is_attacker_destination(baseline_location):
            return findings
    except requests.RequestException:
        baseline = None

    for index, (key, _value) in enumerate(params):
        test_params = params.copy()
        test_params[index] = (key, ATTACKER_HOST)
        test_query = urlencode(test_params)
        test_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            test_query,
            parsed.fragment,
        ))

        try:
            response = requests.get(test_url, headers=headers, timeout=5,
                                    verify=False, allow_redirects=False)
        except requests.RequestException:
            continue

        location = response.headers.get("Location", "")
        if response.status_code not in REDIRECT_STATUSES or not _is_attacker_destination(location):
            continue

        findings.append({
            "type": "OPEN_REDIRECT",
            "url": test_url,
            "parameter": key,
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "verified": True,
            "verification_method": "no-follow-redirect",
            "verification_evidence": {
                "deterministic": True,
                "external_location": True,
                "attacker_controlled_origin": True,
                "status": response.status_code,
                "location": location,
                "baseline_status": baseline.status_code if baseline is not None else None,
                "baseline_location": baseline_location if baseline is not None else "",
            },
            "detail": (f"Parameter `{key}` caused a no-follow {response.status_code} redirect "
                       f"to the exact attacker host: {location}"),
        })
        return findings

    return findings
