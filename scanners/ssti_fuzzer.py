import secrets
import urllib.parse

import requests

from . import utils


def run_ssti_fuzzer(url):
    """Find SSTI candidates with marker-based, multi-payload confirmation.

    A number such as ``49`` is common in normal pages. The marker makes the
    expected value unique and the payload/reflection check prevents a literal
    reflection from being treated as server-side evaluation.
    """
    findings = []
    if "?" not in url:
        return findings

    headers = {}
    if utils.GLOBAL_COOKIE:
        headers["Cookie"] = utils.GLOBAL_COOKIE
    if utils.GLOBAL_BEARER:
        headers["Authorization"] = f"Bearer {utils.GLOBAL_BEARER}"

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
    ]

    for index, (key, _original_value) in enumerate(params):
        marker = f"H1SSTI{secrets.token_hex(5)}"
        baseline_params = params.copy()
        baseline_params[index] = (key, f"{marker}BASE")
        baseline_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urllib.parse.urlencode(baseline_params),
            parsed.fragment,
        ))
        try:
            baseline = requests.get(baseline_url, headers=headers, timeout=5,
                                    verify=False, allow_redirects=False)
        except requests.RequestException:
            continue

        confirmed = []
        for payload, result in payloads:
            test_params = params.copy()
            test_params[index] = (key, f"{payload}{marker}")
            test_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urllib.parse.urlencode(test_params),
                parsed.fragment,
            ))
            try:
                response = requests.get(test_url, headers=headers, timeout=5,
                                        verify=False, allow_redirects=False)
            except requests.RequestException:
                continue

            expected = f"{result}{marker}"
            body = response.text
            # The marker must be newly introduced by evaluation, and the raw
            # expression must not be reflected in the response.
            if (response.status_code < 400 and expected in body
                    and f"{payload}{marker}" not in body
                    and body.count(expected) > baseline.text.count(expected)):
                confirmed.append({
                    "payload": payload,
                    "expected": expected,
                    "status": response.status_code,
                })

        # One payload can still be affected by an engine quirk or a proxy. Two
        # distinct syntaxes producing the same unique marker is stronger proof.
        if len(confirmed) >= 2:
            findings.append({
                "type": "SSTI_RCE",
                "url": urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment)),
                "parameter": key,
                "severity": "HIGH",
                "confidence": "HIGH",
                "verified": True,
                "verification_method": "ssti-multi-payload",
                "verification_evidence": {
                    "deterministic": True,
                    "payload_count": len(confirmed),
                    "payloads": [item["payload"] for item in confirmed],
                    "marker": marker,
                    "baseline_status": baseline.status_code,
                },
                "detail": (f"Two template syntaxes evaluated on parameter `{key}` "
                           f"with unique marker `{marker}`; literal reflection was not observed."),
            })
            return findings

    return findings
