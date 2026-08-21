"""SSTI scanner with reflection-aware, multi-payload confirmation."""

import secrets
from urllib.parse import urlencode, urlparse, urlunparse

from .utils import safe_get


SSTI_PARAMS = ["name", "template", "page", "view", "q", "search", "msg", "text", "content"]
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
]


def _make_url(parsed, params):
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode(params),
        parsed.fragment,
    ))


def check_ssti(url):
    """Test common parameters for server-side expression evaluation."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in SSTI_PARAMS[:5]:
        marker = f"H1SSTI{secrets.token_hex(5)}"
        baseline = safe_get(_make_url(parsed, [(param, f"{marker}BASE")]))
        if not baseline:
            continue

        confirmed = []
        for payload, result in SSTI_PAYLOADS:
            response = safe_get(_make_url(parsed, [(param, f"{payload}{marker}")]))
            if not response or response.status_code >= 400:
                continue
            expected = f"{result}{marker}"
            body = response.text
            if (expected in body
                    and f"{payload}{marker}" not in body
                    and body.count(expected) > baseline.text.count(expected)):
                confirmed.append({
                    "payload": payload,
                    "expected": expected,
                    "status": response.status_code,
                })

        if len(confirmed) >= 2:
            findings.append({
                "type": "SSTI",
                "url": base,
                "parameter": param,
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
                "detail": (f"Two template syntaxes evaluated on parameter `{param}` with "
                           f"unique marker `{marker}`; literal reflection was not observed."),
            })
            return findings

    return findings if findings else None
