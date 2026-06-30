"""
Parameter Discovery Scanner.
Ref: awesome-bugbounty-tools (Arjun, ParamSpider, x8, parameth).
"""
import re
from urllib.parse import urlparse, urlencode
from .utils import stealth_headers, safe_get, run_bin

COMMON_PARAMS = [
    "id", "page", "search", "q", "query", "s", "keyword", "lang",
    "name", "email", "user", "username", "pass", "password",
    "url", "redirect", "next", "return", "callback", "ref",
    "file", "path", "template", "view", "action", "type",
    "category", "sort", "order", "limit", "offset", "token",
    "key", "api_key", "secret", "debug", "test", "admin",
    "cmd", "exec", "command", "code", "data", "input", "output",
    "format", "mode", "target", "host", "port", "dir",
]


def discover_parameters(url):
    """Discover hidden parameters using Arjun or manual brute-force."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Get baseline response
    baseline = safe_get(base)
    if not baseline:
        return None

    baseline_len = len(baseline.text)
    baseline_status = baseline.status_code

    discovered_params = []

    for param in COMMON_PARAMS:
        test_url = f"{base}?{param}=aegis_test_value_12345"
        r = safe_get(test_url)
        if not r:
            continue

        # Check if response differs significantly
        len_diff = abs(len(r.text) - baseline_len)
        if len_diff > 200 or r.status_code != baseline_status:
            # Verify it's not just a generic difference
            test_url2 = f"{base}?{param}=aegis_different_value_67890"
            r2 = safe_get(test_url2)
            if r2:
                len_diff2 = abs(len(r2.text) - len(r.text))
                if len_diff2 > 50:  # Response changes based on param value
                    discovered_params.append({
                        "param": param,
                        "diff": len_diff,
                        "status_changed": r.status_code != baseline_status,
                    })

    if discovered_params:
        param_list = [p["param"] for p in discovered_params]
        findings.append({
            "type": "HIDDEN_PARAMETERS",
            "url": base,
            "severity": "LOW",
            "confidence": "MEDIUM",
            "detail": f"Discovered {len(discovered_params)} hidden params: {', '.join(param_list[:10])}"
        })

        # Check if any discovered params accept sensitive values
        for p in discovered_params:
            if p["param"] in ["debug", "test", "admin", "cmd", "exec", "command"]:
                findings.append({
                    "type": "DANGEROUS_PARAMETER",
                    "url": f"{base}?{p['param']}=1",
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "detail": f"Potentially dangerous parameter '{p['param']}' accepts input"
                })

    return findings if findings else None
