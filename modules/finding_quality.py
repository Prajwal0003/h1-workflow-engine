"""Precision controls for scanner findings.

This module deliberately treats scanner output as a candidate until it carries
machine-checkable evidence. AI explanations, a single HTTP response, and a
scanner's self-reported ``verified`` flag are not sufficient on their own.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


QUALITY_SCHEMA_VERSION = 2
_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def canonical_url(url: str) -> str:
    """Return a stable URL form for duplicate comparison.

    Fragments never reach the server and default ports are redundant. Query
    parameters are sorted so that scanner ordering does not create duplicates.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url.strip())
        hostname = (parts.hostname or "").lower()
        if not hostname:
            return url.strip()
        try:
            port = parts.port
        except ValueError:
            port = None
        if port and not ((parts.scheme.lower() == "http" and port == 80) or
                         (parts.scheme.lower() == "https" and port == 443)):
            host = f"{hostname}:{port}"
        else:
            host = hostname
        if parts.username or parts.password:
            # Do not accidentally collapse URLs containing credentials.
            host = parts.netloc.lower()
        path = parts.path or "/"
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        query = urlencode(sorted(query_pairs), doseq=True)
        return urlunsplit((parts.scheme.lower(), host, path, query, ""))
    except Exception:
        return url.strip()


def finding_family(vulnerability_type: Any) -> str:
    """Map scanner-specific names to a shared vulnerability family."""
    value = str(vulnerability_type or "UNKNOWN").upper()
    if value.startswith("CORS_"):
        return "CORS"
    if value.startswith("GRAPHQL_"):
        return "GRAPHQL"
    if value.startswith("EXPOSED_SECRET_") or value == "HARDCODED_SECRET_LEAK":
        return "EXPOSED_SECRET"
    if value.startswith("SQLI") or value.startswith("SQLMAP_"):
        return "SQLI"
    if value.startswith("SSTI"):
        return "SSTI"
    if "SSRF" in value:
        return "SSRF"
    if value.startswith("IDOR"):
        return "IDOR"
    if "TAKEOVER" in value:
        return "SUBDOMAIN_TAKEOVER"
    if "OPEN_REDIRECT" in value:
        return "OPEN_REDIRECT"
    return value


def finding_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return a payload-insensitive key while retaining program and parameter identity."""
    family = finding_family(finding.get("type"))
    raw_url = canonical_url(str(finding.get("url") or ""))
    try:
        parts = urlsplit(raw_url)
        query_names = sorted({name for name, _ in parse_qsl(parts.query, keep_blank_values=True)})
        endpoint_url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                   urlencode([(name, "") for name in query_names]), ""))
    except Exception:
        endpoint_url = raw_url
    parameter = str(finding.get("parameter") or finding.get("param") or "")
    if not parameter:
        try:
            parameter = ",".join(sorted({name for name, _ in parse_qsl(urlsplit(raw_url).query, keep_blank_values=True)}))
        except Exception:
            parameter = ""
    program = str(finding.get("program") or "unknown")
    return program, family, endpoint_url, parameter


def _merge_details(existing: dict[str, Any], candidate: dict[str, Any]) -> None:
    """Merge non-empty evidence fields and unique detail text into one finding."""
    old_detail = str(existing.get("detail") or "").strip()
    new_detail = str(candidate.get("detail") or "").strip()
    if new_detail and new_detail not in old_detail:
        existing["detail"] = " | ".join(x for x in (old_detail, new_detail) if x)

    for key, value in candidate.items():
        if value in (None, "", [], {}):
            continue
        if key in {"detail", "severity", "confidence", "verified"}:
            continue
        if key not in existing or existing[key] in (None, "", [], {}):
            existing[key] = value


def _finding_strength(finding: dict[str, Any]) -> tuple[int, int, int]:
    """Rank candidates so a deduplicated record keeps the strongest evidence."""
    verified = int(finding.get("verified") is True)
    evidence = int(bool(finding.get("verification_evidence") or finding.get("evidence")))
    severity = _SEVERITY_RANK.get(str(finding.get("severity") or "INFO").upper(), 0)
    return verified, evidence, severity


def deduplicate_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse duplicate scanner outputs without discarding corroborating detail."""
    merged: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
    for raw in findings:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        key = finding_key(item)
        if key not in merged:
            merged[key] = item
            continue
        current = merged[key]
        if _finding_strength(item) > _finding_strength(current):
            winner, loser = item, current
        else:
            winner, loser = current, item
        _merge_details(winner, loser)
        merged[key] = winner
    return list(merged.values())


def _has_timing_evidence(detail: str) -> bool:
    return (
        re.search(r"baseline\s*:\s*[0-9.]+", detail, re.I) is not None
        and len(re.findall(r"delay\d+\s*:\s*[0-9.]+", detail, re.I)) >= 2
        and "verified" in detail.lower()
    )


def has_deterministic_evidence(finding: dict[str, Any]) -> bool:
    """Return whether a candidate has enough deterministic proof for automation.

    The default is intentionally conservative. New scanners must opt in by
    providing ``verification_method`` and ``verification_evidence`` rather than
    relying on a free-form ``verified`` flag.
    """
    if finding.get("verified") is not True:
        return False

    family = finding_family(finding.get("type"))
    detail = str(finding.get("detail") or "")
    method = str(finding.get("verification_method") or "").lower()
    evidence = finding.get("verification_evidence")

    if family == "GRAPHQL":
        # Introspection/schema exposure alone is not an exploit proof.
        return False
    if family in {"SSTI", "SSTI_RCE"}:
        return method == "ssti-multi-payload" and isinstance(evidence, dict) and (
            evidence.get("deterministic") is True and
            int(evidence.get("payload_count", 0) or 0) >= 2
        )
    if family == "SSRF":
        return method == "metadata-signature-with-control" and isinstance(evidence, dict) and (
            evidence.get("deterministic") is True and
            evidence.get("control_signature_absent") is True
        )
    if family == "HOST_HEADER_INJECTION":
        return method == "host-header-redirect" and isinstance(evidence, dict) and (
            evidence.get("deterministic") is True and
            evidence.get("attacker_host") and evidence.get("location")
        )
    if family == "IDOR":
        return method == "dual-session" and isinstance(evidence, dict) and bool(
            evidence.get("subject_a") and evidence.get("subject_b") and
            evidence.get("cross_account_access") is True
        )
    if family == "CORS":
        return (
            method == "cors-two-origin-replay"
            and isinstance(evidence, dict)
            and evidence.get("arbitrary_origin") is True
            and evidence.get("allow_credentials") is True
            and evidence.get("sensitive_response") is True
        )
    if family == "SQLI":
        return method in {"controlled-timing", "sqlmap-confirmed"} and (
            _has_timing_evidence(detail) or
            (isinstance(evidence, dict) and evidence.get("independent_repeats") is True)
        )
    if family == "OPEN_REDIRECT":
        return method == "no-follow-redirect" and isinstance(evidence, dict) and (
            evidence.get("external_location") is True and
            evidence.get("attacker_controlled_origin") is True
        )
    if family == "SUBDOMAIN_TAKEOVER":
        return method == "provider-fingerprint-and-claimability" and isinstance(evidence, dict) and (
            evidence.get("claimable_service") is True and
            evidence.get("provider_fingerprint") is True
        )

    # Generic scanners may become reportable only through an explicitly
    # reviewed verification method. Free-form AI proof or an arbitrary new
    # scanner flag is intentionally not accepted here.
    approved_methods = {
        "dalfox-confirmed",
        "config-file-signature",
        "local-file-signature",
        "xxe-file-signature",
        "jwt-alg-none-controls",
        "sqlmap-confirmed",
        "commix-confirmed",
    }
    return (method in approved_methods and isinstance(evidence, dict)
            and evidence.get("deterministic") is True)


def readiness_reasons(finding: dict[str, Any]) -> list[str]:
    """Explain why a candidate cannot yet be automatically reported."""
    reasons: list[str] = []
    if not finding.get("scope_verified", True):
        reasons.append("Excluded by scope")
    if finding.get("verified") is not True:
        reasons.append("No deterministic verification")
    elif not has_deterministic_evidence(finding):
        reasons.append("Verification lacks type-specific evidence")
    if finding_family(finding.get("type")) == "CORS" and "Credentials" not in str(finding.get("detail", "")):
        reasons.append("CORS without credentials")
    return reasons
