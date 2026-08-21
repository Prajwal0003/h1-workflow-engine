import requests
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def check_cors_misconfig(url):
    """
    Checks for zero-false-positive CORS misconfigurations.
    To be exploitable, it MUST reflect the exact arbitrary Origin AND allow Credentials.
    """
    findings = []
    headers = {"Origin": "https://evil.com"}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"
    
    try:
        r = requests.get(url, headers=headers, timeout=5, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        
        # Zero False Positives Rule: ACAO must exactly match the evil origin AND ACAC must be true.
        # ACAO of "*" with ACAC "true" is rejected by modern browsers, so it's not exploitable.
        if acao == "https://evil.com" and acac == "true":
            # Reflection plus credentials is only a candidate. Account impact
            # requires a sensitive authenticated response, which this single
            # request does not establish. The central scanner performs the
            # two-origin and response-content checks.
            is_telemetry = any(x in url.lower() for x in ["track", "beacon", "analytics", "telemetry", "log", "metrics", "ichnaea"])
            is_empty = len(r.text.strip()) < 25
            severity = "LOW" if is_telemetry or is_empty else "MEDIUM"
            verified = False
            finding_type = "CORS_MISCONFIGURATION"
            detail_suffix = " (Candidate only: sensitive authenticated response not established)"

            findings.append({
                "type": finding_type,
                "url": url,
                "severity": severity,
                "confidence": "MEDIUM",
                "verified": verified,
                "verification_method": "cors-single-origin-hint",
                "verification_evidence": {"deterministic": False, "arbitrary_origin": True, "allow_credentials": True, "sensitive_response": False},
                "detail": f"CORS candidate: the server reflects arbitrary Origins ({acao}) and allows Credentials.{detail_suffix}"
            })
    except Exception: 
        pass
    return findings
