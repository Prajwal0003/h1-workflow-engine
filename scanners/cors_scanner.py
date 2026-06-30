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
            # Heuristics to filter out telemetry/tracking endpoints which intentionally have open CORS
            is_telemetry = any(x in url.lower() for x in ["track", "beacon", "analytics", "telemetry", "log", "metrics", "ichnaea"])
            is_empty = len(r.text.strip()) < 25
            
            if is_telemetry or is_empty:
                severity = "LOW"
                verified = False
                finding_type = "CORS_MISCONFIGURATION"
                detail_suffix = " (Likely False Positive: Telemetry endpoint or empty response)"
            else:
                severity = "CRITICAL"
                verified = True
                finding_type = "CORS_ACCOUNT_TAKEOVER"
                detail_suffix = " A 1-click account takeover is possible."

            findings.append({
                "type": finding_type,
                "url": url,
                "severity": severity,
                "confidence": "HIGH",
                "verified": verified,
                "detail": f"Exploitable CORS misconfiguration detected. The server reflects arbitrary Origins ({acao}) and allows Credentials.{detail_suffix}"
            })
    except Exception: 
        pass
    return findings
