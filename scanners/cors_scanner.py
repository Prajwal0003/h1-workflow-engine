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
            findings.append({
                "type": "CORS_ACCOUNT_TAKEOVER",
                "url": url,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "verified": True,
                "detail": f"Exploitable CORS misconfiguration detected. The server reflects arbitrary Origins ({acao}) and allows Credentials. A 1-click account takeover is possible."
            })
    except Exception: 
        pass
    return findings
