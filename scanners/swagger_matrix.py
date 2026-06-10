import requests
import json
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_swagger_matrix(url):
    """
    Swagger / OpenAPI IDOR Matrix builder.
    Finds swagger.json and extracts all paths for automated auth testing.
    """
    findings = []
    if not url.endswith("swagger.json") and not url.endswith("openapi.json"):
        return findings
        
    try:
        r = requests.get(url, timeout=5, verify=False)
        data = r.json()
        paths = data.get("paths", {})
        if paths:
            findings.append({
                "type": "SWAGGER_API_EXPOSURE",
                "url": url,
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "verified": True,
                "detail": f"Exposed OpenAPI/Swagger definition found! Extracted {len(paths)} hidden API endpoints. Passing to Autopilot Matrix."
            })
    except: pass
    return findings
