"""
API Schema Discovery — Hunts for Swagger and OpenAPI definitions.
"""
from urllib.parse import urlparse
from .utils import safe_get

SWAGGER_PATHS = ['/swagger.json', '/openapi.json', '/api-docs', '/v2/api-docs', '/api/swagger', '/api/v1/swagger.json']

def check_api_schema(url):
    findings = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    
    for path in SWAGGER_PATHS:
        target = f"{base}{path}"
        r = safe_get(target, allow_redirects=False)
        
        if r and r.status_code == 200:
            if "swagger" in r.text.lower() or "openapi" in r.text.lower():
                # Attempt to parse
                is_json = False
                try:
                    data = r.json()
                    is_json = True
                    endpoints_count = len(data.get('paths', {}))
                except:
                    endpoints_count = "unknown number of"
                
                if is_json or "swagger" in r.text[:500].lower():
                    findings.append({
                        "type": "API_SCHEMA_DISCLOSURE",
                        "url": target,
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "duplicate_risk": "MEDIUM",
                        "detail": f"Unauthenticated API schema exposed. Found {endpoints_count} endpoints. Can be used to discover hidden administrative APIs."
                    })
                    break # One schema per domain is enough
    
    return findings if findings else None
