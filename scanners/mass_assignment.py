"""
Mass Assignment Detector — Tests for acceptance of unexpected high-privilege fields in JSON POST requests.
"""
from urllib.parse import urlparse
import requests
from .utils import get_stealth_headers

def check_mass_assignment(url):
    findings = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    
    # We ideally want to test this on POST/PUT endpoints, but we'll try common profile endpoints
    TEST_ENDPOINTS = ['/api/user', '/api/profile', '/account/settings', '/api/v1/users/me']
    
    for ep in TEST_ENDPOINTS:
        target = f"{base}{ep}"
        
        try:
            # Send payload with extra administrative fields
            payload = {
                "name": "testuser",
                "email": "testuser@example.com",
                "role": "admin",
                "isAdmin": True,
                "verified": True,
                "balance": 9999
            }
            
            r = requests.post(target, headers=get_stealth_headers(), json=payload, timeout=5, verify=False, allow_redirects=False)
            
            # If the server returns 200/201 and reflects our injected fields, it might be vulnerable
            if r.status_code in [200, 201]:
                resp_json = r.json()
                
                # Check if our injected fields were saved/reflected
                reflected_fields = []
                for field in ["role", "isAdmin", "verified", "balance"]:
                    if field in resp_json and resp_json[field] == payload[field]:
                        reflected_fields.append(field)
                        
                if reflected_fields:
                    findings.append({
                        "type": "MASS_ASSIGNMENT",
                        "url": target,
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "duplicate_risk": "LOW",
                        "requires_manual_verification": True,
                        "detail": f"Server accepted and reflected unexpected fields: {', '.join(reflected_fields)}. Verify if privilege escalation occurred."
                    })
                    break
                    
        except Exception:
            pass
            
    return findings if findings else None
