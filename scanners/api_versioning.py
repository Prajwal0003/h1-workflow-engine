"""
API Versioning Scanner — Checks for legacy API versions (v1, v2) which might lack security controls.
"""
import re
from urllib.parse import urlparse
from .utils import safe_get

def check_api_versioning(url):
    """Test if older API versions exist and are accessible."""
    findings = []
    
    # If the URL contains an API version, check previous versions
    match = re.search(r'/(v[2-9])/|/(v[1-9][0-9])/', url)
    if not match:
        return None
        
    current_version = match.group(1) or match.group(2)
    version_num = int(current_version[1:])
    
    # We only care if they are on a newer version, so we can test v1, etc.
    if version_num <= 1:
        return None
        
    for older_v in range(1, version_num):
        test_version = f"v{older_v}"
        older_url = url.replace(f"/{current_version}/", f"/{test_version}/")
        
        r1 = safe_get(url)
        r2 = safe_get(older_url)
        
        if r1 and r2 and r2.status_code == 200:
            # Check if the older version returns valid JSON or substantial data
            is_json = "application/json" in r2.headers.get("Content-Type", "")
            if is_json or len(r2.text) > 100:
                findings.append({
                    "type": "LEGACY_API_VERSION",
                    "url": older_url,
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "duplicate_risk": "MEDIUM",
                    "requires_manual_verification": True,
                    "detail": f"Legacy API endpoint found ({test_version}). Originally tested {current_version}. Legacy APIs often lack modern auth/authz controls."
                })
                break
                
    return findings if findings else None
