"""
Web Cache Deception Scanner — Appends static extensions to URLs to trick caches into saving sensitive data.
"""
from urllib.parse import urlparse
from .utils import safe_get

def check_cache_deception(url):
    findings = []
    
    # We append a static extension that CDNs usually cache aggressively
    extensions = [';.css', '/test.js', '%0A.png']
    
    # Send baseline request
    r_baseline = safe_get(url)
    if not r_baseline or r_baseline.status_code != 200:
        return None
        
    # Ensure baseline contains some content
    if len(r_baseline.text) < 100:
        return None
        
    # Check if the response contains cache headers indicating a miss
    cache_header = r_baseline.headers.get("X-Cache", "") + r_baseline.headers.get("CF-Cache-Status", "")
    
    for ext in extensions:
        test_url = url + ext
        r_test = safe_get(test_url, allow_redirects=False)
        
        if r_test and r_test.status_code == 200:
            # If the response length is very similar, the server ignored the extension
            if abs(len(r_test.text) - len(r_baseline.text)) < 50:
                
                # Check cache headers
                test_cache = r_test.headers.get("X-Cache", "").upper() + r_test.headers.get("CF-Cache-Status", "").upper()
                
                if "HIT" in test_cache or "MISS" in test_cache: # We got a cache node to engage
                    findings.append({
                        "type": "WEB_CACHE_DECEPTION",
                        "url": test_url,
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "requires_manual_verification": True,
                        "duplicate_risk": "LOW",
                        "detail": f"Appended '{ext}' to URL. Response was identical and cache headers ({test_cache}) were present. If this is an authenticated endpoint containing PII, this is Web Cache Deception."
                    })
                    break
                    
    return findings if findings else None
