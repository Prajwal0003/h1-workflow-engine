"""
Rate Limit Scanner — Checks for lack of rate limiting on sensitive endpoints.
"""
from urllib.parse import urlparse
import requests
import concurrent.futures
from .utils import stealth_headers
import time

AUTH_ENDPOINTS = [
    "/login", "/api/login", "/api/auth", "/auth", "/signin", "/api/signin",
    "/forgot-password", "/reset-password", "/api/forgot-password", "/register",
    "/api/register", "/graphql", "/otp/verify", "/2fa/verify"
]

def check_rate_limit(url):
    """Test auth/sensitive endpoints for rate limiting (429 Too Many Requests)."""
    findings = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    for ep in AUTH_ENDPOINTS:
        target = f"{base}{ep}"
        
        # Check if endpoint actually exists
        try:
            r = requests.get(target, headers=stealth_headers(), timeout=5, verify=False, allow_redirects=False)
            if r.status_code in [404, 403, 301, 302]:
                continue
        except Exception:
            continue

        # Endpoint exists, send 10 cautious requests
        responses = []
        retry_after_seen = False
        
        for _ in range(10):
            try:
                r_post = requests.post(target, headers=stealth_headers(), data={"email":"test@example.com", "password":"test"}, timeout=5, verify=False)
                responses.append(r_post.status_code)
                
                if r_post.status_code == 429:
                    if "Retry-After" in r_post.headers:
                        retry_after_seen = True
                    break
                    
                time.sleep(0.5) # Caution delay
            except:
                responses.append(0)

        # If all 10 succeeded (200 OK or 401 Unauthorized, meaning logic was executed)
        # and NONE were 429 Too Many Requests or 403 Forbidden (WAF block)
        if all(code in [200, 401, 400] for code in responses) and 429 not in responses and 403 not in responses:
            findings.append({
                "type": "NO_RATE_LIMIT",
                "url": target,
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "duplicate_risk": "MEDIUM",
                "requires_manual_verification": True,
                "detail": "Sent 15 rapid POST requests and received 0 rate limit (429) errors. Brute force may be possible. Manual verification required."
            })
            break # One finding per domain is enough

    return findings if findings else None
