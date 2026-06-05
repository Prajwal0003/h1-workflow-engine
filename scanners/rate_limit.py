"""
Rate Limit Scanner — Checks for lack of rate limiting on sensitive endpoints.
"""
from urllib.parse import urlparse
import requests
import concurrent.futures
from .utils import get_stealth_headers

AUTH_ENDPOINTS = [
    "/login", "/api/login", "/api/auth", "/auth", "/signin", "/api/signin",
    "/forgot-password", "/reset-password", "/api/forgot-password", "/register",
    "/api/register", "/graphql"
]

def check_rate_limit(url):
    """Test auth/sensitive endpoints for rate limiting (429 Too Many Requests)."""
    findings = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    for ep in AUTH_ENDPOINTS:
        target = f"{base}{ep}"
        
        # Check if endpoint actually exists
        try:
            r = requests.get(target, headers=get_stealth_headers(), timeout=5, verify=False, allow_redirects=False)
            if r.status_code in [404, 403, 301, 302]:
                continue
        except Exception:
            continue

        # Endpoint exists, send 15 rapid requests
        responses = []
        def fire_req():
            try:
                return requests.post(target, headers=get_stealth_headers(), data={"email":"test@example.com", "password":"test"}, timeout=5, verify=False).status_code
            except:
                return 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(fire_req) for _ in range(15)]
            responses = [f.result() for f in futures]

        # If all 15 succeeded (200 OK or 401 Unauthorized, meaning logic was executed)
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
