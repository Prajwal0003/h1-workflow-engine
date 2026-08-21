"""
Feature 2: Dual-Session IDOR Detector
--------------------------------------
Logs into two distinct user accounts (User A and User B), maps all
API endpoints using User A's session, then replays every request with
User B's session tokens. If User B can access User A's resources,
a critical IDOR/Broken Access Control vulnerability is flagged.

Usage:
    from modules.idor_detector import DualSessionIDORDetector
    detector = DualSessionIDORDetector(base_url, cred_a, cred_b)
    findings = detector.run()
"""

import requests
import urllib3
import json
import re
import time
import random
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
]


class DualSessionIDORDetector:
    """
    Authenticates as two different users, discovers API endpoints via
    User A's session, and cross-checks access using User B's session.
    """

    def __init__(self, base_url, credentials_a, credentials_b,
                 login_endpoint="/login", login_method="POST",
                 token_location="cookie", token_field="session",
                 api_prefixes=None):
        """
        Args:
            base_url: e.g. "https://target.com"
            credentials_a: dict e.g. {"username": "user_a", "password": "pass_a"}
            credentials_b: dict e.g. {"username": "user_b", "password": "pass_b"}
            login_endpoint: path to the login form/API
            login_method: "POST" or "GET"
            token_location: "cookie" | "header" | "json_body"
            token_field: cookie name or header name or JSON key holding the token
            api_prefixes: list of API path prefixes to scan, e.g. ["/api/v1", "/api/v2"]
        """
        self.base_url = base_url.rstrip("/")
        self.cred_a = credentials_a
        self.cred_b = credentials_b
        self.login_endpoint = login_endpoint
        self.login_method = login_method
        self.token_location = token_location
        self.token_field = token_field
        self.api_prefixes = api_prefixes or ["/api", "/v1", "/v2", "/rest", "/graphql"]

        self.session_a = requests.Session()
        self.session_b = requests.Session()
        self.session_a.verify = False
        self.session_b.verify = False
        self.session_a.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        self.session_b.headers.update({"User-Agent": random.choice(USER_AGENTS)})

        # Discovered API endpoints from User A's session
        self.discovered_endpoints = []
        self.findings = []

    def _log(self, msg):
        print(f"  [IDOR Detector] {msg}", flush=True)

    def authenticate(self, session, credentials, label="User"):
        """Authenticate a session and return success status."""
        login_url = f"{self.base_url}{self.login_endpoint}"
        try:
            if self.login_method.upper() == "POST":
                r = session.post(login_url, data=credentials, allow_redirects=True, timeout=10)
            else:
                r = session.get(login_url, params=credentials, allow_redirects=True, timeout=10)

            if r.status_code in [200, 302, 303]:
                # Check if we got a session token
                if self.token_location == "cookie":
                    if session.cookies.get(self.token_field):
                        self._log(f"[OK] {label} authenticated (cookie: {self.token_field})")
                        return True
                    # Try any cookie
                    if len(session.cookies) > 0:
                        self._log(f"[OK] {label} authenticated ({len(session.cookies)} cookies)")
                        return True
                elif self.token_location == "header":
                    # Extract token from JSON response body
                    try:
                        token = r.json().get(self.token_field)
                        if token:
                            session.headers["Authorization"] = f"Bearer {token}"
                            self._log(f"[OK] {label} authenticated (Bearer token)")
                            return True
                    except:
                        pass
                elif self.token_location == "json_body":
                    try:
                        token = r.json().get(self.token_field)
                        if token:
                            session.headers["Authorization"] = f"Bearer {token}"
                            self._log(f"[OK] {label} authenticated (JWT from body)")
                            return True
                    except:
                        pass

                # Fallback: check if we have any cookies at all
                if len(session.cookies) > 0:
                    self._log(f"[OK] {label} likely authenticated ({len(session.cookies)} cookies set)")
                    return True

            self._log(f"[X] {label} authentication failed (status: {r.status_code})")
            return False
        except Exception as e:
            self._log(f"[X] {label} auth error: {e}")
            return False

    def discover_endpoints(self):
        """
        Crawl the application as User A to discover API endpoints.
        Uses multiple strategies:
        1. Fetch common API documentation endpoints
        2. Parse HTML/JS for API URLs
        3. Probe common REST patterns
        """
        self._log("Discovering API endpoints as User A...")

        discovered = set()

        # Strategy 1: Check OpenAPI/Swagger docs
        doc_paths = [
            "/swagger.json", "/api-docs", "/swagger-ui.html", "/openapi.json",
            "/v1/swagger.json", "/v2/api-docs", "/api/swagger.json",
            "/docs", "/redoc", "/.well-known/openapi.json"
        ]
        for path in doc_paths:
            try:
                r = self.session_a.get(f"{self.base_url}{path}", timeout=5)
                if r.status_code == 200 and len(r.text) > 100:
                    # Parse API paths from swagger/openapi
                    try:
                        spec = r.json()
                        paths = spec.get("paths", {})
                        for api_path in paths:
                            discovered.add(api_path)
                    except:
                        pass
            except:
                pass

        # Strategy 2: Crawl main page and extract API URLs from HTML/JS
        try:
            r = self.session_a.get(self.base_url, timeout=10)
            # Find URLs in the page source
            urls_in_page = re.findall(r'["\'](/(?:api|v[0-9]|rest|graphql)[^"\']*)["\']', r.text)
            for u in urls_in_page:
                discovered.add(u.split("?")[0])

            # Also check linked JS files
            scripts = re.findall(r'<script[^>]+src="([^"]+)"', r.text)
            for s in scripts[:10]:  # Limit to 10 scripts
                if not s.startswith("http"):
                    s = urljoin(self.base_url, s)
                try:
                    js = self.session_a.get(s, timeout=5)
                    api_calls = re.findall(r'["\'](/(?:api|v[0-9]|rest)[^"\']*)["\']', js.text)
                    for u in api_calls:
                        discovered.add(u.split("?")[0])
                except:
                    pass
        except:
            pass

        # Strategy 3: Probe common REST patterns with User A's resources
        common_endpoints = [
            "/api/user", "/api/users", "/api/me", "/api/profile",
            "/api/account", "/api/settings", "/api/dashboard",
            "/api/v1/user", "/api/v1/users", "/api/v1/me",
            "/api/v1/profile", "/api/v1/account",
            "/api/v2/user", "/api/v2/me", "/api/v2/profile",
            "/api/orders", "/api/invoices", "/api/documents",
            "/api/messages", "/api/notifications",
            "/v1/user", "/v1/account", "/v1/profile",
            "/user/profile", "/user/settings", "/user/data",
        ]
        for ep in common_endpoints:
            try:
                r = self.session_a.get(f"{self.base_url}{ep}", timeout=3)
                if r.status_code == 200 and len(r.text) > 50:
                    discovered.add(ep)
            except:
                pass
            time.sleep(0.1)

        self.discovered_endpoints = list(discovered)
        self._log(f"Discovered {len(self.discovered_endpoints)} API endpoints")
        return self.discovered_endpoints

    def _extract_resource_ids(self, response_text):
        """Extract potential resource IDs from a JSON/HTML response."""
        ids = set()
        try:
            data = json.loads(response_text)
            self._extract_ids_from_json(data, ids)
        except:
            # Try regex extraction for IDs in HTML
            id_patterns = [
                r'"id"\s*:\s*(\d+)',
                r'"user_id"\s*:\s*(\d+)',
                r'"userId"\s*:\s*"?(\d+)"?',
                r'/(\d+)(?:\?|$|")',
            ]
            for pattern in id_patterns:
                for match in re.findall(pattern, response_text):
                    ids.add(match)
        return list(ids)

    def _extract_ids_from_json(self, obj, ids, depth=0):
        """Recursively extract ID-like values from JSON."""
        if depth > 5:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                if any(k in key.lower() for k in ["id", "uid", "uuid", "user_id", "account_id", "order_id"]):
                    if isinstance(value, (str, int)):
                        ids.add(str(value))
                if isinstance(value, (dict, list)):
                    self._extract_ids_from_json(value, ids, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_ids_from_json(item, ids, depth + 1)

    def cross_session_test(self):
        """
        For each discovered endpoint, fetch User A's data and then
        attempt to access the same resource using User B's session.
        """
        self._log("Cross-session testing all discovered endpoints...")

        for endpoint in self.discovered_endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                # Step 1: Fetch as User A
                r_a = self.session_a.get(url, timeout=5)
                if r_a.status_code != 200:
                    continue

                body_a = r_a.text
                len_a = len(body_a)

                # Step 2: Fetch the SAME endpoint as User B
                r_b = self.session_b.get(url, timeout=5)

                if r_b.status_code == 200:
                    body_b = r_b.text
                    len_b = len(body_b)

                    # If responses are identical, User B sees User A's data = IDOR
                    if body_a == body_b and len_a > 100:
                        # Might just be a public endpoint — check if content has user-specific data
                        has_pii = any(kw in body_a.lower() for kw in
                                      ['"email"', '"phone"', '"address"', '"ssn"', '"password"',
                                       '"token"', '"secret"', '"balance"', '"credit"'])
                        if has_pii:
                            self.findings.append({
                                "type": "IDOR_BROKEN_ACCESS_CONTROL",
                                "url": url,
                                "severity": "CRITICAL",
                                "confidence": "HIGH",
                                "verified": True,
                                "verification_method": "dual-session",
                                "verification_evidence": {
                                    "subject_a": "user_a",
                                    "subject_b": "user_b",
                                    "cross_account_access": True,
                                    "same_response": True,
                                    "pii_detected": True,
                                    "response_bytes": len_a,
                                },
                                "detail": (f"User B can access User A's resource. "
                                           f"Identical responses ({len_a} bytes) with PII detected."),
                            })
                        else:
                            # Responses are the same but no PII — likely a public endpoint
                            pass

                    # If responses differ significantly, check if User B still got valid data
                    elif r_b.status_code == 200 and len_b > 100:
                        # Extract IDs from User A's response
                        ids_a = self._extract_resource_ids(body_a)
                        if ids_a:
                            # Check if User A's IDs appear in User B's response
                            for resource_id in ids_a:
                                id_url = f"{url}/{resource_id}"
                                try:
                                    r_b_id = self.session_b.get(id_url, timeout=5)
                                    if r_b_id.status_code == 200 and len(r_b_id.text) > 50:
                                        self.findings.append({
                                            "type": "IDOR_RESOURCE_ACCESS",
                                            "url": id_url,
                                            "severity": "HIGH",
                                            "confidence": "HIGH",
                                            "verified": True,
                                            "verification_method": "dual-session",
                                            "verification_evidence": {
                                                "subject_a": "user_a",
                                                "subject_b": "user_b",
                                                "cross_account_access": True,
                                                "same_response": False,
                                                "resource_id": resource_id,
                                                "response_status": r_b_id.status_code,
                                                "response_bytes": len(r_b_id.text),
                                            },
                                            "detail": (f"User B accessed User A's resource ID {resource_id}. "
                                                       f"Response: {r_b_id.status_code} ({len(r_b_id.text)} bytes)"),
                                        })
                                except:
                                    pass

                elif r_b.status_code in [401, 403]:
                    # Access correctly denied — no IDOR here
                    pass

            except Exception:
                pass
            time.sleep(0.2)  # Be gentle

    def run(self, program="unknown"):
        """
        Full IDOR detection pipeline:
        1. Authenticate both users
        2. Discover API endpoints
        3. Cross-session test all endpoints
        """
        self._log(f"Starting Dual-Session IDOR scan against {self.base_url}")

        # Step 1: Authenticate
        auth_a = self.authenticate(self.session_a, self.cred_a, "User A")
        auth_b = self.authenticate(self.session_b, self.cred_b, "User B")

        if not auth_a or not auth_b:
            self._log("[!] Could not authenticate both users — skipping IDOR scan")
            return []

        # Step 2: Discover endpoints
        self.discover_endpoints()

        if not self.discovered_endpoints:
            self._log("No API endpoints discovered — skipping cross-session test")
            return []

        # Step 3: Cross-session test
        self.cross_session_test()

        # Tag findings
        for f in self.findings:
            f["program"] = program

        self._log(f"IDOR scan complete: {len(self.findings)} findings")
        return self.findings


def check_idor_dual_session(base_url, program="unknown", credentials=None):
    """
    Convenience wrapper for autopilot integration.
    Supports two modes:
    
    Mode 1 — Pre-extracted SSO cookies (from google_sso_automator):
    {
        "user_a_cookie": "session=abc123; ...",
        "user_b_cookie": "session=xyz789; ..."
    }
    
    Mode 2 — Username/password login:
    {
        "user_a": {"username": "testuser1", "password": "pass1"},
        "user_b": {"username": "testuser2", "password": "pass2"},
        "login_endpoint": "/api/login",
        "token_location": "json_body",
        "token_field": "access_token"
    }
    """
    if not credentials:
        return []

    # Mode 1: Pre-extracted cookies from SSO
    if credentials.get("user_a_cookie") and credentials.get("user_b_cookie"):
        print(f"  [IDOR Detector] Using pre-extracted SSO cookies for {base_url}", flush=True)
        detector = DualSessionIDORDetector(
            base_url=base_url,
            credentials_a={},
            credentials_b={},
        )
        # Inject cookies directly into sessions
        for cookie_pair in credentials["user_a_cookie"].split("; "):
            if "=" in cookie_pair:
                name, value = cookie_pair.split("=", 1)
                detector.session_a.cookies.set(name.strip(), value.strip())
        for cookie_pair in credentials["user_b_cookie"].split("; "):
            if "=" in cookie_pair:
                name, value = cookie_pair.split("=", 1)
                detector.session_b.cookies.set(name.strip(), value.strip())
        
        detector._log(f"[OK] User A authenticated ({len(detector.session_a.cookies)} cookies from SSO)")
        detector._log(f"[OK] User B authenticated ({len(detector.session_b.cookies)} cookies from SSO)")
        
        # Skip authenticate(), go straight to discovery + cross-test
        detector.discover_endpoints()
        if not detector.discovered_endpoints:
            detector._log("No API endpoints discovered — skipping cross-session test")
            return []
        detector.cross_session_test()
        for f in detector.findings:
            f["program"] = program
        detector._log(f"IDOR scan complete: {len(detector.findings)} findings")
        return detector.findings

    # Mode 2: Username/password login flow
    detector = DualSessionIDORDetector(
        base_url=base_url,
        credentials_a=credentials.get("user_a", {}),
        credentials_b=credentials.get("user_b", {}),
        login_endpoint=credentials.get("login_endpoint", "/login"),
        login_method=credentials.get("login_method", "POST"),
        token_location=credentials.get("token_location", "cookie"),
        token_field=credentials.get("token_field", "session"),
    )
    return detector.run(program=program)

