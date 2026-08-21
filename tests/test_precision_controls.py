import base64
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from modules.ai_triage import _merge_model_results
from modules.finding_quality import (
    canonical_url,
    deduplicate_findings,
    has_deterministic_evidence,
    readiness_reasons,
)


class PrecisionControlTests(unittest.TestCase):
    def test_canonical_url_sorts_query_and_removes_fragment(self):
        self.assertEqual(
            canonical_url("HTTPS://Example.COM:443/a?z=2&b=1#fragment"),
            "https://example.com/a?b=1&z=2",
        )

    def test_duplicate_scanner_outputs_are_collapsed_by_family(self):
        findings = deduplicate_findings([
            {"program": "demo", "type": "CORS_REFLECTION", "url": "https://demo.test/api?b=2&a=1", "severity": "HIGH", "verified": False, "detail": "reflection"},
            {"program": "demo", "type": "CORS_MISCONFIGURATION", "url": "https://demo.test/api?a=1&b=2#x", "severity": "MEDIUM", "verified": False, "detail": "credentials"},
        ])
        self.assertEqual(len(findings), 1)
        self.assertIn("reflection", findings[0]["detail"])
        self.assertIn("credentials", findings[0]["detail"])

    def test_payload_variants_on_same_endpoint_are_collapsed(self):
        findings = deduplicate_findings([
            {"program": "demo", "type": "SQLI_TIME", "url": "https://demo.test/search?id=1%27", "severity": "HIGH", "verified": False},
            {"program": "demo", "type": "SQLI_ERROR", "url": "https://demo.test/search?id=1%27%20OR%201%3D1", "severity": "HIGH", "verified": False},
        ])
        self.assertEqual(len(findings), 1)

    def test_ssti_requires_two_evaluated_syntaxes(self):
        from scanners import ssti

        class Response:
            status_code = 200
            headers = {"Content-Type": "text/plain"}

            def __init__(self, text):
                self.text = text

        def fake_get(url):
            value = parse_qs(urlparse(url).query, keep_blank_values=True)["name"][0]
            if value.endswith("BASE"):
                return Response("baseline")
            if value.startswith("{{7*7}}"):
                return Response("49" + value[len("{{7*7}}") :])
            if value.startswith("${7*7}"):
                return Response("49" + value[len("${7*7}") :])
            return Response(value)

        with patch.object(ssti, "safe_get", side_effect=fake_get):
            finding = ssti.check_ssti("https://demo.test/search")
        self.assertEqual(finding[0]["verification_method"], "ssti-multi-payload")
        self.assertEqual(finding[0]["verification_evidence"]["payload_count"], 2)

    def test_autopilot_headers_read_live_auth_context(self):
        import autopilot
        from scanners import utils

        old_cookie, old_bearer = utils.GLOBAL_COOKIE, utils.GLOBAL_BEARER
        try:
            utils.set_auth_context(cookie="session=abc", bearer="token-xyz")
            headers = autopilot.get_stealth_headers()
            self.assertEqual(headers["Cookie"], "session=abc")
            self.assertEqual(headers["Authorization"], "Bearer token-xyz")
        finally:
            utils.set_auth_context(cookie=old_cookie, bearer=old_bearer)

    def test_ssrf_metadata_requires_control_difference(self):
        from scanners import ssrf

        class Response:
            status_code = 200
            headers = {"Content-Type": "text/plain"}

            def __init__(self, text):
                self.text = text

        def fake_get(url, timeout=8):
            query = parse_qs(urlparse(url).query, keep_blank_values=True)
            value = next(iter(query.values()))[0]
            if "169.254.169.254" in value:
                return Response("ami-id\\ninstance-id\\ninstance-type\\nlocal-hostname\\npublic-hostname\\nsecurity-credentials")
            return Response("normal external response")

        with patch.object(ssrf, "safe_get", side_effect=fake_get):
            finding = ssrf.check_ssrf("https://demo.test/fetch?url=https://example.com")
        self.assertEqual(finding[0]["type"], "SSRF_AWS_METADATA")
        self.assertTrue(finding[0]["verification_evidence"]["control_signature_absent"])

    def test_jwt_alg_none_requires_invalid_token_control(self):
        from scanners import jwt_fuzzer

        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

        original_token = f"{encode({'typ': 'JWT', 'alg': 'HS256'})}.{encode({'role': 'user'})}.signature"
        jwt_fuzzer.utils.GLOBAL_BEARER = original_token
        jwt_fuzzer.utils.GLOBAL_COOKIE = None

        class Response:
            def __init__(self, status_code, text, content_type="application/json"):
                self.status_code = status_code
                self.text = text
                self.headers = {"Content-Type": content_type}

        responses = iter([
            Response(200, '{"role":"user"}'),
            Response(200, '{"role":"admin"}'),
            Response(401, '{"error":"unauthorized"}'),
        ])
        with patch.object(jwt_fuzzer.requests, "get", side_effect=lambda *args, **kwargs: next(responses)):
            finding = jwt_fuzzer.run_jwt_fuzzer("https://demo.test/api/me")
        self.assertEqual(finding[0]["verification_method"], "jwt-alg-none-controls")
        self.assertTrue(finding[0]["verification_evidence"]["status_bypass"])

    def test_open_redirect_requires_exact_attacker_host(self):
        from scanners import open_redirect_fuzzer

        class Response:
            def __init__(self, status_code, location=""):
                self.status_code = status_code
                self.headers = {"Location": location} if location else {}

        responses = iter([
            Response(200),
            Response(302, "https://evil.com/landing"),
        ])
        with patch.object(open_redirect_fuzzer.requests, "get", side_effect=lambda *args, **kwargs: next(responses)):
            finding = open_redirect_fuzzer.run_open_redirect_fuzzer("https://demo.test/next?url=home")
        self.assertTrue(finding[0]["verified"])
        self.assertEqual(finding[0]["verification_method"], "no-follow-redirect")

        responses = iter([Response(200), Response(302, "https://evil.com.attacker.test/")])
        with patch.object(open_redirect_fuzzer.requests, "get", side_effect=lambda *args, **kwargs: next(responses)):
            finding = open_redirect_fuzzer.run_open_redirect_fuzzer("https://demo.test/next?url=home")
        self.assertEqual(finding, [])

    def test_secret_scanner_deduplicates_and_downgrades_pattern_matches(self):
        import autopilot

        class Response:
            def __init__(self, text, status_code=200, content_type="text/html"):
                self.text = text
                self.status_code = status_code
                self.headers = {"Content-Type": content_type}

        html = '<script src="/app.js"></script><script src="/app.js"></script>'
        js = 'const key = "AKIA1234567890ABCDEF"; const placeholder = "your_api_key";'

        def fake_get(url, **kwargs):
            if url == "https://demo.test/":
                return Response(html)
            return Response(js, content_type="application/javascript")

        with patch.object(autopilot.requests, "get", side_effect=fake_get):
            findings = autopilot.check_js_secrets("https://demo.test/")
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0]["verified"])
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_sensitive_path_rejects_html_soft_404(self):
        import autopilot

        class Response:
            status_code = 200
            text = "<html><title>Not Found</title>missing page</html>"
            headers = {"Content-Type": "text/html"}

        with patch.object(autopilot.requests, "get", return_value=Response()):
            finding = autopilot.check_sensitive_single("https://demo.test/.env", 200, 10)
        self.assertIsNone(finding)

    def test_sensitive_env_signature_remains_detectable(self):
        import autopilot

        class Response:
            status_code = 200
            text = "APP_ENV=production\nAPI_KEY=redacted-example-value"
            headers = {"Content-Type": "text/plain"}

        with patch.object(autopilot.requests, "get", return_value=Response()):
            finding = autopilot.check_sensitive_single("https://demo.test/.env", 404, 0)
        self.assertEqual(finding["type"], "EXPOSED_ENV_FILE")
        self.assertTrue(finding["verified"])

    def test_safe_post_merges_custom_headers(self):
        from scanners import utils

        class Response:
            pass

        with patch.object(utils.requests, "post", return_value=Response()) as mocked:
            self.assertIsNotNone(utils.safe_post(
                "https://demo.test/xml",
                data="<x/>",
                headers={"Content-Type": "application/xml"},
            ))
        sent_headers = mocked.call_args.kwargs["headers"]
        self.assertEqual(sent_headers["Content-Type"], "application/xml")
        self.assertIn("User-Agent", sent_headers)

    def test_ai_proof_is_retained_but_not_independent_verification(self):
        finding = {
            "type": "XSS_CANDIDATE",
            "verified": False,
            "ai_proof_available": True,
            "ai_proof_marker_found": True,
            "proof": "VERIFIED: VULNERABLE",
        }
        self.assertFalse(has_deterministic_evidence(finding))

    def test_unreviewed_method_cannot_pass_generic_gate(self):
        finding = {
            "type": "NEW_SCANNER_RESULT",
            "verified": True,
            "verification_method": "unreviewed-scanner",
            "verification_evidence": {"deterministic": True},
        }
        self.assertFalse(has_deterministic_evidence(finding))

    def test_cors_requires_sensitive_authenticated_response(self):
        candidate = {
            "type": "CORS_REFLECTION",
            "verified": True,
            "verification_method": "cors-two-origin-replay",
            "verification_evidence": {
                "arbitrary_origin": True,
                "allow_credentials": True,
                "sensitive_response": False,
            },
        }
        self.assertFalse(has_deterministic_evidence(candidate))
        self.assertIn("Verification lacks type-specific evidence", readiness_reasons(candidate))

    def test_cors_sensitive_response_can_pass(self):
        finding = {
            "type": "CORS_REFLECTION",
            "verified": True,
            "verification_method": "cors-two-origin-replay",
            "verification_evidence": {
                "arbitrary_origin": True,
                "allow_credentials": True,
                "sensitive_response": True,
            },
        }
        self.assertTrue(has_deterministic_evidence(finding))

    def test_dual_session_idor_requires_two_subjects(self):
        finding = {
            "type": "IDOR_RESOURCE_ACCESS",
            "verified": True,
            "verification_method": "dual-session",
            "verification_evidence": {
                "subject_a": "user_a",
                "subject_b": "user_b",
                "cross_account_access": True,
            },
        }
        self.assertTrue(has_deterministic_evidence(finding))

    def test_ai_disagreement_is_review_not_true_positive(self):
        result = _merge_model_results(
            {"verdict": "TRUE_POSITIVE", "confidence": 0.99},
            {"verdict": "FALSE_POSITIVE", "confidence": 0.99},
        )
        self.assertEqual(result["verdict"], "NEEDS_REVIEW")

    def test_ai_malformed_single_response_is_review(self):
        result = _merge_model_results(
            {"verdict": "TRUE_POSITIVE", "confidence": 0.99},
            None,
        )
        self.assertEqual(result["verdict"], "NEEDS_REVIEW")

    def test_ai_high_confidence_consensus_can_confirm_advisory_verdict(self):
        result = _merge_model_results(
            {"verdict": "TRUE_POSITIVE", "confidence": 0.91},
            {"verdict": "TRUE_POSITIVE", "confidence": 0.88},
        )
        self.assertEqual(result["verdict"], "TRUE_POSITIVE")
        self.assertAlmostEqual(result["confidence"], 0.88)


if __name__ == "__main__":
    unittest.main()
