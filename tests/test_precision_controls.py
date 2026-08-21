import unittest

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

    def test_ai_proof_is_retained_but_not_independent_verification(self):
        finding = {
            "type": "XSS_CANDIDATE",
            "verified": False,
            "ai_proof_available": True,
            "ai_proof_marker_found": True,
            "proof": "VERIFIED: VULNERABLE",
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
