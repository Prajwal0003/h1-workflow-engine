import json
import os
import tempfile
import unittest
from contextlib import chdir
from pathlib import Path
from unittest.mock import Mock, patch


class SafeDefaultsTests(unittest.TestCase):
    def test_portal_requires_operator_and_preserves_other_settings(self):
        import config_app

        with tempfile.TemporaryDirectory() as d, chdir(d), patch.dict(os.environ, H1_CONFIG_TOKEN="test-only"):
            Path(".env").write_text("OTHER=preserve\nGEMINI_API_KEY=old-test-value\n")
            client = config_app.app.test_client()
            self.assertEqual(client.get("/").status_code, 401)
            auth = ("operator", "test-only")
            page = client.get("/", auth=auth)
            self.assertEqual(page.status_code, 200)
            self.assertNotIn(b"old-test-value", page.data)
            self.assertEqual(client.post("/", auth=auth, data={"GEMINI_API_KEY":"replace"}).status_code, 403)
            with client.session_transaction() as s:
                token = s["csrf"]
            self.assertEqual(client.post("/", auth=auth, data={"csrf":token, "GEMINI_API_KEY":"new-test-value"}).status_code, 200)
            self.assertEqual(set(Path(".env").read_text().splitlines()), {"OTHER=preserve","GEMINI_API_KEY=new-test-value"})
            self.assertEqual(client.post("/", auth=auth, data={"csrf":token,"UNKNOWN":"x"}).status_code, 400)

    def test_external_script_is_never_fetched_with_session(self):
        from scanners import js_analyzer

        page = Mock(status_code=200, text='<script src="//external.test/a.js"></script><script src="/ok.js"></script>')
        script = Mock(status_code=200, text='')
        with patch.object(js_analyzer.requests, "get", side_effect=[page,script]) as get:
            js_analyzer.check_js_analyzer("https://authorized.test/")
        self.assertEqual([c.args[0] for c in get.call_args_list], ["https://authorized.test/","https://authorized.test/ok.js"])
        self.assertTrue(all(c.kwargs["verify"] and not c.kwargs["allow_redirects"] for c in get.call_args_list))

    def test_telegram_identity_checks_both_chat_and_sender(self):
        import c2_bot

        with patch.object(c2_bot, "CHAT_ID", "123"), patch.object(c2_bot, "ALLOWED_USER_ID", "456"):
            self.assertTrue(c2_bot.authorized_message({"chat":{"id":123},"from":{"id":456}}))
            self.assertFalse(c2_bot.authorized_message({"chat":{"id":123},"from":{"id":999}}))
            self.assertFalse(c2_bot.authorized_message({"chat":{"id":999},"from":{"id":456}}))
            self.assertFalse(c2_bot.authorized_message({}))

    def test_dashboard_escapes_evidence_and_rejects_script_links(self):
        from generate_report import generate_html

        with tempfile.TemporaryDirectory() as d:
            source, output = Path(d)/"input.json", Path(d)/"report.html"
            source.write_text(json.dumps([{"severity":"HIGH", "url":"javascript:alert(1)", "detail":"<script>alert(1)</script>"}]))
            generate_html(source, output)
            html = output.read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;", html)
            self.assertNotIn('href="javascript:', html)
            self.assertNotIn("<script>", html)

    def test_generated_proof_is_stored_without_execution(self):
        import autopilot

        with tempfile.TemporaryDirectory() as d, chdir(d), patch.object(autopilot, "GEMINI_API_KEY", "test-only"), patch.object(autopilot, "get_ai_response", return_value="raise RuntimeError('must never execute')"), patch.object(autopilot.subprocess, "run") as run:
            finding = {"type":"demo","severity":"HIGH","confidence":"HIGH","url":"https://demo.test/"}
            proof = autopilot.ai_exploit_and_prove(finding)
            run.assert_not_called()
            self.assertFalse(proof["verified"])
            self.assertFalse(finding["ai_proof_marker_found"])
            self.assertTrue(Path(finding["poc_script"]).is_file())
