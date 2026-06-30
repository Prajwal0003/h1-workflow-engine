import json

with open("autopilot.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Env vars
env_vars_block = """
GEMINI_API_KEY = ENV_VARS.get("GEMINI_API_KEY", "")
SHODAN_API_KEY = ENV_VARS.get("SHODAN_API_KEY", "")
"""
new_env_vars_block = """
GEMINI_API_KEY = ENV_VARS.get("GEMINI_API_KEY", "")
SHODAN_API_KEY = ENV_VARS.get("SHODAN_API_KEY", "")
NOTION_API_KEY = ENV_VARS.get("NOTION_API_KEY", "")
NOTION_DATABASE_ID = ENV_VARS.get("NOTION_DATABASE_ID", "")
INTERACTSH_URL = ENV_VARS.get("INTERACTSH_URL", "")
"""
content = content.replace(env_vars_block.strip(), new_env_vars_block.strip())

# 2. Notion Ticketing
notion_ticket_code = """
def create_notion_ticket(finding):
    if not NOTION_API_KEY or "your_" in NOTION_API_KEY: return
    if not NOTION_DATABASE_ID or "your_" in NOTION_DATABASE_ID: return
    
    url = "https://api.notion.com/v1/pages"
    headers = {
        "Authorization": f"Bearer {NOTION_API_KEY}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28"
    }
    
    data = {
        "parent": { "database_id": NOTION_DATABASE_ID },
        "properties": {
            "Name": { "title": [ { "text": { "content": f"[{finding.get('severity')}] {finding.get('type')} on {finding.get('program')}" } } ] },
            "Status": { "status": { "name": "Triage" } },
            "Severity": { "select": { "name": finding.get('severity') } },
            "URL": { "url": finding.get('url') }
        }
    }
    
    try:
        r = requests.post(url, headers=headers, json=data, timeout=5)
        if r.status_code == 200:
            log(f"[+] Created Notion Ticket for {finding.get('type')}")
    except: pass
"""
content = content.replace('CORS_ORIGINS = ["https://evil.com"]', notion_ticket_code.strip() + '\n\nCORS_ORIGINS = ["https://evil.com"]')

# 3. Blind SSRF (Interactsh)
blind_ssrf_code = """
def check_blind_oob(url):
    if not INTERACTSH_URL or "your_" in INTERACTSH_URL: return None
    try:
        # Inject OOB URL in X-Forwarded-For and User-Agent
        headers = get_stealth_headers()
        headers["X-Forwarded-For"] = f"http://{INTERACTSH_URL}"
        headers["User-Agent"] = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) curl/7.68.0 http://{INTERACTSH_URL}"
        
        # Inject OOB payload in a dummy query parameter
        test_url = f"{url}?callback=http://{INTERACTSH_URL}&url=http://{INTERACTSH_URL}"
        requests.get(test_url, headers=headers, timeout=3, verify=False)
    except: pass
    return None # We don't return findings here, the interactsh client checks this asynchronously
"""
content = content.replace('def check_js_secrets(url):', blind_ssrf_code.strip() + '\n\ndef check_js_secrets(url):')

# 4. Playwright Headless Crawl
playwright_code = """
def check_headless_spa(url):
    findings = []
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            # Listen to background API calls
            def handle_request(request):
                if "api" in request.url and request.method in ["POST", "PUT", "DELETE"]:
                    findings.append({
                        "type": "HIDDEN_API_STATE_CHANGE",
                        "url": request.url,
                        "severity": "MEDIUM",
                        "detail": f"Discovered background {request.method} API call via Headless SPA render"
                    })
            page.on("request", handle_request)
            
            page.goto(url, timeout=10000, wait_until="networkidle")
            browser.close()
    except Exception as e: pass
    
    # De-duplicate
    unique_findings = []
    seen = set()
    for f in findings:
        sig = f"{f['type']}_{f['url']}"
        if sig not in seen:
            seen.add(sig)
            unique_findings.append(f)
            
    return unique_findings if unique_findings else None
"""
content = content.replace('# --- Engine ---', playwright_code.strip() + '\n\n# --- Engine ---')

# 5. Inject into Engine
content = content.replace('tasks.append(executor.submit(check_js_secrets, b))', 'tasks.append(executor.submit(check_js_secrets, b))\n            tasks.append(executor.submit(check_blind_oob, b))\n            tasks.append(executor.submit(check_headless_spa, b))')

# 6. Notion in Main
content = content.replace('generate_ai_report(f)', 'generate_ai_report(f)\n            create_notion_ticket(f)')

with open("autopilot.py", "w", encoding="utf-8") as f:
    f.write(content)
