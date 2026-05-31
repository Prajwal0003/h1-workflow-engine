import json

with open("autopilot.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Imports
content = content.replace("import platform\n", "import platform\nimport random\nimport re\n")

# 2. Directories
content = content.replace("RESULTS_DIR.mkdir(parents=True, exist_ok=True)", "RESULTS_DIR.mkdir(parents=True, exist_ok=True)\nREPORTS_DIR = Path('reports')\nREPORTS_DIR.mkdir(parents=True, exist_ok=True)")

# 3. Env Vars
content = content.replace('DISCORD_WEBHOOK_URL = ENV_VARS.get("DISCORD_WEBHOOK_URL", "")', 'DISCORD_WEBHOOK_URL = ENV_VARS.get("DISCORD_WEBHOOK_URL", "")\nGEMINI_API_KEY = ENV_VARS.get("GEMINI_API_KEY", "")')

# 4. Stealth Mode
headers_block = """HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Accept": "*/*"
}"""
new_headers_block = """USER_AGENTS = [
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
    }"""
content = content.replace(headers_block, new_headers_block)
content = content.replace("headers=HEADERS", "headers=get_stealth_headers()")
content = content.replace("headers={**HEADERS,", "headers={**get_stealth_headers(),")

# 5. AI Reporter
ai_report_code = """
def generate_ai_report(finding):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY: return
    if finding.get("severity") not in ["HIGH", "CRITICAL"]: return
    
    prompt = f"Write a professional HackerOne bug bounty report for a {finding.get('severity')} severity {finding.get('type')} vulnerability on {finding.get('url')}. Include Description, Impact, and a generic Proof of Concept."
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    try:
        r = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        report_text = r.json()['candidates'][0]['content']['parts'][0]['text']
        safe_name = finding.get('type', 'vuln')
        report_path = REPORTS_DIR / f"report_{safe_name}_{int(time.time())}.md"
        report_path.write_text(report_text, encoding="utf-8")
        log(f"[+] AI generated full bug report at {report_path}")
    except Exception as e: pass
"""
content = content.replace('CORS_ORIGINS = ["https://evil.com"]', ai_report_code.strip() + '\n\nCORS_ORIGINS = ["https://evil.com"]')

# 6. JS Secret Hunter
js_secrets_code = """
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
"""
content = content.replace('# --- Engine ---', js_secrets_code.strip() + '\n\n# --- Engine ---')
content = content.replace('tasks.append(executor.submit(check_ffuf, b))', 'tasks.append(executor.submit(check_ffuf, b))\n            tasks.append(executor.submit(check_js_secrets, b))')

# 7. Continuous Monitoring (State Diffing) in main()
main_code = """
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
            
    out.write_text(json.dumps(all_findings, indent=2))
    log(f"Finished! Found {new_count} NEW issues out of {len(all_findings)} total. Results saved to {out}")
"""
old_main_loop = """
    targets = load_targets()
    if args.target:
        if args.target not in targets:
            log("Target not found")
            return
        targets = {args.target: targets[args.target]}
        
    all_findings = []
    for handle, urls in targets.items():
        all_findings.extend(scan_target_fast(handle, urls))
        
    out = RESULTS_DIR / "latest_fast_scan.json"
    out.write_text(json.dumps(all_findings, indent=2))
    log(f"Finished! Results saved to {out}")
"""
content = content.replace(old_main_loop.strip(), main_code.strip())

# Remove webhooks from scan_target_fast to avoid dupes
content = content.replace("                        send_discord_webhook(r)\n", "")
content = content.replace("                    send_discord_webhook(res)\n", "")

with open("autopilot.py", "w", encoding="utf-8") as f:
    f.write(content)
