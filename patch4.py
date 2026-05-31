import json

with open("autopilot.py", "r", encoding="utf-8") as f:
    content = f.read()

# Self-Learning AI Nuclei Template Generator
ai_nuclei_code = """
def generate_nuclei_template(finding):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY: return
    
    # We only generate templates for uniquely interesting AI/Headless findings, not standard CVEs
    if finding.get("type") not in ["AI_AUTONOMOUS_EXPLOIT_SUCCESS", "HIDDEN_API_STATE_CHANGE"]: return
    
    template_dir = Path("custom-templates")
    template_dir.mkdir(exist_ok=True)
    
    prompt = f'''You are a security engineer writing a Nuclei YAML template.
Based on this vulnerability finding:
Type: {finding.get('type')}
URL: {finding.get('url')}
Detail: {finding.get('detail')}

Write a raw Nuclei YAML template that can detect this exact vulnerability on other hosts.
Do NOT use markdown code blocks. Do NOT add explanations. Just output the raw YAML string.
Make the ID '{finding.get("type").lower()}-custom-template'.'''

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    try:
        r = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=10)
        yaml_content = r.json()['candidates'][0]['content']['parts'][0]['text'].strip()
        
        # Clean up if the AI accidentally wrapped it in markdown
        if yaml_content.startswith("```yaml"): yaml_content = yaml_content[7:]
        if yaml_content.endswith("```"): yaml_content = yaml_content[:-3]
        yaml_content = yaml_content.strip()
        
        safe_id = f"ai_template_{int(time.time())}.yaml"
        template_path = template_dir / safe_id
        template_path.write_text(yaml_content, encoding="utf-8")
        log(f"[+] AI self-learned and generated a new custom Nuclei template at {template_path}")
    except Exception as e: pass
"""

content = content.replace('def ai_autonomous_exploit(url):', ai_nuclei_code.strip() + '\n\ndef ai_autonomous_exploit(url):')

# Add it to the main engine diff loop
content = content.replace('generate_ai_report(f)', 'generate_ai_report(f)\n            generate_nuclei_template(f)')

# Update Docker-compose to run the bot
compose_update = """
  bot:
    build: .
    command: ["python", "c2_bot.py"]
    env_file:
      - .env
    restart: unless-stopped
    depends_on:
      - autopilot
"""
with open("docker-compose.yml", "r") as f:
    compose = f.read()
if "bot:" not in compose:
    with open("docker-compose.yml", "a") as f:
        f.write("\n" + compose_update)

with open("autopilot.py", "w", encoding="utf-8") as f:
    f.write(content)
