import requests
import json
import time
import os
import re
from pathlib import Path

# Try to use Groq for faster/better uncensored template generation
def generate_nuclei_template(cve_title, cve_desc):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key: return None
    
    prompt = f"""You are an elite offensive security researcher.
A new Zero-Day or critical vulnerability has been disclosed:
Title: {cve_title}
Description: {cve_desc}

Write a valid Nuclei v3 YAML template to detect this vulnerability.
Only output the raw YAML code. No markdown formatting, no explanations. Make sure it has 'id', 'info', and 'requests' or 'http' sections.
"""
    
    api_url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": "llama3-70b-8192", "messages": [{"role": "user", "content": prompt}], "temperature": 0.2}
    
    try:
        r = requests.post(api_url, json=payload, headers=headers, timeout=20)
        content = r.json()['choices'][0]['message']['content']
        # Clean markdown
        content = content.replace("```yaml", "").replace("```", "").strip()
        return content
    except Exception as e:
        print(f"Error generating template: {e}")
        return None

def fetch_latest_cves():
    url = "https://cveawg.mitre.org/api/cve/?time_modified.gt="
    # In a real scenario we use the NVD API or MITRE API, but they are heavily rate limited.
    # For this POC, we will scrape a Github repo that tracks zero days or simulate it.
    # Simulated for now, returning a mock high-severity CVE to demonstrate the pipeline.
    return [
        {
            "id": "CVE-2024-99999",
            "title": "Mock RCE in Popular Framework",
            "desc": "A critical remote code execution vulnerability exists in PopularFramework version 1.0.0 via the /api/v1/upload endpoint."
        }
    ]

def watch_for_zero_days():
    print("[*] Starting Zero-Day Watcher...")
    templates_dir = Path("custom-templates")
    templates_dir.mkdir(exist_ok=True)
    
    known_cves_file = Path("data/known_cves.json")
    known_cves = []
    if known_cves_file.exists():
        try:
            known_cves = json.loads(known_cves_file.read_text())
        except: pass

    # Fetch recent CVEs
    cves = fetch_latest_cves()
    
    for cve in cves:
        if cve["id"] not in known_cves:
            print(f"[*] NEW ZERO-DAY DETECTED: {cve['id']} - {cve['title']}")
            template_yaml = generate_nuclei_template(cve["title"], cve["desc"])
            
            if template_yaml and "id:" in template_yaml:
                template_path = templates_dir / f"{cve['id']}.yaml"
                template_path.write_text(template_yaml)
                print(f"[+] Custom Nuclei template generated: {template_path}")
                known_cves.append(cve["id"])
                
                # We would normally trigger nuclei here against all targets
                # subprocess.run(["nuclei", "-t", str(template_path), "-l", "data/all_targets.txt"])
                
    known_cves_file.write_text(json.dumps(known_cves))

if __name__ == "__main__":
    watch_for_zero_days()
