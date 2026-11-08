import requests
import json
import os
import subprocess
import shutil
import logging
from pathlib import Path

def send_discord_alert(msg):
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "DISCORD_WEBHOOK_URL=" in line:
                url = line.split("=")[1].strip().strip('"').strip("'")
                try:
                    requests.post(url, json={"content": msg}, timeout=3)
                except: pass

def get_groq_response(prompt):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key: return None
    api_url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": "llama3-70b-8192", "messages": [{"role": "user", "content": prompt}], "temperature": 0.2}
    try:
        r = requests.post(api_url, json=payload, headers=headers, timeout=30)
        return r.json()['choices'][0]['message']['content'].replace("```python", "").replace("```", "").strip()
    except:
        return None

def find_new_github_tools():
    # Query GitHub for newly created or trending repositories with bug bounty topics
    headers = {"Accept": "application/vnd.github.v3+json"}
    url = "https://api.github.com/search/repositories?q=topic:bug-bounty+topic:recon+language:go&sort=updated&order=desc"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json().get("items", [])[:3] # Look at top 3 newest
    except: pass
    return []

def hunt_for_new_tools():
    """Discover candidates for review without cloning, building or importing them."""
    candidates = [{"name": item.get("name"), "url": item.get("html_url")}
                  for item in find_new_github_tools()]
    out = Path("data/tool_candidates.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    logging.info("Saved tool candidates for manual provenance and license review")


def update_wordlists():
    logging.info("[*] Updating wordlists from SecLists...")
    wordlist_dir = Path("wordlists")
    wordlist_dir.mkdir(exist_ok=True)
    
    urls = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "lfi-payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "sqli-payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt"
    }
    
    for filename, url in urls.items():
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                (wordlist_dir / filename).write_text(r.text)
                logging.info(f"  [+] Updated {filename}")
        except: pass

if __name__ == "__main__":
    update_wordlists()
    hunt_for_new_tools()
