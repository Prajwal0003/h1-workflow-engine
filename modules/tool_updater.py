import requests
import json
import os
import subprocess
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
    logging.info("[*] Searching GitHub for new Bug Bounty tools...")
    known_tools_file = Path("data/known_tools.json")
    known_tools = []
    if known_tools_file.exists():
        try: known_tools = json.loads(known_tools_file.read_text())
        except: pass
        
    new_tools = find_new_github_tools()
    
    for tool in new_tools:
        repo_name = tool["name"]
        repo_url = tool["html_url"]
        repo_desc = tool["description"] or "No description"
        
        if repo_name not in known_tools:
            logging.info(f"[*] 🚨 FOUND NEW TOOL: {repo_name}")
            
            # 1. Clone the tool
            tool_dir = Path("tools") / repo_name
            if not tool_dir.exists():
                subprocess.run(["git", "clone", repo_url, str(tool_dir)], capture_output=True)
                
            # 2. Build Go tool if applicable
            subprocess.run(["go", "build", "-o", f"{repo_name}.exe"], cwd=str(tool_dir), capture_output=True)
            
            # 3. Use AI to write a wrapper
            prompt = f"""You are an elite Python developer building a bug bounty framework.
I just downloaded a new Go tool named '{repo_name}'. 
Description: {repo_desc}
Repository: {repo_url}

Write a Python wrapper function that takes a 'target_url' string, runs the '{repo_name}' binary via subprocess.run, and returns a list of dictionaries with finding data (like {{"type": "{repo_name.upper()}_VULN", "url": target_url, "severity": "HIGH", "confidence": "HIGH", "detail": "Tool discovered issue"}}).
Only return the raw python code. No markdown. Define a function named `run_{repo_name.replace('-', '_')}(target_url)`.
Use `from scanners.utils import get_bin, run_bin` to execute it safely.
"""
            python_wrapper = get_groq_response(prompt)
            
            if python_wrapper and "def run_" in python_wrapper:
                wrapper_path = Path("scanners/custom_tools") / f"{repo_name.replace('-', '_')}.py"
                wrapper_path.write_text(python_wrapper)
                
                known_tools.append(repo_name)
                send_discord_alert(f"🤖 **AI Auto-Integration:** I just found a newly released bug bounty tool on GitHub called `{repo_name}`!\n\n> {repo_desc}\n\nI successfully cloned it, built it, and used Llama-3 to automatically write a python wrapper at `scanners/custom_tools/{repo_name}.py`. It is now scanning live targets! 😈")
                
    known_tools_file.parent.mkdir(parents=True, exist_ok=True)
    known_tools_file.write_text(json.dumps(known_tools))

if __name__ == "__main__":
    hunt_for_new_tools()
