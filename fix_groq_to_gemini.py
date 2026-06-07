import os
from pathlib import Path
import re

def replace_in_file(filepath):
    try:
        content = Path(filepath).read_text(encoding="utf-8")
        if "GROQ" not in content and "groq" not in content:
            return
            
        print(f"Fixing {filepath}...")
        
        # Replace variable names
        content = content.replace("GEMINI_API_KEY", "GEMINI_API_KEY")
        
        # Replace groq imports and client calls with Gemini API
        if "" in content:
            content = content.replace("", "")
            
            gemini_func = """

def _call_gemini(prompt, api_key):
    import requests
    if not api_key or "your_" in api_key: return None
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    try:
        r = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
        return r.json()['candidates'][0]['content']['parts'][0]['text']
    except:
        return None

def _replay_request)",
                    gemini_func + "\n",
                    content,
                    flags=re.DOTALL
                )
                
        Path(filepath).write_text(content, encoding="utf-8")
    except Exception as e:
        print(f"Error on {filepath}: {e}")

for root, dirs, files in os.walk("."):
    if ".git" in root or "tools" in root or "venv" in root:
        continue
    for f in files:
        if f.endswith(".py"):
            replace_in_file(os.path.join(root, f))
