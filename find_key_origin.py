import os
import requests
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def find_key_in_domains(key_to_find):
    # Common HackerOne subdomains to check
    targets = [
        "https://www.hackerone.com",
        "https://hackerone.com",
        "https://api.hackerone.com",
        "https://go.hacker.one",
        "https://support.hackerone.com",
        "https://docs.hackerone.com"
    ]
    
    print(f"[*] Scanning HackerOne subdomains for the exposed key...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    for url in targets:
        print(f"  [>] Checking {url}...")
        try:
            r = requests.get(url, headers=headers, verify=False, timeout=5)
            if key_to_find in r.text:
                print(f"\n[!!!] BINGO! Found the key exactly on: {url}")
                return url
        except Exception as e:
            print(f"  [-] Error accessing {url}: {e}")
            
    print("\n[-] Key was not found on the homepage of common subdomains. It might be buried deep inside a specific JS file or a hidden endpoint.")
    return None

if __name__ == "__main__":
    key = os.environ.get("GOOGLE_MAPS_API_KEY", "")
    if not key:
        raise SystemExit("Supply GOOGLE_MAPS_API_KEY for an authorized test.")
    find_key_in_domains(key)
