import requests
import re
import urllib3

urllib3.disable_warnings()

def check_secret():
    url = "https://crm.na1.insightly.com/bundles/scripts/thirdparty.min.js?v=0c5e1c306d140c2b15cfb33bdb88c6e8"
    try:
        print(f"[*] Fetching JS bundle: {url}")
        r = requests.get(url, verify=False, timeout=10)
        
        # Look for the secret 5e3aa3bf712ea0e2a03b
        matches = re.finditer(r'.{0,30}5e3aa3bf712ea0e2a03b.{0,30}', r.text)
        
        print("\n[*] Context of '5e3aa3bf712ea0e2a03b':")
        found = False
        for m in matches:
            found = True
            print(f"  -> {m.group(0)}")
            
        if not found:
            print("  [-] Could not find that specific string in the bundle.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    check_secret()
