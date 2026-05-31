import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def verify_cors(url):
    print(f"\n[*] Investigating CORS on {url}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Origin": "https://evil.com"
    }
    
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")
        
        if acao == "https://evil.com":
            if acac == "true":
                print("  [!!!] 100% VULNERABLE: Reflects arbitrary Origin AND allows Credentials (Cookies)!")
                print("  [!!!] ACTION: If this endpoint returns sensitive user JSON data when logged in, this is a High severity bug.")
            else:
                print("  [!] VULNERABLE: Reflects arbitrary Origin, but DOES NOT allow Credentials.")
                print("  [!] ACTION: Only exploitable if the endpoint relies on IP-based auth or network position rather than cookies.")
        else:
            print(f"  [-] FALSE POSITIVE: Reflected origin was '{acao}' instead of 'https://evil.com'.")
    except Exception as e:
        print(f"  [-] Error checking CORS: {e}")

if __name__ == "__main__":
    targets = [
        "https://experiences.priceline.com",
        "https://1psb.priceline.com",
        "https://secure.rezserver.com",
        "https://priceline.com",
        "https://www.priceline.com/pwd/v0/pcln-graphql"
    ]
    for t in targets:
        verify_cors(t)
