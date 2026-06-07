import json
import urllib.request
import ssl
import sys

def verify_ssti(url, original_payload, original_result):
    # Try a different payload to see if it's dynamic
    test_payload = "9*9"
    expected = "81"
    
    if "7*7" in url:
        new_url = url.replace("7*7", test_payload)
    else:
        return "Manual verification needed (different payload structure)"
        
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(new_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            body = response.read().decode('utf-8', errors='ignore')
            if expected in body:
                return f"Confirmed! Found {expected} with {test_payload}"
            else:
                return f"False Positive. Could not find {expected}"
    except Exception as e:
        return f"Error: {e}"

def verify_open_redirect(url):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Don't follow redirects automatically
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return urllib.response.addinfourl(fp, headers, req.get_full_url(), code)
            http_error_301 = http_error_303 = http_error_307 = http_error_302
            
        opener = urllib.request.build_opener(NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx))
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        response = opener.open(req, timeout=5)
        
        if response.code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if 'evil.com' in location:
                return f"Confirmed! Redirects to {location}"
            else:
                return f"False Positive? Redirects to {location}"
        else:
            return f"False Positive. Status code {response.code}"
    except Exception as e:
        return f"Error: {e}"

def verify_file_exposure(url):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            body = response.read().decode('utf-8', errors='ignore')
            # Look for common false positive soft 404s (e.g. HTML pages returned for missing files)
            if "<html" in body.lower() and response.code == 200:
                return f"False Positive? Returned an HTML page (soft 404)"
            elif response.code == 200:
                return f"Likely Real. Returned 200 OK and not obvious HTML"
            else:
                return f"False Positive. Status {response.code}"
    except urllib.error.HTTPError as e:
        return f"False Positive. Status {e.code}"
    except Exception as e:
        return f"Error: {e}"

def main():
    try:
        with open('data/autopilot/latest_fast_scan.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Could not find data/autopilot/latest_fast_scan.json")
        return

    findings = {}
    for item in data:
        t = item['type']
        if t not in findings:
            findings[t] = []
        findings[t].append(item)

    print(f"Loaded {len(data)} findings.")
    
    # We will sample a few to verify
    for t, items in findings.items():
        print(f"\n--- {t} ({len(items)} items) ---")
        # Just check up to 3 of each type
        for item in items[:3]:
            print(f"URL: {item['url']}")
            
            if t == 'SSTI':
                res = verify_ssti(item['url'], '7*7', '49')
                print(f"Verification: {res}")
            elif t == 'OPEN_REDIRECT':
                res = verify_open_redirect(item['url'])
                print(f"Verification: {res}")
            elif t in ['WP_CONFIG_BACKUP', 'WP_DEBUG_LOG', 'SENSITIVE_PATH']:
                res = verify_file_exposure(item['url'])
                print(f"Verification: {res}")
            else:
                print("Verification: Skipping automated verify for this type.")
            print()

if __name__ == "__main__":
    main()
