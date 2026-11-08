import os
import requests
import argparse
import sys

def verify_gmaps_key(api_key):
    print("[*] Testing the supplied Google Maps API key.")
    
    vuln_count = 0
    
    endpoints = {
        "Staticmap API": f"https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key={api_key}",
        "StreetView API": f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={api_key}",
        "Geocoding API": f"https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key={api_key}",
        "Directions API": f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={api_key}",
        "Find Place API": f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum&inputtype=textquery&key={api_key}"
    }

    for name, url in endpoints.items():
        print(f"  [>] Testing {name}...")
        try:
            r = requests.get(url, timeout=5)
            # If the API key is invalid or restricted, it will often return 403 or an error message in JSON/image.
            # For JSON endpoints:
            if "json" in url:
                data = r.json()
                if data.get("status") == "REQUEST_DENIED":
                    print(f"  [-] {name}: DENIED (Restricted or Disabled)")
                elif data.get("status") == "OK" or data.get("status") == "ZERO_RESULTS":
                    print(f"  [!] {name}: VULNERABLE (Unrestricted Access)")
                    vuln_count += 1
                else:
                    print(f"  [-] {name}: Error - {data.get('status')}")
            else:
                # For images (StaticMap / StreetView), status code 200 usually means success
                if r.status_code == 200:
                    print(f"  [!] {name}: VULNERABLE (Unrestricted Access)")
                    vuln_count += 1
                elif r.status_code == 403:
                    print(f"  [-] {name}: DENIED (Restricted)")
                else:
                    print(f"  [-] {name}: Unexpected Status {r.status_code}")
                    
        except Exception as e:
            print(f"  [-] Error testing {name}: {type(e).__name__}")

    if vuln_count > 0:
        print(f"\n[!!!] CONCLUSION: API Key is VULNERABLE to {vuln_count} services. High potential for financial impact (Billing abuse)!")
        return True
    else:
        print(f"\n[-] CONCLUSION: API Key appears to be correctly restricted.")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify Google Maps API Key Restrictions")
    parser.add_argument("-k", "--key", help="Google Maps API Key to test")
    args = parser.parse_args()
    
    key = args.key or os.environ.get("GOOGLE_MAPS_API_KEY")
    if not key:
        parser.error("Supply GOOGLE_MAPS_API_KEY or --key for an authorized test.")
    verify_gmaps_key(key)
