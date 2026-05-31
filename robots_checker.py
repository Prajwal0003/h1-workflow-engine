import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://www.priceline.com"

# Using the headers from your curl command
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}

PATHS = [
    "/chkrequest.asp",
    "/cityss.asp",
    "/CustomerService/",
    "/dashboard/",
    "/Dashboard/",
    "/errorpage.htm",
    "/ErrorPage.asp",
    "/finance/",
    "/hotel/accept",
    "/hotel/checkStatus",
    "/hotel/contract",
    "/hotel/hotelOverviewGuide.do",
    "/hr.asp",
    "/Hr.asp",
    "/HR.asp",
    "/Invalid_Data.html",
    "/myprofile/",
    "/MyProfile/",
    "/NewFinance/homeequity/",
    "/NewFinance/infoctr/",
    "/NewFinance/plmortgage/",
    "/oops.html",
    "/privacypolicy/",
    "/qp.asp",
    "/Qp.asp",
    "/receipt/",
    "/rentalcars/accept",
    "/rentalcars/contract",
    "/rentalcars/retailContract",
    "/Session_Timeout.asp",
    "/sharedapps/",
    "/status/",
    "/surveys/",
    "/travel-itinerary/",
    "/WLDefault.asp",
    "/log/client/",
    "/a/api/flight",
    "/s/vestigo/",
    "/s/horizon/"
]

print(f"[*] Checking robots.txt paths on {BASE_URL}...\n")

for path in PATHS:
    target = f"{BASE_URL}{path}"
    try:
        # Use allow_redirects=False to see where they try to send us
        resp = requests.get(target, headers=HEADERS, verify=False, timeout=5, allow_redirects=False)
        
        status = resp.status_code
        if status == 200:
            print(f"[+] {status} OK         - {target} (Size: {len(resp.text)})")
        elif status in [301, 302, 307, 308]:
            redir = resp.headers.get("Location", "")
            print(f"[*] {status} Redirect   - {target} -> {redir}")
        elif status in [401, 403]:
            print(f"[-] {status} Forbidden  - {target}")
        elif status == 404:
            pass # Ignore standard 404s to keep output clean
        else:
            print(f"[?] {status} Unknown    - {target}")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Error on {target}: {str(e)[:50]}")

print("\n[*] Check complete.")
