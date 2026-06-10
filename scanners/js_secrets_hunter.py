import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

SECRET_REGEXES = {
    "AWS Access Key": r"(?i)AKIA[0-9A-Z]{16}",
    "Stripe Standard API": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API": r"rk_live_[0-9a-zA-Z]{24}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "Generic Secret": r"(?i)(api_key|secret|password|token)[\s=:]+[\"']([a-zA-Z0-9\-_]{16,})[\"']"
}

def hunt_js_secrets(url):
    """
    Downloads and scans all linked Javascript files on a page for hardcoded AWS keys, 
    Stripe tokens, Slack tokens, and generic API keys.
    """
    findings = []
    print(f"[*] JS Secrets Hunter analyzing: {url}")
    
    headers = {"User-Agent": "Aegis-Auto/JS-Hunter"}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"
    
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        js_links = [urljoin(url, script['src']) for script in soup.find_all("script", src=True)]
        
        for js_url in set(js_links):
            if any(x in js_url for x in ["jquery", "bootstrap", "google-analytics", "recaptcha", "cloudflare"]): 
                continue
            
            try:
                js_r = requests.get(js_url, headers=headers, timeout=10, verify=False)
                content = js_r.text
                for name, regex in SECRET_REGEXES.items():
                    matches = re.findall(regex, content)
                    for match in set(matches):
                        if isinstance(match, tuple): match = match[1]
                        if len(str(match)) > 150: continue # Prevent false positive massive strings
                        
                        findings.append({
                            "type": "HARDCODED_SECRET_LEAK",
                            "url": js_url,
                            "severity": "CRITICAL",
                            "confidence": "HIGH",
                            "verified": True,
                            "detail": f"Exposed {name} found in JS file: {str(match)[:10]}***"
                        })
            except Exception: 
                pass
    except Exception: 
        pass
    return findings
