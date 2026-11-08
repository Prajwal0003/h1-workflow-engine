"""
JavaScript Source Analyzer — Downloads JS bundles and looks for hidden endpoints and secrets.
"""
import re
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from .utils import get_stealth_headers

def origin_key(parsed):
    scheme = parsed.scheme.lower()
    return scheme, (parsed.hostname or "").lower(), parsed.port or (443 if scheme == "https" else 80)


def check_js_analyzer(url):
    findings = []
    origin = urlparse(url)
    
    try:
        r = requests.get(url, headers=get_stealth_headers(), timeout=5, verify=True, allow_redirects=False)
        if not r or r.status_code != 200:
            return None
            
        soup = BeautifulSoup(r.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        js_urls = []
        for s in scripts:
            src = s['src']
            resolved = urljoin(url, src)
            candidate = urlparse(resolved)
            if (candidate.scheme in ("http", "https") and not candidate.username
                    and not candidate.password and origin_key(candidate) == origin_key(origin)):
                js_urls.append(resolved)

        # Regex patterns
        endpoint_pattern = re.compile(r'(?:"|\')(/api/[a-zA-Z0-9_/?&=-]+)(?:"|\')')
        secret_pattern = re.compile(r'(?i)(?:api_key|apikey|secret|token|auth_token|access_token)[\s:=]+(?:["\'])([a-zA-Z0-9_-]{16,})(?:["\'])')
        
        endpoints_found = set()
        secrets_found = set()
        
        for js_url in js_urls[:5]:  # Limit to 5 scripts to save time
            try:
                jr = requests.get(js_url, headers=get_stealth_headers(), timeout=5, verify=True, allow_redirects=False)
                if jr.status_code == 200:
                    eps = endpoint_pattern.findall(jr.text)
                    for ep in eps:
                        endpoints_found.add(ep)
                        
                    secs = secret_pattern.findall(jr.text)
                    for sec in secs:
                        secrets_found.add(sec)
            except:
                pass
                
        if secrets_found:
            findings.append({
                "type": "JS_HARDCODED_SECRET",
                "url": url,
                "severity": "HIGH",
                "confidence": "HIGH",
                "duplicate_risk": "MEDIUM",
                "detail": f"Found {len(secrets_found)} candidate values in same-origin JavaScript; values omitted."
            })
            
        if endpoints_found:
            findings.append({
                "type": "JS_HIDDEN_ENDPOINTS",
                "url": url,
                "severity": "LOW",
                "confidence": "HIGH",
                "duplicate_risk": "HIGH",
                "requires_manual_verification": True,
                "detail": f"Discovered {len(endpoints_found)} hidden API endpoints in JS bundles. E.g.: {list(endpoints_found)[:3]}"
            })
            
    except: pass
    
    return findings if findings else None
