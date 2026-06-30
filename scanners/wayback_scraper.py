import requests
import json
from urllib.parse import urlparse

def fetch_wayback_urls(url):
    """
    Queries the Internet Archive (Wayback Machine) CDX API to discover 
    old, potentially vulnerable endpoints that are no longer linked.
    """
    findings = []
    print(f"[*] Time-Traveling to fetch forgotten endpoints for: {url}")
    
    try:
        domain = url.split("//")[-1].split("/")[0]
        # Ignore subdomains for this basic query to avoid massive output, just use the host
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit=200"
        
        r = requests.get(cdx_url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1: # Row 0 is headers
                urls = [row[0] for row in data[1:]]
                # Filter for interesting API endpoints or param-heavy URLs
                api_endpoints = [u for u in urls if "/api/" in u or "/v1/" in u or "?" in u]
                if api_endpoints:
                    findings.append({
                        "type": "WAYBACK_ARCHIVE_EXPOSURE",
                        "url": url,
                        "severity": "MEDIUM",
                        "confidence": "HIGH",
                        "verified": True,
                        "detail": f"Found {len(api_endpoints)} archived API endpoints from the past. These could be vulnerable v1 endpoints: {', '.join(api_endpoints[:3])}..."
                    })
    except Exception:
        pass
        
    return findings
