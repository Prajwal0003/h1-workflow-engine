import requests
from rich.console import Console

console = Console()

def check_security_headers(url, headers=None):
    """
    Checks for the absence of standard Security Headers.
    Missing HSTS, X-Content-Type-Options, etc., are low-hanging fruit.
    While often out-of-scope for paid bounties, many VDPs accept these 
    and award points/signal for a complete report.
    """
    console.print(f"[bold cyan][*] Scanning for Missing Security Headers: {url}[/bold cyan]")
    findings = []
    
    try:
        r = requests.get(url, headers=headers, timeout=5)
        resp_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        
        missing_headers = []
        
        # 1. HSTS (Strict-Transport-Security)
        if url.startswith("https://") and "strict-transport-security" not in resp_headers:
            missing_headers.append("Strict-Transport-Security (HSTS)")
            
        # 2. X-Content-Type-Options
        if "x-content-type-options" not in resp_headers or "nosniff" not in resp_headers.get("x-content-type-options", ""):
            missing_headers.append("X-Content-Type-Options: nosniff")
            
        # 3. Content-Security-Policy (CSP)
        if "content-security-policy" not in resp_headers:
             missing_headers.append("Content-Security-Policy (CSP)")
             
        if missing_headers:
            headers_str = ", ".join(missing_headers)
            console.print(f"[bold yellow][!] SIGNAL FARM: Missing Headers at {url} -> {headers_str}[/bold yellow]")
            findings.append(f"Missing Security Headers: {url} ({headers_str})")
            
    except requests.exceptions.RequestException:
        pass
        
    if not findings:
        console.print("[green][+] Standard Security Headers are present.[/green]")
        
    return findings
