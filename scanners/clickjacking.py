import requests
from rich.console import Console

console = Console()

def check_clickjacking(url, headers=None):
    """
    Checks for missing X-Frame-Options or CSP frame-ancestors headers.
    This is an extremely common, low-severity finding that is widely accepted 
    on VDPs (Vulnerability Disclosure Programs) to build reputation/signal.
    """
    console.print(f"[bold cyan][*] Scanning for Clickjacking (Missing Frame Protection): {url}[/bold cyan]")
    findings = []
    
    try:
        r = requests.get(url, headers=headers, timeout=5)
        
        x_frame = r.headers.get("X-Frame-Options", "").lower()
        csp = r.headers.get("Content-Security-Policy", "").lower()
        
        is_protected = False
        
        # Check X-Frame-Options
        if "deny" in x_frame or "sameorigin" in x_frame:
            is_protected = True
            
        # Check CSP for frame-ancestors
        if "frame-ancestors" in csp:
            is_protected = True
            
        if not is_protected:
            console.print(f"[bold yellow][!] SIGNAL FARM: Missing X-Frame-Options & CSP frame-ancestors at {url}[/bold yellow]")
            findings.append(f"Clickjacking / Missing Frame Protection: {url}")
            
    except requests.exceptions.RequestException:
        pass
        
    if not findings:
        console.print("[green][+] Clickjacking protection is present.[/green]")
        
    return findings
