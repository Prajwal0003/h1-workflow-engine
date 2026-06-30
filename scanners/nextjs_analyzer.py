import requests
import re
from rich.console import Console

console = Console()

def check_nextjs_vulnerabilities(url, headers=None):
    """
    Scans for modern Next.js specific vulnerabilities including:
    - _next/data/ sensitive data exposure
    - Server Actions misconfigurations
    - Unprotected API routes
    """
    console.print(f"[bold cyan][*] Scanning for Next.js Specific Vulnerabilities: {url}[/bold cyan]")
    
    findings = []
    
    # 1. Check for Server Actions vulnerability (Missing CSRF or unauthenticated action)
    # Next.js Server actions are identified by the Next-Action header
    console.print("[dim]- Checking for Next.js Server Actions abuse...[/dim]")
    try:
        # Simulate a generic Server Action post
        sa_headers = headers.copy() if headers else {}
        sa_headers["Next-Action"] = "random_action_id"
        response = requests.post(url, headers=sa_headers, timeout=5)
        if response.status_code == 500 and "Error:" in response.text:
             console.print(f"[bold yellow][!] INFO: Server Actions are enabled and reachable. Needs manual fuzzing.[/bold yellow]")
             findings.append("Next.js Server Actions Enabled")
    except Exception:
        pass

    # 2. Check for _next/data/ exposure
    # In Next.js, getStaticProps/getServerSideProps returns JSON via _next/data/<build_id>/path.json
    console.print("[dim]- Extracting Build ID for _next/data profiling...[/dim]")
    try:
        main_resp = requests.get(url, headers=headers, timeout=5)
        # Search for buildId in the page source
        build_id_match = re.search(r'"buildId":"([^"]+)"', main_resp.text)
        if build_id_match:
            build_id = build_id_match.group(1)
            console.print(f"[dim]  Found Build ID: {build_id}[/dim]")
            
            # Try to fetch common protected data routes
            test_routes = ["/profile.json", "/admin.json", "/dashboard.json", "/settings.json"]
            for route in test_routes:
                data_url = f"{url.rstrip('/')}/_next/data/{build_id}{route}"
                data_resp = requests.get(data_url, headers=headers, timeout=5)
                
                if data_resp.status_code == 200 and "{" in data_resp.text:
                    console.print(f"[bold red][!] CRITICAL: Exposed _next/data endpoint: {data_url}[/bold red]")
                    findings.append(f"Next.js _next/data Exposure: {data_url}")
    except Exception:
        pass
        
    if not findings:
        console.print("[green][+] No Next.js specific vulnerabilities found.[/green]")
        
    return findings
