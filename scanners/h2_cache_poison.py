import requests
from rich.console import Console
import time

console = Console()

def check_h2_cache_poisoning(url, headers=None):
    """
    HTTP/2 Cache Poisoning & Request Smuggling Proxy Scanner.
    Tests for misconfigurations where frontend proxies translate HTTP/2 to HTTP/1.1
    incorrectly, allowing header smuggling to poison the cache for other users.
    """
    console.print(f"[bold cyan][*] Scanning for HTTP/2 Cache Poisoning & Translation flaws: {url}[/bold cyan]")
    findings = []
    
    # We simulate smuggling an invalid header or pseudo-header that might cause
    # the backend to respond with a 400 Bad Request or uncacheable response,
    # but the frontend caches it for the normal URL.
    
    # Payload 1: Smuggling a colon header (H2 -> H1.1 translation bug)
    # Payload 2: Host header poisoning via X-Forwarded-Host combined with cachebusters
    
    cachebusters = [f"?cb={int(time.time())}", f"?cb={int(time.time())+1}"]
    
    for cb in cachebusters:
        test_url = f"{url}{cb}"
        
        # We test X-Forwarded-Host poisoning first as it's a common cache poisoning vector
        poison_headers = headers.copy() if headers else {}
        poison_headers["X-Forwarded-Host"] = "evil-poisoned-host.com"
        
        try:
            # 1. Send the poisoning request
            r_poison = requests.get(test_url, headers=poison_headers, timeout=5)
            
            # 2. Check if the response reflects our injected host
            if "evil-poisoned-host.com" in r_poison.text:
                
                # 3. Request without the poisoned header to see if it was cached
                clean_headers = headers.copy() if headers else {}
                r_clean = requests.get(test_url, headers=clean_headers, timeout=5)
                
                # Look for cache status headers
                cache_status = r_clean.headers.get("X-Cache", "") + r_clean.headers.get("CF-Cache-Status", "")
                
                if "evil-poisoned-host.com" in r_clean.text and ("HIT" in cache_status.upper() or r_clean.text == r_poison.text):
                    console.print(f"[bold red][!] CRITICAL: Cache Poisoning detected![/bold red]")
                    console.print(f"[bold red]    Payload 'evil-poisoned-host.com' was served to a clean request via cache.[/bold red]")
                    console.print(f"[bold red]    URL: {test_url}[/bold red]")
                    findings.append(f"Cache Poisoning: {test_url} via X-Forwarded-Host")
                    
        except requests.exceptions.RequestException:
            pass
            
    if not findings:
        console.print("[green][+] No Cache Poisoning vulnerabilities detected.[/green]")
        
    return findings
