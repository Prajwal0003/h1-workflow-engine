import argparse
import urllib.parse
from rich.console import Console

# Import the main scanners registry
from scanners import *
import scanners

console = Console()

def run_all_modules_on_target(url):
    console.print(f"\n[bold magenta]=================================================[/bold magenta]")
    console.print(f"[bold magenta] 🚀 INITIATING DIRECT OMNI-SCAN FOR: {url} [/bold magenta]")
    console.print(f"[bold magenta]=================================================[/bold magenta]")
    console.print("[dim]Bypassing HackerOne scope checks. Firing all 48 modules directly...[/dim]\n")
    
    # Extract domain for things that only need a domain
    domain = urllib.parse.urlparse(url).netloc
    if not domain:
        domain = url
        url = f"https://{domain}"

    # 1. Bleeding Edge / AI Modules
    console.print("[bold yellow]\n[+] RUNNING BLEEDING-EDGE MODULES[/bold yellow]")
    try:
        scanners.check_llm_prompt_injection(url)
        scanners.check_nextjs_vulnerabilities(url)
        scanners.check_repo_jacking(url)
        scanners.check_403_bypass(url)
        scanners.check_cswsh(url)
        scanners.check_oauth_redirect_bypass(url)
        scanners.check_css_exfiltration(url)
        scanners.check_h2_cache_poisoning(url)
    except Exception as e:
        console.print(f"[red]Error in bleeding-edge modules: {e}[/red]")

    # 2. Advanced Vulnerability Modules
    console.print("[bold red]\n[+] RUNNING ADVANCED EXPLOIT MODULES[/bold red]")
    try:
        scanners.check_xss(url)
        scanners.check_ssrf(url)
        scanners.check_ssti(url)
        scanners.check_csrf(url)
        scanners.check_xxe(url)
        scanners.check_request_smuggling(url)
        scanners.check_cache_poisoning(url)
        scanners.check_command_injection(url)
    except Exception as e:
        console.print(f"[red]Error in advanced modules: {e}[/red]")
        
    # 3. Signal Farming Modules
    console.print("[bold magenta]\n[+] RUNNING SIGNAL FARMING MODULES[/bold magenta]")
    try:
        scanners.check_dmarc_spf(f"http://{domain}")
        scanners.check_clickjacking(url)
        scanners.check_security_headers(url)
    except Exception as e:
         console.print(f"[red]Error in signal farming modules: {e}[/red]")
         
    console.print("\n[bold green][+] DIRECT OMNI-SCAN COMPLETE![/bold green]")

def main():
    parser = argparse.ArgumentParser(description="Directly target a specific URL with all scanners.")
    parser.add_argument("target", help="The exact URL to scan (e.g., https://store.epicgames.com/)")
    args = parser.parse_args()
    
    target_url = args.target
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
        
    run_all_modules_on_target(target_url)

if __name__ == "__main__":
    main()
