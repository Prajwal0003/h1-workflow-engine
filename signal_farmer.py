import argparse
import sys
from rich.console import Console
from scanners.dmarc_spf_scanner import check_dmarc_spf
from scanners.clickjacking import check_clickjacking
from scanners.security_headers import check_security_headers
import urllib.parse

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Signal Farming Scanner for VDPs.")
    parser.add_argument("target", help="The target URL or domain to scan (e.g., https://example.com or example.com)")
    args = parser.parse_args()
    
    target = args.target
    if not target.startswith("http"):
        domain = target
        url = f"https://{target}"
    else:
        url = target
        domain = urllib.parse.urlparse(url).netloc
        
    console.print(f"\n[bold magenta]=================================================[/bold magenta]")
    console.print(f"[bold magenta] 🚀 INITIATING VDP SIGNAL FARMING FOR: {domain} [/bold magenta]")
    console.print(f"[bold magenta]=================================================[/bold magenta]")
    console.print("[dim]Targeting low-severity bugs to boost HackerOne Reputation...[/dim]\n")
    
    # 1. DMARC/SPF Check (Needs just the domain structure)
    check_dmarc_spf(f"http://{domain}")
    print("\n")
    
    # 2. Clickjacking Check (Needs full URL)
    check_clickjacking(url)
    print("\n")
    
    # 3. Security Headers Check (Needs full URL)
    check_security_headers(url)
    print("\n")
    
    console.print("[bold green][+] SIGNAL FARMING COMPLETE! Check output for farmable reports.[/bold green]\n")

if __name__ == "__main__":
    main()
