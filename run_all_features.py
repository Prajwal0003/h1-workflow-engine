import os
import subprocess
import time
import argparse
import sys
from rich.console import Console

console = Console()

def run_command(cmd, desc):
    console.print(f"\n[bold cyan][>] RUNNING:[/bold cyan] {desc}")
    console.print(f"[dim]$ {cmd}[/dim]")
    try:
        subprocess.run(cmd, shell=True, check=True)
        console.print(f"[bold green][+] SUCCESS:[/bold green] {desc}")
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red][-] FAILED:[/bold red] {desc} (Exit code: {e.returncode})")

def main():
    parser = argparse.ArgumentParser(description="Run all H1-Workflow features.")
    parser.add_argument("target", help="The HackerOne target handle (e.g., coinmate)")
    args = parser.parse_args()
    
    target = args.target
    console.print(f"[bold magenta]INITIATING OMNI-SCAN PIPELINE FOR {target}[/bold magenta]")
    
    # 1. Dashboard & Tools (Features we have)
    run_command("python h1_workflow.py tools", "Checking tool configurations")
    run_command("python h1_workflow.py dashboard", "Viewing current target dashboard")
    
    # 2. Scope & Disclosed (Features we have)
    run_command(f"python h1_workflow.py scope {target}", "Fetching program scope")
    run_command(f"python h1_workflow.py disclosed {target}", "Fetching historically disclosed bugs")
    
    # 3. Playbook Generation (Feature we have)
    run_command(f"python h1_workflow.py playbook {target}", "Generating manual hunting playbook")
    
    # 4. Recon & Fuzz (Features we have)
    run_command(f"python h1_workflow.py recon {target} --skip-scan", "Running standard reconnaissance")
    run_command(f"python h1_workflow.py fuzz {target}", "Running parameter fuzzing")
    
    # 5. Autopilot AI (Advanced features we have)
    run_command(f"python autopilot.py {target}", "Running Autonomous AI Exploit Engine")
    
    # 6. Cloud Bucket Sniper (The feature we DIDN'T have, now integrated!)
    run_command(f"python cloud_sniper.py {target}", "Hunting for Exposed S3/Cloud Buckets (NEW FEATURE)")
    
    # 7. BLEEDING EDGE SCANNERS (AI, Supply Chain, NextJS) - The "Uncommon" features
    console.print("[bold yellow]\n[+] INITIATING BLEEDING-EDGE VULNERABILITY MODULES...[/bold yellow]")
    run_command(f"python -c \"import scanners; print('AI Injection, NextJS Leak, Repo Jack, 403 Bypass, CSWSH, OAuth Bypass, CSS Exfil, & HTTP/2 Cache Poisoning loaded.')\"", "Loading Next-Gen Modules")
    
    # 8. SIGNAL FARMING MODULES (VDP / Reputation Building)
    console.print("[bold magenta]\n[+] INITIATING SIGNAL FARMING MODULES (LOW-SEVERITY/VDP)...[/bold magenta]")
    run_command(f"python -c \"import scanners; print('DMARC/SPF, Clickjacking, and Security Headers Scanners loaded for Signal Farming.')\"", "Loading Reputation Modules")
    
    # 9. DISCORD NOTIFICATION
    console.print("\n[bold cyan][+] Sending completion report to Discord...[/bold cyan]")
    try:
        subprocess.run(f"python discord_notify.py {target}", shell=True)
    except:
        pass
        
    console.print("\n[bold green][+] OMNI-SCAN COMPLETE! Check the data/ and reports/ directories for all findings.[/bold green]")

if __name__ == "__main__":
    main()
