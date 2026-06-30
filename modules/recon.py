"""
Recon module — Automated reconnaissance pipeline for bug bounty targets.
Orchestrates: subdomain enumeration → HTTP probing → vulnerability scanning.
Can run overnight unattended.
"""

import json
import subprocess
import time
import shutil
from datetime import datetime
from pathlib import Path

from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from . import config
from .config import console
from . import scope as scope_module


def run_tool(cmd, input_data=None, timeout=600):
    """Run an external tool and capture output."""
    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=True
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "returncode": -1, "success": False}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "Tool not found", "returncode": -1, "success": False}


def check_recon_tools():
    """Check which recon tools are available and report status."""
    tools = config.get_available_tools()

    table = Table(title="[bold]🔧 Recon Tools Status[/bold]", border_style="cyan")
    table.add_column("Tool", style="bold white")
    table.add_column("Status", width=10)
    table.add_column("Purpose", style="dim")

    tool_info = {
        "subfinder": "Subdomain enumeration",
        "httpx": "HTTP probing & technology detection",
        "nuclei": "Vulnerability scanning with templates",
    }

    for tool, available in tools.items():
        status = "[green]✓ Found[/green]" if available else "[red]✗ Missing[/red]"
        purpose = tool_info.get(tool, "")
        table.add_row(tool, status, purpose)

    console.print(table)

    missing = [t for t, a in tools.items() if not a]
    if missing:
        console.print(f"\n[yellow]⚠ Missing tools: {', '.join(missing)}[/yellow]")
        console.print("[dim]Install with: go install -v github.com/projectdiscovery/<tool>/v2/cmd/<tool>@latest[/dim]")
        console.print("[dim]Or: pip install <tool> (for Python-based tools)[/dim]")

    return tools


def subdomain_enum(domains, handle, timeout=300):
    """Run subdomain enumeration using subfinder."""
    if not shutil.which(config.SUBFINDER_PATH):
        console.print("[yellow]⚠ subfinder not found. Skipping subdomain enumeration.[/yellow]")
        console.print("[dim]Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest[/dim]")
        return []

    console.print(f"\n[bold cyan]🔍 Subdomain Enumeration ({len(domains)} root domains)[/bold cyan]")

    all_subdomains = set()
    domain_input = "\n".join(domains)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running subfinder...", total=None)

        result = run_tool(
            f"{config.SUBFINDER_PATH} -silent -all",
            input_data=domain_input,
            timeout=timeout
        )

        if result["success"] and result["stdout"]:
            subs = result["stdout"].strip().split("\n")
            all_subdomains.update(s.strip() for s in subs if s.strip())
            progress.update(task, description=f"Found {len(all_subdomains)} subdomains")
        else:
            console.print(f"[yellow]⚠ subfinder: {result.get('stderr', 'no output')}[/yellow]")

    console.print(f"[green]✓ Found {len(all_subdomains)} unique subdomains[/green]")

    # Save subdomains
    sub_file = config.RECON_DIR / f"{handle}_subdomains.txt"
    sub_file.write_text("\n".join(sorted(all_subdomains)))
    console.print(f"[dim]💾 Saved to {sub_file}[/dim]")

    return sorted(all_subdomains)


def http_probe(targets, handle, timeout=300):
    """Run HTTP probing using httpx to find live hosts."""
    if not shutil.which(config.HTTPX_PATH):
        console.print("[yellow]⚠ httpx not found. Skipping HTTP probing.[/yellow]")
        console.print("[dim]Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest[/dim]")
        return []

    console.print(f"\n[bold cyan]🌐 HTTP Probing ({len(targets)} targets)[/bold cyan]")

    target_input = "\n".join(targets)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running httpx...", total=None)

        result = run_tool(
            f"{config.HTTPX_PATH} -silent -status-code -title -tech-detect -json",
            input_data=target_input,
            timeout=timeout
        )

        live_hosts = []
        if result["success"] and result["stdout"]:
            for line in result["stdout"].strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    host_data = json.loads(line)
                    live_hosts.append({
                        "url": host_data.get("url", ""),
                        "status_code": host_data.get("status_code", 0),
                        "title": host_data.get("title", ""),
                        "tech": host_data.get("tech", []),
                        "content_length": host_data.get("content_length", 0),
                        "webserver": host_data.get("webserver", ""),
                    })
                except json.JSONDecodeError:
                    # Plain text output (URL only)
                    if line.startswith("http"):
                        live_hosts.append({"url": line, "status_code": 0, "title": "", "tech": []})

            progress.update(task, description=f"Found {len(live_hosts)} live hosts")
        else:
            console.print(f"[yellow]⚠ httpx: {result.get('stderr', 'no output')}[/yellow]")

    console.print(f"[green]✓ Found {len(live_hosts)} live hosts[/green]")

    # Save results
    probe_file = config.RECON_DIR / f"{handle}_httpx.json"
    probe_file.write_text(json.dumps(live_hosts, indent=2))
    console.print(f"[dim]💾 Saved to {probe_file}[/dim]")

    # Display table
    if live_hosts:
        table = Table(title=f"[bold]🌐 Live Hosts — {handle}[/bold]", border_style="green", show_lines=False)
        table.add_column("#", style="dim", width=4)
        table.add_column("URL", style="bold cyan", min_width=35)
        table.add_column("Status", style="yellow", width=7)
        table.add_column("Title", style="white", width=25)
        table.add_column("Tech", style="magenta", width=20)

        for i, h in enumerate(live_hosts[:50], 1):
            url = h["url"]
            if len(url) > 45:
                url = url[:42] + "..."
            title = h.get("title", "")[:25]
            tech = ", ".join(h.get("tech", [])[:3]) if h.get("tech") else "—"
            status = str(h.get("status_code", "?"))

            table.add_row(str(i), url, status, title, tech)

        console.print(table)

    return live_hosts


def vuln_scan(targets, handle, timeout=900):
    """Run vulnerability scanning using nuclei with default templates."""
    if not shutil.which(config.NUCLEI_PATH):
        console.print("[yellow]⚠ nuclei not found. Skipping vulnerability scanning.[/yellow]")
        console.print("[dim]Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/dim]")
        return []

    # Use live URLs from httpx results if available
    urls = []
    for t in targets:
        if isinstance(t, dict):
            urls.append(t.get("url", ""))
        else:
            urls.append(t)
    urls = [u for u in urls if u]

    console.print(f"\n[bold cyan]🔬 Vulnerability Scanning ({len(urls)} targets)[/bold cyan]")
    console.print("[dim]Using nuclei with default templates (severity: low,medium,high,critical)[/dim]")

    target_input = "\n".join(urls)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running nuclei (this may take a while)...", total=None)

        result = run_tool(
            f"{config.NUCLEI_PATH} -silent -severity low,medium,high,critical -json",
            input_data=target_input,
            timeout=timeout
        )

        findings = []
        if result["success"] and result["stdout"]:
            for line in result["stdout"].strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template_id": finding.get("template-id", ""),
                        "name": finding.get("info", {}).get("name", ""),
                        "severity": finding.get("info", {}).get("severity", ""),
                        "host": finding.get("host", ""),
                        "matched_url": finding.get("matched-at", ""),
                        "type": finding.get("type", ""),
                        "description": finding.get("info", {}).get("description", ""),
                        "tags": finding.get("info", {}).get("tags", []),
                    })
                except json.JSONDecodeError:
                    pass

            progress.update(task, description=f"Found {len(findings)} potential vulnerabilities")

    console.print(f"[green]✓ Scan complete: {len(findings)} findings[/green]")

    # Save results
    scan_file = config.RECON_DIR / f"{handle}_nuclei.json"
    scan_file.write_text(json.dumps(findings, indent=2))
    console.print(f"[dim]💾 Saved to {scan_file}[/dim]")

    # Display findings
    if findings:
        table = Table(
            title=f"[bold]🔬 Vulnerability Findings — {handle}[/bold]",
            border_style="red",
            show_lines=True
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Template", style="bold white", min_width=20)
        table.add_column("Severity", width=10)
        table.add_column("Host", style="cyan", min_width=25)
        table.add_column("Type", style="dim", width=8)

        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for i, f in enumerate(findings[:50], 1):
            severity = f.get("severity", "?")
            sev_color = severity_colors.get(severity.lower(), "white")
            host = f.get("matched_url", f.get("host", "?"))
            if len(host) > 35:
                host = host[:32] + "..."

            table.add_row(
                str(i),
                f.get("name", f.get("template_id", "?")),
                f"[{sev_color}]{severity.upper()}[/{sev_color}]",
                host,
                f.get("type", "?")
            )

        console.print(table)

    return findings


def full_recon(handle, skip_scan=False):
    """
    Run the full recon pipeline for a target:
    1. Extract domains from scope
    2. Subdomain enumeration (subfinder)
    3. HTTP probing (httpx)
    4. Vulnerability scanning (nuclei) — optional

    Designed to run overnight unattended.
    """
    start_time = time.time()

    console.print(Panel(
        f"[bold]🚀 Full Recon Pipeline — {handle}[/bold]\n"
        f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        border_style="bright_cyan",
        padding=(1, 2)
    ))

    # Step 1: Check tools
    console.print("\n[bold]=== Step 0: Tool Check ===[/bold]")
    tools = check_recon_tools()

    # Step 2: Get scope / extract domains
    console.print("\n[bold]=== Step 1: Scope & Domain Extraction ===[/bold]")
    domains = scope_module.extract_domains(handle)

    if not domains:
        # Try fetching scope first
        scope_data = scope_module.get_scope(handle)
        if scope_data:
            domains = scope_module.extract_domains(handle)

    if not domains:
        console.print("[red]✗ No domains found. Cannot proceed with recon.[/red]")
        return None

    console.print(f"[green]✓ {len(domains)} root domains/wildcards extracted[/green]")
    for d in domains[:10]:
        console.print(f"  [dim]• {d}[/dim]")
    if len(domains) > 10:
        console.print(f"  [dim]... and {len(domains) - 10} more[/dim]")

    # Step 3: Subdomain enumeration
    console.print("\n[bold]=== Step 2: Subdomain Enumeration ===[/bold]")
    subdomains = subdomain_enum(domains, handle, timeout=600)

    # Combine root domains + discovered subdomains
    all_targets = sorted(set(domains) | set(subdomains))
    console.print(f"[green]✓ {len(all_targets)} total unique targets[/green]")

    # Step 4: HTTP probing
    console.print("\n[bold]=== Step 3: HTTP Probing ===[/bold]")
    live_hosts = http_probe(all_targets, handle, timeout=600)

    # Step 5: Vulnerability scanning
    if not skip_scan and live_hosts:
        console.print("\n[bold]=== Step 4: Vulnerability Scanning ===[/bold]")
        findings = vuln_scan(live_hosts, handle, timeout=1800)
    else:
        findings = []
        if skip_scan:
            console.print("\n[dim]Skipping vulnerability scan (--skip-scan)[/dim]")
        elif not live_hosts:
            console.print("\n[dim]No live hosts to scan.[/dim]")

    # Save combined results
    elapsed = time.time() - start_time
    recon_summary = {
        "handle": handle,
        "started_at": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed),
        "domains": len(domains),
        "subdomains": len(subdomains),
        "total_targets": len(all_targets),
        "live_hosts": len(live_hosts),
        "findings": len(findings),
        "tools_used": {k: v for k, v in tools.items()},
    }

    summary_file = config.RECON_DIR / f"{handle}_recon.json"
    summary_file.write_text(json.dumps(recon_summary, indent=2))

    # Final summary
    elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"
    console.print(Panel(
        f"[bold green]✓ Recon Complete — {handle}[/bold green]\n\n"
        f"  ⏱  Duration:       {elapsed_str}\n"
        f"  🌐 Root domains:   {len(domains)}\n"
        f"  🔍 Subdomains:     {len(subdomains)}\n"
        f"  ✅ Live hosts:     {len(live_hosts)}\n"
        f"  🔬 Findings:       {len(findings)}\n\n"
        f"  📁 Results saved to: {config.RECON_DIR / handle}_*",
        border_style="green",
        padding=(1, 2)
    ))

    return recon_summary
