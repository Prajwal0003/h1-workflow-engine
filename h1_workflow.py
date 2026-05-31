#!/usr/bin/env python3
"""
h1_workflow.py — HackerOne Bug Bounty Workflow CLI

Commands:
  search    Search and list HackerOne programs
  pick      Interactive target picker
  scope     Get structured scope for a program
  disclosed View publicly disclosed bug reports
  recon     Run full reconnaissance pipeline
  dashboard Show your targets and progress
  tools     Check available recon tools

Usage:
  python h1_workflow.py search [--keyword KEYWORD] [--bounty-only] [--refresh]
  python h1_workflow.py pick
  python h1_workflow.py scope <handle>
  python h1_workflow.py disclosed [handle] [--limit N]
  python h1_workflow.py recon <handle> [--skip-scan]
  python h1_workflow.py pipeline <handle>   # scope → recon → disclosed (overnight mode)
  python h1_workflow.py dashboard
  python h1_workflow.py tools
"""

import sys
import os
import argparse
from rich.console import Console
from rich.panel import Panel

# Fix Windows console encoding
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(force_terminal=True)

BANNER = """
[bold cyan]
  _   _ _  __        __         _    __ _
 | | | / | \\ \\      / /__  _ __| | _/ _| | _____      __
 | |_| | |  \\ \\ /\\ / / _ \\| '__| |/ / |_| |/ _ \\ \\ /\\ / /
 |  _  | |   \\ V  V / (_) | |  |   <|  _|  | (_) \\ V  V /
 |_| |_|_|    \\_/\\_/ \\___/|_|  |_|\\_\\_| |_|\\___/ \\_/\\_/
[/bold cyan]
[dim]  Bug Bounty Workflow Engine - HackerOne Edition[/dim]
"""


def cmd_search(args):
    """Search and list programs."""
    from modules import programs

    # Load from cache or fetch fresh
    if args.refresh:
        program_list = programs.fetch_programs(use_api=True, use_public=True)
    else:
        program_list = programs.load_cached_programs()
        if not program_list:
            program_list = programs.fetch_programs(use_api=True, use_public=True)

    # Apply filters
    filtered = programs.search_programs(
        program_list,
        keyword=args.keyword,
        bounty_only=args.bounty_only,
        asset_type=args.asset_type,
    )

    # Display
    programs.display_programs(filtered, limit=args.limit)


def cmd_pick(args):
    """Interactive target picker."""
    from modules import targets, scope as scope_module, recon, disclosed

    result = targets.interactive_pick()

    if result and result.get("action"):
        handle = result["program"]["handle"]
        action = result["action"]

        if action == 1:
            scope_module.get_scope(handle)
        elif action == 2:
            scope_module.get_scope(handle)
            recon.full_recon(handle, skip_scan=True)
        elif action == 3:
            disclosed.get_disclosed_bugs(handle)
        elif action == 4:
            cmd_pipeline_run(handle, skip_scan=False)


def cmd_scope(args):
    """Get scope for a program."""
    from modules import scope as scope_module
    scope_module.get_scope(args.handle)


def cmd_disclosed(args):
    """View disclosed bugs."""
    from modules import disclosed
    disclosed.get_disclosed_bugs(
        handle=args.handle if args.handle else None,
        limit=args.limit
    )


def cmd_recon(args):
    """Run recon pipeline."""
    from modules import recon
    recon.full_recon(args.handle, skip_scan=args.skip_scan)


def cmd_pipeline(args):
    """Full pipeline: scope → recon → disclosed (overnight mode)."""
    cmd_pipeline_run(args.handle, skip_scan=args.skip_scan, mode=args.mode, local_dir=args.local_dir)


def cmd_pipeline_run(handle, skip_scan=False, mode="h1", local_dir=None):
    """Execute the full pipeline for a handle."""
    from modules import scope as scope_module, recon, disclosed, mantis_bridge
    import time

    start = time.time()
    console.print(Panel(
        f"[bold]🚀 FULL PIPELINE — {handle}[/bold]\n"
        f"[dim]Mode: {mode.upper()}[/dim]",
        border_style="bright_green",
        padding=(1, 2)
    ))
    
    if mode in ["h1", "both"]:
        # Step 1: Scope
        console.print("\n" + "=" * 60)
        console.print("[bold cyan]PHASE 1: SCOPE RETRIEVAL[/bold cyan]")
        console.print("=" * 60)
        scope_module.get_scope(handle)
    
        # Step 2: Full recon
        console.print("\n" + "=" * 60)
        console.print("[bold cyan]PHASE 2: RECONNAISSANCE[/bold cyan]")
        console.print("=" * 60)
        recon.full_recon(handle, skip_scan=skip_scan)
    
        # Step 3: Disclosed bugs
        console.print("\n" + "=" * 60)
        console.print("[bold cyan]PHASE 3: DISCLOSED BUGS[/bold cyan]")
        console.print("=" * 60)
        disclosed.get_disclosed_bugs(handle, limit=50)
        
    if mode in ["mantis", "both"]:
        if not local_dir:
            console.print("\n[red]✗ Local directory required for mantis mode. Use --local-dir[/red]")
        else:
            console.print("\n" + "=" * 60)
            console.print("[bold cyan]PHASE: MANTISHACK SAST[/bold cyan]")
            console.print("=" * 60)
            mantis_bridge.run_mantis_scan(local_dir)

    elapsed = time.time() - start
    elapsed_str = f"{int(elapsed // 3600)}h {int((elapsed % 3600) // 60)}m {int(elapsed % 60)}s"

    console.print(Panel(
        f"[bold green]✅ PIPELINE COMPLETE — {handle}[/bold green]\n\n"
        f"  ⏱  Total time: {elapsed_str}\n"
        f"  📁 All results saved to: data/\n\n"
        f"  [dim]Next steps:[/dim]\n"
        f"  [dim]  1. Review findings in data/recon/{handle}_nuclei.json[/dim]\n"
        f"  [dim]  2. Study disclosed bugs in data/disclosed_{handle}.json[/dim]\n"
        f"  [dim]  3. Start manual testing on live hosts[/dim]",
        border_style="green",
        padding=(1, 2)
    ))


def cmd_dashboard(args):
    """Show the dashboard."""
    from modules import targets
    targets.show_dashboard()


def cmd_fuzz(args):
    """Run parameter fuzzing."""
    import json
    from pathlib import Path
    from modules import fuzz, config

    # Try to load httpx results to get URLs
    probe_file = config.RECON_DIR / f"{args.handle}_httpx.json"
    if not probe_file.exists():
        console.print(f"[red]✗ No httpx results found for {args.handle}. Run recon first.[/red]")
        return
        
    try:
        hosts = json.loads(probe_file.read_text())
        fuzz.discover_vulnerabilities(hosts, args.handle)
    except Exception as e:
        console.print(f"[red]✗ Failed to parse hosts: {e}[/red]")


def cmd_playbook(args):
    """Generate manual hunting playbook."""
    import json
    from modules import playbook, config
    
    # Try to extract tech stack from httpx results
    tech_stack = set()
    probe_file = config.RECON_DIR / f"{args.handle}_httpx.json"
    if probe_file.exists():
        try:
            hosts = json.loads(probe_file.read_text())
            for h in hosts:
                if "tech" in h and h["tech"]:
                    tech_stack.update(h["tech"])
        except Exception:
            pass
            
    playbook.generate_playbook(args.handle, list(tech_stack))


def cmd_mantis(args):
    """Run mantishack SAST scan."""
    from modules import mantis_bridge
    mantis_bridge.run_mantis_scan(args.target_dir)


def cmd_tools(args):
    """Check available recon tools."""
    from modules import recon, config

    recon.check_recon_tools()

    console.print("\n[bold]API Configuration:[/bold]")
    if config.has_api_credentials():
        console.print(f"  [green]✓ HackerOne API: Configured (user: {config.H1_API_USERNAME})[/green]")
    else:
        console.print("  [red]✗ HackerOne API: Not configured[/red]")
        console.print("  [dim]Copy .env.example to .env and add your credentials[/dim]")


def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        description="H1 Workflow — HackerOne Bug Bounty Workflow Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # search
    p_search = subparsers.add_parser("search", help="Search and list programs")
    p_search.add_argument("--keyword", "-k", help="Search keyword (name/handle)")
    p_search.add_argument("--bounty-only", "-b", action="store_true", help="Only paid bounty programs")
    p_search.add_argument("--asset-type", "-a", default="all", help="Filter by asset type")
    p_search.add_argument("--limit", "-l", type=int, default=30, help="Max results to display")
    p_search.add_argument("--refresh", "-r", action="store_true", help="Force refresh from API")

    # pick
    p_pick = subparsers.add_parser("pick", help="Interactive target picker")

    # scope
    p_scope = subparsers.add_parser("scope", help="Get scope for a program")
    p_scope.add_argument("handle", help="Program handle (e.g., 'security')")

    # disclosed
    p_disclosed = subparsers.add_parser("disclosed", help="View disclosed bug reports")
    p_disclosed.add_argument("handle", nargs="?", help="Program handle (optional)")
    p_disclosed.add_argument("--limit", "-l", type=int, default=25, help="Max reports to show")

    # recon
    p_recon = subparsers.add_parser("recon", help="Run reconnaissance pipeline")
    p_recon.add_argument("handle", help="Program handle")
    p_recon.add_argument("--skip-scan", action="store_true", help="Skip nuclei vulnerability scan")

    # fuzz
    p_fuzz = subparsers.add_parser("fuzz", help="Run parameter fuzzing")
    p_fuzz.add_argument("handle", help="Program handle")

    # playbook
    p_playbook = subparsers.add_parser("playbook", help="Generate custom hunting playbook")
    p_playbook.add_argument("handle", help="Program handle")
    
    # mantis
    p_mantis = subparsers.add_parser("mantis", help="Run Mantishack SAST scan")
    p_mantis.add_argument("target_dir", help="Local directory to scan")

    # pipeline
    p_pipeline = subparsers.add_parser("pipeline", help="Full pipeline execution")
    p_pipeline.add_argument("handle", help="Program handle")
    p_pipeline.add_argument("--skip-scan", action="store_true", help="Skip nuclei vulnerability scan")
    p_pipeline.add_argument("--mode", choices=["h1", "mantis", "both"], default="h1", help="Execution mode (default: h1)")
    p_pipeline.add_argument("--local-dir", help="Local directory to scan (required for mantis/both mode)")

    # dashboard
    p_dashboard = subparsers.add_parser("dashboard", help="Show targets dashboard")

    # tools
    p_tools = subparsers.add_parser("tools", help="Check available recon tools")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        console.print("\n[bold cyan]Quick start:[/bold cyan]")
        console.print("  1. [cyan]python h1_workflow.py search --bounty-only[/cyan]  — Find paid programs")
        console.print("  2. [cyan]python h1_workflow.py pick[/cyan]                  — Pick a target interactively")
        console.print("  3. [cyan]python h1_workflow.py pipeline <handle>[/cyan]     — Run full overnight pipeline")
        return

    commands = {
        "search": cmd_search,
        "pick": cmd_pick,
        "scope": cmd_scope,
        "disclosed": cmd_disclosed,
        "recon": cmd_recon,
        "fuzz": cmd_fuzz,
        "playbook": cmd_playbook,
        "mantis": cmd_mantis,
        "pipeline": cmd_pipeline,
        "dashboard": cmd_dashboard,
        "tools": cmd_tools,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
