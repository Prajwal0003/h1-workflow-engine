"""
Target Picker module — Interactive program selection with rich UI.
Provides filtering, sorting, and interactive selection of bug bounty targets.
"""

import json
from pathlib import Path

from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt, Confirm
from rich import box

from . import config
from .config import console
from . import programs
from . import scope as scope_module


def interactive_pick(program_list=None):
    """
    Interactive target picker with filters and selection.
    Returns the selected program dict.
    """
    console.print(Panel(
        "[bold]🎯 H1 Target Picker[/bold]\n"
        "Find and select your next bug bounty target",
        border_style="bright_cyan",
        padding=(1, 2)
    ))

    # Load programs if not provided
    if program_list is None:
        program_list = programs.load_cached_programs()
        if not program_list:
            console.print("[cyan]No cached programs. Fetching fresh data...[/cyan]")
            program_list = programs.fetch_programs()

    if not program_list:
        console.print("[red]✗ No programs available.[/red]")
        return None

    console.print(f"\n[dim]Total programs loaded: {len(program_list)}[/dim]")

    # Apply filters
    filtered = apply_interactive_filters(program_list)

    if not filtered:
        console.print("[red]✗ No programs match your filters.[/red]")
        return None

    # Display results
    displayed = programs.display_programs(filtered, limit=30)

    # Let user pick
    console.print()
    choice = IntPrompt.ask(
        "[bold cyan]Enter program number to select (0 to cancel)[/bold cyan]",
        default=0
    )

    if choice == 0 or choice > len(displayed):
        console.print("[dim]Cancelled.[/dim]")
        return None

    selected = displayed[choice - 1]
    handle = selected["handle"]

    console.print(f"\n[bold green]✓ Selected: {selected['name']} ({handle})[/bold green]")
    console.print(f"[dim]URL: {selected.get('url', 'N/A')}[/dim]")

    # Ask what to do next
    console.print("\n[bold]What would you like to do?[/bold]")
    console.print("  [cyan]1[/cyan] — Get scope (list in-scope assets)")
    console.print("  [cyan]2[/cyan] — Run recon (subdomain enum + probing)")
    console.print("  [cyan]3[/cyan] — View disclosed bugs")
    console.print("  [cyan]4[/cyan] — Full pipeline (scope → recon → scan)")
    console.print("  [cyan]0[/cyan] — Just save selection")

    action = IntPrompt.ask("[bold cyan]Action[/bold cyan]", default=1)

    save_selection(selected)

    return {"program": selected, "action": action}


def apply_interactive_filters(program_list):
    """Apply user-chosen filters interactively."""
    console.print("\n[bold]🔧 Filters[/bold]")

    # Keyword filter
    keyword = Prompt.ask(
        "  Search keyword (name/handle)",
        default=""
    )

    # Bounty only
    bounty_only = Confirm.ask(
        "  Show only paid bounty programs?",
        default=True
    )

    # Asset type
    console.print("  Asset types: [cyan]all, url, domain, wildcard, cidr, mobile[/cyan]")
    asset_type = Prompt.ask(
        "  Filter by asset type",
        default="all"
    )

    filtered = programs.search_programs(
        program_list,
        keyword=keyword if keyword else None,
        bounty_only=bounty_only,
        asset_type=asset_type if asset_type != "all" else None,
    )

    console.print(f"\n[green]✓ {len(filtered)} programs match your filters[/green]")
    return filtered


def quick_pick(program_list, keyword):
    """
    Non-interactive quick pick — search by keyword and return top results.
    Good for scripting and overnight runs.
    """
    filtered = programs.search_programs(
        program_list,
        keyword=keyword,
        bounty_only=True
    )

    if not filtered:
        console.print(f"[red]✗ No programs matching '{keyword}'[/red]")
        return None

    displayed = programs.display_programs(filtered, limit=10)
    return filtered


def save_selection(program):
    """Save a selected program to the selections file."""
    selections_file = config.DATA_DIR / "selections.json"

    selections = []
    if selections_file.exists():
        try:
            selections = json.loads(selections_file.read_text())
        except json.JSONDecodeError:
            selections = []

    # Add to selections (avoid duplicates by handle)
    handles = {s.get("handle") for s in selections}
    if program["handle"] not in handles:
        selections.append({
            "handle": program["handle"],
            "name": program["name"],
            "url": program.get("url", ""),
            "offers_bounties": program.get("offers_bounties", False),
            "selected_at": __import__("datetime").datetime.utcnow().isoformat(),
        })
        selections_file.write_text(json.dumps(selections, indent=2))
        console.print(f"[dim]💾 Saved selection: {program['handle']}[/dim]")


def show_dashboard():
    """Show a dashboard of all selected targets and their status."""
    selections_file = config.DATA_DIR / "selections.json"

    if not selections_file.exists():
        console.print("[yellow]No targets selected yet. Use 'pick' to select targets.[/yellow]")
        return

    selections = json.loads(selections_file.read_text())

    table = Table(
        title="[bold]📊 Bug Bounty Dashboard[/bold]",
        show_lines=True,
        border_style="bright_cyan",
        box=box.ROUNDED
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Handle", style="bold cyan", min_width=18)
    table.add_column("Name", style="white", min_width=22)
    table.add_column("Bounty", style="green", width=7)
    table.add_column("Scope", style="magenta", width=8)
    table.add_column("Recon", style="yellow", width=8)
    table.add_column("Selected", style="dim", width=12)

    for i, s in enumerate(selections, 1):
        handle = s["handle"]

        # Check if scope exists
        scope_file = config.TARGETS_DIR / f"{handle}.json"
        has_scope = "✓" if scope_file.exists() else "—"

        # Check if recon exists
        recon_file = config.RECON_DIR / f"{handle}_recon.json"
        has_recon = "✓" if recon_file.exists() else "—"

        bounty = "💰" if s.get("offers_bounties") else "—"
        selected_at = s.get("selected_at", "?")[:10]

        table.add_row(str(i), handle, s.get("name", "?"), bounty, has_scope, has_recon, selected_at)

    console.print(table)
