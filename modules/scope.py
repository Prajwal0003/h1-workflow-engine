"""
Scope module — Retrieve and parse structured scopes for HackerOne programs.
Extracts domains, wildcards, URLs, CIDRs, and mobile apps from target programs.
"""

import json
import time
from datetime import datetime
from pathlib import Path

import requests
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import config
from .config import console


def fetch_scope_api(handle):
    """Fetch structured scope from HackerOne API."""
    auth = config.get_auth()
    if not auth:
        return None

    url = f"{config.H1_PROGRAMS_URL}/{handle}/structured_scopes"
    all_scopes = []
    page = 1

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"Fetching scope for {handle}...", total=None)

        while True:
            try:
                resp = requests.get(
                    url,
                    auth=auth,
                    headers={"Accept": "application/json"},
                    params={"page[size]": 100, "page[number]": page},
                    timeout=30
                )

                if resp.status_code == 401:
                    console.print("[red]✗ Authentication failed.[/red]")
                    return None
                if resp.status_code == 404:
                    console.print(f"[red]✗ Program '{handle}' not found.[/red]")
                    return None
                if resp.status_code == 429:
                    console.print("[yellow]⚠ Rate limited. Waiting 60s...[/yellow]")
                    time.sleep(60)
                    continue
                resp.raise_for_status()

                data = resp.json()
                scopes = data.get("data", [])

                if not scopes:
                    break

                for s in scopes:
                    attrs = s.get("attributes", {})
                    all_scopes.append({
                        "asset_identifier": attrs.get("asset_identifier", ""),
                        "asset_type": attrs.get("asset_type", ""),
                        "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
                        "eligible_for_submission": attrs.get("eligible_for_submission", True),
                        "instruction": attrs.get("instruction", ""),
                        "max_severity": attrs.get("max_severity", ""),
                        "created_at": attrs.get("created_at", ""),
                        "updated_at": attrs.get("updated_at", ""),
                    })

                progress.update(task, description=f"Fetching scope... page {page} ({len(all_scopes)} assets)")
                page += 1
                time.sleep(config.API_DELAY)

            except requests.exceptions.RequestException as e:
                console.print(f"[red]✗ API error: {e}[/red]")
                break

    return all_scopes


def fetch_scope_public(handle, programs_cache=None):
    """Extract scope from cached public data."""
    if programs_cache is None:
        # Load from cache file
        if not config.CACHE_FILE.exists():
            console.print("[yellow]⚠ No cached data. Run 'search' first.[/yellow]")
            return None
        try:
            cache = json.loads(config.CACHE_FILE.read_text())
            programs_cache = cache.get("programs", [])
        except (json.JSONDecodeError, KeyError):
            return None

    for p in programs_cache:
        if p.get("handle", "").lower() == handle.lower():
            return p.get("in_scope", [])

    console.print(f"[yellow]⚠ Program '{handle}' not found in cache.[/yellow]")
    return None


def get_scope(handle):
    """
    Get scope for a program. Tries API first, falls back to public data.
    Saves results to disk.
    """
    console.print(f"\n[bold]🔍 Getting scope for: [cyan]{handle}[/cyan][/bold]\n")

    scopes = None

    # Try API first
    if config.has_api_credentials():
        scopes = fetch_scope_api(handle)
        if scopes:
            console.print(f"[green]✓ Got {len(scopes)} scope items from API[/green]")

    # Fallback to public data
    if scopes is None:
        console.print("[dim]Trying public data...[/dim]")
        scopes = fetch_scope_public(handle)
        if scopes:
            console.print(f"[green]✓ Got {len(scopes)} scope items from public data[/green]")

    if not scopes:
        console.print(f"[red]✗ Could not find scope for '{handle}'[/red]")
        return None

    # Categorize and save
    scope_data = categorize_scope(scopes)
    save_scope(handle, scope_data)
    display_scope(handle, scope_data)

    return scope_data


def categorize_scope(scopes):
    """Categorize scope items by asset type."""
    categories = {
        "domains": [],
        "wildcards": [],
        "urls": [],
        "cidrs": [],
        "mobile": [],
        "other": [],
        "all": scopes,
    }

    for s in scopes:
        asset = s.get("asset_identifier", "")
        asset_type = s.get("asset_type", "").upper()

        if asset_type in ("URL", "DOMAIN"):
            if asset.startswith("*."):
                categories["wildcards"].append(s)
            else:
                categories["domains"].append(s)
        elif asset_type == "WILDCARD":
            categories["wildcards"].append(s)
        elif asset_type == "CIDR":
            categories["cidrs"].append(s)
        elif asset_type in ("GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID",
                            "OTHER_IPA", "OTHER_APK", "TESTFLIGHT"):
            categories["mobile"].append(s)
        elif "://" in asset:
            categories["urls"].append(s)
        else:
            # Try to detect type from the identifier
            if asset.startswith("*."):
                categories["wildcards"].append(s)
            elif "/" in asset and "." in asset:
                categories["urls"].append(s)
            elif "." in asset:
                categories["domains"].append(s)
            else:
                categories["other"].append(s)

    return categories


def save_scope(handle, scope_data):
    """Save scope data to disk."""
    output = {
        "handle": handle,
        "fetched_at": datetime.utcnow().isoformat(),
        "summary": {k: len(v) for k, v in scope_data.items() if k != "all"},
        "total": len(scope_data.get("all", [])),
        "scope": scope_data
    }

    filepath = config.TARGETS_DIR / f"{handle}.json"
    filepath.write_text(json.dumps(output, indent=2, default=str))
    console.print(f"[dim]💾 Saved to {filepath}[/dim]")


def display_scope(handle, scope_data):
    """Display scope in a rich table."""
    # Summary panel
    summary_parts = []
    for category, items in scope_data.items():
        if category == "all":
            continue
        if items:
            summary_parts.append(f"  [bold]{category.upper()}[/bold]: {len(items)}")

    summary_text = "\n".join(summary_parts) if summary_parts else "  No scope data"
    console.print(Panel(summary_text, title=f"[bold cyan]📋 Scope Summary — {handle}[/bold cyan]",
                        border_style="cyan"))

    # Detailed table
    table = Table(
        title=f"[bold]🎯 In-Scope Assets for {handle}[/bold]",
        show_lines=False,
        border_style="bright_cyan"
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Asset", style="bold white", min_width=35)
    table.add_column("Type", style="cyan", width=12)
    table.add_column("Bounty", style="green", width=7)
    table.add_column("Severity", style="yellow", width=10)

    for i, s in enumerate(scope_data.get("all", []), 1):
        asset = s.get("asset_identifier", "?")
        asset_type = s.get("asset_type", "?")
        bounty = "💰" if s.get("eligible_for_bounty") else "—"
        severity = s.get("max_severity", "—") or "—"

        if len(asset) > 45:
            asset = asset[:42] + "..."

        table.add_row(str(i), asset, asset_type, bounty, severity)

    console.print(table)


def extract_domains(handle):
    """
    Extract all unique domains/wildcards from a saved target scope.
    Returns a flat list of domain strings suitable for recon tools.
    """
    filepath = config.TARGETS_DIR / f"{handle}.json"
    if not filepath.exists():
        console.print(f"[yellow]⚠ No scope data for '{handle}'. Run 'scope {handle}' first.[/yellow]")
        return []

    data = json.loads(filepath.read_text())
    scope = data.get("scope", {})

    domains = set()

    for category in ["domains", "wildcards", "urls"]:
        for item in scope.get(category, []):
            asset = item.get("asset_identifier", "")
            # Clean up the domain
            asset = asset.strip()
            if asset.startswith("http://"):
                asset = asset[7:]
            if asset.startswith("https://"):
                asset = asset[8:]
            if "/" in asset:
                asset = asset.split("/")[0]
            if ":" in asset:
                asset = asset.split(":")[0]
            if asset:
                domains.add(asset)

    return sorted(domains)
