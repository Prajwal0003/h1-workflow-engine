"""
Programs module — Search, list, and filter HackerOne bug bounty programs.
Uses the HackerOne API (if credentials available) + public bounty-targets-data as fallback.
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import config
from .config import console


def fetch_programs_api(max_pages=50):
    """Fetch programs from HackerOne API with pagination."""
    auth = config.get_auth()
    if not auth:
        console.print("[yellow]⚠ No API credentials found. Use 'public' mode.[/yellow]")
        return None

    all_programs = []
    page = 1

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Fetching programs from HackerOne API...", total=None)

        while page <= max_pages:
            try:
                resp = requests.get(
                    config.H1_PROGRAMS_URL,
                    auth=auth,
                    headers={"Accept": "application/json"},
                    params={"page[size]": 100, "page[number]": page},
                    timeout=30
                )

                if resp.status_code == 401:
                    console.print("[red]✗ Authentication failed. Check your API credentials.[/red]")
                    return None
                if resp.status_code == 429:
                    console.print("[yellow]⚠ Rate limited. Waiting 60s...[/yellow]")
                    time.sleep(60)
                    continue
                resp.raise_for_status()

                data = resp.json()
                programs = data.get("data", [])

                if not programs:
                    break

                for p in programs:
                    attrs = p.get("attributes", {})
                    all_programs.append({
                        "id": p.get("id"),
                        "handle": attrs.get("handle", ""),
                        "name": attrs.get("name", ""),
                        "url": f"https://hackerone.com/{attrs.get('handle', '')}",
                        "offers_bounties": attrs.get("offers_bounties", False),
                        "submission_state": attrs.get("submission_state", ""),
                        "state": attrs.get("state", ""),
                        "started_accepting_at": attrs.get("started_accepting_at", ""),
                        "bookmarked": attrs.get("bookmarked", False),
                        "allows_bounty_splitting": attrs.get("allows_bounty_splitting", False),
                        "source": "api"
                    })

                progress.update(task, description=f"Fetching programs... page {page} ({len(all_programs)} found)")
                page += 1
                time.sleep(config.API_DELAY)

            except requests.exceptions.RequestException as e:
                console.print(f"[red]✗ API error on page {page}: {e}[/red]")
                break

    return all_programs


def fetch_programs_public():
    """Fetch programs from public bounty-targets-data repository."""
    console.print("[cyan]⟳ Fetching programs from public bounty-targets-data...[/cyan]")

    try:
        resp = requests.get(config.BOUNTY_TARGETS_URL, timeout=60)
        resp.raise_for_status()
        raw_programs = resp.json()

        programs = []
        for p in raw_programs:
            targets = p.get("targets", {})
            in_scope = targets.get("in_scope", [])

            programs.append({
                "id": None,
                "handle": p.get("handle", ""),
                "name": p.get("name", ""),
                "url": p.get("url", ""),
                "offers_bounties": p.get("offers_bounties", False),
                "submission_state": p.get("submission_state", "open"),
                "state": "public_mode",
                "started_accepting_at": None,
                "bookmarked": False,
                "allows_bounty_splitting": False,
                "source": "public",
                "in_scope_count": len(in_scope),
                "in_scope": in_scope,
                "managed": p.get("managed", False),
            })

        console.print(f"[green]✓ Fetched {len(programs)} programs from public data[/green]")
        return programs

    except requests.exceptions.RequestException as e:
        console.print(f"[red]✗ Failed to fetch public data: {e}[/red]")
        return []


def fetch_programs(use_api=True, use_public=True):
    """
    Fetch programs from all available sources.
    Returns a merged, deduplicated list.
    """
    all_programs = []

    # Try API first
    if use_api and config.has_api_credentials():
        api_programs = fetch_programs_api()
        if api_programs:
            all_programs.extend(api_programs)
            console.print(f"[green]✓ {len(api_programs)} programs from API[/green]")

    # Also fetch public data for broader coverage
    if use_public:
        public_programs = fetch_programs_public()
        if public_programs:
            # Merge: skip duplicates by handle
            existing_handles = {p["handle"] for p in all_programs}
            new_public = [p for p in public_programs if p["handle"] not in existing_handles]
            all_programs.extend(new_public)
            console.print(f"[green]✓ {len(new_public)} additional programs from public data[/green]")

    # Cache results
    cache_programs(all_programs)
    return all_programs


def cache_programs(programs):
    """Cache programs to disk."""
    cache_data = {
        "fetched_at": datetime.utcnow().isoformat(),
        "count": len(programs),
        "programs": programs
    }
    config.CACHE_FILE.write_text(json.dumps(cache_data, indent=2, default=str))


def load_cached_programs(max_age_hours=6):
    """Load programs from cache if recent enough."""
    if not config.CACHE_FILE.exists():
        return None

    try:
        cache_data = json.loads(config.CACHE_FILE.read_text())
        fetched_at = datetime.fromisoformat(cache_data["fetched_at"])

        if datetime.utcnow() - fetched_at > timedelta(hours=max_age_hours):
            console.print("[yellow]⚠ Cache is stale (> {max_age_hours}h). Refreshing...[/yellow]")
            return None

        programs = cache_data["programs"]
        console.print(f"[dim]📦 Loaded {len(programs)} programs from cache "
                      f"(fetched {fetched_at.strftime('%Y-%m-%d %H:%M UTC')})[/dim]")
        return programs

    except (json.JSONDecodeError, KeyError):
        return None


def search_programs(programs, keyword=None, bounty_only=False, asset_type=None, state="open"):
    """
    Filter programs by various criteria.

    Args:
        programs: List of program dicts
        keyword: Search in program name/handle
        bounty_only: Only show programs that pay bounties
        asset_type: Filter by asset type in scope (url, domain, wildcard, etc.)
        state: Filter by submission state
    """
    results = programs

    if bounty_only:
        results = [p for p in results if p.get("offers_bounties")]

    if state:
        results = [p for p in results if p.get("submission_state", "").lower() == state.lower()
                   or state.lower() == "all"]

    if keyword:
        kw = keyword.lower()
        results = [p for p in results if
                   kw in p.get("name", "").lower() or
                   kw in p.get("handle", "").lower()]

    if asset_type and asset_type != "all":
        filtered = []
        for p in results:
            in_scope = p.get("in_scope", [])
            if in_scope:
                types = {s.get("asset_type", "").lower() for s in in_scope}
                if asset_type.lower() in types:
                    filtered.append(p)
            else:
                # No scope data cached — include it (scope will be fetched later)
                filtered.append(p)
        results = filtered

    return results


def display_programs(programs, limit=30):
    """Display programs in a rich table."""
    table = Table(
        title=f"[bold]🎯 HackerOne Programs ({len(programs)} total, showing top {min(limit, len(programs))})[/bold]",
        show_lines=False,
        border_style="bright_cyan"
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Handle", style="bold cyan", min_width=20)
    table.add_column("Name", style="white", min_width=25)
    table.add_column("Bounty", style="green", width=7)
    table.add_column("State", style="yellow", width=10)
    table.add_column("Scope", style="magenta", width=6)
    table.add_column("Source", style="dim", width=8)

    for i, p in enumerate(programs[:limit], 1):
        bounty = "💰 Yes" if p.get("offers_bounties") else "—"
        state = p.get("submission_state", "?")
        scope_count = str(p.get("in_scope_count", "?"))
        source = p.get("source", "?")
        handle = p.get("handle", "?")
        name = p.get("name", "?")

        # Truncate long names
        if len(name) > 30:
            name = name[:27] + "..."

        table.add_row(str(i), handle, name, bounty, state, scope_count, source)

    console.print(table)
    return programs[:limit]
