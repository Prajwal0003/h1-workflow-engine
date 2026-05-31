"""
Disclosed Bugs module — Fetch and display publicly disclosed bug reports.
Uses public bounty-targets-data and HackerOne hacktivity for learning patterns.
"""

import json
import time
from datetime import datetime

import requests
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from . import config
from .config import console


def fetch_hacktivity(handle=None, limit=25):
    """
    Fetch public hacktivity (disclosed reports) from HackerOne.
    Uses the HackerOne hacktivity page which is publicly accessible.
    """
    console.print(f"\n[bold]📜 Fetching disclosed bugs{f' for {handle}' if handle else ''}...[/bold]\n")

    # Use the public hacktivity API endpoint
    url = "https://hackerone.com/graphql"
    
    query = """
    query HacktivityPageQuery($queryString: String, $orderBy: HacktivityItemOrderInput, $secureOrderBy: FiltersHacktivityItemFilterOrder, $where: FiltersHacktivityItemFilterInput, $count: Int, $cursor: String) {
      hacktivity_items(
        first: $count
        after: $cursor
        query: $queryString
        order_by: $orderBy
        secure_order_by: $secureOrderBy
        where: $where
      ) {
        edges {
          node {
            ... on HacktivityItemInterface {
              id
              reporter {
                username
              }
              team {
                handle
                name
              }
              vote_count
              upvoted: is_voted
              disclosed_at
              severity_rating
              report {
                title
                substate
                url
                id
              }
              ... on Disclosed {
                severity_rating
                total_awarded_amount
                currency
              }
            }
          }
        }
      }
    }
    """

    variables = {
        "count": limit,
        "orderBy": {"field": "popular", "direction": "DESC"},
        "where": {}
    }

    if handle:
        variables["where"]["team"] = {"handle": {"_eq": handle}}

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        resp = requests.post(
            url,
            json={"query": query, "variables": variables},
            headers=headers,
            timeout=30
        )

        if resp.status_code != 200:
            console.print(f"[yellow]⚠ Hacktivity API returned {resp.status_code}. Trying fallback...[/yellow]")
            return fetch_hacktivity_fallback(handle, limit)

        data = resp.json()
        edges = (data.get("data", {})
                     .get("hacktivity_items", {})
                     .get("edges", []))

        reports = []
        for edge in edges:
            node = edge.get("node", {})
            report = node.get("report", {})
            team = node.get("team", {})
            reporter = node.get("reporter", {})

            reports.append({
                "title": report.get("title", "Untitled"),
                "url": report.get("url", ""),
                "program": team.get("name", "?"),
                "handle": team.get("handle", "?"),
                "reporter": reporter.get("username", "?"),
                "severity": node.get("severity_rating", "?"),
                "bounty": node.get("total_awarded_amount", 0),
                "currency": node.get("currency", "USD"),
                "votes": node.get("vote_count", 0),
                "disclosed_at": node.get("disclosed_at", ""),
                "state": report.get("substate", "?"),
            })

        return reports

    except requests.exceptions.RequestException as e:
        console.print(f"[red]✗ Failed to fetch hacktivity: {e}[/red]")
        return fetch_hacktivity_fallback(handle, limit)


def fetch_hacktivity_fallback(handle=None, limit=25):
    """
    Fallback: scrape basic disclosed info from public sources.
    This is a simpler approach when the GraphQL API is blocked.
    """
    console.print("[dim]Using fallback method for disclosed bugs...[/dim]")

    if not handle:
        console.print("[yellow]Fallback requires a specific program handle.[/yellow]")
        return []

    # Try the HackerOne API for disclosed reports (if we have creds)
    if config.has_api_credentials():
        auth = config.get_auth()
        url = f"https://api.hackerone.com/v1/hackers/programs/{handle}/reports"
        try:
            resp = requests.get(
                url,
                auth=auth,
                headers={"Accept": "application/json"},
                params={"page[size]": limit, "filter[state][]": "disclosed"},
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                reports = []
                for r in data.get("data", []):
                    attrs = r.get("attributes", {})
                    reports.append({
                        "title": attrs.get("title", "Untitled"),
                        "url": f"https://hackerone.com/reports/{r.get('id', '')}",
                        "program": handle,
                        "handle": handle,
                        "reporter": "?",
                        "severity": attrs.get("severity_rating", "?"),
                        "bounty": attrs.get("bounty_amount", 0),
                        "currency": "USD",
                        "votes": 0,
                        "disclosed_at": attrs.get("disclosed_at", ""),
                        "state": attrs.get("substate", "?"),
                    })
                return reports
        except requests.exceptions.RequestException:
            pass

    return []


def display_disclosed(reports, limit=25):
    """Display disclosed bugs in a rich table."""
    if not reports:
        console.print("[yellow]No disclosed reports found.[/yellow]")
        return

    table = Table(
        title=f"[bold]📜 Disclosed Bug Reports ({len(reports)} found)[/bold]",
        show_lines=True,
        border_style="bright_magenta"
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Title", style="bold white", min_width=35)
    table.add_column("Program", style="cyan", width=15)
    table.add_column("Severity", style="yellow", width=10)
    table.add_column("Bounty", style="green", width=10)
    table.add_column("Reporter", style="dim", width=12)
    table.add_column("Votes", style="magenta", width=6)

    for i, r in enumerate(reports[:limit], 1):
        title = r.get("title", "?")
        if len(title) > 45:
            title = title[:42] + "..."

        bounty = r.get("bounty", 0)
        bounty_str = f"${bounty:,.0f}" if bounty else "—"
        severity = r.get("severity", "?") or "—"
        votes = str(r.get("votes", 0))

        table.add_row(
            str(i),
            title,
            r.get("handle", "?"),
            severity,
            bounty_str,
            r.get("reporter", "?"),
            votes
        )

    console.print(table)


def get_disclosed_bugs(handle=None, limit=25):
    """Main entry point: fetch + display disclosed bugs."""
    reports = fetch_hacktivity(handle=handle, limit=limit)
    display_disclosed(reports, limit=limit)

    # Cache results
    if reports:
        cache_data = {
            "handle": handle,
            "fetched_at": datetime.utcnow().isoformat(),
            "count": len(reports),
            "reports": reports
        }
        cache_file = config.DATA_DIR / f"disclosed_{handle or 'all'}.json"
        cache_file.write_text(json.dumps(cache_data, indent=2, default=str))
        console.print(f"[dim]💾 Cached {len(reports)} reports[/dim]")

    return reports
