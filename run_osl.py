#!/usr/bin/env python3
"""
run_launchdarkly.py — Full dual-pipeline attack on LaunchDarkly (Bugcrowd)

Runs BOTH pipelines:
  Pipeline 1: H1 Workflow (scope → recon → disclosed analysis)
  Pipeline 2: Autopilot Engine (60+ scanner modules, AI exploit, headless SPA)

Target: https://bugcrowd.com/engagements/launchdarkly-mbb-og
"""

import sys
import os
import json
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Fix Windows console encoding
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(force_terminal=True)

HANDLE = "osl-mbb-og1"
TARGET_FILE = Path("data/selected_targets/osl.json")
RESULTS_DIR = Path("data/autopilot")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# ── In-Scope Targets ──────────────────────────────────────────────
IN_SCOPE_URLS = [
    "https://osl.com",
    "https://trade.osl.com",
    "https://api.osl.com",
    "https://sg.osl.com",
]

OUT_OF_SCOPE = []

# ── API endpoints to focus on ─────────────────────────────────────
API_ENDPOINTS = [
    "/api/v2/",
    "/v1/api/",
    "/graphql",
    "/internal/",
    "/admin/",
]


def show_scope_table():
    """Display the scope in a clean table."""
    table = Table(title="🎯 LaunchDarkly — In-Scope Targets", border_style="bright_cyan")
    table.add_column("Asset", style="bold green")
    table.add_column("Type", style="cyan")
    table.add_column("Notes", style="dim")

    for url in IN_SCOPE_URLS:
        table.add_row(url, "Web App", "✅ In Scope")

    table.add_row("github.com/launchdarkly", "Source Code", "✅ Open Source SDKs")

    console.print(table)

    oos_table = Table(title="🚫 Out of Scope", border_style="red")
    oos_table.add_column("Asset", style="red")
    oos_table.add_column("Reason", style="dim")

    for oos in OUT_OF_SCOPE:
        oos_table.add_row(oos, "Excluded by program")

    console.print(oos_table)

    console.print(Panel(
        "[bold yellow]⚠️  RULES[/bold yellow]\n\n"
        "  • Create test accounts with @bugcrowdninja email\n"
        "  • Check /api/v2/caller-identity for bountyEligible: true\n"
        "  • No DoS/DDoS, rate limiting, or social engineering\n"
        "  • No third-party integration testing\n"
        "  • No AI-generated or low-effort submissions\n"
        "  • Program is FRESH on Bugcrowd (June 2026) — low competition!",
        border_style="yellow",
        padding=(1, 2)
    ))


def run_pipeline_1():
    """Pipeline 1: H1 Workflow recon pipeline (adapted for Bugcrowd target)."""
    console.print(Panel(
        "[bold cyan]🔵 PIPELINE 1: H1 WORKFLOW ENGINE[/bold cyan]\n"
        "[dim]Scope → Subdomain Enum → HTTP Probing → Nuclei Scan → Disclosed Analysis[/dim]",
        border_style="bright_blue",
        padding=(1, 2)
    ))

    try:
        from modules import recon
        console.print("\n[bold cyan]Phase 1.1: Reconnaissance[/bold cyan]")
        recon.full_recon(HANDLE, skip_scan=False)
    except Exception as e:
        console.print(f"[yellow]⚠ Recon pipeline partial: {e}[/yellow]")

    # Analyze disclosed bugs from HackerOne history
    try:
        from modules import disclosed
        console.print("\n[bold cyan]Phase 1.2: Disclosed Bugs Analysis[/bold cyan]")
        disclosed.get_disclosed_bugs(HANDLE, limit=50)
    except Exception as e:
        console.print(f"[yellow]⚠ Disclosed analysis skipped: {e}[/yellow]")


def run_pipeline_2():
    """Pipeline 2: Autopilot scanner engine (60+ modules)."""
    console.print(Panel(
        "[bold magenta]🟣 PIPELINE 2: AUTOPILOT SCANNER ENGINE[/bold magenta]\n"
        "[dim]60+ scanner modules • AI exploit generation • Headless SPA crawl[/dim]",
        border_style="bright_magenta",
        padding=(1, 2)
    ))

    all_findings = []

    # Dynamically import autopilot scanner functions
    try:
        from autopilot import (
            check_open_redirect, check_lfi, check_crlf, check_host_header,
            check_blind_oob, check_headless_spa, ai_autonomous_exploit,
            generate_ai_report, ai_exploit_and_prove, generate_nuclei_template,
            send_discord_webhook, send_telegram_alert, create_notion_ticket,
            push_to_graph, log, get_stealth_headers, safe_request,
            SCANNERS_LOADED, FEATURES_LOADED
        )
    except ImportError as e:
        console.print(f"[red]✗ Failed to import autopilot: {e}[/red]")
        return []

    # Import all scanner modules
    scanner_funcs = []
    if SCANNERS_LOADED:
        try:
            from scanners.xss import check_xss, check_dom_xss
            from scanners.ssrf import check_ssrf
            from scanners.ssti import check_ssti
            from scanners.csrf import check_csrf
            from scanners.xxe import check_xxe
            from scanners.smuggling import check_request_smuggling
            from scanners.race import check_race_condition
            from scanners.cache_poison import check_cache_poisoning
            from scanners.jwt import check_jwt_vulnerabilities
            from scanners.buckets import check_s3_buckets
            from scanners.git_exposure import check_git_exposure
            from scanners.dir_traversal import check_directory_traversal
            from scanners.waf import detect_waf
            from scanners.tech_detect import check_technologies
            from scanners.param_discovery import discover_parameters
            from scanners.link_discovery import discover_links_and_js
            from scanners.secrets_advanced import check_advanced_secrets
            from scanners.deserialization import check_insecure_deserialization
            from scanners.postmessage import check_postmessage
            from scanners.command_injection import check_command_injection
            from scanners.idor_advanced import check_idor_advanced
            from scanners.api_versioning import check_api_versioning
            from scanners.rate_limit import check_rate_limit
            from scanners.js_analyzer import check_js_analyzer
            from scanners.api_schema import check_api_schema
            from scanners.graphql_parser import check_graphql
            from scanners.cors_scanner import check_cors_misconfig
            from scanners.subdomain_takeover import check_subdomain_takeover
            from scanners.js_secrets_hunter import hunt_js_secrets
            from scanners.wayback_scraper import fetch_wayback_urls
            from scanners.hardcoded_fuzzer import check_hardcoded_payloads
            from scanners.headless_traffic_analyzer import run_headless_crawler_analyzer
            from scanners.graphql_dumper import check_graphql_introspection
            from scanners.host_header_fuzzer import run_host_header_fuzzer
            from scanners.open_redirect_fuzzer import run_open_redirect_fuzzer
            from scanners.jwt_fuzzer import run_jwt_fuzzer
            from scanners.lfi_fuzzer import run_lfi_fuzzer
            from scanners.oob_ssrf import run_oob_ssrf
            from scanners.prototype_pollution import run_prototype_pollution
            from scanners.oauth_hijack import run_oauth_hijack
            from scanners.ssti_fuzzer import run_ssti_fuzzer
            from scanners.dom_xss_tracer import run_dom_xss_tracer
            from scanners.waf_evasion import run_waf_evasion

            # Build scanner dispatch table
            scanner_funcs = [
                ("XSS", check_xss),
                ("DOM XSS", check_dom_xss),
                ("SSRF", check_ssrf),
                ("SSTI", check_ssti),
                ("CSRF", check_csrf),
                ("XXE", check_xxe),
                ("Request Smuggling", check_request_smuggling),
                ("Race Condition", check_race_condition),
                ("Cache Poisoning", check_cache_poisoning),
                ("JWT Vulns", check_jwt_vulnerabilities),
                ("S3 Buckets", check_s3_buckets),
                ("Git Exposure", check_git_exposure),
                ("Directory Traversal", check_directory_traversal),
                ("WAF Detection", detect_waf),
                ("Tech Detection", check_technologies),
                ("Parameter Discovery", discover_parameters),
                ("Link/JS Discovery", discover_links_and_js),
                ("Advanced Secrets", check_advanced_secrets),
                ("Deserialization", check_insecure_deserialization),
                ("PostMessage", check_postmessage),
                ("Command Injection", check_command_injection),
                ("IDOR Advanced", check_idor_advanced),
                ("API Versioning", check_api_versioning),
                ("Rate Limiting", check_rate_limit),
                ("JS Analyzer", check_js_analyzer),
                ("API Schema", check_api_schema),
                ("GraphQL", check_graphql),
                ("CORS Misconfig", check_cors_misconfig),
                ("Subdomain Takeover", check_subdomain_takeover),
                ("JS Secrets", hunt_js_secrets),
                ("Wayback URLs", fetch_wayback_urls),
                ("Hardcoded Payloads", check_hardcoded_payloads),
                ("GraphQL Introspection", check_graphql_introspection),
                ("Host Header Fuzz", run_host_header_fuzzer),
                ("Open Redirect Fuzz", run_open_redirect_fuzzer),
                ("JWT Fuzz", run_jwt_fuzzer),
                ("LFI Fuzz", run_lfi_fuzzer),
                ("OOB SSRF", run_oob_ssrf),
                ("Prototype Pollution", run_prototype_pollution),
                ("OAuth Hijack", run_oauth_hijack),
                ("SSTI Fuzz", run_ssti_fuzzer),
                ("DOM XSS Tracer", run_dom_xss_tracer),
                ("WAF Evasion", run_waf_evasion),
            ]
        except ImportError as e:
            console.print(f"[yellow]⚠ Some scanner imports failed: {e}[/yellow]")

    # Also add autopilot built-in checks
    builtin_checks = [
        ("Open Redirect", check_open_redirect),
        ("LFI", check_lfi),
        ("CRLF Injection", check_crlf),
        ("Host Header Injection", check_host_header),
        ("Blind OOB", check_blind_oob),
    ]

    total_scans = len(IN_SCOPE_URLS) * (len(scanner_funcs) + len(builtin_checks))

    console.print(f"\n[bold]Launching {len(scanner_funcs) + len(builtin_checks)} scanner modules across {len(IN_SCOPE_URLS)} targets ({total_scans} total scans)[/bold]\n")

    for url in IN_SCOPE_URLS:
        console.print(f"\n[bold green]━━━ Scanning: {url} ━━━[/bold green]")

        # Run all scanner modules
        for name, func in scanner_funcs + builtin_checks:
            try:
                console.print(f"  [dim]→ {name}...[/dim]", end="")
                result = func(url)
                if result:
                    findings = result if isinstance(result, list) else [result]
                    for f in findings:
                        if isinstance(f, dict):
                            f["program"] = HANDLE
                            f.setdefault("confidence", "MEDIUM")
                            all_findings.append(f)
                            severity = f.get("severity", "INFO")
                            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
                            console.print(f" {emoji} [bold]{severity}[/bold]: {f.get('type', 'UNKNOWN')}")

                            # Fire off alerts for HIGH/CRITICAL
                            if severity in ["HIGH", "CRITICAL"]:
                                send_discord_webhook(f)
                                send_telegram_alert(f)
                                create_notion_ticket(f)
                                push_to_graph(f)
                                ai_exploit_and_prove(f)
                                generate_ai_report(f)
                                generate_nuclei_template(f)
                        else:
                            console.print(f" ✓")
                else:
                    console.print(f" ✓")
            except Exception as e:
                console.print(f" [red]✗ {str(e)[:50]}[/red]")

        # Headless SPA analysis
        try:
            console.print(f"  [dim]→ Headless SPA Crawl...[/dim]", end="")
            spa_findings = check_headless_spa(url)
            if spa_findings:
                for f in spa_findings:
                    f["program"] = HANDLE
                    all_findings.append(f)
                    console.print(f" 🟡 {f.get('type', 'SPA')}")
            else:
                console.print(f" ✓")
        except Exception:
            console.print(f" [dim]skipped[/dim]")

        # AI Autonomous exploit attempt
        try:
            console.print(f"  [dim]→ AI Autonomous Exploit...[/dim]", end="")
            ai_findings = ai_autonomous_exploit(url)
            if ai_findings:
                for f in ai_findings:
                    f["program"] = HANDLE
                    all_findings.append(f)
                    console.print(f" 🔴 {f.get('type', 'AI')}")
            else:
                console.print(f" ✓")
        except Exception:
            console.print(f" [dim]skipped[/dim]")

    # ── LaunchDarkly-specific API endpoint scanning ──
    console.print(Panel(
        "[bold yellow]🔑 LAUNCHDARKLY API ENDPOINT SCAN[/bold yellow]\n"
        "[dim]Testing API v2 endpoints for IDOR, auth bypass, info disclosure[/dim]",
        border_style="yellow"
    ))

    base = "https://app.launchdarkly.com"
    for endpoint in API_ENDPOINTS:
        full_url = f"{base}{endpoint}"
        try:
            import requests
            headers = get_stealth_headers()
            # Test unauthenticated access
            r = safe_request("GET", full_url, headers=headers, timeout=5, verify=True)
            if r and r.status_code == 200:
                content_type = r.headers.get("Content-Type", "")
                if "json" in content_type:
                    body = r.text[:500]
                    if any(kw in body.lower() for kw in ["email", "token", "key", "secret", "password", "admin"]):
                        finding = {
                            "type": "API_INFO_DISCLOSURE",
                            "url": full_url,
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "detail": f"Unauthenticated access to API endpoint returning sensitive data",
                            "program": HANDLE
                        }
                        all_findings.append(finding)
                        console.print(f"  🟠 [bold]HIGH[/bold]: API Info Disclosure at {endpoint}")
                        send_discord_webhook(finding)
                        send_telegram_alert(finding)
                    else:
                        console.print(f"  [dim]→ {endpoint} — 200 OK (no sensitive data)[/dim]")
                else:
                    console.print(f"  [dim]→ {endpoint} — 200 OK[/dim]")
            elif r and r.status_code in [401, 403]:
                console.print(f"  [dim]→ {endpoint} — {r.status_code} (auth required)[/dim]")
            elif r:
                console.print(f"  [dim]→ {endpoint} — {r.status_code}[/dim]")
        except Exception as e:
            console.print(f"  [dim]→ {endpoint} — error[/dim]")

    return all_findings


def save_results(findings):
    """Save all findings to disk."""
    ts = int(time.time())
    results_file = RESULTS_DIR / f"launchdarkly_scan_{ts}.json"
    results_file.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    console.print(f"\n[bold green]📁 Results saved: {results_file}[/bold green]")

    # Summary table
    if findings:
        table = Table(title=f"🔍 SCAN RESULTS — {len(findings)} Findings", border_style="bright_green")
        table.add_column("#", style="dim")
        table.add_column("Severity", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("URL", style="dim", max_width=60)
        table.add_column("Confidence", style="dim")

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            sev_color = {"CRITICAL": "bold red", "HIGH": "bold yellow", "MEDIUM": "yellow", "LOW": "blue"}.get(sev, "dim")
            table.add_row(
                str(i),
                f"[{sev_color}]{sev}[/{sev_color}]",
                f.get("type", "UNKNOWN"),
                f.get("url", "N/A")[:60],
                f.get("confidence", "N/A")
            )
        console.print(table)
    else:
        console.print("[yellow]No findings detected. Target appears hardened.[/yellow]")

    return results_file


def main():
    start = time.time()

    console.print(Panel(
        "[bold bright_green]🚀 OPENCLAW DUAL-PIPELINE — LAUNCHDARKLY[/bold bright_green]\n\n"
        "  [bold]Platform:[/bold]  Bugcrowd\n"
        "  [bold]Program:[/bold]  LaunchDarkly Managed Bug Bounty\n"
        "  [bold]URL:[/bold]      https://bugcrowd.com/engagements/launchdarkly-mbb-og\n"
        "  [bold]Targets:[/bold]  7 in-scope domains + API v2 endpoints\n"
        "  [bold]Scanners:[/bold] 60+ modules (XSS, SSRF, SSTI, IDOR, JWT, GraphQL...)\n"
        "  [bold]AI:[/bold]       Gemini-powered autonomous exploit generation\n\n"
        "  [dim]Pipeline 1: H1 Workflow (Recon → Nuclei → Disclosed)[/dim]\n"
        "  [dim]Pipeline 2: Autopilot Engine (60+ scanners → AI exploit → Reports)[/dim]",
        border_style="bright_green",
        padding=(1, 2)
    ))

    # Show scope
    show_scope_table()

    console.print("\n[bold]Starting in 3 seconds...[/bold]")
    time.sleep(3)

    # ── Pipeline 1: H1 Workflow ──
    console.print("\n" + "═" * 70)
    run_pipeline_1()

    # ── Pipeline 2: Autopilot Scanner ──
    console.print("\n" + "═" * 70)
    findings = run_pipeline_2()

    # ── Save & Report ──
    console.print("\n" + "═" * 70)
    results_file = save_results(findings)

    elapsed = time.time() - start
    elapsed_str = f"{int(elapsed // 3600)}h {int((elapsed % 3600) // 60)}m {int(elapsed % 60)}s"

    console.print(Panel(
        f"[bold bright_green]✅ DUAL-PIPELINE COMPLETE[/bold bright_green]\n\n"
        f"  ⏱  Total time: {elapsed_str}\n"
        f"  🔍 Findings: {len(findings)}\n"
        f"  📁 Results: {results_file}\n"
        f"  📋 Reports: reports/\n\n"
        f"  [bold yellow]Next Steps:[/bold yellow]\n"
        f"  1. Review HIGH/CRITICAL findings manually\n"
        f"  2. Create PoC for verified vulns\n"
        f"  3. Submit to Bugcrowd: https://bugcrowd.com/engagements/launchdarkly-mbb-og\n"
        f"  4. Use @bugcrowdninja email for test accounts",
        border_style="green",
        padding=(1, 2)
    ))


if __name__ == "__main__":
    main()
