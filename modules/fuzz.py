"""
Fuzz module — Safe parameter fuzzing for discovery.
Injects benign payloads into query parameters to discover potential vulnerabilities.
"""

import json
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import config
from .config import console

# Benign payloads
SQLI_PAYLOAD = "'"
XSS_PAYLOAD = "XSS-TEST-STRING-999"

def discover_vulnerabilities(urls, handle):
    """Safely fuzzes URL parameters for SQLi and XSS reflections."""
    findings = []
    
    # Filter URLs that actually have parameters
    param_urls = []
    for u in urls:
        if isinstance(u, dict):
            url_str = u.get("url", "")
        else:
            url_str = u
            
        if "?" in url_str:
            param_urls.append(url_str)
            
    if not param_urls:
        console.print("[dim]No URLs with parameters found to fuzz.[/dim]")
        return []
        
    console.print(f"\n[bold cyan]🕷 Fuzzing {len(param_urls)} parameterized URLs...[/bold cyan]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fuzzing parameters...", total=len(param_urls))
        
        for url in param_urls:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query)
            
            for i, (key, value) in enumerate(params):
                # --- Test SQLi ---
                sqli_test_params = params.copy()
                sqli_test_params[i] = (key, value + SQLI_PAYLOAD)
                sqli_url = urlunparse(parsed._replace(query=urlencode(sqli_test_params)))
                
                try:
                    res = requests.get(sqli_url, headers=config.HEADERS, timeout=5, verify=False)
                    if "SQL syntax" in res.text or "mysql_fetch" in res.text or "ORA-" in res.text:
                        findings.append({
                            "type": "SQLi Error",
                            "url": url,
                            "parameter": key,
                            "payload": sqli_url
                        })
                except Exception:
                    pass
                    
                time.sleep(0.1) # Rate limiting
                
                # --- Test XSS ---
                xss_test_params = params.copy()
                xss_test_params[i] = (key, XSS_PAYLOAD)
                xss_url = urlunparse(parsed._replace(query=urlencode(xss_test_params)))
                
                try:
                    res = requests.get(xss_url, headers=config.HEADERS, timeout=5, verify=False)
                    if XSS_PAYLOAD in res.text:
                        findings.append({
                            "type": "XSS Reflection",
                            "url": url,
                            "parameter": key,
                            "payload": xss_url
                        })
                except Exception:
                    pass
                
                time.sleep(0.1) # Rate limiting
                
            progress.advance(task)
            
    if findings:
        console.print(f"[bold red]Found {len(findings)} potential injection points![/bold red]")
        
        # Save to file
        out_file = config.RECON_DIR / f"{handle}_fuzz_findings.json"
        out_file.write_text(json.dumps(findings, indent=2))
        console.print(f"[dim]💾 Saved fuzzing results to {out_file}[/dim]")
        
        for f in findings[:10]:
            console.print(f"  [yellow]• [{f['type']}] Parameter '{f['parameter']}'[/yellow] at {f['url']}")
    else:
        console.print("[green]No obvious injection points found.[/green]")
        
    return findings
