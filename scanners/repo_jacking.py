import requests
import json
import re
from rich.console import Console

console = Console()

def check_repo_jacking(url, headers=None):
    """
    Scans exposed package.json or requirements.txt files for dependencies
    that do not exist on public registries (Dependency Confusion / Repo Jacking).
    This is an advanced Supply Chain attack vector.
    """
    console.print(f"[bold cyan][*] Scanning for Supply Chain & Repo Jacking vulnerabilities: {url}[/bold cyan]")
    
    findings = []
    
    # Common locations for package files
    files_to_check = ["/package.json", "/package-lock.json"]
    
    for file_path in files_to_check:
        target_url = f"{url.rstrip('/')}{file_path}"
        try:
            response = requests.get(target_url, headers=headers, timeout=5)
            if response.status_code == 200 and "dependencies" in response.text:
                console.print(f"[bold green][+] Found {file_path} at {target_url}[/bold green]")
                
                try:
                    data = response.json()
                    deps = {}
                    if "dependencies" in data:
                        deps.update(data["dependencies"])
                    if "devDependencies" in data:
                        deps.update(data["devDependencies"])
                        
                    for pkg_name in deps.keys():
                        # Exclude private scoped packages starting with @company (requires deeper logic)
                        if pkg_name.startswith('@'):
                            continue
                            
                        # Query NPM registry
                        npm_url = f"https://registry.npmjs.org/{pkg_name}"
                        npm_resp = requests.get(npm_url, timeout=3)
                        
                        # If the package is NOT found on NPM, it's vulnerable to dependency confusion!
                        if npm_resp.status_code == 404:
                            console.print(f"[bold red][!] CRITICAL: Dependency Confusion / Repo Jacking possible for package: '{pkg_name}'[/bold red]")
                            findings.append(f"Repo Jacking: '{pkg_name}' is missing on NPM (Found in {target_url})")
                            
                except json.JSONDecodeError:
                    pass
                    
        except requests.exceptions.RequestException:
            pass
            
    if not findings:
        console.print("[green][+] No Dependency Confusion / Repo Jacking vulnerabilities detected.[/green]")
        
    return findings
