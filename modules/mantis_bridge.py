"""
Mantishack bridge module — Integrates Mantishack's SAST features defensively.
"""

import os
import subprocess
from pathlib import Path
from . import config
from .config import console

def run_mantis_scan(target_dir):
    """
    Executes the defensive Mantishack SAST scan on a local directory.
    Uses only safe analysis parameters (no exploitation).
    """
    target_path = Path(target_dir).absolute()
    
    if not target_path.exists() or not target_path.is_dir():
        console.print(f"[red]✗ Directory not found: {target_dir}[/red]")
        console.print("[dim]Mantishack requires local source code to perform static analysis.[/dim]")
        return False
        
    mantis_script = Path("scanners/mantishack_features/mantishack.py").absolute()
    
    if not mantis_script.exists():
        console.print("[red]✗ Mantishack repository not found in scanners/mantishack_features[/red]")
        console.print("[dim]Please ensure the repository was cloned correctly.[/dim]")
        return False
        
    console.print(f"\n[bold cyan]🔎 Running Mantishack SAST Scan on: {target_dir}[/bold cyan]")
    console.print("[dim]Executing static analysis and auth-audit...[/dim]")
    
    # We use subprocess to run the python script from the ext dir
    cmd = [
        "python", str(mantis_script),
        "scan",
        "--repo", str(target_path),
        "--policy-groups", "auth,logging,security-audit"
    ]
    
    env = os.environ.copy()
    if config.GEMINI_API_KEY:
        env["GEMINI_API_KEY"] = config.GEMINI_API_KEY
        console.print("[dim]Using Gemini API for LLM analysis logic.[/dim]")
    
    try:
        # Note: Depending on mantishack's exact requirements, it might need to be run from its own dir.
        # We will run it from its own directory for safety.
        mantis_dir = mantis_script.parent
        
        result = subprocess.run(
            cmd,
            cwd=str(mantis_dir),
            capture_output=True,
            text=True,
            env=env
        )
        
        if result.returncode == 0:
            console.print("[green]✓ Mantishack scan completed successfully.[/green]")
            # Assuming mantishack outputs to stdout or a specific file, we print a summary
            out_lines = [line for line in result.stdout.split("\n") if "finding" in line.lower() or "error" in line.lower() or "warning" in line.lower()]
            if out_lines:
                console.print("[yellow]Scan Highlights:[/yellow]")
                for line in out_lines[:10]:
                    console.print(f"  {line.strip()}")
            else:
                console.print("[dim]No major findings printed to stdout.[/dim]")
                
            return True
        else:
            console.print(f"[red]✗ Mantishack scan failed with code {result.returncode}[/red]")
            console.print(f"[dim]Stderr: {result.stderr[:500]}[/dim]")
            return False
            
    except Exception as e:
        console.print(f"[red]✗ Failed to execute Mantishack: {e}[/red]")
        return False
