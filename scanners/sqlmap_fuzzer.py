import re
import subprocess
import sys
from pathlib import Path
from . import utils

def run_sqlmap_scan(url):
    """
    Automated Deep SQLi Scanning via SQLMap.
    Only fires if simple heuristics / payloads trigger an error.
    """
    findings = []
    
    sqlmap_dir = Path("data/sqlmap")
    sqlmap_py = sqlmap_dir / "sqlmap.py"
    
    if not sqlmap_py.exists():
        return findings
        
    print(f"[*] Dispatching SQLMap Agent to heavily scan: {url}")
    
    # We use batch mode, random agent, fastest risk level, and --smart 
    # to only test parameters that are heuristics-positive for injection.
    cmd = [
        sys.executable, str(sqlmap_py.absolute()),
        "-u", url,
        "--batch",
        "--random-agent",
        "--level=1",
        "--risk=1",
        "--smart", 
        "--threads=10",
        "--dbs" # Try to extract databases if vulnerable
    ]
    
    if utils.GLOBAL_COOKIE:
        cmd.extend(["--cookie", utils.GLOBAL_COOKIE])
    if utils.GLOBAL_BEARER:
        cmd.extend(["--headers", f"Authorization: Bearer {utils.GLOBAL_BEARER}"])
    
    try:
        # Run sqlmap with a hard timeout of 10 minutes to prevent hanging
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        output = result.stdout.lower()
        vuln_match = re.search(r"parameter ['\"]([^'\"]+)['\"].{0,120}is vulnerable", result.stdout, re.I | re.S)
        vuln_param = vuln_match.group(1) if vuln_match else None
        if result.returncode == 0 and vuln_param and "is vulnerable" in output:
            findings.append({
                "type": "SQLMAP_CONFIRMED_SQLI",
                "url": url,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "verified": True,
                "verification_method": "sqlmap-confirmed",
                "verification_evidence": {
                    "deterministic": True,
                    "tool": "sqlmap",
                    "parameter": vuln_param,
                    "success_markers": ["is vulnerable", "available databases"],
                    "output_excerpt": result.stdout[-1200:],
                },
                "detail": f"SQLMap confirmed SQL injection on parameter '{vuln_param}'. Review the attached tool evidence before submission."
            })
            
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        pass
        
    return findings
