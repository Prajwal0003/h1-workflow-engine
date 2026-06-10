import subprocess
import os
import random
from pathlib import Path

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
        "python", str(sqlmap_py.absolute()),
        "-u", url,
        "--batch",
        "--random-agent",
        "--level=1",
        "--risk=1",
        "--smart", 
        "--threads=10",
        "--dbs" # Try to extract databases if vulnerable
    ]
    
    try:
        # Run sqlmap with a hard timeout of 10 minutes to prevent hanging
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        output = result.stdout.lower()
        
        if "is vulnerable" in output or "available databases" in output:
            
            # Try to extract the vulnerable parameter name from the output
            vuln_param = "Unknown Parameter"
            for line in result.stdout.splitlines():
                if "parameter '" in line and "' is vulnerable" in line:
                    vuln_param = line.split("parameter '")[1].split("'")[0]
            
            findings.append({
                "type": "SQLMAP_CONFIRMED_SQLI",
                "url": url,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "verified": True, # Hard-verified by SQLmap
                "detail": f"SQLMap confirmed a critical SQL Injection on parameter '{vuln_param}'. Exploit successful."
            })
            
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        pass
        
    return findings
