import re
import subprocess
import sys
from pathlib import Path
from . import utils

def run_commix_scan(url):
    """
    Automated Command Injection Scanning via Commix.
    """
    findings = []
    commix_py = Path("data/commix/commix.py")
    
    if not commix_py.exists():
        return findings
        
    print(f"[*] Dispatching Commix Agent to test Command Injection on: {url}")
    
    cmd = [
        sys.executable, str(commix_py.absolute()),
        "--url", url,
        "--batch", 
        "--level=1",
        "--smart",
        "--os-cmd=id"
    ]
    
    if utils.GLOBAL_COOKIE:
        cmd.extend(["--cookie", utils.GLOBAL_COOKIE])
    if utils.GLOBAL_BEARER:
        cmd.extend(["--headers", f"Authorization: Bearer {utils.GLOBAL_BEARER}"])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.lower()
        uid_match = re.search(r"\buid=\d+", output)
        shell_marker = "pseudo-terminal" in output and ("shell" in output or "command" in output)
        if result.returncode == 0 and ("is vulnerable" in output or uid_match or shell_marker):
            findings.append({
                "type": "COMMIX_CONFIRMED_CMD_INJECTION",
                "url": url,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "verified": True,
                "verification_method": "commix-confirmed",
                "verification_evidence": {
                    "deterministic": True,
                    "tool": "commix",
                    "success_markers": ["is vulnerable", "uid=", "pseudo-terminal"],
                    "output_excerpt": result.stdout[-1200:],
                },
                "detail": "Commix confirmed command injection. Review the attached tool evidence before submission."
            })
            
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
        
    return findings
