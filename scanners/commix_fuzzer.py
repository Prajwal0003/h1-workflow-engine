import subprocess
from pathlib import Path
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

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
        "python", str(commix_py.absolute()),
        "--url", url,
        "--batch", 
        "--level=1",
        "--smart",
        "--os-cmd=id"
    ]
    
    if GLOBAL_COOKIE:
        cmd.extend(["--cookie", GLOBAL_COOKIE])
    if GLOBAL_BEARER:
        cmd.extend(["--headers", f"Authorization: Bearer {GLOBAL_BEARER}"])
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.lower()
        
        # Commix usually prints out "(*nix)" or "Windows" or "uid=" when 'id' works
        if "is vulnerable" in output or "uid=" in output or "pseudo-terminal" in output:
            findings.append({
                "type": "COMMIX_CONFIRMED_CMD_INJECTION",
                "url": url,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "verified": True,
                "detail": "Commix confirmed a critical OS Command Injection vulnerability. Arbitrary code execution is possible."
            })
            
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
        
    return findings
