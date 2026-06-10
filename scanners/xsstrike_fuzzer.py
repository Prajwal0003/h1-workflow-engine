import subprocess
from pathlib import Path

def run_xsstrike_scan(url):
    """
    Automated XSS Scanning via XSStrike.
    """
    findings = []
    xsstrike_py = Path("data/XSStrike/xsstrike.py")
    
    if not xsstrike_py.exists():
        return findings
        
    if "?" not in url:
        return findings # XSStrike typically needs a query param to test explicitly
        
    print(f"[*] Dispatching XSStrike Agent to test XSS on: {url}")
    
    cmd = [
        "python", str(xsstrike_py.absolute()),
        "-u", url,
        "--batch"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = result.stdout.lower()
        
        if "vulnerable" in output and "payload:" in output:
            payload = "Unknown Payload"
            
            for line in result.stdout.splitlines():
                if "Payload:" in line:
                    payload = line.split("Payload:")[1].strip()
                    
            findings.append({
                "type": "XSSTRIKE_CONFIRMED_XSS",
                "url": url,
                "severity": "HIGH",
                "confidence": "HIGH",
                "verified": True,
                "detail": f"XSStrike found a confirmed XSS. Generated payload: {payload}"
            })
            
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
        
    return findings
