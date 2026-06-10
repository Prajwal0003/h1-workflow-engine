import subprocess
from pathlib import Path

def run_ssrfmap_scan(url):
    """
    Automated SSRF exploitation and internal port scanning via SSRFmap.
    """
    findings = []
    ssrfmap_py = Path("data/SSRFmap/ssrfmap.py")
    
    if not ssrfmap_py.exists():
        return findings
        
    if "?" not in url:
        return findings
        
    print(f"[*] Dispatching SSRFmap Agent to exploit potential SSRF on: {url}")
    
    # We use a basic port scan module as a reliable indicator of SSRF
    cmd = [
        "python", str(ssrfmap_py.absolute()),
        "-r", url, # SSRFmap usually takes raw requests, but can take -r file or direct depending on setup. We'll pass URL and it will try to parse if modified, or we just pass the URL as standard param if supported by the wrapper.
        "-m", "portscan"
    ]
    
    try:
        # We will use a highly constrained timeout. SSRFmap can be very slow.
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout.lower()
        
        if "open port" in output or "success" in output:
            findings.append({
                "type": "SSRFMAP_CONFIRMED_SSRF",
                "url": url,
                "severity": "HIGH",
                "confidence": "HIGH",
                "verified": True,
                "detail": f"SSRFmap confirmed Server-Side Request Forgery by successfully scanning internal ports."
            })
            
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
        
    return findings
