import subprocess
import json
from pathlib import Path
from urllib.parse import urlparse

def run_arjun_scan(url):
    """
    Automated Hidden Parameter Discovery via Arjun.
    Finds undocumented HTTP parameters that might lead to vulnerabilities.
    """
    findings = []
    arjun_py = Path("data/Arjun/arjun.py")
    
    if not arjun_py.exists():
        return findings
        
    print(f"[*] Dispatching Arjun Agent to find hidden parameters on: {url}")
    
    # We output to JSON to easily parse the discovered parameters
    output_file = Path("scratch/arjun_out.json")
    if output_file.exists():
        output_file.unlink()
        
    cmd = [
        "python", str(arjun_py.absolute()),
        "-u", url,
        "-t", "10",
        "--passive", "-", # Disable passive sources to keep it fast/focused
        "-oJ", str(output_file)
    ]
    
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if output_file.exists():
            data = json.loads(output_file.read_text())
            for target_url, params_data in data.items():
                params = params_data.get("params", [])
                if params:
                    findings.append({
                        "type": "ARJUN_HIDDEN_PARAMS",
                        "url": target_url,
                        "severity": "LOW", # Usually informational, but opens up attack surface
                        "confidence": "HIGH",
                        "verified": True,
                        "detail": f"Arjun discovered hidden/undocumented HTTP parameters: {', '.join(params)}. These should be fuzzed for IDOR/SQLi."
                    })
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
        
    return findings
