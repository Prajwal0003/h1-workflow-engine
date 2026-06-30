import subprocess
import json
from pathlib import Path

def run_naabu_scan(url):
    """
    Runs ProjectDiscovery's Naabu port scanner to find non-standard open ports.
    """
    findings = []
    naabu_bin = Path("data/naabu_bin/naabu.exe")
    if not naabu_bin.exists():
        return findings
        
    domain = url.split("//")[-1].split("/")[0]
    print(f"[*] Dispatching Naabu to scan infrastructure ports on: {domain}")
    
    output_file = Path(f"scratch/naabu_out_{domain}.json")
    if output_file.exists(): 
        output_file.unlink()
    
    # We use top 1000 ports to be fast enough for a continuous pipeline
    cmd = [
        str(naabu_bin.absolute()),
        "-host", domain,
        "-top-ports", "1000",
        "-json",
        "-o", str(output_file),
        "-silent"
    ]
    
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if output_file.exists():
            open_ports = []
            with open(output_file, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        port = data.get("port")
                        # Ignore standard web ports, we only want hidden infrastructure
                        if port and port not in [80, 443]:
                            open_ports.append(str(port))
                    except Exception: 
                        pass
            
            if open_ports:
                findings.append({
                    "type": "NON_STANDARD_PORT_EXPOSURE",
                    "url": url,
                    "severity": "MEDIUM",
                    "confidence": "HIGH",
                    "verified": True, # Zero FP since Naabu actively verified the TCP connection
                    "detail": f"Naabu discovered non-standard open ports on the target infrastructure: {', '.join(open_ports)}. These should be investigated for exposed Dev/Admin services."
                })
    except Exception:
        pass
        
    return findings
