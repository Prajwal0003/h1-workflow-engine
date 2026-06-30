"""
Port Scanner — Wrapper around naabu for fast port scanning.
Ref: awesome-bugbounty-tools (naabu, masscan, RustScan, nmap).
"""
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from .utils import run_bin


INTERESTING_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

HIGH_RISK_PORTS = {3306, 5432, 27017, 6379, 11211, 9200, 3389, 5900, 23, 21, 445, 139}


def check_ports(url):
    """Run port scan on target host using naabu."""
    findings = []
    hostname = urlparse(url).hostname
    if not hostname:
        return None

    # Try naabu first
    out = run_bin("naabu", ["-host", hostname, "-json", "-silent", "-top-ports", "100"], timeout=60)

    if out:
        for line in out.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                port = data.get("port", 0)
                service = INTERESTING_PORTS.get(port, "Unknown")
                severity = "HIGH" if port in HIGH_RISK_PORTS else "MEDIUM" if port not in {80, 443, 8080, 8443} else "LOW"

                if port in HIGH_RISK_PORTS:
                    findings.append({
                        "type": "EXPOSED_PORT",
                        "url": f"{hostname}:{port}",
                        "severity": severity,
                        "confidence": "HIGH",
                        "detail": f"Port {port} ({service}) open — high-risk service exposed"
                    })
                elif port not in {80, 443}:
                    findings.append({
                        "type": "OPEN_PORT",
                        "url": f"{hostname}:{port}",
                        "severity": severity,
                        "confidence": "HIGH",
                        "detail": f"Port {port} ({service}) open"
                    })
            except (json.JSONDecodeError, KeyError):
                pass
    else:
        # Fallback: socket-based scan for top critical ports
        import socket
        for port in sorted(HIGH_RISK_PORTS)[:10]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    service = INTERESTING_PORTS.get(port, "Unknown")
                    findings.append({
                        "type": "EXPOSED_PORT",
                        "url": f"{hostname}:{port}",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "detail": f"Port {port} ({service}) open (socket scan)"
                    })
            except Exception:
                pass

    # --- State Tracking & Diffing Logic ---
    state_file = Path("data") / f"port_state_{hostname}.json"
    known_ports = set()
    if state_file.exists():
        try:
            known_ports = set(json.loads(state_file.read_text(encoding="utf-8")))
        except Exception:
            pass
            
    current_ports = set()
    new_findings = []
    
    for finding in findings:
        try:
            port = finding["url"].split(":")[-1]
            current_ports.add(port)
            if port not in known_ports:
                new_findings.append(finding)
        except Exception:
            new_findings.append(finding) # Fallback

    if current_ports:
        os.makedirs("data", exist_ok=True)
        state_file.write_text(json.dumps(list(current_ports), indent=2), encoding="utf-8")

    return new_findings if new_findings else None
