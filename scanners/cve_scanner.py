import os
import json
import subprocess
from pathlib import Path
from urllib.parse import urljoin
import requests
import random

def get_stealth_headers():
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    ]
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*"
    }

def check_cve_2021_36873(url):
    """
    Specific check for CVE-2021-36873: iQ Block Country < 1.2.12 - Authenticated Stored XSS
    """
    findings = []
    target = url.rstrip("/")
    readme_url = f"{target}/wp-content/plugins/iq-block-country/readme.txt"
    try:
        r = requests.get(readme_url, headers=get_stealth_headers(), timeout=5, verify=False)
        if r.status_code == 200 and "iQ Block Country" in r.text:
            import re
            version_match = re.search(r"Stable tag:\s*([0-9\.]+)", r.text)
            if version_match:
                version = version_match.group(1)
                parts = [int(x) for x in version.split(".") if x.isdigit()]
                if len(parts) >= 3:
                    if parts[0] <= 1 and parts[1] <= 2 and parts[2] < 12:
                        findings.append({
                            "type": "CVE-2021-36873_IQ_BLOCK_COUNTRY_XSS",
                            "url": readme_url,
                            "severity": "MEDIUM",
                            "confidence": "HIGH",
                            "detail": f"iQ Block Country plugin version {version} is vulnerable to Authenticated Stored XSS (CVE-2021-36873)."
                        })
    except Exception:
        pass
    return findings

def check_all_cves(url):
    """
    Runs Nuclei with CVE tags to verify all known CVE vulnerabilities.
    """
    findings = []
    nuclei_exe = Path("tools/nuclei/nuclei.exe")
    
    if not nuclei_exe.exists():
        return findings
        
    try:
        # We use -tags cve to scan for all CVEs, -jsonl for easy parsing
        cmd = [
            str(nuclei_exe.absolute()),
            "-u", url,
            "-tags", "cve",
            "-silent",
            "-jsonl"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line.strip())
                vuln_id = data.get("info", {}).get("name", "Unknown CVE")
                cve_id = data.get("template-id", "CVE-Unknown")
                severity = data.get("info", {}).get("severity", "medium").upper()
                matched_at = data.get("matched-at", url)
                
                findings.append({
                    "type": cve_id,
                    "url": matched_at,
                    "severity": severity,
                    "confidence": "HIGH",
                    "detail": f"Nuclei discovered {vuln_id}."
                })
            except json.JSONDecodeError:
                pass
                
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        pass
        
    return findings

def run_cve_scans(url):
    all_findings = []
    
    # Run the specific requested CVE
    specific_findings = check_cve_2021_36873(url)
    if specific_findings:
        all_findings.extend(specific_findings)
        
    # Run all generic CVEs via Nuclei engine
    mass_findings = check_all_cves(url)
    if mass_findings:
        all_findings.extend(mass_findings)
        
    return all_findings
