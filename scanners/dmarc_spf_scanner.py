import dns.resolver
from rich.console import Console
import urllib.parse

console = Console()

def check_dmarc_spf(url, headers=None):
    """
    Scans for missing or weak SPF and DMARC records.
    This is a classic P4/P5 bug used to farm reputation on VDPs (Vulnerability Disclosure Programs).
    Many unpaid programs accept this for easy points.
    """
    findings = []
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(':')[0]
    
    if not domain:
        return findings
        
    console.print(f"[bold cyan][*] Scanning for Email Spoofing (DMARC/SPF): {domain}[/bold cyan]")
    
    # 1. Check SPF Record
    spf_found = False
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().lower()
            if "v=spf1" in txt:
                spf_found = True
                if "~all" in txt or "+all" in txt:
                    findings.append(f"Weak SPF Record (SoftFail/Pass All): {domain} -> {txt}")
                break
    except Exception:
        pass
        
    if not spf_found:
        findings.append(f"Missing SPF Record: {domain}")
        
    # 2. Check DMARC Record
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_found = False
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().lower()
            if "v=dmarc1" in txt:
                dmarc_found = True
                if "p=none" in txt:
                    findings.append(f"Weak DMARC Policy (p=none): {domain} -> {txt}")
                break
    except Exception:
        pass
        
    if not dmarc_found:
        findings.append(f"Missing DMARC Record: {domain}")

    if findings:
        for f in findings:
            console.print(f"[bold yellow][!] SIGNAL FARM: {f}[/bold yellow]")
    else:
        console.print("[green][+] DMARC/SPF is properly configured.[/green]")
        
    return findings
