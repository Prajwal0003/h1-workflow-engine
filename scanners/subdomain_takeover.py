import dns.resolver
import requests

TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": "NoSuchBucket",
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "zendesk.com": "Help Center Closed",
    "pantheonsite.io": "The lack of site indicates",
    "wpengine.com": "Do you want to register",
    "fastly.net": "Fastly error: unknown domain"
}

def check_subdomain_takeover(url):
    """
    Analyzes the DNS CNAME records of the target to find dangling subdomains
    that point to unclaimed cloud services (S3, Github, Shopify).
    """
    findings = []
    domain = url.split("//")[-1].split("/")[0]
    
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).rstrip('.').lower()
            
            for vulnerable_cname, error_msg in TAKEOVER_SIGNATURES.items():
                if vulnerable_cname in cname:
                    print(f"[*] Subdomain Takeover Engine investigating potential dangling CNAME: {cname} on {domain}")
                    try:
                        # Verify it's actually unclaimed by fetching HTTP and checking the signature
                        r = requests.get(f"http://{domain}", timeout=5, verify=False)
                        if error_msg in r.text:
                            findings.append({
                                "type": "SUBDOMAIN_TAKEOVER",
                                "url": url,
                                "severity": "CRITICAL",
                                "confidence": "HIGH",
                                "verified": True,
                                "detail": f"Subdomain {domain} is pointing to an unclaimed {vulnerable_cname} service via CNAME ({cname})! Immediate takeover is possible."
                            })
                    except Exception:
                        pass
    except Exception:
        pass
        
    return findings
