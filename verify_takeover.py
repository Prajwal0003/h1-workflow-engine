import requests
import dns.resolver
from urllib.parse import urlparse

def check_takeover_vulnerability(url):
    host = urlparse(url).hostname
    print(f"\n[*] Investigating {host}")
    
    # 1. DNS Verification
    print("  [1] Verifying NXDOMAIN via multiple resolvers...")
    is_nxdomain = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1'] # Google and Cloudflare
        resolver.resolve(host, 'A')
        print("    [-] Domain resolves to an IP. NOT a takeover candidate.")
        return
    except dns.resolver.NXDOMAIN:
        print("    [+] CONFIRMED: Domain throws NXDOMAIN.")
        is_nxdomain = True
    except Exception as e:
        print(f"    [?] DNS Error: {e}")
        return

    # 2. CNAME Chain Analysis
    if is_nxdomain:
        print("  [2] Analyzing CNAME chain for dangling records...")
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']
            answers = resolver.resolve(host, 'CNAME')
            for rdata in answers:
                cname_target = str(rdata.target)
                print(f"    [!] Found CNAME pointing to: {cname_target}")
                
                # Check if it points to a vulnerable cloud provider
                vuln_providers = ["s3.amazonaws.com", "github.io", "herokuapp.com", "azurewebsites.net", "trafficmanager.net", "fastly.net"]
                for provider in vuln_providers:
                    if provider in cname_target:
                        print(f"    [!!!] 100% VULNERABLE: Dangling CNAME pointing to {provider}.")
                        print(f"    [!!!] ACTION: Register the bucket/app name '{cname_target.split('.')[0]}' on {provider} to takeover!")
                        return
                
                print("    [!] Dangling CNAME points to unknown provider. Might be vulnerable, but requires manual registration investigation.")
                return
        except dns.resolver.NoAnswer:
            print("    [-] No CNAME records found. It's just an unconfigured A record. Not exploitable.")
        except Exception as e:
            print(f"    [-] Could not fetch CNAME: {e}")

if __name__ == "__main__":
    targets = [
        "https://status.wordpress.org",
        "https://glotpress.blog",
        "https://wordpress.tv",
        "https://codex.wordpress.org",
        "https://codex.bbpress.org",
        "https://codex.buddypress.org",
        "https://org.wordpress.android"
    ]
    for t in targets:
        check_takeover_vulnerability(t)
