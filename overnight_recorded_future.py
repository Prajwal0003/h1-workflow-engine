#!/usr/bin/env python3
"""
Recorded Future — 24/7 Continuous Bug Bounty Scanner
====================================================
Runs indefinitely, cycling through all 7 in-scope targets with
rotating attack modules. Sleeps between cycles to avoid rate limiting.

Target: https://bugcrowd.com/engagements/recorded-future-mbb-og
Rewards: P1=$5,000 | P2=$2,000 | P3=$750 | P4=$250

Usage: python overnight_recorded_future.py
       (runs until you Ctrl+C it)
"""
import requests
import re
import json
import time
import sys
import os
import random
from pathlib import Path
from datetime import datetime

os.environ["PYTHONIOENCODING"] = "utf-8"
try: sys.stdout.reconfigure(encoding="utf-8")
except: pass

# ── Configuration ──
TARGETS = [
    "https://www.recordedfuture.com",
    "https://app.recordedfuture.com",
    "https://api.recordedfuture.com",
    "https://id.recordedfuture.com",
    "https://tria.ge",
    "https://hatching.io",
    "https://geminiadvisory.io",
]

# Subdomains to discover
SUBDOMAIN_WORDLIST = [
    "admin", "staging", "dev", "test", "qa", "uat", "beta", "alpha",
    "internal", "vpn", "mail", "smtp", "pop", "imap", "ftp", "sftp",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "deploy",
    "jira", "confluence", "wiki", "docs", "blog", "portal", "dashboard",
    "grafana", "kibana", "prometheus", "sentry", "monitor", "status",
    "cdn", "static", "assets", "media", "images", "files", "upload",
    "sandbox", "demo", "preview", "stage", "prod", "production",
    "auth", "sso", "login", "oauth", "saml", "ldap", "cas",
    "api-v1", "api-v2", "api-v3", "gateway", "proxy", "lb",
    "db", "redis", "mongo", "elastic", "kafka", "rabbit", "mq",
    "backup", "archive", "legacy", "old", "new", "v2", "v3",
    "support", "help", "feedback", "ticket", "crm",
    "shop", "store", "billing", "payment", "invoice",
    "data", "analytics", "metrics", "logs", "trace",
    "ws", "websocket", "socket", "stream", "events", "hook", "webhook",
]

RESULTS_DIR = Path("data/autopilot/overnight")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = RESULTS_DIR / "overnight_log.jsonl"

ALL_FINDINGS = []
CYCLE_COUNT = 0

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(msg):
    print(f"[{ts()}] {msg}")

def save_finding(finding):
    ALL_FINDINGS.append(finding)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(finding, default=str) + "\n")
    sev = finding.get("severity", "INFO")
    emoji = {"CRITICAL":"!!!","HIGH":"!!","MEDIUM":"!","LOW":".","INFO":"i"}.get(sev,"?")
    log(f"  [{emoji}] [{sev}] {finding.get('type','?')} @ {finding.get('url','?')[:60]}")

def get_headers():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]
    return {
        "User-Agent": random.choice(agents),
        "Accept": "text/html,application/json",
        "Accept-Language": "en-US,en;q=0.9",
    }

def safe_get(url, **kwargs):
    try:
        return requests.get(url, headers=get_headers(), timeout=kwargs.get("timeout", 8), 
                          allow_redirects=kwargs.get("redirects", True), verify=True)
    except:
        return None

# ── Attack Module 1: Subdomain Discovery ──
def scan_subdomains(base_domain):
    log(f"[SUBDOMAIN] Enumerating subdomains for {base_domain}...")
    found = []
    for word in SUBDOMAIN_WORDLIST:
        sub = f"https://{word}.{base_domain}"
        try:
            r = requests.get(sub, headers=get_headers(), timeout=3, allow_redirects=True)
            if r.status_code < 500:
                found.append(sub)
                log(f"  LIVE: {sub} [{r.status_code}]")
                
                # Check for sensitive subdomains
                if word in ["admin","staging","dev","test","qa","uat","internal","jenkins",
                           "gitlab","jira","confluence","grafana","kibana","sentry"]:
                    save_finding({
                        "severity": "HIGH",
                        "type": "SENSITIVE_SUBDOMAIN",
                        "url": sub,
                        "detail": f"Internal/sensitive subdomain {word}.{base_domain} is publicly accessible",
                        "timestamp": str(datetime.now()),
                    })
        except:
            pass
    log(f"  Found {len(found)} live subdomains for {base_domain}")
    return found

# ── Attack Module 2: Header Analysis ──
def scan_headers(url):
    log(f"[HEADERS] Analyzing response headers for {url}...")
    r = safe_get(url)
    if not r: return
    
    # Check for missing security headers
    important = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "XCTO",
        "X-Frame-Options": "XFO",
    }
    for header, name in important.items():
        if header not in r.headers:
            save_finding({
                "severity": "LOW",
                "type": f"MISSING_SECURITY_HEADER_{name}",
                "url": url,
                "detail": f"Missing {header} header",
                "timestamp": str(datetime.now()),
            })
    
    # Check for info leaks in headers
    for k, v in r.headers.items():
        kl = k.lower()
        if any(x in kl for x in ["x-powered", "x-aspnet", "x-debug", "x-runtime"]):
            save_finding({
                "severity": "LOW",
                "type": "SERVER_INFO_LEAK_HEADER",
                "url": url,
                "detail": f"Info leak header: {k}: {v}",
                "timestamp": str(datetime.now()),
            })
        if "internal" in v.lower() or "staging" in v.lower() or "debug" in v.lower():
            save_finding({
                "severity": "MEDIUM",
                "type": "INTERNAL_INFO_LEAK_HEADER",
                "url": url,
                "detail": f"Internal info in header: {k}: {v}",
                "timestamp": str(datetime.now()),
            })

# ── Attack Module 3: JS Secret Extraction ──
def scan_js_secrets(url):
    log(f"[JS-SECRETS] Scanning JS bundles from {url}...")
    r = safe_get(url)
    if not r: return
    
    js_links = re.findall(r'src="([^"]*\.js[^"]*)"', r.text)
    
    patterns = {
        "AWS_KEY": r'AKIA[0-9A-Z]{16}',
        "PRIVATE_KEY": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        "SLACK_WEBHOOK": r'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
        "SLACK_TOKEN": r'xox[bpors]-[0-9a-zA-Z-]+',
        "GITHUB_TOKEN": r'gh[pso]_[A-Za-z0-9_]{36,}',
        "GOOGLE_API": r'AIza[0-9A-Za-z_-]{35}',
        "SENTRY_DSN": r'https://[a-f0-9]+@[a-z0-9.]*sentry[a-z0-9.]*/\d+',
        "JWT_TOKEN": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        "INTERNAL_URL": r'https?://[a-z0-9.-]+\.(internal|corp|local|staging|dev)\.[a-z]+',
        "FIREBASE": r'[a-z0-9-]+\.firebaseio\.com',
        "MAILGUN": r'key-[0-9a-zA-Z]{32}',
        "TWILIO": r'SK[a-f0-9]{32}',
        "STRIPE": r'sk_live_[0-9a-zA-Z]{24,}',
        "HEROKU": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    }
    
    for link in js_links[:20]:
        if not link.startswith("http"):
            base = url.rstrip("/")
            link = base + link if link.startswith("/") else base + "/" + link
        
        try:
            jr = safe_get(link, timeout=5)
            if not jr: continue
            text = jr.text
            
            for name, pattern in patterns.items():
                matches = re.findall(pattern, text)
                if matches:
                    for m in matches[:2]:
                        val = m if isinstance(m, str) else str(m)
                        # Skip known false positives (redaction regexes, etc)
                        idx = text.find(val)
                        context = text[max(0,idx-30):min(len(text),idx+len(val)+30)] if idx > -1 else ""
                        if "replace(" in context or "regex" in context.lower() or "filter" in context.lower():
                            continue
                        save_finding({
                            "severity": "HIGH" if name in ["AWS_KEY","PRIVATE_KEY","STRIPE","SLACK_TOKEN","GITHUB_TOKEN"] else "MEDIUM",
                            "type": f"JS_SECRET_{name}",
                            "url": link,
                            "detail": f"Found {name}: {val[:60]}...",
                            "timestamp": str(datetime.now()),
                        })
        except:
            pass

# ── Attack Module 4: API Endpoint Discovery ──
def scan_api_endpoints(url):
    log(f"[API] Probing API endpoints on {url}...")
    
    paths = [
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/graphql", "/graphiql",
        "/.well-known/openid-configuration",
        "/.well-known/security.txt",
        "/swagger.json", "/swagger/", "/swagger-ui/",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/redoc/",
        "/health", "/healthz", "/ready", "/readyz",
        "/status", "/version", "/info",
        "/robots.txt", "/sitemap.xml",
        "/debug/", "/debug/vars", "/debug/pprof/",
        "/metrics", "/prometheus/",
        "/admin/", "/admin/login",
        "/.env", "/.git/config", "/.git/HEAD",
        "/config.json", "/config.yml",
        "/wp-json/", "/wp-admin/",
        "/actuator/", "/actuator/env", "/actuator/health",
    ]
    
    for path in paths:
        full = url.rstrip("/") + path
        r = safe_get(full, timeout=5)
        if not r: continue
        
        if r.status_code == 200:
            ct = r.headers.get("Content-Type", "")
            
            # High-value finds
            if path in ["/.env", "/.git/config", "/.git/HEAD", "/debug/vars", "/debug/pprof/",
                        "/actuator/env", "/config.json"]:
                save_finding({
                    "severity": "CRITICAL",
                    "type": "SENSITIVE_ENDPOINT_EXPOSED",
                    "url": full,
                    "detail": f"Sensitive endpoint accessible: {path} (Status: 200, Type: {ct[:30]})",
                    "timestamp": str(datetime.now()),
                })
            elif path in ["/swagger.json", "/openapi.json", "/graphiql", "/api-docs"]:
                save_finding({
                    "severity": "MEDIUM",
                    "type": "API_DOCS_EXPOSED",
                    "url": full,
                    "detail": f"API documentation accessible: {path}",
                    "timestamp": str(datetime.now()),
                })
            elif "json" in ct:
                try:
                    data = r.json()
                    body = json.dumps(data)[:300]
                    if any(kw in body.lower() for kw in ["token","secret","password","key","admin","email"]):
                        save_finding({
                            "severity": "HIGH",
                            "type": "API_INFO_DISCLOSURE",
                            "url": full,
                            "detail": f"Sensitive data in JSON response: {body[:150]}",
                            "timestamp": str(datetime.now()),
                        })
                except:
                    pass

# ── Attack Module 5: CORS Misconfiguration ──
def scan_cors(url):
    log(f"[CORS] Testing CORS policy on {url}...")
    
    evil_origins = [
        "https://evil.com",
        "https://recordedfuture.com.evil.com",
        "null",
        "https://www.recordedfuture.com.attacker.com",
    ]
    
    for origin in evil_origins:
        try:
            headers = get_headers()
            headers["Origin"] = origin
            r = requests.get(url, headers=headers, timeout=5)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == origin or acao == "*":
                sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
                save_finding({
                    "severity": sev,
                    "type": "CORS_MISCONFIGURATION",
                    "url": url,
                    "detail": f"Reflected origin: {origin} -> ACAO: {acao}, ACAC: {acac}",
                    "timestamp": str(datetime.now()),
                })
        except:
            pass

# ── Attack Module 6: Open Redirect ──
def scan_open_redirect(url):
    log(f"[REDIRECT] Testing open redirects on {url}...")
    
    payloads = [
        "//evil.com", "//evil.com/%2f..",
        "https://evil.com", "/\\evil.com",
        "////evil.com", "https:evil.com",
    ]
    params = ["url", "redirect", "next", "return", "returnTo", "goto", "target", "rurl", "dest", "redirect_uri", "continue"]
    
    for param in params:
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"
            try:
                r = requests.get(test_url, headers=get_headers(), timeout=5, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    save_finding({
                        "severity": "MEDIUM",
                        "type": "OPEN_REDIRECT",
                        "url": test_url,
                        "detail": f"Redirects to: {loc}",
                        "timestamp": str(datetime.now()),
                    })
                    return  # One is enough
            except:
                pass

# ── Attack Module 7: GraphQL Introspection ──
def scan_graphql(url):
    log(f"[GRAPHQL] Testing GraphQL introspection on {url}...")
    
    gql_paths = ["/graphql", "/graphiql", "/api/graphql", "/gql", "/query"]
    introspection = '{"query":"{ __schema { types { name } } }"}'
    
    for path in gql_paths:
        full = url.rstrip("/") + path
        try:
            headers = get_headers()
            headers["Content-Type"] = "application/json"
            r = requests.post(full, data=introspection, headers=headers, timeout=5)
            if r.status_code == 200 and "__schema" in r.text:
                save_finding({
                    "severity": "MEDIUM",
                    "type": "GRAPHQL_INTROSPECTION_ENABLED",
                    "url": full,
                    "detail": f"Full GraphQL schema introspection is enabled",
                    "timestamp": str(datetime.now()),
                })
        except:
            pass

# ── Main Loop ──
def run_cycle():
    global CYCLE_COUNT
    CYCLE_COUNT += 1
    
    log(f"")
    log(f"{'='*70}")
    log(f"  CYCLE #{CYCLE_COUNT} STARTING")
    log(f"  Targets: {len(TARGETS)} | Total findings so far: {len(ALL_FINDINGS)}")
    log(f"{'='*70}")
    
    for target in TARGETS:
        log(f"")
        log(f"--- Scanning: {target} ---")
        
        # Run all attack modules
        scan_headers(target)
        scan_cors(target)
        scan_api_endpoints(target)
        scan_js_secrets(target)
        scan_open_redirect(target)
        scan_graphql(target)
        
        # Small delay between targets
        time.sleep(random.uniform(2, 5))
    
    # Subdomain scan (only every 5th cycle to avoid hammering DNS)
    if CYCLE_COUNT % 5 == 1:
        for domain in ["recordedfuture.com", "tria.ge", "hatching.io", "geminiadvisory.io"]:
            scan_subdomains(domain)
    
    # Save cycle results
    cycle_file = RESULTS_DIR / f"cycle_{CYCLE_COUNT}_{int(time.time())}.json"
    cycle_file.write_text(json.dumps(ALL_FINDINGS, indent=2, default=str), encoding="utf-8")
    log(f"")
    log(f"Cycle #{CYCLE_COUNT} complete. {len(ALL_FINDINGS)} total findings saved to {cycle_file.name}")

def main():
    log(f"")
    log(f"{'='*70}")
    log(f"  RECORDED FUTURE 24/7 CONTINUOUS SCANNER")
    log(f"  Program: https://bugcrowd.com/engagements/recorded-future-mbb-og")
    log(f"  Targets: {len(TARGETS)} domains")
    log(f"  Rewards: P1=$5,000 | P2=$2,000 | P3=$750 | P4=$250")
    log(f"  Press Ctrl+C to stop")
    log(f"{'='*70}")
    
    cycle_delay = 300  # 5 minutes between full cycles
    
    while True:
        try:
            run_cycle()
            log(f"")
            log(f"Sleeping {cycle_delay//60} minutes before next cycle...")
            time.sleep(cycle_delay)
        except KeyboardInterrupt:
            log(f"")
            log(f"Stopped by user. Total findings: {len(ALL_FINDINGS)}")
            
            # Final save
            final = RESULTS_DIR / f"final_results_{int(time.time())}.json"
            final.write_text(json.dumps(ALL_FINDINGS, indent=2, default=str), encoding="utf-8")
            log(f"Final results saved to: {final}")
            break
        except Exception as e:
            log(f"Error in cycle: {e}")
            log(f"Retrying in 60 seconds...")
            time.sleep(60)

if __name__ == "__main__":
    main()
