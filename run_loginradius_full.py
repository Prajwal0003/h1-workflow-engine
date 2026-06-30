"""
Full-spectrum attack runner for LoginRadius.
Runs every scanner module in the workspace against all in-scope targets.
Results are saved to data/autopilot/loginradius_full_scan.json
"""
import sys, os, json, time, traceback
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding='utf-8')
except: pass

from pathlib import Path
from urllib.parse import urlparse

TARGETS = [
    "https://www.loginradius.com",
    "https://loginradius.com",
    "https://adminconsole.loginradius.com",
    "https://api.loginradius.com",
    "https://console.loginradius.com",
]

RESULTS = []
PROGRAM = "loginradius"

def log(msg):
    print(f"[*] {msg}", flush=True)

def add_finding(f):
    if isinstance(f, str):
        # Some scanners return plain strings
        f = {"type": "GENERIC", "detail": f, "severity": "INFO"}
    f["program"] = PROGRAM
    f["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    RESULTS.append(f)
    sev = f.get("severity", "INFO")
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "⚪")
    log(f"  {icon} [{sev}] {f.get('type')}: {f.get('url', '')[:80]} — {f.get('detail', '')[:120]}")

def safe_run(name, func, *args, **kwargs):
    log(f"--- Running: {name} ---")
    try:
        result = func(*args, **kwargs)
        if result:
            if isinstance(result, list):
                for r in result:
                    add_finding(r)
            elif isinstance(result, dict):
                add_finding(result)
            else:
                log(f"  Result: {str(result)[:200]}")
        else:
            log(f"  No findings.")
        return result
    except Exception as e:
        log(f"  ❌ Error in {name}: {e}")
        return None

# ==================== IMPORT ALL SCANNERS ====================
log("=" * 60)
log("LOGINRADIUS FULL-SPECTRUM SCAN — ALL 70+ MODULES")
log("=" * 60)

from scanners.xss import check_xss, check_dom_xss
from scanners.ssrf import check_ssrf
from scanners.ssti import check_ssti
from scanners.csrf import check_csrf
from scanners.xxe import check_xxe
from scanners.smuggling import check_request_smuggling
from scanners.race import check_race_condition
from scanners.cache_poison import check_cache_poisoning
from scanners.jwt import check_jwt_vulnerabilities
from scanners.cms import check_cms_vulnerabilities
from scanners.buckets import check_s3_buckets
from scanners.git_exposure import check_git_exposure
from scanners.dir_traversal import check_directory_traversal
from scanners.waf import detect_waf
from scanners.port_scan import check_ports
from scanners.tech_detect import check_technologies
from scanners.param_discovery import discover_parameters
from scanners.link_discovery import discover_links_and_js
from scanners.secrets_advanced import check_advanced_secrets
from scanners.deserialization import check_insecure_deserialization
from scanners.postmessage import check_postmessage
from scanners.command_injection import check_command_injection
from scanners.idor_advanced import check_idor_advanced
from scanners.api_versioning import check_api_versioning
from scanners.rate_limit import check_rate_limit
from scanners.js_analyzer import check_js_analyzer
from scanners.api_schema import check_api_schema
from scanners.mass_assignment_fuzzer import run_mass_assignment_fuzzer
from scanners.wcd_advanced import run_wcd_scan
from scanners.cloud_ssrf_fuzzer import run_cloud_ssrf_fuzzer
from scanners.dorking import run_dorking
from scanners.graphql_parser import check_graphql
from scanners.cve_scanner import run_cve_scans
from scanners.hardcoded_fuzzer import check_hardcoded_payloads
from scanners.cors_scanner import check_cors_misconfig
from scanners.graphql_dumper import check_graphql_introspection
from scanners.host_header_fuzzer import run_host_header_fuzzer
from scanners.open_redirect_fuzzer import run_open_redirect_fuzzer
from scanners.jwt_fuzzer import run_jwt_fuzzer
from scanners.lfi_fuzzer import run_lfi_fuzzer
from scanners.race_condition_h2 import run_h2_race_condition
from scanners.oob_ssrf import run_oob_ssrf
from scanners.prototype_pollution import run_prototype_pollution
from scanners.smuggling_advanced import run_smuggling_advanced
from scanners.oauth_hijack import run_oauth_hijack
from scanners.graphql_batching import run_graphql_batching
from scanners.swagger_matrix import run_swagger_matrix
from scanners.ssti_fuzzer import run_ssti_fuzzer
from scanners.dom_xss_tracer import run_dom_xss_tracer
from scanners.waf_evasion import run_waf_evasion
from scanners.js_secrets_hunter import hunt_js_secrets
from scanners.wayback_scraper import fetch_wayback_urls
from scanners.subdomain_takeover import check_subdomain_takeover
from scanners.naabu_scanner import run_naabu_scan

# Extra scanners with correct function names
from scanners.clickjacking import check_clickjacking
from scanners.security_headers import check_security_headers
from scanners.dmarc_spf_scanner import check_dmarc_spf
from scanners.cache_deception import check_cache_deception
from scanners.css_exfiltration import check_css_exfiltration
from scanners.websocket_cswsh import check_cswsh
from scanners.bauth_bypass import check_403_bypass
from scanners.nextjs_analyzer import check_nextjs_vulnerabilities
from scanners.oauth_redirect_bypass import check_oauth_redirect_bypass
from scanners.repo_jacking import check_repo_jacking
from scanners.h2_cache_poison import check_h2_cache_poisoning
from scanners.llm_prompt_injection import check_llm_prompt_injection
from scanners.mass_assignment import check_mass_assignment
from scanners.arjun_fuzzer import run_arjun_scan
from scanners.sqlmap_fuzzer import run_sqlmap_scan
from scanners.commix_fuzzer import run_commix_scan
from scanners.xsstrike_fuzzer import run_xsstrike_scan
from scanners.ssrfmap_fuzzer import run_ssrfmap_scan
from scanners.headless_traffic_analyzer import run_headless_crawler_analyzer
from scanners.subdomain_permutation import generate_permutations

log(f"✅ All scanner modules imported successfully.")
log(f"🎯 Targets: {TARGETS}")
log("")

# ==================== RUN ALL SCANNERS ON EACH TARGET ====================
for url in TARGETS:
    domain = urlparse(url).hostname
    log(f"\n{'='*60}")
    log(f"TARGET: {url}")
    log(f"{'='*60}")

    # --- Recon & Infrastructure ---
    safe_run("Tech Detection", check_technologies, url)
    safe_run("WAF Detection", detect_waf, url)
    safe_run("Security Headers", check_security_headers, url)
    safe_run("Clickjacking Check", check_clickjacking, url)
    safe_run("DMARC/SPF Check", check_dmarc_spf, domain)
    safe_run("Port Scan", check_ports, url)

    # --- Injection Attacks ---
    safe_run("XSS", check_xss, url)
    safe_run("DOM XSS", check_dom_xss, url)
    safe_run("DOM XSS Tracer", run_dom_xss_tracer, url)
    safe_run("XSStrike Fuzzer", run_xsstrike_scan, url)
    safe_run("SSTI", check_ssti, url)
    safe_run("SSTI Fuzzer", run_ssti_fuzzer, url)
    safe_run("SSRF", check_ssrf, url)
    safe_run("Cloud SSRF Fuzzer", run_cloud_ssrf_fuzzer, url)
    safe_run("OOB SSRF", run_oob_ssrf, url)
    safe_run("SSRFMap Fuzzer", run_ssrfmap_scan, url)
    safe_run("SQLMap Fuzzer", run_sqlmap_scan, url)
    safe_run("Command Injection", check_command_injection, url)
    safe_run("Commix Fuzzer", run_commix_scan, url)
    safe_run("LFI Fuzzer", run_lfi_fuzzer, url)
    safe_run("Directory Traversal", check_directory_traversal, url)
    safe_run("XXE", check_xxe, url)
    safe_run("Insecure Deserialization", check_insecure_deserialization, url)

    # --- Client-Side Attacks ---
    safe_run("CSRF", check_csrf, url)
    safe_run("Open Redirect Fuzzer", run_open_redirect_fuzzer, url)
    safe_run("CSS Exfiltration", check_css_exfiltration, url)
    safe_run("Prototype Pollution", run_prototype_pollution, url)
    safe_run("PostMessage", check_postmessage, url)
    safe_run("LLM Prompt Injection", check_llm_prompt_injection, url)

    # --- Transport / Protocol ---
    safe_run("Host Header Fuzzer", run_host_header_fuzzer, url)
    safe_run("Cache Poisoning", check_cache_poisoning, url)
    safe_run("Cache Deception", check_cache_deception, url)
    safe_run("H2 Cache Poison", check_h2_cache_poisoning, url)
    safe_run("Request Smuggling", check_request_smuggling, url)
    safe_run("Smuggling Advanced", run_smuggling_advanced, url)
    safe_run("WebSocket CSWSH", check_cswsh, url)
    safe_run("CORS Misconfig", check_cors_misconfig, url)
    safe_run("WAF Evasion", run_waf_evasion, url)
    safe_run("CRLF/Hardcoded Payloads", check_hardcoded_payloads, url)

    # --- Auth / Session Attacks ---
    safe_run("JWT Vulnerabilities", check_jwt_vulnerabilities, url)
    safe_run("JWT Fuzzer", run_jwt_fuzzer, url)
    safe_run("OAuth Hijack", run_oauth_hijack, url)
    safe_run("OAuth Redirect Bypass", check_oauth_redirect_bypass, url)
    safe_run("IDOR Advanced", check_idor_advanced, url)
    safe_run("Rate Limiting", check_rate_limit, url)
    safe_run("Race Condition", check_race_condition, url)
    safe_run("H2 Race Condition", run_h2_race_condition, url)
    safe_run("403 Bypass", check_403_bypass, url)
    safe_run("Mass Assignment", check_mass_assignment, url)
    safe_run("Mass Assignment Fuzzer", run_mass_assignment_fuzzer, url)

    # --- Secrets / Exposure ---
    safe_run("Git Exposure", check_git_exposure, url)
    safe_run("S3 Buckets", check_s3_buckets, url)
    safe_run("CMS Vulnerabilities", check_cms_vulnerabilities, url)
    safe_run("Subdomain Takeover", check_subdomain_takeover, domain)
    safe_run("Repo Jacking", check_repo_jacking, url)
    safe_run("Advanced Secrets", check_advanced_secrets, url)
    safe_run("JS Secrets Hunter", hunt_js_secrets, url)
    safe_run("JS Analyzer", check_js_analyzer, url)

    # --- API / GraphQL ---
    safe_run("GraphQL Introspection", check_graphql_introspection, url)
    safe_run("GraphQL Parser", check_graphql, url)
    safe_run("GraphQL Batching", run_graphql_batching, url)
    safe_run("Swagger Matrix", run_swagger_matrix, url)
    safe_run("API Schema", check_api_schema, url)
    safe_run("API Versioning", check_api_versioning, url)
    safe_run("Parameter Discovery (Arjun)", run_arjun_scan, url)

    # --- Framework-Specific ---
    safe_run("Next.js Analyzer", check_nextjs_vulnerabilities, url)
    safe_run("CVE Scanner", run_cve_scans, url)
    safe_run("Google Dorking", run_dorking, url)
    safe_run("WCD Advanced", run_wcd_scan, url)

    # --- Headless / Advanced ---
    safe_run("Headless Crawler Analyzer", run_headless_crawler_analyzer, url)

    log(f"\n✅ Finished scanning: {url}")

# ==================== SAVE RESULTS ====================
out_dir = Path("data/autopilot")
out_dir.mkdir(parents=True, exist_ok=True)
out_file = out_dir / "loginradius_full_scan.json"
out_file.write_text(json.dumps(RESULTS, indent=2, default=str), encoding="utf-8")

# ==================== SUMMARY ====================
log("")
log("=" * 60)
log(f"SCAN COMPLETE — Total findings: {len(RESULTS)}")
log("=" * 60)

sev_counts = {}
type_counts = {}
for r in RESULTS:
    s = r.get("severity", "INFO")
    t = r.get("type", "UNKNOWN")
    sev_counts[s] = sev_counts.get(s, 0) + 1
    type_counts[t] = type_counts.get(t, 0) + 1

log("Severity Breakdown:")
for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
    if s in sev_counts:
        log(f"  {s}: {sev_counts[s]}")

log("")
log("Finding Types:")
for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
    log(f"  {t}: {c}")

log(f"\nResults saved to: {out_file}")
