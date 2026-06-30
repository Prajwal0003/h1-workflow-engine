"""
Vimeo IDOR Tester — Automated access control testing
=====================================================
Tests if Account B can access Account A's private resources.
YOU run this with YOUR OWN test accounts.

SETUP:
  1. Create 2 Vimeo accounts (Account A and Account B)
  2. Go to https://developer.vimeo.com/apps
  3. Create an app on EACH account and get an access token
     (Select scopes: private, video_files, edit, upload)
  4. Upload a PRIVATE video on Account A
  5. Run this script with both tokens

USAGE:
  python vimeo_idor_test.py --token-a "YOUR_TOKEN_A" --token-b "YOUR_TOKEN_B"
"""

import requests
import json
import sys
import os
import argparse
import time

if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

API_BASE = "https://api.vimeo.com"

# Colors for terminal
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def api_get(endpoint, token):
    """Make a GET request to Vimeo API."""
    try:
        resp = requests.get(
            f"{API_BASE}{endpoint}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.vimeo.*+json;version=3.4",
            },
            timeout=15,
        )
        return resp
    except requests.exceptions.RequestException as e:
        print(f"  {RED}[ERROR] Request failed: {e}{RESET}")
        return None


def api_patch(endpoint, token, data):
    """Make a PATCH request to Vimeo API."""
    try:
        resp = requests.patch(
            f"{API_BASE}{endpoint}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/vnd.vimeo.*+json;version=3.4",
            },
            json=data,
            timeout=15,
        )
        return resp
    except requests.exceptions.RequestException as e:
        print(f"  {RED}[ERROR] Request failed: {e}{RESET}")
        return None


def api_delete(endpoint, token):
    """Make a DELETE request to Vimeo API."""
    try:
        resp = requests.delete(
            f"{API_BASE}{endpoint}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.vimeo.*+json;version=3.4",
            },
            timeout=15,
        )
        return resp
    except requests.exceptions.RequestException as e:
        print(f"  {RED}[ERROR] Request failed: {e}{RESET}")
        return None


def check_result(test_name, resp, expect_blocked=True):
    """Check if an IDOR test passed or failed."""
    if resp is None:
        print(f"  {YELLOW}[SKIP]{RESET} {test_name} - Request failed")
        return "skip"

    status = resp.status_code

    if expect_blocked:
        if status in (401, 403, 404):
            print(f"  {GREEN}[SAFE]{RESET} {test_name} - Blocked ({status})")
            return "safe"
        elif status == 200:
            print(f"  {RED}[VULN]{RESET} {test_name} - {BOLD}ACCESS GRANTED ({status}) - POSSIBLE IDOR!{RESET}")
            return "vuln"
        else:
            print(f"  {YELLOW}[INFO]{RESET} {test_name} - Status {status}")
            return "info"
    else:
        if status == 200:
            print(f"  {GREEN}[OK]{RESET} {test_name} - Works ({status})")
            return "ok"
        else:
            print(f"  {YELLOW}[INFO]{RESET} {test_name} - Status {status}")
            return "info"


def main():
    parser = argparse.ArgumentParser(
        description="Vimeo IDOR Tester - Test access controls between two accounts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--token-a", required=True, help="API token for Account A (the victim)")
    parser.add_argument("--token-b", required=True, help="API token for Account B (the attacker)")
    args = parser.parse_args()

    token_a = args.token_a
    token_b = args.token_b

    print(f"""
{CYAN}{BOLD}================================================================
  VIMEO IDOR TESTER
  Testing access controls between two accounts
================================================================{RESET}

  This script checks if Account B can access Account A's
  private resources. All tests use YOUR OWN accounts only.
  
  {YELLOW}No real users are affected. No data is modified.{RESET}
""")

    findings = []

    # ===== STEP 1: Get account info =====
    print(f"{BOLD}[STEP 1] Getting account information...{RESET}")

    resp_a = api_get("/me", token_a)
    resp_b = api_get("/me", token_b)

    if not resp_a or resp_a.status_code != 200:
        print(f"  {RED}Token A is invalid. Check your token.{RESET}")
        print(f"  Status: {resp_a.status_code if resp_a else 'No response'}")
        if resp_a:
            print(f"  Response: {resp_a.text[:200]}")
        sys.exit(1)

    if not resp_b or resp_b.status_code != 200:
        print(f"  {RED}Token B is invalid. Check your token.{RESET}")
        sys.exit(1)

    user_a = resp_a.json()
    user_b = resp_b.json()

    user_a_uri = user_a.get("uri", "")
    user_b_uri = user_b.get("uri", "")
    user_a_name = user_a.get("name", "Unknown")
    user_b_name = user_b.get("name", "Unknown")

    print(f"  Account A: {user_a_name} ({user_a_uri})")
    print(f"  Account B: {user_b_name} ({user_b_uri})")
    print()

    # ===== STEP 2: Get Account A's videos =====
    print(f"{BOLD}[STEP 2] Getting Account A's videos...{RESET}")

    resp = api_get(f"{user_a_uri}/videos", token_a)
    if not resp or resp.status_code != 200:
        print(f"  {YELLOW}Could not list Account A's videos. Upload a video first.{RESET}")
        videos_a = []
    else:
        videos_a = resp.json().get("data", [])
        print(f"  Found {len(videos_a)} videos on Account A")
        for v in videos_a[:5]:
            privacy = v.get("privacy", {}).get("view", "?")
            print(f"    - {v.get('name', 'Untitled')} [{privacy}] ({v.get('uri', '')})")

    print()

    # ===== STEP 3: IDOR Tests =====
    print(f"{BOLD}[STEP 3] Running IDOR tests...{RESET}")
    print(f"  {CYAN}Testing if Account B can access Account A's resources{RESET}")
    print()

    # Test 3.1: Can B see A's profile details?
    print(f"  {BOLD}--- 3.1: Profile Access ---{RESET}")
    resp = api_get(user_a_uri, token_b)
    result = check_result("Read Account A's profile with B's token", resp)
    if result == "vuln":
        findings.append("Profile IDOR: Account B can read Account A's full profile")

    time.sleep(0.3)

    # Test 3.2: Can B list A's videos?
    print(f"\n  {BOLD}--- 3.2: Video Listing ---{RESET}")
    resp = api_get(f"{user_a_uri}/videos", token_b)
    result = check_result("List Account A's videos with B's token", resp)
    if result == "vuln":
        findings.append("Video List IDOR: Account B can list Account A's videos")
        # Check if private videos are included
        if resp:
            vids = resp.json().get("data", [])
            private_vids = [v for v in vids if v.get("privacy", {}).get("view") != "anybody"]
            if private_vids:
                print(f"    {RED}{BOLD}>>> PRIVATE VIDEOS EXPOSED! ({len(private_vids)} found){RESET}")
                findings.append(f"CRITICAL: {len(private_vids)} private videos exposed via IDOR")

    time.sleep(0.3)

    # Test 3.3: Can B access A's specific private videos?
    if videos_a:
        print(f"\n  {BOLD}--- 3.3: Direct Video Access ---{RESET}")
        for v in videos_a[:3]:
            video_uri = v.get("uri", "")
            video_name = v.get("name", "Untitled")
            privacy = v.get("privacy", {}).get("view", "?")

            resp = api_get(video_uri, token_b)
            result = check_result(
                f"Access '{video_name}' [{privacy}] with B's token",
                resp,
            )
            if result == "vuln":
                findings.append(f"Video IDOR: B can access A's video '{video_name}' (privacy: {privacy})")
            time.sleep(0.3)

    # Test 3.4: Can B edit A's profile?
    print(f"\n  {BOLD}--- 3.4: Profile Edit (Read-only test) ---{RESET}")
    # We use the same name so even if it "works", nothing changes
    resp = api_patch(user_a_uri, token_b, {"name": user_a_name})
    result = check_result("Edit Account A's profile name with B's token", resp)
    if result == "vuln":
        findings.append("Profile Edit IDOR: Account B can modify Account A's profile!")

    time.sleep(0.3)

    # Test 3.5: Can B edit A's video?
    if videos_a:
        print(f"\n  {BOLD}--- 3.5: Video Edit (Read-only test) ---{RESET}")
        v = videos_a[0]
        video_uri = v.get("uri", "")
        original_name = v.get("name", "Untitled")
        # Use same name so nothing actually changes
        resp = api_patch(video_uri, token_b, {"name": original_name})
        result = check_result(
            f"Edit video '{original_name}' with B's token",
            resp,
        )
        if result == "vuln":
            findings.append(f"Video Edit IDOR: B can edit A's video!")

    time.sleep(0.3)

    # Test 3.6: Can B access A's albums/showcases?
    print(f"\n  {BOLD}--- 3.6: Albums/Showcases ---{RESET}")
    resp = api_get(f"{user_a_uri}/albums", token_b)
    result = check_result("List Account A's albums with B's token", resp)
    if result == "vuln":
        findings.append("Albums IDOR: Account B can list Account A's albums")

    time.sleep(0.3)

    # Test 3.7: Can B access A's folders?
    print(f"\n  {BOLD}--- 3.7: Folders/Projects ---{RESET}")
    resp = api_get(f"{user_a_uri}/projects", token_b)
    result = check_result("List Account A's projects with B's token", resp)
    if result == "vuln":
        findings.append("Projects IDOR: Account B can list Account A's projects")

    time.sleep(0.3)

    # Test 3.8: Can B access A's followers/following?
    print(f"\n  {BOLD}--- 3.8: Social Data ---{RESET}")
    resp = api_get(f"{user_a_uri}/followers", token_b)
    result = check_result("List Account A's followers with B's token", resp)
    if result == "vuln":
        findings.append("Followers IDOR: Account B can list Account A's followers")

    resp = api_get(f"{user_a_uri}/following", token_b)
    result = check_result("List Account A's following with B's token", resp)

    time.sleep(0.3)

    # Test 3.9: Can B access A's likes?
    print(f"\n  {BOLD}--- 3.9: Likes ---{RESET}")
    resp = api_get(f"{user_a_uri}/likes", token_b)
    result = check_result("List Account A's liked videos with B's token", resp)
    if result == "vuln":
        findings.append("Likes IDOR: Account B can list Account A's liked videos")

    time.sleep(0.3)

    # Test 3.10: Can B access A's watch history?
    print(f"\n  {BOLD}--- 3.10: Watch History ---{RESET}")
    resp = api_get(f"{user_a_uri}/watched/videos", token_b)
    result = check_result("List Account A's watch history with B's token", resp)
    if result == "vuln":
        findings.append("Watch History IDOR: Account B can see A's watch history!")

    time.sleep(0.3)

    # Test 3.11: Can B access A's feed?
    print(f"\n  {BOLD}--- 3.11: Feed ---{RESET}")
    resp = api_get(f"{user_a_uri}/feed", token_b)
    result = check_result("Access Account A's feed with B's token", resp)
    if result == "vuln":
        findings.append("Feed IDOR: Account B can access Account A's private feed")

    time.sleep(0.3)

    # Test 3.12: Can B access A's pictures (avatars)?
    print(f"\n  {BOLD}--- 3.12: Pictures/Avatars ---{RESET}")
    resp = api_get(f"{user_a_uri}/pictures", token_b)
    result = check_result("List Account A's pictures with B's token", resp)

    time.sleep(0.3)

    # Test 3.13: Can B access A's portfolios?
    print(f"\n  {BOLD}--- 3.13: Portfolios ---{RESET}")
    resp = api_get(f"{user_a_uri}/portfolios", token_b)
    result = check_result("List Account A's portfolios with B's token", resp)

    # ===== SUMMARY =====
    print(f"""
{CYAN}{BOLD}================================================================
  RESULTS SUMMARY
================================================================{RESET}
""")

    if findings:
        print(f"  {RED}{BOLD}VULNERABILITIES FOUND: {len(findings)}{RESET}")
        print()
        for i, f in enumerate(findings, 1):
            print(f"  {RED}{i}. {f}{RESET}")

        print(f"""
  {YELLOW}{BOLD}NEXT STEPS:{RESET}
  1. Take screenshots of each finding
  2. Document the exact API calls (this script output works)
  3. Report on HackerOne: https://hackerone.com/vimeo/reports/new
  4. Use the report template in the hunting playbook
""")
    else:
        print(f"  {GREEN}{BOLD}No IDOR vulnerabilities found.{RESET}")
        print(f"  Vimeo's access controls appear to be working correctly")
        print(f"  for the endpoints tested.")
        print()
        print(f"  {CYAN}This doesn't mean there are NO bugs — try:{RESET}")
        print(f"  - Testing with different video privacy settings")
        print(f"  - Testing team/organization endpoints if you have a team account")
        print(f"  - Testing with numeric IDs instead of URI paths")
        print(f"  - Testing GraphQL endpoints if available")

    # Save results
    results_file = os.path.join(os.path.dirname(__file__), "data", "recon", "vimeo_idor_results.json")
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    with open(results_file, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user_a": user_a_uri,
            "user_b": user_b_uri,
            "findings": findings,
            "total_tests": 13,
            "vulnerabilities": len(findings),
        }, f, indent=2)
    print(f"\n  Results saved to: {results_file}")


if __name__ == "__main__":
    main()
