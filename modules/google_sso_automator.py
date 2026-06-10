import asyncio
import json
import logging
from pathlib import Path
from playwright.async_api import async_playwright

logging.basicConfig(level=logging.INFO)

import requests

def send_discord_alert(msg):
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "DISCORD_WEBHOOK_URL=" in line:
                url = line.split("=")[1].strip().strip('"').strip("'")
                try:
                    requests.post(url, json={"content": msg}, timeout=3)
                except: pass

async def check_has_sso(target_login_url):
    """Headless pre-check to see if a page actually has a Google SSO button."""
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(target_login_url, timeout=15000)
            sso_button = page.locator("button:has-text('Google'), a:has-text('Google'), div[role='button']:has-text('Google')").first
            await sso_button.wait_for(state="visible", timeout=5000)
            await browser.close()
            return True
        except Exception:
            try: await browser.close()
            except: pass
            return False

async def automate_google_login(target_login_url, email, password, profile_dir_name):
    """
    Automates Google SSO on a target website.
    Uses a persistent browser context to avoid Google's anti-bot protections.
    """
    # First, do a silent headless check so we don't pop up windows on random sites (like truecaller business)
    if not await check_has_sso(target_login_url):
        logging.info(f"[!] No Google SSO detected on {target_login_url}. Skipping interactive login to prevent unwanted popups.")
        return ""
        
    profile_path = Path("data/browser_profiles") / profile_dir_name
    profile_path.mkdir(parents=True, exist_ok=True)
    
    async with async_playwright() as p:
        # Launch non-headless to avoid Google anti-bot and allow manual CAPTCHA solving if needed
        browser = await p.chromium.launch_persistent_context(
            user_data_dir=str(profile_path),
            headless=False, # Restored to visible mode as requested by user
            args=["--disable-blink-features=AutomationControlled"]
        )
        
        page = browser.pages[0] if browser.pages else await browser.new_page()
        
        logging.info(f"[*] Navigating to {target_login_url}")
        await page.goto(target_login_url)
        
        # 1. Look for the "Sign in with Google" button on the target site
        logging.info("[*] Attempting to find Google SSO button...")
        try:
            # Common selectors for Google SSO buttons
            sso_button = page.locator("button:has-text('Google'), a:has-text('Google'), div[role='button']:has-text('Google')").first
            await sso_button.wait_for(state="visible", timeout=10000)
            await sso_button.click()
        except Exception:
            logging.warning("[!] Could not auto-detect Google SSO button. Please click it manually in the opened browser within 20 seconds.")
            await asyncio.sleep(20)
            
        # 2. Wait for Google Login popup or redirect
        logging.info("[*] Waiting for Google authentication page...")
        try:
            await page.wait_for_url("**/accounts.google.com/**", timeout=15000)
            
            # Check if "Choose an account" is visible (Profile already exists)
            choose_account = page.locator(f"div[data-email='{email}']")
            if await choose_account.count() > 0:
                logging.info("[*] Persistent session detected! Clicking 'Choose an account' instead of typing credentials.")
                await choose_account.first.click()
            else:
                # Fresh login flow
                # Fill Email
                logging.info(f"[*] Entering email: {email}")
                await page.fill("input[type='email']", email)
                await page.keyboard.press("Enter")
                
                # Wait for password field
                await page.wait_for_selector("input[type='password']", state="visible", timeout=10000)
                await asyncio.sleep(1) # Small delay to act human
                
                # Fill Password
                logging.info("[*] Entering password...")
                await page.fill("input[type='password']", password)
                await page.keyboard.press("Enter")
                
                send_discord_alert(f"🚨 **Action Required:** The Autopilot is logging into `{target_login_url}` using `{email}`. Please check your phone for a Google 2FA/Verification prompt!")
                
            # Wait for redirect back to target
            logging.info("[*] Waiting for redirect back to target application...")
            await page.wait_for_url(lambda url: "accounts.google.com" not in url, timeout=45000)
            send_discord_alert(f"✅ Google login successful for `{email}`!")
            
        except Exception as e:
            logging.info("[*] Already logged in to Google in this profile, or manual intervention required.")
            # Wait a bit for the user to manually intervene if Google throws a CAPTCHA or 2FA
            await asyncio.sleep(15)
            
        logging.info("[*] Login flow complete. Extracting session cookies...")
        await asyncio.sleep(5) # Let the target site load and set its JWTs/Cookies
        
        cookies = await browser.cookies()
        cookie_dict = {c["name"]: c["value"] for c in cookies}
        
        # Convert to string format for the scanner
        cookie_string = "; ".join([f"{k}={v}" for k, v in cookie_dict.items()])
        logging.info(f"[+] Successfully extracted {len(cookie_dict)} cookies!")
        
        await browser.close()
        return cookie_string

def get_sso_credentials(target_url, email_a, pass_a, email_b, pass_b):
    logging.info(f"=== Starting Automated Google SSO for {target_url} ===")
    
    cookie_a = asyncio.run(automate_google_login(target_url, email_a, pass_a, "profile_a"))
    cookie_b = asyncio.run(automate_google_login(target_url, email_b, pass_b, "profile_b"))
    
    # Save to idor_credentials.json dynamically
    creds_file = Path("data/idor_credentials.json")
    try:
        creds = json.loads(creds_file.read_text())
    except:
        creds = {}
        
    # Extract domain as key
    domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
    
    creds[domain] = {
        "user_a_cookie": cookie_a,
        "user_b_cookie": cookie_b
    }
    
    creds_file.write_text(json.dumps(creds, indent=2))
    logging.info(f"[+] Saved fresh IDOR credentials for {domain}!")
    return creds[domain]

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 6:
        print("Usage: python google_sso_automator.py <login_url> <email_a> <pass_a> <email_b> <pass_b>")
    else:
        get_sso_credentials(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
