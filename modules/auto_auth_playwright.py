import asyncio
import json
from playwright.async_api import async_playwright

async def get_session_cookies(login_url, username, password, username_selector, password_selector, submit_selector):
    async with async_playwright() as p:
        # Launch Chromium headless
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        print(f"[*] Navigating to {login_url}")
        await page.goto(login_url)

        print(f"[*] Filling credentials for {username}")
        await page.fill(username_selector, username)
        await page.fill(password_selector, password)
        
        print("[*] Submitting login form")
        # Click the submit button and wait for navigation (dashboard load)
        async with page.expect_navigation():
            await page.click(submit_selector)
        
        # Give the page an extra second to set any async cookies (like JWTs)
        await asyncio.sleep(2)

        print("[*] Extracting cookies")
        cookies = await context.cookies()
        
        # Convert playwright cookies to a standard dict for requests.Session
        cookie_dict = {c["name"]: c["value"] for c in cookies}
        
        await browser.close()
        return cookie_dict

def extract_cookies_sync(login_url, username, password, u_sel, p_sel, s_sel):
    return asyncio.run(get_session_cookies(login_url, username, password, u_sel, p_sel, s_sel))

if __name__ == "__main__":
    # Test script block
    print("Testing Playwright Auth Module")
