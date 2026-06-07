import argparse
from playwright.sync_api import sync_playwright
import time

def solve_ctf(url, username, password, challenge_name, flag):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        print(f"Navigating to login page: {url}/login")
        page.goto(f'{url}/login')

        print("Filling credentials...")
        page.fill('input[name="name"]', username)
        page.fill('input[name="password"]', password)
        
        print("Submitting login...")
        page.click('button[type="submit"], input[type="submit"], #submit')
        
        print("Logged in. Navigating to challenges...")
        time.sleep(3)
        page.goto(f'{url}/challenges')

        print(f"Looking for challenge: {challenge_name}")
        page.wait_for_selector(f'text="{challenge_name}"', timeout=15000)
        page.click(f'text="{challenge_name}"')
        
        print("Waiting for submission form...")
        page.wait_for_selector('input[id="challenge-input"]', timeout=15000)
        
        print(f"Submitting the flag: {flag}")
        page.fill('input[id="challenge-input"]', flag)
        page.click('button[id="challenge-submit"]')
        
        time.sleep(5)
        print("Done submitting!")
        
        # Keep it open for a few seconds to visually confirm
        time.sleep(5)
        context.close()
        browser.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTFd Platform Auto Solver")
    parser.add_argument("--url", default="https://dalctf2026.com", help="Base URL of the CTF platform")
    parser.add_argument("--username", required=True, help="Your CTF username")
    parser.add_argument("--password", required=True, help="Your CTF password")
    parser.add_argument("--challenge", required=True, help="The exact name of the challenge to click")
    parser.add_argument("--flag", required=True, help="The flag to submit")
    
    args = parser.parse_args()
    solve_ctf(args.url, args.username, args.password, args.challenge, args.flag)
