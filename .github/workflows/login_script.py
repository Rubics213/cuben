import sys
import json
from playwright.sync_api import sync_playwright

domain = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]

login_url = f"https://{domain}/admin/auth/login"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()
    try:
        page.goto(login_url, timeout=15000)
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle")
        cookies = context.cookies()
        with open(f"auth_cookies/{domain.replace('.', '_')}_cookies.json", "w") as f:
            json.dump(cookies, f, indent=2)
    except Exception as e:
        print(f"Login failed for {domain}: {e}")
    finally:
        browser.close()

