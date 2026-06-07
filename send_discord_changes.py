import os
import requests
from pathlib import Path
from datetime import datetime

def send_report():
    env_vars = {}
    if Path(".env").exists():
        for line in Path(".env").read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env_vars[k.strip()] = v.strip()
    
    webhook_url = env_vars.get("DISCORD_WEBHOOK_URL")
    if not webhook_url:
        print("ERROR: DISCORD_WEBHOOK_URL not found in .env")
        return
    webhook_url = webhook_url.strip('"').strip("'")

    content = """
🔧 **System Patched & 24/7 Scanning Enabled** 🔧
=========================================
The agent has successfully applied critical security patches to the `h1-workflow` pipeline itself. Continuous 24/7/365 Bug Bounty scanning is now configured.

**Changes Applied:**
✅ **Fixed Command Injection**: GitHub Actions workflow input (`target`) is now safely passed via environment variables, preventing RCE on the CI/CD runner.
✅ **Dropped Root Privileges**: Added a dedicated `scanner` user to `Dockerfile` to prevent the Docker container from running as `root`.
✅ **Secured Network Transport**: Updated OOB vulnerability probing in `autopilot.py` to use `https://` exclusively, preventing data interception.

**Continuous Operation:**
⚙️ The system is now configured to automatically scan and filter out false positives autonomously. Only verified `HIGH` and `CRITICAL` findings will trigger this webhook.
"""

    payload = {
        "username": "MantisHack Security Pipeline",
        "avatar_url": "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/Shield_icon_-_red.svg/1024px-Shield_icon_-_red.svg.png",
        "embeds": [
            {
                "title": "✅ Patches Applied Successfully",
                "description": content,
                "color": 3066993,
                "footer": {"text": f"Update Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print("Successfully sent report to Discord webhook!")
    except Exception as e:
        print(f"Failed to send Discord webhook: {e}")

if __name__ == "__main__":
    send_report()
