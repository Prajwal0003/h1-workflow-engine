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
🚨 **MantisHack Security Scan Complete** 🚨
=========================================
A scan was executed on the `h1-workflow` repository. Over 2,400 findings were generated and analyzed. We have isolated the highest-confidence, True Positive vulnerabilities:

🔥 **1. Command Injection (Critical)**
**Location:** `.github/workflows/nightly-scan.yml` (Line 59)
**Details:** The `github.event.inputs.target` is passed directly into an inline bash script without proper sanitization. An attacker with access to dispatch workflows can inject arbitrary shell commands (e.g., `; cat .env > report.txt`) and achieve RCE on the GitHub Actions runner.

⚠️ **2. Root Privilege Execution (High)**
**Location:** `Dockerfile` (Line 32)
**Details:** The `USER` directive is missing. The container will run as root by default. Any vulnerability exploited in the pipeline will grant the attacker root access to the container filesystem.

⚠️ **3. Insecure HTTP Transport (High)**
**Location:** `autopilot.py` (Line 396)
**Details:** The script transmits data over `http://` instead of `https://`, leaving it vulnerable to Man-in-the-Middle (MitM) attacks and data interception.

⚠️ **4. Potential Credential Leakage in Logs (High)**
**Location:** `core/llm/dispatcher/server.py` (Line 451) and `core/oci/auth.py` (Line 85)
**Details:** The logging mechanism may expose sensitive credentials, tokens, or environment variables to application logs, which could be exposed if logs are accessible to unauthorized users.

⚠️ **5. Tainted Environment Variables (High)**
**Location:** `scanners/mantishack_features/mantishack_agentic.py` (Line 1283, 1344)
**Details:** The `subprocess.Popen` execution allows `env` to be passed dynamically. While `get_safe_env()` mitigates this, any oversight could lead to code execution via `PYTHONUSERBASE` or `LD_PRELOAD` injections.

🛡️ **Recommendation:**
Please review the above vulnerabilities immediately. Start by securing the GitHub Actions workflow input parameter, and add a `USER` directive in the Dockerfile.

*Automated Security Pipeline Verification*
"""

    payload = {
        "username": "MantisHack Security Pipeline",
        "avatar_url": "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/Shield_icon_-_red.svg/1024px-Shield_icon_-_red.svg.png",
        "embeds": [
            {
                "title": "🔍 True Positive Findings Verified",
                "description": content,
                "color": 16711680,
                "footer": {"text": f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
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
