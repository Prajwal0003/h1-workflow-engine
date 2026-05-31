import os
import sys
import json
import requests
import subprocess
from pathlib import Path
from urllib.parse import urlparse

ENV_VARS = {}
if Path(".env").exists():
    for line in Path(".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            ENV_VARS[k.strip()] = v.strip()

TELEGRAM_TOKEN = ENV_VARS.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = ENV_VARS.get("TELEGRAM_CHAT_ID", "")

def send_msg(text):
    if not TELEGRAM_TOKEN or "your_" in TELEGRAM_TOKEN: return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": CHAT_ID, "text": text})
    except: pass

def get_updates(offset=None):
    if not TELEGRAM_TOKEN or "your_" in TELEGRAM_TOKEN: return []
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates"
        params = {"timeout": 30}
        if offset: params["offset"] = offset
        r = requests.get(url, params=params, timeout=35)
        return r.json().get("result", [])
    except: return []

def run_bot():
    print("[*] Starting Telegram C2 Bot...")
    send_msg("🤖 Autopilot Bug Bounty C2 Online. Send /scan <program> to begin.")
    offset = None
    
    while True:
        updates = get_updates(offset)
        for u in updates:
            offset = u["update_id"] + 1
            msg = u.get("message", {})
            text = msg.get("text", "").strip()
            
            if text.startswith("/scan "):
                target = text.split(" ")[1]
                send_msg(f"🚀 Initializing autonomous scan on: {target}...")
                try:
                    # Trigger autopilot
                    cmd = ["python", "autopilot.py", target]
                    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    send_msg(f"✅ Scan kicked off in the background. You will receive notifications for CRITICAL findings.")
                except Exception as e:
                    send_msg(f"❌ Failed to start scan: {e}")
                    
            elif text == "/status":
                send_msg("🟢 System is online and waiting for commands. Nuclei, FFUF, and Playwright are ready.")

if __name__ == "__main__":
    run_bot()
