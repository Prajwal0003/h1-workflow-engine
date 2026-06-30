import requests
import json
import os
import argparse
from rich.console import Console

console = Console()

def send_to_discord(target, message, webhook_url=None):
    if not webhook_url:
        webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")
        
    if not webhook_url:
        console.print("[red][-] DISCORD_WEBHOOK_URL not found. Cannot send to Discord.[/red]")
        return False
        
    embed = {
        "title": f"🚀 Aegis-Auto Omni-Scan Completed: {target}",
        "description": message,
        "color": 0x00FF00, # Green
        "footer": {"text": "Aegis-Auto Bug Bounty Pipeline"}
    }
    
    payload = {
        "username": "Aegis-Auto Bot",
        "avatar_url": "https://i.imgur.com/4M34hiw.png",
        "embeds": [embed]
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 204:
            console.print("[bold green][+] Successfully sent notification to Discord![/bold green]")
            return True
        else:
            console.print(f"[bold red][-] Failed to send to Discord. Status: {response.status_code}[/bold red]")
            return False
    except Exception as e:
        console.print(f"[bold red][-] Error sending to Discord: {e}[/bold red]")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send scan results to Discord")
    parser.add_argument("target", help="The target that was scanned")
    parser.add_argument("--message", default="Omni-Scan Pipeline has completed. Check the local reports/ folder for findings.", help="Message to send")
    parser.add_argument("--webhook", help="Discord Webhook URL (or set DISCORD_WEBHOOK_URL env var)")
    
    args = parser.parse_args()
    send_to_discord(args.target, args.message, args.webhook)
