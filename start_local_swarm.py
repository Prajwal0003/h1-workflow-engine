import os
import time
import subprocess
from pathlib import Path
import json

ASCII_ART = """
   ___             _        _         _        
  / _ \__ _ _ __  (_)__ _  /_\  _   _| |_ ___  
 / /_)/ _` | '_ \ | / _` |//_\\| | | | __/ _ \ 
/ ___/ (_| | | | || | (_| /  _  \ |_| | || (_) |
\/    \__,_|_| |_|/ |\__, \_/ \_/\__,_|\__\___/ 
                |__/ |___/                      
      [ LOCAL SWARM NODE - 24/7 RADAR ]
"""

def setup_env():
    env_file = Path(".env")
    if not env_file.exists():
        print("[!] No .env file found. Let's set up your local API keys.")
        print("You can press ENTER to skip any key, but Gemini is required for AI Triage.")
        
        keys = {
            "GEMINI_API_KEY": input("Enter Gemini API Key (Required for AI): ").strip(),
            "HACKERONE_USERNAME": input("Enter HackerOne Username: ").strip(),
            "HACKERONE_API_TOKEN": input("Enter HackerOne API Token: ").strip(),
            "DISCORD_WEBHOOK_URL": input("Enter Discord Webhook URL (for alerts): ").strip(),
            "SHODAN_API_KEY": input("Enter Shodan API Key: ").strip(),
            "CENSYS_API_ID": input("Enter Censys API ID: ").strip(),
            "CENSYS_API_SECRET": input("Enter Censys API Secret: ").strip(),
        }
        
        env_content = "\n".join([f"{k}={v}" for k, v in keys.items() if v])
        env_file.write_text(env_content)
        print("[+] .env file created successfully!\n")

def check_tools():
    if not Path("tools").exists() or not Path("wordlists").exists():
        print("[*] Tools not found locally. Initiating massive local tool download...")
        print("[*] This will download ~300 tools. Please be patient.")
        subprocess.run(["python", "setup_tools.py"])

def start_swarm():
    print(ASCII_ART)
    print("[*] Initializing Local Swarm Node...")
    
    setup_env()
    check_tools()
    
    print("\n[*] Local radar is ACTIVE. Connecting to dynamic target streams...")
    
    # Infinite loop to keep the laptop scanning 24/7
    cycle = 1
    while True:
        print(f"\n" + "="*50)
        print(f"[*] STARTING SWARM CYCLE #{cycle}")
        print("="*50)
        
        try:
            # We run the autopilot in dynamic mode. It will randomly pick targets or find new ones.
            # Running via subprocess to ensure clean memory state every run
            subprocess.run(["python", "autopilot.py", "--dynamic"])
            
            print(f"[+] Cycle #{cycle} Complete.")
            print("[*] Resting for 15 minutes to prevent IP bans before next cycle...")
            time.sleep(15 * 60) # 15 minute cooldown between full runs
            cycle += 1
            
        except KeyboardInterrupt:
            print("\n[*] Local Swarm Node shutting down. Good hunting!")
            break
        except Exception as e:
            print(f"\n[-] Error in swarm cycle: {e}")
            time.sleep(60)

if __name__ == "__main__":
    start_swarm()
