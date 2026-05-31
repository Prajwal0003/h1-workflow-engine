import os
import subprocess
from pathlib import Path
from dotenv import load_dotenv

GH_CLI = r"C:\Program Files\GitHub CLI\gh.exe"
REPO_NAME = "h1-workflow-engine"

def run_cmd(cmd):
    print(f"[*] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if result.returncode != 0:
        print(f"[-] Failed: {result.stderr}")
    else:
        print(f"[+] Success: {result.stdout.strip()}")
    return result.returncode == 0

def main():
    print("[*] Committing code...")
    run_cmd("git init")
    run_cmd("git config --global user.name \"Prajwal0003\"")
    run_cmd("git config --global user.email \"prajwal0003@github.com\"")
    run_cmd("git add .")
    run_cmd('git commit -m "Initial commit for H1-Workflow Omni-Scan Engine"')

    print(f"[*] Creating private repository '{REPO_NAME}'...")
    # Create private repo, link as origin, and push
    success = run_cmd(f'"{GH_CLI}" repo create {REPO_NAME} --private --source=. --remote=origin --push')
    if not success:
        # If repo exists, just try to push
        run_cmd("git push -u origin master")

    print("[*] Setting up GitHub Secrets for Actions...")
    env_path = Path(".env")
    if env_path.exists():
        load_dotenv(env_path)
        secrets = [
            "HACKERONE_USERNAME", "HACKERONE_API_TOKEN", "DISCORD_WEBHOOK_URL",
            "GEMINI_API_KEY", "SHODAN_API_KEY", "NOTION_API_KEY",
            "NOTION_DATABASE_ID", "INTERACTSH_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"
        ]
        
        for key in secrets:
            val = os.environ.get(key)
            if val and val.strip():
                # Write to temp file to securely set secret without shell injection
                temp_file = Path(f"temp_{key}.txt")
                temp_file.write_text(val)
                print(f"  -> Setting secret {key}...")
                run_cmd(f'"{GH_CLI}" secret set {key} < {temp_file.name}')
                temp_file.unlink()
    
    print("[+] Deployment complete!")

if __name__ == "__main__":
    main()
