import time
import subprocess
import logging
from datetime import datetime
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', handlers=[
    logging.FileHandler("autopilot_247.log"),
    logging.StreamHandler(sys.stdout)
])

def discover_fresh_targets(h1_count=10, bc_count=10):
    """Pull 10 targets from HackerOne + 10 from Bugcrowd using target discovery module."""
    logging.info(f"🔍 Discovering {h1_count} H1 + {bc_count} BC targets...")
    try:
        from modules.target_discovery import discover_targets
        handles = discover_targets(h1_count=h1_count, bc_count=bc_count)
        logging.info(f"✅ Discovered {len(handles)} fresh targets: {handles}")
        return handles
    except Exception as e:
        logging.error(f"Target discovery failed: {e}")
        return []

def run_autopilot(target, sso_emails=None, sso_passes=None):
    logging.info(f"Starting 24/7 Bug Bounty Autopilot Scan on target: {target}...")
    try:
        # Run autopilot targeting a specific program from data/selected_targets/
        cmd = ["python", "autopilot.py", target]
        if sso_emails and sso_passes:
            cmd.extend(["--google-sso-emails", sso_emails, "--google-sso-passes", sso_passes])
        
        # Use Popen to allow it to run completely detached if necessary, or just wait.
        # check=True will raise an exception on non-zero exit code
        process = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
        process.wait()
        
        if process.returncode == 0:
            logging.info("Scan completed successfully. Sleeping until next cycle.")
        else:
            logging.error(f"Autopilot exited with code {process.returncode}")
            
    except Exception as e:
        logging.error(f"Autopilot encountered an error: {e}")

def run_zero_day_watcher():
    logging.info("Checking for new Zero-Day CVEs and generating custom Nuclei templates...")
    try:
        subprocess.run(["python", "-m", "modules.zero_day_watcher"], check=True, capture_output=True, text=True)
    except Exception as e:
        logging.error(f"Zero-Day Watcher encountered an error: {e}")

def run_tool_updater():
    logging.info("Checking GitHub for newly released Bug Bounty tools...")
    try:
        subprocess.run(["python", "-m", "modules.tool_updater"], check=True, capture_output=True, text=True)
    except Exception as e:
        logging.error(f"Tool Updater encountered an error: {e}")

def run_burp_analyzer():
    logging.info("Pulling latest Burp Suite HTTP traffic for MCP AI Analysis...")
    try:
        # Run the burp analyzer we just built
        subprocess.run(["python", "modules/burp_analyzer.py"], check=True, capture_output=True, text=True)
    except Exception as e:
        logging.error(f"Burp Analyzer encountered an error (is Burp running?): {e}")

def run_github_api_hunter():
    logging.info("Hunting GitHub for exposed API keys (Claude/Anthropic)...")
    try:
        subprocess.run(["python", "scanners/github_api_hunter.py"], check=True, capture_output=True, text=True)
    except Exception as e:
        logging.error(f"GitHub API Hunter encountered an error: {e}")

if __name__ == "__main__":
    sso_emails = None
    sso_passes = None
    
    # Parse arguments robustly
    for i in range(len(sys.argv)):
        if sys.argv[i] == "--google-sso-emails" and i + 1 < len(sys.argv):
            sso_emails = sys.argv[i+1]
        elif sys.argv[i] == "--google-sso-passes" and i + 1 < len(sys.argv):
            sso_passes = sys.argv[i+1]
    
    # Fallback: read SSO creds from .env if not provided via CLI
    if not sso_emails or not sso_passes:
        from pathlib import Path
        env_file = Path(".env")
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith("GOOGLE_SSO_EMAILS="):
                    sso_emails = line.split("=", 1)[1].strip().strip('"').strip("'")
                elif line.startswith("GOOGLE_SSO_PASSWORDS="):
                    sso_passes = line.split("=", 1)[1].strip().strip('"').strip("'")
            
    logging.info(f"Starting Daemon. SSO Emails configured: {'Yes' if sso_emails else 'No'}")
        
    cycle = 0
    while True:
        cycle += 1
        logging.info(f"{'='*60}")
        logging.info(f"🔄 CYCLE {cycle} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info(f"{'='*60}")
        
        # Run support modules first
        run_tool_updater()
        run_zero_day_watcher()
        run_burp_analyzer()
        run_github_api_hunter()
        
        # --- MULTI-TARGET DISCOVERY ---
        # Pull 10 from HackerOne + 10 from Bugcrowd
        targets = discover_fresh_targets(h1_count=10, bc_count=10)
        
        if not targets:
            logging.warning("⚠️  No targets discovered this cycle. Retrying in 30 minutes.")
            time.sleep(1800)
            continue
        
        logging.info(f"🎯 Scanning {len(targets)} targets this cycle:")
        for i, t in enumerate(targets, 1):
            logging.info(f"   {i:2d}. {t}")
        
        # Scan each target
        for idx, target in enumerate(targets, 1):
            logging.info(f"")
            logging.info(f"{'─'*50}")
            logging.info(f"🎯 [{idx}/{len(targets)}] Scanning: {target}")
            logging.info(f"{'─'*50}")
            run_autopilot(target=target, sso_emails=sso_emails, sso_passes=sso_passes)
            
            # Brief cooldown between targets to avoid burning IPs
            if idx < len(targets):
                cooldown = 30
                logging.info(f"⏳ Cooling down {cooldown}s before next target...")
                time.sleep(cooldown)
        
        # Cycle complete
        logging.info(f"")
        logging.info(f"{'='*60}")
        logging.info(f"✅ CYCLE {cycle} COMPLETE — Scanned {len(targets)} targets")
        logging.info(f"Next cycle (fresh targets) starts in 60 minutes.")
        logging.info(f"Process is alive 24/7/365. Do not close this terminal.")
        logging.info(f"{'='*60}")
        time.sleep(3600)
