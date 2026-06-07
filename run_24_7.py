import time
import subprocess
import logging
from datetime import datetime
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', handlers=[
    logging.FileHandler("autopilot_247.log"),
    logging.StreamHandler(sys.stdout)
])

def run_autopilot(sso_emails=None, sso_passes=None):
    logging.info("Starting 24/7 Bug Bounty Autopilot Scan...")
    try:
        # Run autopilot targeting dynamic targets, which expands surface automatically.
        cmd = ["python", "autopilot.py", "--dynamic"]
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

if __name__ == "__main__":
    sso_emails = None
    sso_passes = None
    
    # Parse arguments robustly
    for i in range(len(sys.argv)):
        if sys.argv[i] == "--google-sso-emails" and i + 1 < len(sys.argv):
            sso_emails = sys.argv[i+1]
        elif sys.argv[i] == "--google-sso-passes" and i + 1 < len(sys.argv):
            sso_passes = sys.argv[i+1]
            
    logging.info(f"Starting Daemon. SSO Emails configured: {'Yes' if sso_emails else 'No'}")
        
    while True:
        run_tool_updater()
        run_zero_day_watcher()
        run_autopilot(sso_emails, sso_passes)
        
        # Run every 60 minutes (3600 seconds)
        logging.info("Next scan will start in 60 minutes. Process is alive 24/7/365. Do not close this terminal.")
        time.sleep(3600)
