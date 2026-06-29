# H1-Workflow | Bug Bounty Automation Engine

A comprehensive suite of automation scripts, reconnaissance tools, and custom vulnerability scanners designed to streamline the bug bounty workflow, with a particular focus on HackerOne programs and continuous assessment.

## 🚀 Core Components

### 1. 🎯 HackerOne Workflow CLI (`h1_workflow.py`)
A unified command-line interface to interact directly with HackerOne.
- **Search & Pick:** Discover and interactively select programs (`search`, `pick`).
- **Scope Extraction:** Automatically parse and structure in-scope assets (`scope`).
- **Disclosed Reports:** Review publicly disclosed bugs to understand program tendencies (`disclosed`).
- **Full Recon Pipeline:** Chain scope extraction and reconnaissance in overnight modes (`pipeline`).

### 2. 🤖 Continuous Assessment (Autopilot)
- **`autopilot.py` / `run_24_7.py`:** Autonomous 24/7 scanning engines that monitor assets, parse out-of-scope items, and systematically launch deep probes.
- **`c2_bot.py` & Discord Integrations:** Remote command and control via Telegram, coupled with real-time alerting to Discord (`discord_notify.py`, `send_discord_changes.py`).

### 3. 🕸️ Reconnaissance & Target Discovery
- **Mass Recon:** Automated subdomain enumeration and port scanning (`mass_recon.py`, `visual_recon.py`).
- **Target Analysis:** Identify high-value targets and analyze tech stacks (`analyze_targets.py`, `find_targets.py`).
- **Secret & Key Hunting:** Scan for exposed secrets and validate Google Maps keys (`check_secrets.py`, `verify_gmaps_key.py`, `find_key_origin.py`).

### 4. 🔬 Target-Specific Scanners
Customized deep-dive tools built for specific bug bounty programs or technology stacks:
- **Recorded Future:** `mega_rf_scanner.py`, `run_recorded_future.py`
- **LaunchDarkly:** `deep_dive_launchdarkly.py`, `run_launchdarkly.py`
- **Vimeo:** `vimeo_recon.py`, `vimeo_idor_test.py`
- **Priceline / Stripchat:** `fetch_priceline.py`, `stripchat_recon.py`

### 5. 🛡️ Vulnerability Verification
Dedicated scripts to validate findings and eliminate false positives before reporting:
- **SQLi:** `verify_sqli.py`
- **CORS / Open Redirects:** `verify_cors.py`, `verify_open_redirects.py`
- **Subdomain Takeover:** `verify_takeover.py`
- **SSTI:** `verify_ssti_insightly.py`

### 6. 🛠️ Tooling & Infrastructure
- **Tool Management:** Automatically install and update external dependencies like `naabu`, `subfinder`, `katana`, etc. (`setup_tools.py`, `install_tools.sh`, `modules/tool_updater.py`).
- **AI Integrations:** Utilities for leveraging LLMs to parse context or find vulnerabilities (`fix_groq_to_gemini.py`, `test_ai.py`, `scanners/llm_prompt_injection.py`).
- **Reporting:** Generate PDF reports for triagers (`generate_pdf_report.py`, `generate_report.py`).

## ⚙️ Quick Start

### Prerequisites
Make sure you have Python 3.11+ installed. Ensure you configure your `.env` based on `.env.example`.

```bash
# Clone the repository
git clone https://github.com/Prajwal0003/h1-workflow-engine.git
cd h1-workflow-engine

# Run the automated setup script for your OS
# For Windows:
setup.bat

# For Linux / macOS:
chmod +x setup.sh
./setup.sh
```

### Usage Examples
```bash
# Search HackerOne programs interactively
python h1_workflow.py pick

# Run an automated deep dive on a specific program
python h1_workflow.py pipeline <handle>

# Start the continuous 24/7 autopilot scanner
python run_24_7.py
```

---
*Disclaimer: This repository is intended strictly for authorized, ethical bug bounty research. Do not use these tools on programs or targets where you do not have explicit permission to test.*
