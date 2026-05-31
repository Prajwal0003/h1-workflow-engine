"""
Configuration module for H1 Workflow.
Handles API credentials, paths, and settings.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console

# Fix Windows console encoding globally
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Shared console for all modules
console = Console(force_terminal=True)

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TARGETS_DIR = DATA_DIR / "selected_targets"
RECON_DIR = DATA_DIR / "recon"
CACHE_FILE = DATA_DIR / "programs_cache.json"
DISCLOSED_CACHE = DATA_DIR / "disclosed_cache.json"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
TARGETS_DIR.mkdir(exist_ok=True)
RECON_DIR.mkdir(exist_ok=True)

# Load .env from project root
env_path = PROJECT_ROOT / ".env"
if env_path.exists():
    load_dotenv(env_path)

# HackerOne API
H1_API_USERNAME = os.environ.get("H1_API_USERNAME")
H1_API_TOKEN = os.environ.get("H1_API_TOKEN")

# Gemini API
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

TOOLS_DIR = PROJECT_ROOT / "tools"

def get_tool_path(tool_name, env_var):
    path = os.getenv(env_var)
    if path:
        return path
        
    ext = ".exe" if sys.platform == "win32" else ""
    local_path = TOOLS_DIR / tool_name / f"{tool_name}{ext}"
    if local_path.exists():
        return str(local_path)
    return tool_name

# Recon tool paths (auto-detect if not set)
SUBFINDER_PATH = get_tool_path("subfinder", "SUBFINDER_PATH")
HTTPX_PATH = get_tool_path("httpx", "HTTPX_PATH")
NUCLEI_PATH = get_tool_path("nuclei", "NUCLEI_PATH")

# API endpoints
H1_API_BASE = "https://api.hackerone.com/v1"
H1_PROGRAMS_URL = f"{H1_API_BASE}/hackers/programs"
H1_HACKTIVITY_URL = "https://hackerone.com/graphql"

# Public data fallback
BOUNTY_TARGETS_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/hackerone_data.json"

# Rate limiting
API_RATE_LIMIT = 600  # requests per minute
API_DELAY = 0.1  # seconds between requests


def has_api_credentials():
    """Check if valid API credentials are configured."""
    return bool(H1_API_USERNAME and H1_API_TOKEN
                and H1_API_USERNAME != "your_api_token_identifier"
                and H1_API_TOKEN != "your_api_token_value")


def get_auth():
    """Get HTTP Basic Auth tuple for HackerOne API."""
    if not has_api_credentials():
        return None
    return (H1_API_USERNAME, H1_API_TOKEN)


def check_tool(tool_name, tool_path):
    """Check if an external tool is available."""
    import shutil
    if Path(tool_path).exists():
        return True
    return shutil.which(tool_path) is not None


def get_available_tools():
    """Return dict of available recon tools."""
    tools = {
        "subfinder": check_tool("subfinder", SUBFINDER_PATH),
        "httpx": check_tool("httpx", HTTPX_PATH),
        "nuclei": check_tool("nuclei", NUCLEI_PATH),
    }
    return tools
