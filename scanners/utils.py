"""Shared utilities for all scanner modules."""
import random
import platform
import subprocess
import requests
from pathlib import Path
from urllib.parse import urlparse

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
]

GLOBAL_COOKIE = None
GLOBAL_BEARER = None

def set_auth_context(cookie=None, bearer=None):
    global GLOBAL_COOKIE, GLOBAL_BEARER
    GLOBAL_COOKIE = cookie
    GLOBAL_BEARER = bearer

def get_stealth_headers():
    return stealth_headers()

def stealth_headers():
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    }
    if GLOBAL_COOKIE:
        headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER:
        headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"
    return headers

def _request_headers(overrides=None):
    """Merge scanner-specific headers with the shared authentication context."""
    headers = stealth_headers()
    if overrides:
        headers.update(overrides)
    return headers


def safe_get(url, timeout=5, **kwargs):
    try:
        overrides = kwargs.pop("headers", None)
        return requests.get(url, headers=_request_headers(overrides), timeout=timeout,
                            verify=False, **kwargs)
    except Exception:
        return None


def safe_post(url, timeout=5, **kwargs):
    try:
        overrides = kwargs.pop("headers", None)
        return requests.post(url, headers=_request_headers(overrides), timeout=timeout,
                             verify=False, **kwargs)
    except Exception:
        return None

def get_bin(name):
    import shutil
    ext = ".exe" if platform.system().lower() == "windows" else ""
    
    # Check multiple possible locations
    possible_paths = [
        Path("tools") / name / f"{name}{ext}",
        Path("tools") / f"{name}{ext}",
        Path("data") / f"{name}_bin" / f"{name}{ext}",
        Path(f"{name}{ext}")
    ]
    
    for p in possible_paths:
        if p.exists():
            return str(p.absolute())
            
    # Fallback to system PATH
    sys_path = shutil.which(name)
    if sys_path:
        return sys_path
        
    return None

def run_bin(name, args, timeout=30, input_data=None):
    bin_path = get_bin(name)
    if not bin_path:
        return None
    try:
        result = subprocess.run(
            [bin_path] + args,
            capture_output=True, text=True, timeout=timeout,
            input=input_data
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None

def base_url(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
