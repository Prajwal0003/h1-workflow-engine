import os
import sys
import platform
import urllib.request
import zipfile
import tarfile
import subprocess
from pathlib import Path
import shutil

TOOLS_DIR = Path("tools")
TOOLS_DIR.mkdir(exist_ok=True)

NUCLEI_VERSION = "3.2.9"
FFUF_VERSION = "2.1.0"
SUBFINDER_VERSION = "2.6.6"
GAU_VERSION = "2.2.3"

def get_platform_info():
    sys_os = platform.system().lower()
    arch = platform.machine().lower()
    
    if sys_os == "windows":
        os_name = "windows"
        arch_name = "amd64" if arch in ["amd64", "x86_64"] else "386"
        ext = "zip"
    elif sys_os == "linux":
        os_name = "linux"
        arch_name = "amd64" if arch in ["amd64", "x86_64"] else "386"
        ext = "zip" # Nuclei releases are zip for all platforms now
    elif sys_os == "darwin":
        os_name = "macOS"
        arch_name = "arm64" if arch == "arm64" else "amd64"
        ext = "zip"
    else:
        print(f"[-] Unsupported OS: {sys_os}")
        sys.exit(1)
        
    return os_name, arch_name, ext

def download_and_extract(url, dest_dir, ext):
    print(f"[*] Downloading {url}...")
    temp_file = dest_dir / f"temp_download.{ext}"
    
    try:
        urllib.request.urlretrieve(url, temp_file)
        print(f"[*] Extracting...")
        if ext == "zip":
            with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                zip_ref.extractall(dest_dir)
        elif ext == "tar.gz":
            with tarfile.open(temp_file, 'r:gz') as tar_ref:
                tar_ref.extractall(dest_dir)
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        if temp_file.exists():
            temp_file.unlink()

def install_nuclei(os_name, arch_name):
    print("\n--- Installing Nuclei ---")
    nuclei_dir = TOOLS_DIR / "nuclei"
    nuclei_dir.mkdir(exist_ok=True)
    
    # Check if exists
    exe_name = "nuclei.exe" if os_name == "windows" else "nuclei"
    if (nuclei_dir / exe_name).exists():
        print("[+] Nuclei already installed.")
        return

    url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{NUCLEI_VERSION}/nuclei_{NUCLEI_VERSION}_{os_name}_{arch_name}.zip"
    download_and_extract(url, nuclei_dir, "zip")
    
    # Make executable on Linux/Mac
    if os_name != "windows":
        os.chmod(nuclei_dir / "nuclei", 0o755)
    print("[+] Nuclei installed successfully.")

def install_ffuf(os_name, arch_name):
    print("\n--- Installing FFUF ---")
    ffuf_dir = TOOLS_DIR / "ffuf"
    ffuf_dir.mkdir(exist_ok=True)
    
    exe_name = "ffuf.exe" if os_name == "windows" else "ffuf"
    if (ffuf_dir / exe_name).exists():
        print("[+] FFUF already installed.")
        return

    ext = "zip" if os_name == "windows" else "tar.gz"
    url = f"https://github.com/ffuf/ffuf/releases/download/v{FFUF_VERSION}/ffuf_{FFUF_VERSION}_{os_name}_{arch_name}.{ext}"
    download_and_extract(url, ffuf_dir, ext)
    
    if os_name != "windows":
        os.chmod(ffuf_dir / "ffuf", 0o755)
    print("[+] FFUF installed successfully.")

def install_subfinder(os_name, arch_name):
    print("\n--- Installing Subfinder ---")
    dest_dir = TOOLS_DIR / "subfinder"
    dest_dir.mkdir(exist_ok=True)
    exe_name = "subfinder.exe" if os_name == "windows" else "subfinder"
    if (dest_dir / exe_name).exists(): return
    url = f"https://github.com/projectdiscovery/subfinder/releases/download/v{SUBFINDER_VERSION}/subfinder_{SUBFINDER_VERSION}_{os_name}_{arch_name}.zip"
    download_and_extract(url, dest_dir, "zip")
    if os_name != "windows": os.chmod(dest_dir / "subfinder", 0o755)

def install_gau(os_name, arch_name):
    print("\n--- Installing GAU (Get All URLs) ---")
    dest_dir = TOOLS_DIR / "gau"
    dest_dir.mkdir(exist_ok=True)
    exe_name = "gau.exe" if os_name == "windows" else "gau"
    if (dest_dir / exe_name).exists(): return
    ext = "tar.gz" if os_name != "windows" else "zip"
    # GAU releases use slightly different naming
    arch_gau = "amd64" if arch_name == "amd64" else "386"
    if os_name == "macOS": arch_gau = "arm64" if arch_name == "arm64" else "amd64"
    
    url = f"https://github.com/lc/gau/releases/download/v{GAU_VERSION}/gau_{GAU_VERSION}_{os_name}_{arch_gau}.{ext}"
    download_and_extract(url, dest_dir, ext)
    if os_name != "windows": os.chmod(dest_dir / "gau", 0o755)

def install_git_tool(repo_url, tool_name):
    print(f"\n--- Installing {tool_name} ---")
    dest_dir = TOOLS_DIR / tool_name
    if dest_dir.exists():
        print(f"[+] {tool_name} already installed.")
        return
        
    print(f"[*] Cloning {repo_url}...")
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest_dir)], check=True)
        print(f"[+] {tool_name} installed successfully.")
    except Exception as e:
        print(f"[-] Failed to clone {tool_name}: {e}")
        
    # Install pip requirements if present
    req_file = dest_dir / "requirements.txt"
    if req_file.exists():
        print(f"[*] Installing Python dependencies for {tool_name}...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(req_file)], check=False)

def download_wordlists():
    print("\n--- Downloading Industry-Standard Wordlists ---")
    wordlists_dir = Path("wordlists")
    wordlists_dir.mkdir(exist_ok=True)
    
    lists = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "raft-small-directories.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"
    }
    
    for name, url in lists.items():
        dest = wordlists_dir / name
        if not dest.exists():
            print(f"[*] Downloading {name} from SecLists...")
            try:
                urllib.request.urlretrieve(url, dest)
                print(f"[+] Downloaded {name} successfully.")
            except Exception as e:
                print(f"[-] Failed to download {name}: {e}")
        else:
            print(f"[+] {name} already exists.")

def create_env_template():
    print("\n--- Setting up API Keys Template ---")
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    template = """# Bug Bounty Pipeline API Keys
# Rename this file to .env and add your keys here!
# DO NOT COMMIT .env TO GITHUB!

HACKERONE_USERNAME=your_username
HACKERONE_API_TOKEN=your_api_token
DISCORD_WEBHOOK_URL=your_discord_webhook_here
GEMINI_API_KEY=your_gemini_api_key_here
SHODAN_API_KEY=your_shodan_key
NOTION_API_KEY=your_notion_api_key
NOTION_DATABASE_ID=your_notion_database_id
INTERACTSH_URL=your_id.interact.sh
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_telegram_chat_id
GITHUB_TOKEN=your_github_token
"""
    if not env_example.exists():
        env_example.write_text(template)
        print("[+] Created .env.example for GitHub")
        
    if not env_file.exists():
        env_file.write_text(template)
        print("[+] Created .env for local use")

if __name__ == "__main__":
    print("[*] Starting Cross-Platform Tools Installer...")
    os_name, arch_name, ext = get_platform_info()
    print(f"[*] Detected OS: {os_name} | Arch: {arch_name}")
    
    install_nuclei(os_name, arch_name)
    install_ffuf(os_name, arch_name)
    install_subfinder(os_name, arch_name)
    install_gau(os_name, arch_name)
    install_git_tool("https://github.com/sqlmapproject/sqlmap.git", "sqlmap")
    install_git_tool("https://github.com/s0md3v/XSStrike.git", "xsstrike")
    download_wordlists()
    create_env_template()
    
    print("\n[+] All tools downloaded to the 'tools/' directory!")
    print("[+] Your project is now fully self-contained and cross-platform.")
