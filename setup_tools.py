"""
setup_tools.py — Cross-platform tool installer for the Aegis-Auto security pipeline.
Downloads and installs all recon, exploitation, and enumeration tools from binary releases.
Covers ALL categories from awesome-bugbounty-tools:
  Recon: subfinder, httpx, dnsx, naabu, katana, gowitness, alterx, uncover
  Exploitation: dalfox, nuclei, ffuf, sqlmap, xsstrike
  Secrets: trufflehog, gitleaks, noseyparker
  Misc: gau, wafw00f, notify, interactsh-client, wpscan
"""

import os
import sys
import platform
import urllib.request
import zipfile
import tarfile
import subprocess
from pathlib import Path
import shutil
import re

TOOLS_DIR = Path("tools")
TOOLS_DIR.mkdir(exist_ok=True)

# --- Tool Versions ---
NUCLEI_VERSION = "3.2.9"
FFUF_VERSION = "2.1.0"
SUBFINDER_VERSION = "2.6.6"
GAU_VERSION = "2.2.3"
HTTPX_VERSION = "1.6.6"
NAABU_VERSION = "2.3.1"
KATANA_VERSION = "1.1.0"
DALFOX_VERSION = "2.9.3"
DNSX_VERSION = "1.2.1"
ALTERX_VERSION = "0.0.4"
GOWITNESS_VERSION = "3.0.5"
NOTIFY_VERSION = "1.0.6"
INTERACTSH_VERSION = "1.2.0"
UNCOVER_VERSION = "1.0.9"
CDNCHECK_VERSION = "1.1.0"
TLSX_VERSION = "1.1.7"
MAPCIDR_VERSION = "1.1.34"
ASNMAP_VERSION = "1.1.0"
CVEMAP_VERSION = "0.0.7"
TRUFFLEHOG_VERSION = "3.78.2"
GITLEAKS_VERSION = "8.18.4"

def get_platform_info():
    sys_os = platform.system().lower()
    arch = platform.machine().lower()

    if sys_os == "windows":
        os_name = "windows"
        arch_name = "amd64" if arch in ["amd64", "x86_64"] else "386"
        ext = "zip"
    elif sys_os == "linux":
        os_name = "linux"
        arch_name = "amd64" if arch in ["amd64", "x86_64"] else "arm64" if arch == "aarch64" else "386"
        ext = "zip"
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
        elif ext in ("tar.gz", "tgz"):
            with tarfile.open(temp_file, 'r:gz') as tar_ref:
                tar_ref.extractall(dest_dir)
        print(f"[+] Extracted to {dest_dir}")
    except Exception as e:
        print(f"[-] Error downloading/extracting: {e}")
    finally:
        if temp_file.exists():
            temp_file.unlink()


def install_go_binary(name, version, url_template, os_name, arch_name):
    """Generic installer for Go-based tools released as zip/tar.gz."""
    print(f"\n--- Installing {name} v{version} ---")
    dest_dir = TOOLS_DIR / name
    dest_dir.mkdir(exist_ok=True)

    exe_name = f"{name}.exe" if os_name == "windows" else name
    if (dest_dir / exe_name).exists():
        print(f"[+] {name} already installed.")
        return

    ext = "zip"
    url = url_template.format(version=version, os=os_name, arch=arch_name, ext=ext)
    download_and_extract(url, dest_dir, ext)

    if os_name != "windows" and (dest_dir / name).exists():
        os.chmod(dest_dir / name, 0o755)
    print(f"[+] {name} installed successfully.")


# --- ProjectDiscovery Suite ---

def install_nuclei(os_name, arch_name):
    install_go_binary("nuclei", NUCLEI_VERSION,
        "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_ffuf(os_name, arch_name):
    print(f"\n--- Installing FFUF v{FFUF_VERSION} ---")
    dest_dir = TOOLS_DIR / "ffuf"
    dest_dir.mkdir(exist_ok=True)
    exe_name = "ffuf.exe" if os_name == "windows" else "ffuf"
    if (dest_dir / exe_name).exists():
        print("[+] FFUF already installed.")
        return
    ext = "zip" if os_name == "windows" else "tar.gz"
    url = f"https://github.com/ffuf/ffuf/releases/download/v{FFUF_VERSION}/ffuf_{FFUF_VERSION}_{os_name}_{arch_name}.{ext}"
    download_and_extract(url, dest_dir, ext)
    if os_name != "windows" and (dest_dir / "ffuf").exists():
        os.chmod(dest_dir / "ffuf", 0o755)
    print("[+] FFUF installed successfully.")

def install_subfinder(os_name, arch_name):
    install_go_binary("subfinder", SUBFINDER_VERSION,
        "https://github.com/projectdiscovery/subfinder/releases/download/v{version}/subfinder_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_httpx(os_name, arch_name):
    install_go_binary("httpx", HTTPX_VERSION,
        "https://github.com/projectdiscovery/httpx/releases/download/v{version}/httpx_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_naabu(os_name, arch_name):
    install_go_binary("naabu", NAABU_VERSION,
        "https://github.com/projectdiscovery/naabu/releases/download/v{version}/naabu_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_katana(os_name, arch_name):
    install_go_binary("katana", KATANA_VERSION,
        "https://github.com/projectdiscovery/katana/releases/download/v{version}/katana_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_dnsx(os_name, arch_name):
    install_go_binary("dnsx", DNSX_VERSION,
        "https://github.com/projectdiscovery/dnsx/releases/download/v{version}/dnsx_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_alterx(os_name, arch_name):
    install_go_binary("alterx", ALTERX_VERSION,
        "https://github.com/projectdiscovery/alterx/releases/download/v{version}/alterx_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_notify(os_name, arch_name):
    install_go_binary("notify", NOTIFY_VERSION,
        "https://github.com/projectdiscovery/notify/releases/download/v{version}/notify_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_interactsh(os_name, arch_name):
    install_go_binary("interactsh-client", INTERACTSH_VERSION,
        "https://github.com/projectdiscovery/interactsh/releases/download/v{version}/interactsh-client_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_uncover(os_name, arch_name):
    install_go_binary("uncover", UNCOVER_VERSION,
        "https://github.com/projectdiscovery/uncover/releases/download/v{version}/uncover_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_cdncheck(os_name, arch_name):
    install_go_binary("cdncheck", CDNCHECK_VERSION,
        "https://github.com/projectdiscovery/cdncheck/releases/download/v{version}/cdncheck_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_tlsx(os_name, arch_name):
    install_go_binary("tlsx", TLSX_VERSION,
        "https://github.com/projectdiscovery/tlsx/releases/download/v{version}/tlsx_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_mapcidr(os_name, arch_name):
    install_go_binary("mapcidr", MAPCIDR_VERSION,
        "https://github.com/projectdiscovery/mapcidr/releases/download/v{version}/mapcidr_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_asnmap(os_name, arch_name):
    install_go_binary("asnmap", ASNMAP_VERSION,
        "https://github.com/projectdiscovery/asnmap/releases/download/v{version}/asnmap_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

def install_cvemap(os_name, arch_name):
    install_go_binary("cvemap", CVEMAP_VERSION,
        "https://github.com/projectdiscovery/cvemap/releases/download/v{version}/cvemap_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

# --- XSS / Exploitation ---

def install_dalfox(os_name, arch_name):
    install_go_binary("dalfox", DALFOX_VERSION,
        "https://github.com/hahwul/dalfox/releases/download/v{version}/dalfox_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

# --- Screenshots ---

def install_gowitness(os_name, arch_name):
    install_go_binary("gowitness", GOWITNESS_VERSION,
        "https://github.com/sensepost/gowitness/releases/download/{version}/gowitness-{version}-{os}-{arch}",
        os_name, arch_name)

# --- URL Discovery ---

def install_gau(os_name, arch_name):
    print(f"\n--- Installing GAU v{GAU_VERSION} ---")
    dest_dir = TOOLS_DIR / "gau"
    dest_dir.mkdir(exist_ok=True)
    exe_name = "gau.exe" if os_name == "windows" else "gau"
    if (dest_dir / exe_name).exists():
        print("[+] GAU already installed.")
        return
    ext = "tar.gz" if os_name != "windows" else "zip"
    url = f"https://github.com/lc/gau/releases/download/v{GAU_VERSION}/gau_{GAU_VERSION}_{os_name}_{arch_name}.{ext}"
    download_and_extract(url, dest_dir, ext)
    if os_name != "windows" and (dest_dir / "gau").exists():
        os.chmod(dest_dir / "gau", 0o755)
    print("[+] GAU installed successfully.")

# --- Secret Scanning ---

def install_trufflehog(os_name, arch_name):
    print(f"\n--- Installing TruffleHog v{TRUFFLEHOG_VERSION} ---")
    dest_dir = TOOLS_DIR / "trufflehog"
    dest_dir.mkdir(exist_ok=True)
    exe_name = "trufflehog.exe" if os_name == "windows" else "trufflehog"
    if (dest_dir / exe_name).exists():
        print("[+] TruffleHog already installed.")
        return
    ext = "tar.gz"
    url = f"https://github.com/trufflesecurity/trufflehog/releases/download/v{TRUFFLEHOG_VERSION}/trufflehog_{TRUFFLEHOG_VERSION}_{os_name}_{arch_name}.{ext}"
    download_and_extract(url, dest_dir, ext)
    if os_name != "windows" and (dest_dir / "trufflehog").exists():
        os.chmod(dest_dir / "trufflehog", 0o755)

def install_gitleaks(os_name, arch_name):
    install_go_binary("gitleaks", GITLEAKS_VERSION,
        "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_{os}_{arch}.{ext}",
        os_name, arch_name)

# --- Git-cloned Python tools ---

def install_git_tool(repo_url, tool_name):
    print(f"\n--- Installing {tool_name} ---")
    dest_dir = TOOLS_DIR / tool_name
    if dest_dir.exists():
        print(f"[+] {tool_name} already installed.")
        return

    print(f"[*] Cloning {repo_url}...")
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest_dir)], check=True)
        print(f"[+] {tool_name} cloned successfully.")
    except Exception as e:
        print(f"[-] Failed to clone {tool_name}: {e}")
        return

    # Install pip requirements if present
    req_file = dest_dir / "requirements.txt"
    if req_file.exists():
        print(f"[*] Installing Python dependencies for {tool_name}...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(req_file)], check=False)


# --- Wordlists ---

def download_wordlists():
    print("\n--- Downloading Industry-Standard Wordlists ---")
    wordlists_dir = Path("wordlists")
    wordlists_dir.mkdir(exist_ok=True)

    lists = {
        "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "raft-small-directories.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        "lfi-linux.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
        "sqli-payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
        "xss-payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-BruteLogic.txt",
        "open-redirect-payloads.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/open-redirect-payloads.txt",
        "subdomains-top1million-5000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
        "api-endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
    }

    for name, url in lists.items():
        dest = wordlists_dir / name
        if not dest.exists():
            print(f"[*] Downloading {name}...")
            try:
                urllib.request.urlretrieve(url, dest)
                print(f"[+] Downloaded {name}")
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
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
"""
    if not env_example.exists():
        env_example.write_text(template)
        print("[+] Created .env.example")

    if not env_file.exists():
        env_file.write_text(template)
        print("[+] Created .env")


if __name__ == "__main__":
    print("=" * 60)
    print("  AEGIS-AUTO — Full Arsenal Installer")
    print("  Based on awesome-bugbounty-tools")
    print("=" * 60)
    os_name, arch_name, ext = get_platform_info()
    print(f"[*] Detected OS: {os_name} | Arch: {arch_name}\n")

    # === ProjectDiscovery Suite ===
    install_nuclei(os_name, arch_name)
    install_subfinder(os_name, arch_name)
    install_httpx(os_name, arch_name)
    install_naabu(os_name, arch_name)
    install_katana(os_name, arch_name)
    install_dnsx(os_name, arch_name)
    install_alterx(os_name, arch_name)
    install_notify(os_name, arch_name)
    install_interactsh(os_name, arch_name)
    install_uncover(os_name, arch_name)
    install_cdncheck(os_name, arch_name)
    install_tlsx(os_name, arch_name)
    install_mapcidr(os_name, arch_name)
    install_asnmap(os_name, arch_name)
    install_cvemap(os_name, arch_name)

    # === Fuzzing / Exploitation ===
    install_ffuf(os_name, arch_name)
    install_dalfox(os_name, arch_name)

    # === URL / Link Discovery ===
    install_gau(os_name, arch_name)

    # === Secret Scanning ===
    install_trufflehog(os_name, arch_name)
    install_gitleaks(os_name, arch_name)

    # === Python/Git-Cloned Tools ===
    install_git_tool("https://github.com/sqlmapproject/sqlmap.git", "sqlmap")
    install_git_tool("https://github.com/s0md3v/XSStrike.git", "xsstrike")
    install_git_tool("https://github.com/s0md3v/Corsy.git", "corsy")
    install_git_tool("https://github.com/s0md3v/Arjun.git", "arjun")
    install_git_tool("https://github.com/devanshbatham/ParamSpider.git", "paramspider")
    install_git_tool("https://github.com/Nefcore/CRLFsuite.git", "crlfsuite")
    install_git_tool("https://github.com/r0075h3ll/Oralyzer.git", "oralyzer")
    install_git_tool("https://github.com/swisskyrepo/SSRFmap.git", "ssrfmap")
    install_git_tool("https://github.com/vladko312/SSTImap.git", "sstimap")
    install_git_tool("https://github.com/ticarpi/jwt_tool.git", "jwt_tool")
    install_git_tool("https://github.com/EnableSecurity/wafw00f.git", "wafw00f")
    install_git_tool("https://github.com/wireghoul/dotdotpwn.git", "dotdotpwn")
    install_git_tool("https://github.com/GerbenJavado/LinkFinder.git", "linkfinder")
    install_git_tool("https://github.com/m4ll0k/SecretFinder.git", "secretfinder")
    install_git_tool("https://github.com/arthaud/git-dumper.git", "git-dumper")
    install_git_tool("https://github.com/sa7mon/S3Scanner.git", "s3scanner")
    install_git_tool("https://github.com/commixproject/commix.git", "commix")
    install_git_tool("https://github.com/defparam/smuggler.git", "smuggler")
    install_git_tool("https://github.com/epinna/tplmap.git", "tplmap")
    install_git_tool("https://github.com/0xInfection/XSRFProbe.git", "xsrfprobe")

def install_awesome_bugbounty_tools_mass():
    print("\n--- Mass Cloning awesome-bugbounty-tools ---")
    mass_dir = TOOLS_DIR / "awesome_mass"
    mass_dir.mkdir(exist_ok=True)

    print("[*] Fetching awesome-bugbounty-tools README...")
    try:
        url = "https://raw.githubusercontent.com/vavkamil/awesome-bugbounty-tools/master/README.md"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')

        # Find all github repo links
        repos = re.findall(r'https://github\.com/([\w\-]+)/([\w\-]+)', content)
        # Remove duplicates while preserving order
        unique_repos = list(dict.fromkeys(repos))

        print(f"[*] Found {len(unique_repos)} potential tools to clone!")

        # Clone all tools (no limit)
        count = 0
        for owner, repo in unique_repos:
            if repo.lower() == "awesome-bugbounty-tools":
                continue

            repo_url = f"https://github.com/{owner}/{repo}.git"
            dest = mass_dir / repo
            if not dest.exists():
                print(f"[*] Mass cloning {repo} ({count+1}/{len(unique_repos)})...")
                subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            count += 1

        print(f"[+] Mass clone complete! Downloaded {count} tools.")
    except Exception as e:
        print(f"[-] Failed mass clone: {e}")

    install_awesome_bugbounty_tools_mass()

    # === Wordlists & Config ===
    download_wordlists()
    create_env_template()

    print("\n" + "=" * 60)
    print("  [+] Full Arsenal Installed!")
    print("  [+] Tools: tools/")
    print("  [+] Mass Tools: tools/awesome_mass/")
    print("  [+] Wordlists: wordlists/")
    print("=" * 60)
