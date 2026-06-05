#!/bin/bash
# ============================================================
# AEGIS-AUTO — Full Arsenal Installer (Linux/Kali)
# Based on awesome-bugbounty-tools by vavkamil
# ============================================================

echo "============================================================"
echo "  AEGIS-AUTO — Full Arsenal Installer"
echo "============================================================"

echo "[*] Updating apt repositories..."
sudo apt update

echo "[*] Installing system dependencies..."
sudo apt install -y nmap sqlmap golang python3-pip git wget curl \
    libpcap-dev chromium-browser jq

# --- Go Tools (ProjectDiscovery Suite + Others) ---
echo "[*] Installing Go-based tools..."

GO_TOOLS=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/cvemap/cmd/cvemap@latest"
    "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/hakluke/hakrevdns@latest"
    "github.com/hakluke/hakoriginfinder@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    "github.com/haccer/subjack@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/sw33tLie/bbscope@latest"
    "github.com/PentestPad/subzy@latest"
    "github.com/edoardottt/cariddi@latest"
    "github.com/s0rg/crawley/cmd/crawley@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    echo "[*] Installing $tool..."
    go install -v "$tool" 2>/dev/null
done

# Copy Go binaries to PATH
echo "[*] Copying Go binaries to /usr/local/bin..."
sudo cp ~/go/bin/* /usr/local/bin/ 2>/dev/null

# --- Python Tools (Git-cloned) ---
echo "[*] Installing Python-based tools..."

PYTHON_TOOLS=(
    "https://github.com/s0md3v/XSStrike.git"
    "https://github.com/s0md3v/Corsy.git"
    "https://github.com/s0md3v/Arjun.git"
    "https://github.com/s0md3v/uro.git"
    "https://github.com/devanshbatham/ParamSpider.git"
    "https://github.com/Nefcore/CRLFsuite.git"
    "https://github.com/r0075h3ll/Oralyzer.git"
    "https://github.com/swisskyrepo/SSRFmap.git"
    "https://github.com/vladko312/SSTImap.git"
    "https://github.com/ticarpi/jwt_tool.git"
    "https://github.com/EnableSecurity/wafw00f.git"
    "https://github.com/GerbenJavado/LinkFinder.git"
    "https://github.com/m4ll0k/SecretFinder.git"
    "https://github.com/arthaud/git-dumper.git"
    "https://github.com/sa7mon/S3Scanner.git"
    "https://github.com/commixproject/commix.git"
    "https://github.com/defparam/smuggler.git"
    "https://github.com/epinna/tplmap.git"
    "https://github.com/0xInfection/XSRFProbe.git"
    "https://github.com/wireghoul/dotdotpwn.git"
    "https://github.com/devanshbatham/OpenRedireX.git"
)

for repo in "${PYTHON_TOOLS[@]}"; do
    tool_name=$(basename "$repo" .git)
    dest="tools/$tool_name"
    if [ ! -d "$dest" ]; then
        echo "[*] Cloning $tool_name..."
        git clone --depth 1 "$repo" "$dest" 2>/dev/null
        if [ -f "$dest/requirements.txt" ]; then
            pip3 install -r "$dest/requirements.txt" --break-system-packages 2>/dev/null
        fi
    else
        echo "[+] $tool_name already installed."
    fi
done

# --- Secret Scanners ---
echo "[*] Installing secret scanning tools..."
# TruffleHog
if ! command -v trufflehog &>/dev/null; then
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
fi
# Gitleaks
if ! command -v gitleaks &>/dev/null; then
    go install github.com/gitleaks/gitleaks/v8@latest
    sudo cp ~/go/bin/gitleaks /usr/local/bin/
fi

# --- Nuclei Templates ---
echo "[*] Updating Nuclei templates..."
nuclei -update-templates 2>/dev/null

# --- Wordlists ---
echo "[*] Downloading wordlists..."
python3 setup_tools.py

echo ""
echo "============================================================"
echo "  [+] Full Arsenal Installed!"
echo "  [+] $(ls ~/go/bin/ 2>/dev/null | wc -l) Go tools in ~/go/bin/"
echo "  [+] $(ls tools/ 2>/dev/null | wc -l) Python tools in tools/"
echo "============================================================"
