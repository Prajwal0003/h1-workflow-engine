#!/bin/bash
echo "[*] Updating apt repositories..."
sudo apt update

echo "[*] Installing standard tools (Nmap, SQLMap, golang, python3-pip)..."
sudo apt install -y nmap sqlmap golang python3-pip git

echo "[*] Installing Nuclei..."
# Install nuclei using Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/local/bin/

echo "[*] Installing FFUF..."
# Install FFUF using Go
go install github.com/ffuf/ffuf/v2@latest
sudo cp ~/go/bin/ffuf /usr/local/bin/

echo "[*] Installing XSStrike..."
if [ ! -d "$HOME/XSStrike" ]; then
    git clone https://github.com/s0md3v/XSStrike.git ~/XSStrike
fi
cd ~/XSStrike
pip3 install -r requirements.txt --break-system-packages

echo "[*] Installation Complete!"
echo "You can now run: nmap, sqlmap, nuclei, ffuf"
echo "XSStrike is located at ~/XSStrike/xsstrike.py"
