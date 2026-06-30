#!/bin/bash
echo "============================================================"
echo "  H1-Workflow | Initial Setup Script (Linux/macOS)"
echo "============================================================"

echo "[*] Creating Python virtual environment..."
python3 -m venv venv

echo "[*] Activating virtual environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Downloading required bug bounty tools and wordlists..."
python setup_tools.py

echo "============================================================"
echo "  [+] Setup Complete!"
echo "  [+] Run 'source venv/bin/activate' to activate the environment."
echo "============================================================"
