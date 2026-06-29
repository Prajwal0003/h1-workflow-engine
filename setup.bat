@echo off
echo ============================================================
echo   H1-Workflow ^| Initial Setup Script (Windows)
echo ============================================================

echo [*] Creating Python virtual environment...
python -m venv venv

echo [*] Activating virtual environment and installing dependencies...
call venv\Scripts\activate.bat
pip install --upgrade pip
pip install -r requirements.txt

echo [*] Downloading required bug bounty tools and wordlists...
python setup_tools.py

echo ============================================================
echo   [+] Setup Complete!
echo   [+] Run 'venv\Scripts\activate' to activate the environment.
echo ============================================================
