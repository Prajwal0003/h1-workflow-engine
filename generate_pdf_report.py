import os
import json
import time
from pathlib import Path
import requests
try:
    from fpdf import FPDF
except ImportError:
    print("[-] Please run: pip install fpdf")
    exit(1)

# Load ENV
ENV_VARS = {}
if Path(".env").exists():
    for line in Path(".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            ENV_VARS[k.strip()] = v.strip()

GEMINI_API_KEY = ENV_VARS.get("GEMINI_API_KEY", "")

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Aegis-Auto: Final Executive Vulnerability Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_ai_exploitation_manual(findings):
    if not GEMINI_API_KEY or "your_" in GEMINI_API_KEY:
        return "AI Manual Generation Skipped: No valid Gemini API Key found."
    
    # Summarize findings for the prompt
    vuln_summary = ""
    for f in findings[:15]: # Limit to top 15 to avoid token limits
        vuln_summary += f"- {f.get('severity')} | {f.get('type')} | {f.get('url')}\n"
    
    prompt = f"""You are a Senior Offensive Security Engineer. I just ran an automated scanner and found these vulnerabilities:
{vuln_summary}

Please provide:
1. An Executive Summary of the overall risk.
2. A Step-by-Step Manual Exploitation Guide for the most critical findings. 
(For example, if there is a SENSITIVE_PATH like /admin, give me 3 exact techniques to try to bypass the login. If there is SQLi, tell me exactly how to manually verify and exploit it).
Make the steps clear, actionable, and formatted in plain text (no markdown code blocks, just plain text with dashes for bullet points so it fits cleanly in a PDF)."""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    
    print("[*] Consulting AI for exploitation manual...")
    try:
        r = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
        text = r.json()['candidates'][0]['content']['parts'][0]['text']
        return text
    except Exception as e:
        return f"Failed to generate AI manual: {e}"

def generate_pdf():
    results_path = Path("data/autopilot/latest_fast_scan.json")
    if not results_path.exists():
        print("[-] No scan results found. Run autopilot.py first.")
        return
        
    findings = json.loads(results_path.read_text())
    
    pdf = PDFReport()
    pdf.add_page()
    
    # 1. Add Findings Table
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Raw Vulnerability Findings:", 0, 1)
    pdf.set_font("Arial", size=10)
    
    for f in findings:
        pdf.set_text_color(0, 0, 0)
        if f.get("severity") == "CRITICAL": pdf.set_text_color(255, 0, 0)
        elif f.get("severity") == "HIGH": pdf.set_text_color(255, 165, 0)
        
        line = f"[{f.get('severity')}] {f.get('type')} - {f.get('url')}"
        pdf.multi_cell(0, 8, line)
    
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    
    # 2. Add AI Exploitation Manual
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "AI Exploitation Manual & Next Steps:", 0, 1)
    pdf.set_font("Arial", size=10)
    
    ai_manual = generate_ai_exploitation_manual(findings)
    
    # fpdf handles basic utf-8 but might choke on emojis, replacing common ones
    ai_manual = ai_manual.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 6, ai_manual)
    
    # Save
    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "Aegis_Auto_Final_Report.pdf"
    pdf.output(str(out_file))
    print(f"[+] Final PDF Report generated at: {out_file}")

if __name__ == "__main__":
    generate_pdf()
