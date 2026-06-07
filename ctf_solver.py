import argparse
import requests
import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

def get_ai_response(prompt):
    """Query Groq/Llama3 for CTF solutions and code generation."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("[!] No GROQ_API_KEY found in .env!")
        return None
        
    api_url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": "llama3-70b-8192", 
        "messages": [{"role": "user", "content": prompt}], 
        "temperature": 0.3
    }
    try:
        r = requests.post(api_url, json=payload, headers=headers, timeout=30)
        return r.json()['choices'][0]['message']['content'].strip()
    except Exception as e:
        print(f"[!] AI API Error: {e}")
        return None

def analyze_ctf(challenge_desc, source_code=None):
    """Analyze the CTF challenge and generate an exploit script."""
    print("\n[*] 🧠 AI is analyzing the CTF challenge...")
    
    prompt = f"""You are an elite CTF player and vulnerability researcher.
I need to solve a CTF challenge. Here is the description:
{challenge_desc}

"""
    if source_code:
        prompt += f"Here is the provided source code:\n```\n{source_code}\n```\n"
        
    prompt += """
Please provide:
1. An explanation of the vulnerability.
2. A complete Python exploit script to retrieve the flag. Wrap the exploit script in ```python blocks.
"""
    
    response = get_ai_response(prompt)
    if response:
        print("\n=== 🎯 CTF ANALYSIS & EXPLOIT ===\n")
        print(response)
        return response
    return None

def extract_technique_for_bug_bounty(challenge_desc, ai_analysis):
    """Convert the CTF vulnerability into a generic Bug Bounty scanner."""
    print("\n[*] 🔄 Distilling CTF technique into Bug Bounty weapon...")
    
    prompt = f"""You are an offensive security engineer.
You just solved a CTF challenge with the following details:
Description: {challenge_desc}
Analysis: {ai_analysis}

Your task is to take the underlying vulnerability concept from this CTF and write a Python scanner wrapper for it so we can use it in our live Bug Bounty pipeline.
Requirements:
1. Define a function starting with `run_` (e.g., `run_pickle_desync(target_url)`).
2. It should take a `target_url` as input.
3. Use the `requests` module to probe the `target_url` for this vulnerability (use generic payloads).
4. Return a list of findings, for example: `[{{"type": "CUSTOM_CTF_VULN", "url": target_url, "severity": "HIGH", "confidence": "MEDIUM", "detail": "Found vulnerable endpoint"}}]`
5. Only return the raw python code. No markdown formatting. No explanation.
"""
    
    scanner_code = get_ai_response(prompt)
    if scanner_code:
        scanner_code = scanner_code.replace("```python", "").replace("```", "").strip()
        
        # Save it directly into the custom_tools directory
        safe_name = "".join(x if x.isalnum() else "_" for x in challenge_desc[:20]).lower()
        filepath = Path("scanners/custom_tools") / f"ctf_technique_{safe_name}.py"
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(scanner_code)
        
        print(f"\n[+] Successfully distilled CTF concept into Bug Bounty scanner: {filepath}")
        print("[+] This scanner will automatically be loaded by your 24/7 Autopilot daemon!")

def main():
    parser = argparse.ArgumentParser(description="Standalone AI CTF Solver & Pipeline Integrator")
    parser.add_argument("description", help="Description of the CTF challenge")
    parser.add_argument("--source", "-s", help="Path to the challenge source code file", default=None)
    parser.add_argument("--integrate", "-i", action="store_true", help="Learn from this CTF and add the technique to the Bug Bounty Pipeline")
    
    args = parser.parse_args()
    
    source_content = None
    if args.source:
        try:
            source_content = Path(args.source).read_text()
        except Exception as e:
            print(f"[!] Could not read source code file: {e}")
            return
            
    analysis = analyze_ctf(args.description, source_content)
    
    if args.integrate and analysis:
        extract_technique_for_bug_bounty(args.description, analysis)

if __name__ == "__main__":
    main()
