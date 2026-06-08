"""AI Brain Module — OmniClaw Integration for Exploit Generation & Validation"""
import json, subprocess, sys, time, re
from pathlib import Path
from typing import Dict, Optional, List
import requests

class AIOmniClawBrain:
    def __init__(self, api_key: str, api_provider: str = "gemini", max_iterations: int = 6):
        self.api_key = api_key
        self.api_provider = api_provider
        self.max_iterations = max_iterations
        self.findings_dir = Path("exploits")
        self.findings_dir.mkdir(exist_ok=True)
    
    def exploit_finding(self, finding: Dict) -> Optional[Dict]:
        vuln_type = finding.get("type", "")
        target_url = finding.get("url", "")
        detail = finding.get("detail", "")
        severity = finding.get("severity", "")
        
        if severity not in ["MEDIUM", "HIGH", "CRITICAL"]:
            return None
        
        print(f"\n[*] AI Brain generating exploit for {vuln_type}...")
        for iteration in range(self.max_iterations):
            prompt = f"Generate Python exploit for {vuln_type} at {target_url}. Detail: {detail}. Must print VERIFIED: VULNERABLE if successful."
            exploit_code = self._call_llm(prompt)
            if not exploit_code:
                continue
            
            exploit_code = self._sanitize(exploit_code)
            if not exploit_code:
                continue
            
            try:
                poc_dir = self.findings_dir / "generators"
                poc_dir.mkdir(exist_ok=True)
                safe_type = re.sub(r'[^a-zA-Z0-9_]', '_', vuln_type)[:30]
                poc_file = poc_dir / f"poc_{safe_type}_{int(time.time())}.py"
                poc_file.write_text(exploit_code)
                
                result = subprocess.run([sys.executable, str(poc_file)], capture_output=True, text=True, timeout=30)
                output = result.stdout.strip()
                
                if "VERIFIED: VULNERABLE" in output:
                    print(f"  [+] Exploit verified on iteration {iteration + 1}")
                    proof = {"finding_type": vuln_type, "url": target_url, "poc_script": exploit_code, "poc_output": output, "verified": True}
                    proof_dir = self.findings_dir / "validators"
                    proof_dir.mkdir(exist_ok=True)
                    proof_file = proof_dir / f"proof_{safe_type}_{int(time.time())}.json"
                    proof_file.write_text(json.dumps(proof, indent=2))
                    return proof
            except:
                pass
        
        return None
    
    def _call_llm(self, prompt: str) -> Optional[str]:
        if self.api_provider == "gemini":
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}"
                r = requests.post(url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=20)
                return r.json()['candidates'][0]['content']['parts'][0]['text'] if r.status_code == 200 else None
            except: return None
        return None
    
    def _sanitize(self, code: str) -> Optional[str]:
        code = code.strip()
        for marker in ["```python", "```"]:
            code = code.replace(marker, "").strip()
        dangerous = ["os.system", "subprocess", "open(", "exec(", "__import__"]
        return code if not any(d in code for d in dangerous) else None
