import subprocess
import json
import logging
from pathlib import Path
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER, get_bin
import os
import shutil

def run_headless_crawler_analyzer(url):
    """
    Simulates the Burp Suite proxy experience but entirely headlessly!
    It uses Katana (a next-generation crawling tool) to crawl the target,
    capture all requests and responses, and then feeds them to the AI logic
    for deep Business Logic / IDOR analysis, without needing Burp installed.
    """
    findings = []
    
    katana_bin = get_bin("katana")
    if not katana_bin:
        if shutil.which("katana"):
            katana_bin = "katana"
        else:
            logging.error("[-] Katana binary not found. Cannot run headless AI analyzer.")
            return findings
        
    print(f"[*] Dispatching Headless AI Crawler (Katana) to analyze traffic on: {url}")
    
    output_file = Path("scratch/katana_out.json")
    if output_file.exists():
        output_file.unlink()
        
    # Run Katana with headless browser crawling to execute JS and capture complete DOM/responses
    cmd = [
        str(Path(katana_bin).absolute()) if katana_bin != "katana" else katana_bin,
        "-u", url,
        "-headless",
        "-depth", "2", # Keep it shallow so we don't overwhelm the AI
        "-js-crawl",
        "-json",
        "-o", str(output_file)
    ]
    
    headers = []
    if GLOBAL_COOKIE:
        headers.append(f"Cookie: {GLOBAL_COOKIE}")
    if GLOBAL_BEARER:
        headers.append(f"Authorization: Bearer {GLOBAL_BEARER}")
        
    for h in headers:
        cmd.extend(["-H", h])
    
    try:
        # Crawl for up to 3 minutes
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        
        if output_file.exists():
            traffic = []
            with open(output_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        req = data.get("request", {})
                        resp = data.get("response", {})
                        
                        traffic.append({
                            "url": req.get("endpoint", ""),
                            "method": req.get("method", "GET"),
                            "status_code": resp.get("status_code", "000"),
                            "request": req.get("body", "") or req.get("raw", ""),
                            "response": resp.get("body", "") or resp.get("raw", "")
                        })
                    except Exception:
                        pass
            
            if traffic:
                print(f"[*] Katana captured {len(traffic)} requests. Feeding to AI Engine for deep logic analysis...")
                
                recent = traffic[-15:] # Only send 15 to stay in context
                prompt = f"""You are an elite Bug Bounty Hunter. 
Analyze the following HTTP traffic captured by our headless crawler on {url}.
Specifically hunt for:
1. IDOR (Insecure Direct Object References)
2. Broken Access Control / Auth Flow Issues
3. Business Logic Flaws
4. Information Disclosure in JS or API responses

Traffic Data:
"""
                for idx, req in enumerate(recent):
                    req_body = str(req.get("request", ""))[:800]
                    resp_body = str(req.get("response", ""))[:800]
                    prompt += f"--- Request {idx+1} ---\n"
                    prompt += f"Method: {req.get('method')}\nURL: {req.get('url')}\nStatus: {req.get('status_code')}\n"
                    prompt += f"Request snippet:\n{req_body}\n"
                    prompt += f"Response snippet:\n{resp_body}\n\n"
                    
                prompt += "\nOutput ONLY valid JSON containing a list of findings. Format: [{\"type\": \"<vuln_type>\", \"url\": \"<url>\", \"severity\": \"<HIGH/MEDIUM>\", \"detail\": \"<reasoning>\"}]"
                try:
                    from autopilot import get_ai_response
                    ai_analysis = get_ai_response(prompt)
                    
                    if ai_analysis:
                        ai_analysis = ai_analysis.replace("```json", "").replace("```", "").strip()
                        parsed_findings = json.loads(ai_analysis)
                        for f in parsed_findings:
                            if isinstance(f, dict) and "type" in f:
                                f["confidence"] = "MEDIUM"
                                f["verified"] = False
                                f["source"] = "AI_TRAFFIC_ANALYZER"
                                findings.append(f)
                except Exception as e:
                    print(f"[-] AI returned invalid JSON for traffic analysis: {e}")

    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"Error in headless crawler: {e}")
        
    return findings
