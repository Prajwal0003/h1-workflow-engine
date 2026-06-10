import requests
import json
import logging
import os
from pathlib import Path

# Provide compatibility with autopilot's AI caller if available
try:
    from autopilot import get_ai_response
except ImportError:
    # Fallback if run standalone
    def get_ai_response(prompt):
        return "[!] AI Engine not loaded. Run via autopilot.py."

class BurpMCPAnalyzer:
    def __init__(self, burp_rest_url="http://127.0.0.1:1337"):
        """
        Integrates with Burp Suite via its REST API (or a proxy MCP server) 
        to analyze recent HTTP traffic for vulnerabilities.
        """
        self.burp_url = burp_rest_url.rstrip("/")
        
    def fetch_proxy_history(self):
        logging.info(f"[*] Fetching proxy history from Burp MCP / REST API at {self.burp_url}...")
        try:
            # Assumes Burp Suite REST API endpoint for proxy history
            r = requests.get(f"{self.burp_url}/v0.1/proxy/history", timeout=5)
            if r.status_code == 200:
                data = r.json()
                # If the API returns a list, return it
                return data if isinstance(data, list) else data.get("messages", [])
        except Exception as e:
            logging.error(f"[-] Could not connect to Burp Suite: {e}")
            logging.info("[i] Ensure Burp Suite REST API is running or MCP server is active on port 1337.")
        return []

    def hunt_for_vulnerabilities(self):
        """
        Pulls recent requests and feeds them to the AI for advanced analysis.
        Use Cases: Request Analysis, IDOR Hunting, Business Logic Testing, Auth Flow Review.
        """
        traffic = self.fetch_proxy_history()
        if not traffic:
            return
            
        logging.info(f"[*] Analyzing {min(len(traffic), 15)} recent Burp requests with AI...")
        
        # Take the last 15 requests to stay within context limits
        recent = traffic[-15:]
        prompt = """You are an elite Bug Bounty Hunter and Web Application Security Expert. 
Analyze the following Burp Suite proxy traffic for potential vulnerabilities. 
Specifically hunt for:
1. IDOR (Insecure Direct Object References)
2. Broken Access Control / Auth Flow Issues
3. Business Logic Flaws
4. Information Disclosure in JS or API responses

Traffic Data:
"""
        
        for idx, req in enumerate(recent):
            url = req.get("url", "Unknown URL")
            method = req.get("method", "GET")
            status = req.get("status_code", "000")
            
            # Truncate payloads to avoid massive context
            request_body = str(req.get("request", ""))[:800]
            response_body = str(req.get("response", ""))[:800]
            
            prompt += f"--- Request {idx+1} ---\n"
            prompt += f"Method: {method}\nURL: {url}\nStatus: {status}\n"
            prompt += f"Request snippet:\n{request_body}\n"
            prompt += f"Response snippet:\n{response_body}\n\n"
            
        prompt += "\nOutput a structured vulnerability assessment. Highlight any suspicious endpoints, weak authentication flows, or predictable parameters that warrant manual testing."
        
        analysis = get_ai_response(prompt)
        
        report_path = Path("reports/burp_ai_analysis.md")
        report_path.parent.mkdir(exist_ok=True)
        report_path.write_text(analysis if analysis else "AI Analysis failed.", encoding="utf-8")
        logging.info(f"[+] Burp MCP AI Analysis complete! Saved to {report_path}")
        return analysis

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    analyzer = BurpMCPAnalyzer()
    analyzer.hunt_for_vulnerabilities()
