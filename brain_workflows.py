#!/usr/bin/env python3
"""Brain Workflow Orchestrator — Full Exploitation Pipeline"""
import json
import argparse
from pathlib import Path
from modules.ai_brain import AIOmniClawBrain
from modules.h1_reporter import H1Reporter

def run_brain_pipeline(handle: str, api_key: str, h1_token: str = None, h1_user: str = None):
    print(f"\n{'='*60}\n🧠 BRAIN PIPELINE - {handle}\n{'='*60}")
    
    findings_dir = Path("data/autopilot")
    findings_file = findings_dir / "verified_findings.json"
    
    if not findings_file.exists():
        print(f"[-] No findings at {findings_file}. Run autopilot.py first")
        return
    
    findings = json.loads(findings_file.read_text())
    print(f"[+] Loaded {len(findings)} findings")
    
    # Step 1: AI Exploit Generation
    brain = AIOmniClawBrain(api_key, "gemini", max_iterations=6)
    verified = []
    
    for finding in findings:
        if finding.get("severity") in ["MEDIUM", "HIGH", "CRITICAL"]:
            proof = brain.exploit_finding(finding)
            if proof:
                verified.append((finding, proof))
    
    print(f"\n[+] Verified {len(verified)}/{len(findings)} exploits")
    
    # Step 2: Auto-submit to HackerOne
    if h1_token and h1_user:
        reporter = H1Reporter(h1_token, h1_user)
        for finding, proof in verified:
            finding["verified"] = True
            finding["poc_output"] = proof.get("poc_output", "")
            reporter.submit_report(handle, finding)
    
    # Step 3: Save results
    results = {
        "program": handle,
        "total": len(findings),
        "verified": len(verified),
        "proofs": [{"finding": f[0], "proof": f[1]} for f in verified]
    }
    
    results_file = findings_dir / f"brain_results_{handle}.json"
    results_file.write_text(json.dumps(results, indent=2))
    print(f"[+] Results saved to {results_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brain Workflow Orchestrator")
    parser.add_argument("handle", help="HackerOne program handle")
    parser.add_argument("--gemini-key", required=True, help="Gemini API key")
    parser.add_argument("--h1-token", help="H1 API token")
    parser.add_argument("--h1-user", help="H1 username")
    args = parser.parse_args()
    
    run_brain_pipeline(args.handle, args.gemini_key, args.h1_token, args.h1_user)
