"""
Feature 1: AI-Driven Triage Module
-----------------------------------
Sends raw HTTP request/response pairs to Gemini AI for intelligent
false-positive elimination. Replaces naive string-matching verification
with contextual analysis of WAF responses, soft 404s, and generic reflections.

Usage:
    from modules.ai_triage import ai_triage_finding
    result = ai_triage_finding(finding, gemini_api_key)
    # result = {"verdict": "TRUE_POSITIVE"|"FALSE_POSITIVE"|"NEEDS_REVIEW",
    #           "confidence": 0.0-1.0, "reasoning": "...", "severity_adjust": "HIGH"|None}
"""

import requests
import urllib3
import random
import json
import time
import re
from urllib.parse import urlparse, urlencode

urllib3.disable_warnings()

MODELS = ["gemini-2.5-flash", "gemini-1.5-pro", "gemini-1.5-flash"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
]





def _call_gemini(prompt, api_key):
    import requests
    if not api_key or "your_" in api_key: return None
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    payload = {"contents": [{"parts":[{"text": prompt}]}]}
    try:
        r = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
        return r.json()['candidates'][0]['content']['parts'][0]['text']
    except:
        return None

def _call_groq(prompt):
    import requests
    import os
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or "your_" in api_key: return None
    api_url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": "llama3-70b-8192", "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
    try:
        r = requests.post(api_url, json=payload, headers=headers, timeout=15)
        return r.json()['choices'][0]['message']['content']
    except:
        return None

def _replay_request(url, method="GET", headers=None, data=None, timeout=8):
    """Replay the HTTP request and capture the full request/response for AI analysis."""
    try:
        h = headers or {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}
        if method.upper() == "POST":
            r = requests.post(url, headers=h, data=data, timeout=timeout, verify=False, allow_redirects=False)
        else:
            r = requests.get(url, headers=h, timeout=timeout, verify=False, allow_redirects=False)

        # Build human-readable request representation
        parsed = urlparse(url)
        req_line = f"{method.upper()} {parsed.path}{'?' + parsed.query if parsed.query else ''} HTTP/1.1"
        req_headers = f"Host: {parsed.hostname}\n" + "\n".join(f"{k}: {v}" for k, v in h.items())

        # Build response representation (truncate body to save tokens)
        resp_headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body = r.text[:3000]  # Truncate large bodies

        http_transaction = (
            f"--- HTTP REQUEST ---\n{req_line}\n{req_headers}\n\n"
            f"--- HTTP RESPONSE ---\nHTTP/1.1 {r.status_code} {r.reason}\n{resp_headers}\n\n{body}"
        )
        return http_transaction, r.status_code, r.text
    except Exception as e:
        return None, None, None


def ai_triage_finding(finding, api_key):
    """
    Use Gemini AI to intelligently verify whether a scanner finding is a
    true positive, false positive, or needs manual review.

    Args:
        finding: dict with keys: type, url, severity, detail, confidence
        api_key: Gemini API key string

    Returns:
        dict with verdict, confidence score, reasoning, and optional severity adjustment
    """
    if not api_key or "your_" in api_key:
        return {"verdict": "NEEDS_REVIEW", "confidence": 0.0, "reasoning": "No API key configured"}

    vuln_type = finding.get("type", "UNKNOWN")
    target_url = finding.get("url", "")
    detail = finding.get("detail", "")
    original_severity = finding.get("severity", "MEDIUM")

    # Replay the suspicious request to capture full HTTP transaction
    http_transaction, status_code, body = _replay_request(target_url)
    if not http_transaction:
        return {"verdict": "NEEDS_REVIEW", "confidence": 0.0, "reasoning": "Could not replay HTTP request"}

    # Also get a baseline (clean request to the root domain)
    parsed = urlparse(target_url)
    baseline_url = f"{parsed.scheme}://{parsed.netloc}/"
    baseline_transaction, baseline_status, baseline_body = _replay_request(baseline_url)

    prompt = f"""You are an expert penetration tester performing vulnerability triage.

VULNERABILITY TYPE: {vuln_type}
REPORTED SEVERITY: {original_severity}
SCANNER DETAIL: {detail}

SUSPICIOUS HTTP TRANSACTION:
{http_transaction}

BASELINE (Clean Request to Root):
{baseline_transaction or 'N/A'}

ANALYSIS INSTRUCTIONS:
1. Is this a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE?
2. Pre-submission verification checks:
   - Check for WAF blocks ("Request Rejected", "support ID", etc.)
   - Check for redirects masquerading as sensitive file exposure
   - For CORS vulnerabilities: Check if access-control-allow-credentials flag is present in the response. If missing, it's FALSE_POSITIVE or low severity.
   - Soft 404 pages that return HTTP 200 but show error content
   - The response body being identical or nearly identical to the baseline
3. Duplicate Risk Assessment:
   - Based on common bug bounty patterns, rate the duplicate risk: LOW, MEDIUM, HIGH, or VERY_HIGH.
   - For example, basic CORS or missing headers are usually VERY_HIGH. IDORs or Logic bugs are LOW.
4. If TRUE POSITIVE, does the evidence warrant the reported severity or should it be adjusted?

RESPOND IN EXACTLY THIS JSON FORMAT (no markdown, no code blocks):
{{"verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE" or "NEEDS_REVIEW", "confidence": 0.0 to 1.0, "reasoning": "explanation of WAF/redirect checks", "severity_adjust": null or "CRITICAL" or "HIGH" or "MEDIUM" or "LOW", "duplicate_risk": "VERY_HIGH" or "HIGH" or "MEDIUM" or "LOW"}}
"""

    def _parse(resp):
        if not resp: return None
        try:
            c = resp.strip()
            if c.startswith("```json"): c = c[7:]
            if c.startswith("```"): c = c[3:]
            if c.endswith("```"): c = c[:-3]
            res = json.loads(c.strip())
            return res
        except:
            if "true positive" in resp.lower(): return {"verdict": "TRUE_POSITIVE", "confidence": 0.3}
            if "false positive" in resp.lower(): return {"verdict": "FALSE_POSITIVE", "confidence": 0.3}
            return None

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f_gemini = executor.submit(_call_gemini, prompt, api_key)
        f_groq = executor.submit(_call_groq, prompt)
        
        gemini_res = _parse(f_gemini.result())
        groq_res = _parse(f_groq.result())

    if not gemini_res and not groq_res:
        return {"verdict": "NEEDS_REVIEW", "confidence": 0.0, "reasoning": "Both AI APIs failed"}

    # If only one succeeded, trust it
    if gemini_res and not groq_res: return gemini_res
    if groq_res and not gemini_res: return groq_res

    # Consensus logic: If EITHER AI says TRUE_POSITIVE, we keep it (Relaxed Filter for Uncensored Groq)
    if gemini_res.get("verdict") == "TRUE_POSITIVE" or groq_res.get("verdict") == "TRUE_POSITIVE":
        return {"verdict": "TRUE_POSITIVE", "confidence": max(gemini_res.get("confidence", 0), groq_res.get("confidence", 0)), "reasoning": f"At least one AI verified it. Gemini: {gemini_res.get('verdict')}, Groq: {groq_res.get('verdict')}"}
    
    # If both say FALSE_POSITIVE
    if gemini_res.get("verdict") == "FALSE_POSITIVE" and groq_res.get("verdict") == "FALSE_POSITIVE":
        return {"verdict": "FALSE_POSITIVE", "confidence": max(gemini_res.get("confidence", 0), groq_res.get("confidence", 0)), "reasoning": "Both AIs agreed it is a false positive."}
        
    return {"verdict": "NEEDS_REVIEW", "confidence": 0.5, "reasoning": f"No consensus: Gemini={gemini_res.get('verdict')}, Groq={groq_res.get('verdict')}"}


def batch_triage(findings, api_key, severity_filter=None, max_findings=20):
    """
    Triage a batch of findings, optionally filtering by severity.

    Args:
        findings: list of finding dicts
        api_key: Gemini API key
        severity_filter: list of severities to triage (e.g., ["HIGH", "CRITICAL"])
        max_findings: max number of findings to triage per batch (API rate limiting)

    Returns:
        list of (finding, triage_result) tuples
    """
    results = []
    count = 0

    for finding in findings:
        if count >= max_findings:
            break
        if severity_filter and finding.get("severity") not in severity_filter:
            continue

        print(f"  [AI Triage] Analyzing {finding.get('type')} at {finding.get('url', '')[:60]}...", flush=True)
        result = ai_triage_finding(finding, api_key)
        results.append((finding, result))
        count += 1

        # Rate limiting — be gentle with the API
        time.sleep(1.0)

    return results
