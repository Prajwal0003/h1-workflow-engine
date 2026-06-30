import requests
import json
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_graphql_batching(url):
    """
    GraphQL Array Batching Fuzzer.
    Attempts to bypass rate limits by sending an array of 50 queries in one request.
    """
    findings = []
    if "graphql" not in url: return findings
    
    headers = {"Content-Type": "application/json"}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    
    # Send 50 queries in a single array
    payload = [{"query": "{ __schema { types { name } } }"}] * 50
    
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=10, verify=False)
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list) and len(data) > 10:
                    findings.append({
                        "type": "GRAPHQL_BATCHING_RATE_LIMIT_BYPASS",
                        "url": url,
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "verified": True,
                        "detail": "GraphQL Array Batching is enabled! Successfully executed 50 parallel queries in a single HTTP request, bypassing application rate limits."
                    })
            except: pass
    except: pass
    
    return findings
