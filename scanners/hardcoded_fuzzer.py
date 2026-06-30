import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.payload_extractor import extract_payloads
import random
import time

def check_hardcoded_payloads(url):
    findings = []
    
    # 1. Parse payloads
    all_payloads = extract_payloads()
    if not all_payloads:
        return findings

    # We select some categories that are safe to automatically fuzz
    fuzz_categories = ['Cross Site Scripting (XSS)', 'Sql-Injection', 'OS-command Injection']
    
    # 2. Check if URL has query parameters
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    if not params:
        # We could fuzz paths, but it's noisy. For now, stick to parameters.
        return findings

    print(f"[*] Hardcoded Fuzzer attacking {url} with extracted payloads...")
    
    for category in fuzz_categories:
        # Match our folders to extracted keys
        matching_keys = [k for k in all_payloads.keys() if category.lower() in k.lower()]
        for key in matching_keys:
            # Take a random sample of 5 payloads per category to avoid spamming
            payloads_to_test = random.sample(all_payloads[key], min(5, len(all_payloads[key])))
            
            for payload in payloads_to_test:
                # Fuzz each parameter
                for param_name in params.keys():
                    # Create new injected params
                    fuzzed_params = params.copy()
                    fuzzed_params[param_name] = payload
                    
                    # Reconstruct URL
                    new_query = urlencode(fuzzed_params, doseq=True)
                    fuzzed_url = urlunparse(parsed_url._replace(query=new_query))
                    
                    try:
                        headers = {"User-Agent": "Aegis-Auto/HardcodedFuzzer"}
                        r = requests.get(fuzzed_url, headers=headers, timeout=5, verify=False)
                        
                        # Basic heuristics for success (this is very basic and meant to bypass LLM filters)
                        if "XSS" in category and payload in r.text:
                            findings.append({
                                "type": "HARDCODED_XSS_REFLECTION",
                                "url": fuzzed_url,
                                "severity": "MEDIUM",
                                "confidence": "MEDIUM",
                                "detail": f"Payload {payload} was reflected in the response."
                            })
                        elif "Sql" in category and any(err in r.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-", "postgresql"]):
                            findings.append({
                                "type": "HARDCODED_SQLI_ERROR",
                                "url": fuzzed_url,
                                "severity": "HIGH",
                                "confidence": "MEDIUM",
                                "detail": f"SQL error detected when injecting payload {payload}."
                            })
                        elif "Command" in category and "root:x:0:0:" in r.text:
                            findings.append({
                                "type": "HARDCODED_CMD_INJECTION",
                                "url": fuzzed_url,
                                "severity": "CRITICAL",
                                "confidence": "HIGH",
                                "detail": f"Command injection detected with payload {payload}."
                            })
                            
                    except Exception:
                        pass
                        
                    time.sleep(0.1) # small delay to prevent massive rate limits

    return findings
