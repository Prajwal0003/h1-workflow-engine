import requests
import json
from scanners.utils import GLOBAL_COOKIE, GLOBAL_BEARER

def check_graphql_introspection(url):
    """
    Hunts for exposed GraphQL endpoints and automatically attempts to 
    dump the full database schema via Introspection queries.
    """
    findings = []
    
    endpoints = []
    if "graphql" in url:
        endpoints.append(url)
    else:
        # Just grab the base domain and append common graphql paths
        base = url.split("//")[-1].split("/")[0]
        scheme = url.split("://")[0]
        endpoints.extend([
            f"{scheme}://{base}/graphql",
            f"{scheme}://{base}/api/graphql",
            f"{scheme}://{base}/v1/graphql"
        ])
        
    headers = {"Content-Type": "application/json"}
    if GLOBAL_COOKIE: headers["Cookie"] = GLOBAL_COOKIE
    if GLOBAL_BEARER: headers["Authorization"] = f"Bearer {GLOBAL_BEARER}"
    
    introspection_query = {"query": "{ __schema { types { name fields { name } } } }"}
    
    for ep in set(endpoints):
        try:
            r = requests.post(ep, headers=headers, json=introspection_query, timeout=5, verify=False)
            if r.status_code == 200 and "__schema" in r.text and "types" in r.text:
                try:
                    data = r.json()
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    if types:
                        sensitive_mutations = []
                        for t in types:
                            if t.get("name") in ["Mutation", "RootMutation"]:
                                fields = t.get("fields") or []
                                sensitive_mutations = [f["name"] for f in fields if f.get("name")]
                        
                        mutations_str = ", ".join(sensitive_mutations[:5]) if sensitive_mutations else "None found"
                        
                        findings.append({
                            "type": "GRAPHQL_INTROSPECTION_LEAK",
                            "url": ep,
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "verified": True, # Zero FP because it successfully parsed a valid GraphQL schema
                            "detail": f"GraphQL Introspection is ENABLED! Dumped full API schema. Sensitive mutations available: {mutations_str}"
                        })
                        break # Only report once per target base
                except Exception: 
                    pass
        except Exception: 
            pass
        
    return findings
