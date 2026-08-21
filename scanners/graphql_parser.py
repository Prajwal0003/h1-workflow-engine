import json
import logging
from urllib.parse import urlparse

import requests

def check_graphql(url):
    findings = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # Common GraphQL endpoints
    endpoints = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/graphql/console", "/graphiql", "/graphql.php"
    ]
    
    # Introspection query payload
    introspection_query = {
        "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n        directives {\n          name\n          description\n          locations\n          args {\n            ...InputValue\n          }\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n        args {\n          ...InputValue\n        }\n        type {\n          ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n      }\n      inputFields {\n        ...InputValue\n      }\n      interfaces {\n        ...TypeRef\n      }\n      enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n      }\n      possibleTypes {\n        ...TypeRef\n      }\n    }\n\n    fragment InputValue on __InputValue {\n      name\n      description\n      type { ...TypeRef }\n      defaultValue\n    }\n\n    fragment TypeRef on __Type {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n                ofType {\n                  kind\n                  name\n                  ofType {\n                    kind\n                    name\n                  }\n                }\n              }\n            }\n          }\n        }\n      }\n    }\n  "
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    for ep in endpoints:
        target_url = f"{base_url}{ep}"
        try:
            r = requests.post(target_url, json=introspection_query, headers=headers, timeout=5, verify=False)
            if r.status_code == 200 and "__schema" in r.text:
                findings.append({
                    "type": "GRAPHQL_INTROSPECTION",
                    "url": target_url,
                    "detail": "GraphQL Introspection is enabled. This exposes the entire API schema.",
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "verified": False,
                    "verification_method": "graphql-introspection",
                    "verification_evidence": {
                        "deterministic": False,
                        "schema_exposed": True,
                        "impact": "not_established",
                    }
                })
                # We only need to find it once per host
                break
            
            # Check for generic GraphQL error which indicates the endpoint exists but introspection is disabled
            if r.status_code in [200, 400] and ("GRAPHQL_VALIDATION_FAILED" in r.text or "must be a string" in r.text or "syntax error" in r.text.lower()):
                findings.append({
                    "type": "GRAPHQL_ENDPOINT_DISCOVERED",
                    "url": target_url,
                    "detail": "Hidden GraphQL endpoint discovered, but introspection is disabled.",
                    "severity": "LOW",
                    "confidence": "LOW",
                    "verified": False,
                    "verification_method": "graphql-endpoint-discovery",
                    "verification_evidence": {
                        "deterministic": False,
                        "introspection_disabled": True,
                    }
                })
                break
                
        except Exception:
            pass

    return findings
