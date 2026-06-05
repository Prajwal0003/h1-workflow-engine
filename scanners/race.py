"""
Race Condition Scanner.
Ref: awesome-bugbounty-tools (racepwn, turbo-intruder, requests-racer).
"""
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import stealth_headers


def check_race_condition(url):
    """Detect race conditions by sending parallel requests and checking for inconsistencies."""
    findings = []

    # Test 1: Send 10 identical GET requests simultaneously
    results = []
    def send_req(i):
        try:
            start = time.time()
            r = requests.get(url, headers=stealth_headers(), timeout=10, verify=False)
            elapsed = time.time() - start
            return {"status": r.status_code, "length": len(r.text), "elapsed": elapsed, "idx": i}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_req, i) for i in range(10)]
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)

    if len(results) < 5:
        return None

    # Analyze: if response lengths vary significantly, there may be a race condition
    lengths = [r["length"] for r in results]
    statuses = [r["status"] for r in results]

    unique_lengths = len(set(lengths))
    unique_statuses = len(set(statuses))

    if unique_statuses > 1 and any(s in [500, 503, 429] for s in statuses):
        findings.append({
            "type": "RACE_CONDITION_STATUS_MISMATCH",
            "url": url,
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "detail": f"Parallel requests returned mixed statuses: {set(statuses)}"
        })

    if unique_lengths > 2:
        length_variance = max(lengths) - min(lengths)
        if length_variance > 500:
            findings.append({
                "type": "RACE_CONDITION_CANDIDATE",
                "url": url,
                "severity": "MEDIUM",
                "confidence": "LOW",
                "detail": f"Response length varies under concurrent load ({length_variance} byte diff)"
            })

    return findings if findings else None
