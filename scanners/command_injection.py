"""
Command Injection Scanner.
Ref: awesome-bugbounty-tools (commix).
"""
import time
from urllib.parse import urlparse
from .utils import stealth_headers, safe_get

CMD_PAYLOADS = [
    (";sleep 5;", 4.0),
    ("|sleep 5|", 4.0),
    ("$(sleep 5)", 4.0),
    ("`sleep 5`", 4.0),
    ("& ping -c 5 127.0.0.1 &", 4.0),
    ("%0asleep 5%0a", 4.0),
    ("|| sleep 5 ||", 4.0),
]

CMD_PARAMS = ["cmd", "exec", "command", "ping", "query", "host", "ip", "url", "to", "domain", "dir"]

LINUX_OUTPUT_MARKERS = ["uid=", "gid=", "root:x:0:0"]
WIN_OUTPUT_MARKERS = ["Volume Serial Number", "Directory of", "Windows"]


def check_command_injection(url):
    """Test for OS command injection via time-based and output-based detection."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in CMD_PARAMS[:6]:
        # Baseline timing
        try:
            start = time.time()
            safe_get(f"{base}?{param}=test", timeout=10)
            baseline = time.time() - start
        except Exception:
            baseline = 0.5

        for payload, min_delay in CMD_PAYLOADS[:4]:
            target = f"{base}?{param}={payload}"
            try:
                start = time.time()
                r = safe_get(target, timeout=15)
                elapsed = time.time() - start

                if not r:
                    continue

                # Time-based detection
                delay = elapsed - baseline
                if delay >= min_delay:
                    # Verify with second request
                    start2 = time.time()
                    safe_get(target, timeout=15)
                    elapsed2 = time.time() - start2

                    if (elapsed2 - baseline) >= min_delay * 0.7:
                        findings.append({
                            "type": "COMMAND_INJECTION_TIME",
                            "url": target,
                            "severity": "CRITICAL",
                            "confidence": "HIGH",
                            "detail": f"Time-based cmd injection via {param}= (delay: {delay:.1f}s, verified: {elapsed2 - baseline:.1f}s)"
                        })
                        return findings

                # Output-based detection
                if any(marker in r.text for marker in LINUX_OUTPUT_MARKERS + WIN_OUTPUT_MARKERS):
                    findings.append({
                        "type": "COMMAND_INJECTION_OUTPUT",
                        "url": target,
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "detail": f"Command output reflected in response via {param}="
                    })
                    return findings

            except Exception:
                continue

    return findings if findings else None
