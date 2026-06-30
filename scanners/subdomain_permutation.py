"""
Subdomain Permutation Generator.
Ref: awesome-bugbounty-tools (alterx, gotator, ripgen, dnsgen, altdns).
"""
from .utils import run_bin


COMMON_PREFIXES = [
    "dev", "staging", "stage", "test", "qa", "uat", "pre", "prod",
    "api", "app", "admin", "panel", "portal", "internal", "intranet",
    "vpn", "mail", "smtp", "ftp", "cdn", "static", "assets", "media",
    "blog", "shop", "store", "pay", "billing", "dashboard",
    "jenkins", "jira", "gitlab", "git", "ci", "cd", "deploy",
    "monitor", "grafana", "kibana", "elastic", "redis", "db",
    "backup", "old", "new", "beta", "alpha", "demo", "sandbox",
]


def generate_permutations(domain):
    """Generate subdomain permutations using alterx or manual generation."""
    permutations = set()

    # Try alterx first
    alterx_out = run_bin("alterx", ["-p", "{{word}}.{{suffix}}", "-silent"], timeout=15, input_data=domain)
    if alterx_out:
        for line in alterx_out.strip().split('\n'):
            line = line.strip()
            if line and "." in line:
                permutations.add(line)

    if permutations:
        return list(permutations)

    # Manual permutation fallback
    parts = domain.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    for prefix in COMMON_PREFIXES:
        permutations.add(f"{prefix}.{base}")
        permutations.add(f"{prefix}-{parts[0]}.{'.'.join(parts[1:])}" if len(parts) > 1 else f"{prefix}-{domain}")
        if len(parts) > 2:
            permutations.add(f"{prefix}.{parts[0]}.{'.'.join(parts[1:])}")

    return list(permutations)
