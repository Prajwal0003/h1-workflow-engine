"""
scanners/__init__.py — Modular scanner registry for Aegis-Auto.
All scanner modules are auto-discovered and integrated into the autopilot engine.
"""

from .xss import check_xss, check_dom_xss
from .ssrf import check_ssrf
from .ssti import check_ssti
from .csrf import check_csrf
from .xxe import check_xxe
from .smuggling import check_request_smuggling
from .race import check_race_condition
from .cache_poison import check_cache_poisoning
from .jwt import check_jwt_vulnerabilities
from .cms import check_cms_vulnerabilities
from .buckets import check_s3_buckets
from .git_exposure import check_git_exposure
from .dir_traversal import check_directory_traversal
from .waf import detect_waf
from .port_scan import check_ports
from .tech_detect import check_technologies
from .param_discovery import discover_parameters
from .link_discovery import discover_links_and_js
from .secrets_advanced import check_advanced_secrets
from .deserialization import check_insecure_deserialization
from .postmessage import check_postmessage
from .subdomain_permutation import generate_permutations
from .command_injection import check_command_injection
from .idor_advanced import check_idor_advanced

__all__ = [
    "check_xss", "check_dom_xss", "check_ssrf", "check_ssti", "check_csrf",
    "check_xxe", "check_request_smuggling", "check_race_condition",
    "check_cache_poisoning", "check_jwt_vulnerabilities", "check_cms_vulnerabilities",
    "check_s3_buckets", "check_git_exposure", "check_directory_traversal",
    "detect_waf", "check_ports", "check_technologies", "discover_parameters",
    "discover_links_and_js", "check_advanced_secrets", "check_insecure_deserialization",
    "check_postmessage", "generate_permutations", "check_command_injection",
    "check_idor_advanced",
]
