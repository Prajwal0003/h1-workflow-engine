"""
Feature 3: Continuous State-Diffing Engine
-------------------------------------------
Compares the current application state (JS files, API schemas, subdomains,
endpoints) against a previously saved snapshot. When new assets appear
(new subdomain, new JS file, new API endpoint), it triggers targeted
scanning ONLY on the delta — making the scanner fast and first-to-hack.

Usage:
    from modules.state_diff import StateDiffEngine
    engine = StateDiffEngine("data/state_snapshots")
    delta = engine.diff_and_update("target.com", current_assets)
    # delta = {"new_subdomains": [...], "new_endpoints": [...], "new_js_files": [...],
    #          "modified_js_files": [...], "removed_assets": [...]}
"""

import json
import hashlib
import time
import re
import requests
import urllib3
from pathlib import Path
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings()


class StateDiffEngine:
    """
    Maintains a persistent state of each target's attack surface and
    computes deltas between scan cycles. Only new/changed assets get
    forwarded for active scanning — reducing noise and catching fresh
    attack surface before anyone else.
    """

    def __init__(self, snapshots_dir="data/state_snapshots"):
        self.snapshots_dir = Path(snapshots_dir)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def _snapshot_path(self, domain):
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
        return self.snapshots_dir / f"{safe}.json"

    def _load_snapshot(self, domain):
        path = self._snapshot_path(domain)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except:
                pass
        return None

    def _save_snapshot(self, domain, snapshot):
        path = self._snapshot_path(domain)
        path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")

    def _hash_content(self, content):
        return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

    def collect_current_state(self, base_url, subdomains=None):
        """
        Actively collect the current state of a target:
        - Subdomains
        - JavaScript files (with content hashes)
        - API endpoints discovered in JS
        - HTTP response headers fingerprint
        """
        parsed = urlparse(base_url)
        domain = parsed.hostname

        state = {
            "domain": domain,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "subdomains": sorted(subdomains or []),
            "js_files": {},       # path -> content_hash
            "api_endpoints": [],  # discovered API paths
            "headers_fingerprint": "",
            "technologies": [],
        }

        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        headers = {"User-Agent": ua}

        try:
            # Fetch main page
            r = requests.get(base_url, headers=headers, timeout=10, verify=False)
            state["headers_fingerprint"] = self._hash_content(
                json.dumps(dict(r.headers), sort_keys=True)
            )

            # Extract technology hints from headers
            techs = []
            server = r.headers.get("Server", "")
            if server:
                techs.append(f"Server:{server}")
            powered_by = r.headers.get("X-Powered-By", "")
            if powered_by:
                techs.append(f"X-Powered-By:{powered_by}")
            state["technologies"] = techs

            # Find all JS files
            scripts = re.findall(r'<script[^>]+src="([^"]+)"', r.text)
            # Also check for dynamically loaded modules
            scripts += re.findall(r'(?:import|require)\s*\(\s*["\']([^"\']+\.js)', r.text)

            for script_src in scripts:
                if not script_src.startswith("http"):
                    script_src = urljoin(base_url, script_src)
                try:
                    js_r = requests.get(script_src, headers=headers, timeout=5, verify=False)
                    if js_r.status_code == 200:
                        content_hash = self._hash_content(js_r.text)
                        state["js_files"][script_src] = content_hash

                        # Extract API endpoints from JS
                        api_patterns = re.findall(
                            r'["\']/(api|v[0-9]|rest|graphql)/[^"\']*["\']', js_r.text
                        )
                        full_apis = re.findall(
                            r'["\'](/(?:api|v[0-9]|rest|graphql)[^"\']*)["\']', js_r.text
                        )
                        for api in full_apis:
                            clean = api.split("?")[0]
                            if clean not in state["api_endpoints"]:
                                state["api_endpoints"].append(clean)
                except:
                    pass

            # Also extract APIs from inline scripts
            inline_apis = re.findall(r'["\'](/(?:api|v[0-9]|rest|graphql)[^"\']*)["\']', r.text)
            for api in inline_apis:
                clean = api.split("?")[0]
                if clean not in state["api_endpoints"]:
                    state["api_endpoints"].append(clean)

            state["api_endpoints"] = sorted(set(state["api_endpoints"]))

        except Exception as e:
            print(f"  [State Diff] Error collecting state: {e}", flush=True)

        return state

    def diff(self, domain, current_state):
        """
        Compare current state against the last snapshot and return
        a delta of new/changed/removed assets.
        """
        previous = self._load_snapshot(domain)

        delta = {
            "domain": domain,
            "timestamp": current_state["timestamp"],
            "is_first_scan": previous is None,
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_js_files": [],
            "modified_js_files": [],   # JS files with changed content hash
            "removed_js_files": [],
            "new_api_endpoints": [],
            "removed_api_endpoints": [],
            "tech_changes": [],
            "header_fingerprint_changed": False,
        }

        if previous is None:
            # First scan — everything is "new"
            delta["new_subdomains"] = current_state["subdomains"]
            delta["new_js_files"] = list(current_state["js_files"].keys())
            delta["new_api_endpoints"] = current_state["api_endpoints"]
            return delta

        # Subdomain diff
        prev_subs = set(previous.get("subdomains", []))
        curr_subs = set(current_state["subdomains"])
        delta["new_subdomains"] = sorted(curr_subs - prev_subs)
        delta["removed_subdomains"] = sorted(prev_subs - curr_subs)

        # JS file diff
        prev_js = previous.get("js_files", {})
        curr_js = current_state["js_files"]
        delta["new_js_files"] = sorted(set(curr_js.keys()) - set(prev_js.keys()))
        delta["removed_js_files"] = sorted(set(prev_js.keys()) - set(curr_js.keys()))
        for js_url in set(curr_js.keys()) & set(prev_js.keys()):
            if curr_js[js_url] != prev_js[js_url]:
                delta["modified_js_files"].append(js_url)

        # API endpoint diff
        prev_apis = set(previous.get("api_endpoints", []))
        curr_apis = set(current_state["api_endpoints"])
        delta["new_api_endpoints"] = sorted(curr_apis - prev_apis)
        delta["removed_api_endpoints"] = sorted(prev_apis - curr_apis)

        # Technology changes
        prev_techs = set(previous.get("technologies", []))
        curr_techs = set(current_state["technologies"])
        if prev_techs != curr_techs:
            delta["tech_changes"] = sorted(curr_techs - prev_techs)

        # Header fingerprint
        delta["header_fingerprint_changed"] = (
            current_state["headers_fingerprint"] != previous.get("headers_fingerprint", "")
        )

        return delta

    def diff_and_update(self, domain, current_state=None, base_url=None, subdomains=None):
        """
        Compute the diff and save the new snapshot atomically.
        Either pass a pre-collected current_state, or pass base_url to auto-collect.
        """
        if current_state is None:
            if base_url is None:
                raise ValueError("Must provide either current_state or base_url")
            current_state = self.collect_current_state(base_url, subdomains)

        delta = self.diff(domain, current_state)
        self._save_snapshot(domain, current_state)

        # Print summary
        changes = (
            len(delta["new_subdomains"]) +
            len(delta["new_js_files"]) +
            len(delta["modified_js_files"]) +
            len(delta["new_api_endpoints"])
        )
        if delta["is_first_scan"]:
            print(f"  [State Diff] First scan — baselined {len(current_state['subdomains'])} subdomains, "
                  f"{len(current_state['js_files'])} JS files, {len(current_state['api_endpoints'])} APIs", flush=True)
        elif changes > 0:
            print(f"  [State Diff] 🔥 {changes} changes detected! "
                  f"New subs: {len(delta['new_subdomains'])}, "
                  f"New JS: {len(delta['new_js_files'])}, "
                  f"Modified JS: {len(delta['modified_js_files'])}, "
                  f"New APIs: {len(delta['new_api_endpoints'])}", flush=True)
        else:
            print(f"  [State Diff] No changes since last scan", flush=True)

        return delta

    def get_priority_scan_targets(self, delta, base_url):
        """
        Convert a delta into a prioritized list of URLs that should be
        immediately scanned by the exploit engine.
        """
        priority_urls = []

        # New API endpoints are top priority
        for api in delta.get("new_api_endpoints", []):
            priority_urls.append({
                "url": f"{base_url.rstrip('/')}{api}",
                "reason": "NEW_API_ENDPOINT",
                "priority": "CRITICAL",
            })

        # Modified JS files — secrets or new functionality may have been pushed
        for js_url in delta.get("modified_js_files", []):
            priority_urls.append({
                "url": js_url,
                "reason": "MODIFIED_JS_FILE",
                "priority": "HIGH",
            })

        # New JS files
        for js_url in delta.get("new_js_files", []):
            priority_urls.append({
                "url": js_url,
                "reason": "NEW_JS_FILE",
                "priority": "HIGH",
            })

        # New subdomains
        for sub in delta.get("new_subdomains", []):
            priority_urls.append({
                "url": f"https://{sub}" if not sub.startswith("http") else sub,
                "reason": "NEW_SUBDOMAIN",
                "priority": "MEDIUM",
            })

        return priority_urls
