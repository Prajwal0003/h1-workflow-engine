"""
Target Discovery Module — Multi-Platform Target Fetcher
Pulls 10 targets from HackerOne + 10 from Bugcrowd per cycle.
Creates autopilot-compatible JSON files in data/selected_targets/.
Rotates targets each cycle to maximize coverage.
"""

import json
import time
import random
import logging
import requests
import urllib3
from pathlib import Path
from urllib.parse import urlparse

urllib3.disable_warnings()

logger = logging.getLogger("target_discovery")

H1_DATA_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/hackerone_data.json"
BC_DATA_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/bugcrowd_data.json"

TARGETS_DIR = Path("data/selected_targets")
DISCOVERY_CACHE = Path("data/discovery_cache.json")
HISTORY_FILE = Path("data/target_history.json")

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"


def _fetch_h1_programs():
    """Fetch all HackerOne programs from bounty-targets-data."""
    logger.info("Fetching HackerOne programs from bounty-targets-data...")
    try:
        r = requests.get(H1_DATA_URL, timeout=60)
        r.raise_for_status()
        programs = r.json()
        logger.info(f"Loaded {len(programs)} HackerOne programs")
        return programs
    except Exception as e:
        logger.error(f"Failed to fetch H1 programs: {e}")
        return []


def _fetch_bc_programs():
    """Fetch all Bugcrowd programs from bounty-targets-data."""
    logger.info("Fetching Bugcrowd programs from bounty-targets-data...")
    try:
        r = requests.get(BC_DATA_URL, timeout=60)
        r.raise_for_status()
        programs = r.json()
        logger.info(f"Loaded {len(programs)} Bugcrowd programs")
        return programs
    except Exception as e:
        logger.error(f"Failed to fetch Bugcrowd programs: {e}")
        return []


def _check_url_live(url, timeout=5):
    """Quick liveness check on a URL."""
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                         verify=False, allow_redirects=True)
        if r.status_code in [200, 301, 302, 403]:
            body = r.text.lower()
            parking = ["domain is for sale", "buy this domain", "parked",
                       "godaddy", "sedoparking", "this domain"]
            if any(p in body for p in parking):
                return False
            if len(r.text) < 200:
                return False
            return True
    except Exception:
        pass
    return False


def _load_history():
    """Load previously scanned targets to avoid repeats."""
    if HISTORY_FILE.exists():
        try:
            data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            return data
        except Exception:
            pass
    return {"scanned_handles": [], "last_rotation": None}


def _save_history(history):
    """Save scan history."""
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")


def _filter_h1_candidates(programs, already_scanned):
    """Filter HackerOne programs to good scanning candidates."""
    candidates = []
    for p in programs:
        if not p.get("offers_bounties", False):
            continue

        handle = p.get("handle", "")
        if not handle or handle in already_scanned:
            continue

        # Extract web URLs from scope
        in_scope = p.get("targets", {}).get("in_scope", [])
        web_urls = []
        wildcard_domains = []
        scope_items = []

        for t in in_scope:
            asset = t.get("asset_identifier", "")
            atype = t.get("asset_type", "").upper()

            if atype in ("APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID",
                         "HARDWARE", "WINDOWS_APP", "OTHER_APK", "CIDR",
                         "SOURCE_CODE", "EXECUTABLE", "OTHER"):
                continue

            scope_items.append({
                "asset_identifier": asset,
                "asset_type": atype,
                "instruction": t.get("instruction", ""),
                "eligible_for_submission": t.get("eligible_for_submission", True)
            })

            if atype == "WILDCARD" or asset.startswith("*."):
                wildcard_domains.append(asset)
            elif atype in ("URL", "DOMAIN") or ("." in asset and " " not in asset):
                clean = asset.strip().rstrip("/")
                if not clean.startswith("http"):
                    clean = f"https://{clean}"
                if "*" not in clean:
                    web_urls.append(clean)

        if not web_urls and not wildcard_domains:
            continue

        candidates.append({
            "source": "hackerone",
            "handle": handle,
            "name": p.get("name", handle),
            "url": p.get("url", f"https://hackerone.com/{handle}"),
            "web_urls": web_urls[:15],
            "wildcards": wildcard_domains[:10],
            "scope_items": scope_items,
            "scope_size": len(in_scope),
            "score": len(web_urls) + len(wildcard_domains) * 3,  # Wildcards are gold
        })

    return candidates


def _filter_bc_candidates(programs, already_scanned):
    """Filter Bugcrowd programs to good scanning candidates."""
    candidates = []
    for p in programs:
        # Bugcrowd uses max_payout > 0 to indicate bounty programs
        max_payout = p.get("max_payout", 0)
        if not max_payout or max_payout <= 0:
            continue

        # Extract handle from the URL (e.g. https://bugcrowd.com/engagements/foo -> bc_foo)
        bc_url = p.get("url", "")
        code = bc_url.rstrip("/").split("/")[-1] if bc_url else ""
        name = p.get("name", code)
        handle = f"bc_{code}" if code else f"bc_{name.replace(' ', '_').lower()[:30]}"
        if not handle or handle == "bc_" or handle in already_scanned:
            continue

        in_scope = p.get("targets", {}).get("in_scope", [])
        web_urls = []
        wildcard_domains = []
        scope_items = []

        for t in in_scope:
            asset = t.get("target", "") or t.get("uri", "")
            atype = t.get("type", "").lower()

            # Skip non-web targets
            if atype in ("android", "ios", "hardware", "iot", "other"):
                continue

            scope_items.append({
                "asset_identifier": asset,
                "asset_type": atype.upper() if atype else "URL",
                "instruction": t.get("name", ""),
                "eligible_for_submission": True
            })

            if asset.startswith("*."):
                wildcard_domains.append(asset)
            elif "." in asset and " " not in asset and "*" not in asset:
                clean = asset.strip().rstrip("/")
                if not clean.startswith("http"):
                    clean = f"https://{clean}"
                web_urls.append(clean)

        if not web_urls and not wildcard_domains:
            continue

        candidates.append({
            "source": "bugcrowd",
            "handle": handle,
            "name": name,
            "url": bc_url,
            "web_urls": web_urls[:15],
            "wildcards": wildcard_domains[:10],
            "scope_items": scope_items,
            "scope_size": len(in_scope),
            "score": len(web_urls) + len(wildcard_domains) * 3,
        })

    return candidates


def _create_target_json(candidate):
    """Create autopilot-compatible target JSON in data/selected_targets/."""
    handle = candidate["handle"]
    safe_handle = handle.replace("/", "_").replace("\\", "_").replace(" ", "_")

    # Build scope structure matching autopilot.py's load_targets() format
    scope_all = []
    for item in candidate.get("scope_items", []):
        scope_all.append({
            "asset_identifier": item["asset_identifier"],
            "asset_type": item["asset_type"],
            "instruction": item.get("instruction", ""),
            "eligible_for_submission": item.get("eligible_for_submission", True),
        })

    target_data = {
        "handle": handle,
        "name": candidate["name"],
        "url": candidate.get("url", ""),
        "source": candidate["source"],
        "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "all": scope_all
        }
    }

    target_path = TARGETS_DIR / f"{safe_handle}.json"
    TARGETS_DIR.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps(target_data, indent=2), encoding="utf-8")
    logger.info(f"Created target file: {target_path}")
    return safe_handle


def _validate_candidates(candidates, max_validate=5):
    """Check if at least one URL per candidate is live."""
    validated = []
    for c in candidates:
        # Quick check: test up to 3 URLs
        live_count = 0
        for url in c["web_urls"][:3]:
            if _check_url_live(url):
                live_count += 1
                break  # One live URL is enough
            time.sleep(0.2)

        if live_count > 0 or c["wildcards"]:
            validated.append(c)
            if len(validated) >= max_validate:
                break

    return validated


def discover_targets(h1_count=10, bc_count=10):
    """
    Main discovery function. Fetches targets from both platforms,
    filters, validates, and creates target JSON files.

    Returns list of target handles ready for autopilot.
    """
    history = _load_history()
    already_scanned = set(history.get("scanned_handles", []))

    # Keep history from getting too large — only remember last 200
    if len(already_scanned) > 200:
        history["scanned_handles"] = list(already_scanned)[-100:]
        already_scanned = set(history["scanned_handles"])

    logger.info(f"Already scanned {len(already_scanned)} targets in history")

    # Fetch from both platforms
    h1_programs = _fetch_h1_programs()
    bc_programs = _fetch_bc_programs()

    # Filter to valid candidates
    h1_candidates = _filter_h1_candidates(h1_programs, already_scanned)
    bc_candidates = _filter_bc_candidates(bc_programs, already_scanned)

    logger.info(f"H1 candidates: {len(h1_candidates)} | BC candidates: {len(bc_candidates)}")

    # Sort by score (bigger scope = more attack surface = better)
    h1_candidates.sort(key=lambda x: x["score"], reverse=True)
    bc_candidates.sort(key=lambda x: x["score"], reverse=True)

    # Pick a mix: top scorers + some random ones for variety
    h1_top = h1_candidates[:h1_count // 2]
    h1_random_pool = h1_candidates[h1_count // 2:]
    h1_random = random.sample(h1_random_pool, min(h1_count - len(h1_top), len(h1_random_pool)))
    h1_selected = h1_top + h1_random

    bc_top = bc_candidates[:bc_count // 2]
    bc_random_pool = bc_candidates[bc_count // 2:]
    bc_random = random.sample(bc_random_pool, min(bc_count - len(bc_top), len(bc_random_pool)))
    bc_selected = bc_top + bc_random

    logger.info(f"Selected {len(h1_selected)} H1 + {len(bc_selected)} BC targets for validation")

    # Validate liveness (check more than we need so we can backfill)
    h1_validated = _validate_candidates(h1_selected, max_validate=h1_count)
    bc_validated = _validate_candidates(bc_selected, max_validate=bc_count)

    # If we didn't get enough, try more from the pool
    if len(h1_validated) < h1_count and len(h1_random_pool) > len(h1_random):
        extras = [c for c in h1_random_pool if c not in h1_selected]
        more = _validate_candidates(extras[:20], max_validate=h1_count - len(h1_validated))
        h1_validated.extend(more)

    if len(bc_validated) < bc_count and len(bc_random_pool) > len(bc_random):
        extras = [c for c in bc_random_pool if c not in bc_selected]
        more = _validate_candidates(extras[:20], max_validate=bc_count - len(bc_validated))
        bc_validated.extend(more)

    all_targets = h1_validated + bc_validated
    logger.info(f"Validated {len(h1_validated)} H1 + {len(bc_validated)} BC = {len(all_targets)} total targets")

    # Create target JSON files and collect handles
    target_handles = []
    for candidate in all_targets:
        try:
            handle = _create_target_json(candidate)
            target_handles.append(handle)
            history["scanned_handles"].append(candidate["handle"])
        except Exception as e:
            logger.error(f"Failed to create target for {candidate['handle']}: {e}")

    history["last_rotation"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    history["last_batch"] = {
        "h1_count": len(h1_validated),
        "bc_count": len(bc_validated),
        "handles": target_handles,
    }
    _save_history(history)

    # Save discovery summary
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "h1_total_available": len(h1_candidates),
        "bc_total_available": len(bc_candidates),
        "h1_selected": len(h1_validated),
        "bc_selected": len(bc_validated),
        "targets": [
            {
                "handle": c["handle"],
                "name": c["name"],
                "source": c["source"],
                "urls": len(c["web_urls"]),
                "wildcards": len(c["wildcards"]),
                "score": c["score"],
            }
            for c in all_targets
        ]
    }
    DISCOVERY_CACHE.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return target_handles


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s - %(name)s - %(message)s")
    handles = discover_targets(h1_count=10, bc_count=10)
    print(f"\n{'='*60}")
    print(f"Discovered {len(handles)} targets:")
    for i, h in enumerate(handles, 1):
        print(f"  {i:2d}. {h}")
    print(f"{'='*60}")
