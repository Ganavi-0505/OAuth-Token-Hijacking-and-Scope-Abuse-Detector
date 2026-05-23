"""
Tenant Ingestion Daemon
========================
Background worker that simulates querying the cloud identity directory
for all OAuth permission grants (GET /oauth2PermissionGrants equivalent).

In a real deployment this would call:
  - Google: Admin SDK Directory API → list all tokens
  - Microsoft: GET https://graph.microsoft.com/v1.0/oauth2PermissionGrants

For this demo it polls mock_apps.json and the shared events_log.json,
merges them, re-scores everything, and stores results in memory for
the Flask backend to serve.

Run standalone to verify: python ingestion_daemon.py
"""

import json
import os
import time
import threading
import copy
from scorer import score as compute_score

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
MOCK_APPS_PATH  = os.path.join(BASE_DIR, "../shared/mock_apps.json")
EVENTS_LOG_PATH = os.path.join(BASE_DIR, "../shared/events_log.json")

POLL_INTERVAL = 5  # seconds between tenant re-scans

# Shared in-memory state — Flask reads from this, daemon writes to it
_state = {
    "apps":        [],   # scored app list
    "events":      [],   # live events from offensive track
    "last_synced": None,
    "lock":        threading.Lock()
}


def _load_mock_grants() -> list:
    """
    Simulates GET /oauth2PermissionGrants from the identity directory.
    In production: replace with real Admin SDK call.
    """
    try:
        with open(MOCK_APPS_PATH) as f:
            raw = json.load(f)
        apps = []
        for app in raw:
            scored = copy.deepcopy(app)
            scored.update(compute_score(app["scopes"]))
            scored["revoked"] = False
            apps.append(scored)
        return apps
    except Exception as e:
        print(f"[DAEMON] Error loading mock grants: {e}")
        return []


def _load_events() -> list:
    """
    Read shared events log written by the offensive server.
    This is how the defensive daemon detects live attacks.
    """
    try:
        with open(EVENTS_LOG_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _sync():
    """Full tenant sync — called every POLL_INTERVAL seconds."""
    apps   = _load_mock_grants()
    events = _load_events()

    # Preserve any revocations that happened since last sync
    with _state["lock"]:
        existing_revoked = {
            a["id"] for a in _state["apps"] if a.get("revoked")
        }
        for app in apps:
            if app["id"] in existing_revoked:
                app["revoked"] = True

        _state["apps"]        = apps
        _state["events"]      = events
        _state["last_synced"] = time.strftime("%Y-%m-%dT%H:%M:%S")

    print(f"[DAEMON] Sync complete — {len(apps)} apps, {len(events)} events")


def get_apps() -> list:
    with _state["lock"]:
        return copy.deepcopy(_state["apps"])


def get_events() -> list:
    with _state["lock"]:
        return copy.deepcopy(_state["events"])


def revoke_app(app_id: str) -> bool:
    with _state["lock"]:
        for app in _state["apps"]:
            if app["id"] == app_id:
                app["revoked"] = True
                return True
    return False


def get_stats() -> dict:
    with _state["lock"]:
        active = [a for a in _state["apps"] if not a.get("revoked")]
        events = _state["events"]
        live_attacks = sum(
            1 for e in events
            if e.get("type") == "token_captured" and e.get("status") == "active"
        )
        return {
            "total":        len(active),
            "critical":     sum(1 for a in active if a["level"] == "critical"),
            "high":         sum(1 for a in active if a["level"] == "high"),
            "medium":       sum(1 for a in active if a["level"] == "medium"),
            "low":          sum(1 for a in active if a["level"] == "low"),
            "revoked":      len(_state["apps"]) - len(active),
            "live_attacks": live_attacks,
            "last_synced":  _state["last_synced"],
        }


def start_background_daemon():
    """Start the polling daemon in a background thread."""
    _sync()  # immediate first sync

    def loop():
        while True:
            time.sleep(POLL_INTERVAL)
            _sync()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    print(f"[DAEMON] Ingestion daemon started — polling every {POLL_INTERVAL}s")


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[DAEMON] Running standalone sync test...\n")
    _sync()
    apps = get_apps()
    stats = get_stats()
    print(f"\nStats: {json.dumps(stats, indent=2)}")
    print(f"\nTop risk apps:")
    for app in sorted(apps, key=lambda x: x["score"], reverse=True)[:3]:
        print(f"  [{app['level'].upper():8}] {app['name']:25} score={app['score']}")
        for flag in app["flags"]:
            print(f"    ↳ {flag}")
