"""
Defensive Backend — Port 5000
================================
SOC Analyst Dashboard API + Kill Switch Engine

Routes:
  GET  /                  — SOC Dashboard HTML
  GET  /api/apps          — Scored app list (from ingestion daemon)
  GET  /api/events        — Live event feed from offensive track
  GET  /api/stats         — Aggregated counters
  POST /api/revoke/<id>   — Soft revoke (marks in-memory)
  POST /api/kill/<tid>    — THE KILL SWITCH: fires HTTP DELETE to offensive server
  POST /api/reset         — Reload from mock data
"""

import json
import os
import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

from ingestion_daemon import (
    start_background_daemon,
    get_apps, get_events, get_stats,
    revoke_app as daemon_revoke
)
from scorer import score as compute_score, level_badge_class

OFFENSIVE_HOST = "http://localhost:5001"
EVENTS_LOG     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../shared/events_log.json")

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173", "http://localhost:5001"])


# ── Dashboard HTML ────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    apps   = get_apps()
    stats  = get_stats()
    events = get_events()

    # Enrich apps with badge classes for template
    for a in apps:
        a["badge_class"] = level_badge_class(a["level"])

    # Only show most recent 10 events, newest first
    recent_events = list(reversed(events))[:10]

    return render_template(
        "dashboard.html",
        apps=apps,
        stats=stats,
        events=recent_events
    )


# ── REST API ──────────────────────────────────────────────────────────────────

@app.route("/api/apps")
def api_apps():
    return jsonify(get_apps())


@app.route("/api/events")
def api_events():
    return jsonify(list(reversed(get_events()))[:20])


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/revoke/<app_id>", methods=["POST"])
def api_revoke(app_id: str):
    """
    Soft revoke — marks app as revoked in the daemon's state.
    In production this would call Google Admin SDK:
      DELETE https://www.googleapis.com/admin/directory/v1/users/{user}/tokens/{client_id}
    """
    success = daemon_revoke(app_id)
    return jsonify({"success": success, "id": app_id})


@app.route("/api/kill/<token_id>", methods=["POST"])
def api_kill(token_id: str):
    """
    THE KILL SWITCH — One-Click Active Eviction Engine.

    Fires an HTTP POST to the offensive server's /evict/:id endpoint,
    simulating a zero-trust DELETE to the cloud identity directory.

    This renders the attacker's stolen tokens useless — even if they
    have the token string, the server will reject it as revoked.

    In production this would call:
      Google:    POST https://oauth2.googleapis.com/revoke?token=<refresh_token>
      Microsoft: DELETE https://graph.microsoft.com/v1.0/me/revokeSignInSessions
    """
    try:
        resp = requests.post(
            f"{OFFENSIVE_HOST}/evict/{token_id}",
            timeout=4
        )
        result = resp.json()
        evicted = result.get("evicted", False)

        # Also update our local events log to reflect the kill
        try:
            with open(EVENTS_LOG) as f:
                events = json.load(f)
            for e in events:
                if e.get("token_id") == token_id:
                    e["status"] = "evicted"
            with open(EVENTS_LOG, "w") as f:
                json.dump(events, f, indent=2)
        except Exception:
            pass

        return jsonify({
            "kill_sent":            True,
            "offensive_confirmed":  evicted,
            "token_id":             token_id,
            "message": "Token evicted — attacker access revoked" if evicted
                       else "Kill sent but token not found on offensive server"
        })

    except requests.exceptions.ConnectionError:
        return jsonify({
            "kill_sent": False,
            "error":     "Offensive server unreachable (is it running on port 5001?)",
            "token_id":  token_id
        }), 503

    except requests.exceptions.Timeout:
        return jsonify({
            "kill_sent": False,
            "error":     "Offensive server timed out",
            "token_id":  token_id
        }), 504


@app.route("/api/score", methods=["POST"])
def api_score():
    data = request.get_json() or {}
    return jsonify(compute_score(data.get("scopes", [])))


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Reload app list from mock data — useful during demo."""
    from ingestion_daemon import _sync
    _sync()
    return jsonify({"reset": True})


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n[DEFENSIVE] Starting ingestion daemon...")
    start_background_daemon()
    print("[DEFENSIVE] SOC Dashboard at http://localhost:5000")
    print("[DEFENSIVE] Kill switch ready — will fire to http://localhost:5001/evict/<id>\n")
    app.run(port=5000, debug=True, use_reloader=False)
