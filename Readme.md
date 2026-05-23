# OAuth 2.0 Token Hijacking & Scope Abuse Detector
## Full System — Offensive + Defensive Tracks

```
oauth_project/
├── shared/
│   ├── mock_apps.json          # Simulated tenant app registry
│   └── events_log.json         # Shared log: offensive writes, defensive reads
│
├── offensive/                  # TRACK 1 — Persons 1 & 2 (Port 5001)
│   ├── attacker_server.py      # Flask C2: lure + callback + evict receiver
│   ├── token_decoder.py        # JWT payload decoder (no verification)
│   ├── token_store.py          # In-memory stolen token registry
│   ├── exfiltrator.py          # Automated data exfiltration (Gmail + Drive)
│   ├── requirements.txt
│   └── templates/
│       ├── lure.html           # Phishing portal: "HR Rewards Planner"
│       └── c2.html             # Attacker C2 dashboard (terminal aesthetic)
│
└── defensive/                  # TRACK 2 — Persons 3 & 4 (Port 5000)
    ├── app.py                  # Flask SOC backend + kill switch
    ├── ingestion_daemon.py     # Background tenant polling worker
    ├── scorer.py               # Algorithmic risk scoring matrix
    ├── risk_rules.json         # Threat weight rules + combo penalties
    ├── requirements.txt
    └── templates/
        └── dashboard.html      # SOC Analyst Dashboard (Bootstrap + live JS)
```

---

## The Pipeline (from the diagram)

```
Offensive                              Defensive
---------                              ---------
Phishing Lure (localhost:5001/)
      |
  Victim clicks "Allow"
      |
Attacker C2 Callback ──(writes event)──► Ingestion Daemon reads events_log.json
      |                                         |
Token Swapper runs                       Risk Engine scores app
      |                                         |
Exfiltration Script runs                 SOC Dashboard shows LIVE ATTACK
      |                                         |
C2 shows stolen data         ◄──(POST /evict)── Kill Switch fires
```

---

## TRACK 1 — Offensive Setup

### Step 1: Google Cloud Console (one-time, 10 minutes)
1. Go to https://console.cloud.google.com → New Project
2. APIs & Services → Library → Enable:
   - Gmail API
   - Google Drive API
3. APIs & Services → Credentials → Create OAuth 2.0 Client ID
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:5001/callback`
4. Download JSON → save as `offensive/client_secret.json`
5. OAuth consent screen → set to "External", add your test email as test user

### Step 2: Install & Run
```bash
cd offensive
pip install -r requirements.txt
python attacker_server.py
```

### Step 3: Demo the attack
- Visit http://localhost:5001/ — the phishing lure
- Click "Continue with Google" — crafts malicious OAuth URL
- Log in and consent — Google sends ?code= to /callback
- Callback swaps code → tokens, runs exfiltration, writes to shared log
- View http://localhost:5001/c2 — C2 dashboard showing stolen tokens

---

## TRACK 2 — Defensive Setup

### Install & Run
```bash
cd defensive
pip install -r requirements.txt
python app.py
```

Visit http://localhost:5000/ — SOC Dashboard

### What the dashboard shows:
- All 6 mock OAuth apps scored by risk level
- Live threat feed (polls events_log.json every 3s)
- REVOKE button per app (marks as revoked in daemon state)
- KILL TOKEN button in threat feed → fires POST to localhost:5001/evict/<id>

---

## Integration Flow (run both simultaneously)

Terminal 1:
```bash
cd offensive && python attacker_server.py
```

Terminal 2:
```bash
cd defensive && python app.py
```

**Demo sequence:**
1. Open http://localhost:5000/ — SOC dashboard
2. Open http://localhost:5001/ in another tab — phishing lure
3. Click "Continue with Google" and authorize
4. Watch the SOC dashboard threat feed update with the capture event
5. Click KILL TOKEN in the dashboard
6. Switch to http://localhost:5001/c2 — see the token marked EVICTED

---

## Standalone Exfiltration Test (no Google OAuth needed)

```bash
cd offensive
python exfiltrator.py <your_access_token_here>
```

Outputs: victim profile, last 5 emails (subject + sender), last 5 Drive files.

---

## Scope Risk Scoring Formula

```
score = max(matched_combo_score)
      + sum(individual_weights for unmatched scopes) - 15   [avoids double-count]
      + 15 [compounding penalty if write_scope + offline_access]
      capped at 100

Levels:
  0–39   → LOW      green
  40–69  → MEDIUM   blue
  70–89  → HIGH     yellow
  90–100 → CRITICAL red
```

---

## Ports Reference
| Service              | Port  |
|----------------------|-------|
| Offensive C2 server  | 5001  |
| Defensive SOC backend| 5000  |
| Shared events log    | file  |
