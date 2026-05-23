import base64
import json


def decode_token(id_token: str) -> dict:
    """
    Decode a JWT ID token payload WITHOUT signature verification.
    Demo purposes only — never skip verification in production.
    """
    try:
        parts = id_token.split(".")
        if len(parts) < 2:
            return {"error": "invalid token format"}
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded_bytes)
    except Exception as e:
        return {"error": f"decode failed: {str(e)}", "raw_preview": id_token[:60]}
