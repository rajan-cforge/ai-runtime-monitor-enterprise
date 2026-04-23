import hmac
import os

from fastapi import Header, HTTPException


def validate_api_key(x_api_key: str = Header(...)):
    """FastAPI dependency: validate X-API-Key header.

    Uses ``hmac.compare_digest`` for constant-time comparison. Plain
    ``!=`` leaks key length and per-character match state via response
    timing, which is a real timing-attack vector when the comparison
    short-circuits on the first mismatching byte.
    """
    expected = os.environ.get("CP_API_KEY", "")
    if not expected:
        raise HTTPException(401, "API key not configured on server")
    # compare_digest requires same-length bytes; normalize to avoid
    # raising TypeError on mismatched lengths (returns False instead).
    if not hmac.compare_digest(
        (x_api_key or "").encode("utf-8"),
        expected.encode("utf-8"),
    ):
        raise HTTPException(401, "Invalid API key")
    return x_api_key
