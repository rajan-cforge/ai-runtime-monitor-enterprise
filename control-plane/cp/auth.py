import os

from fastapi import Header, HTTPException


def validate_api_key(x_api_key: str = Header(...)):
    """FastAPI dependency: validate X-API-Key header.

    MVP: direct string comparison of the shared key.
    Per-endpoint bcrypt-based keys will be added later.
    """
    expected = os.environ.get("CP_API_KEY", "")
    if not expected:
        raise HTTPException(401, "API key not configured on server")
    if x_api_key != expected:
        raise HTTPException(401, "Invalid API key")
    return x_api_key
