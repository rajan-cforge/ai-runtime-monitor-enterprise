from __future__ import annotations

import hmac
import os

import bcrypt
from fastapi import Header, HTTPException
from sqlalchemy import text


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


def verify_endpoint_key(db, hostname: str, provided_key: str | None) -> None:
    """Verify a per-endpoint ``X-Endpoint-Key`` against the stored bcrypt hash.

    Behaviour:
    * If the endpoint is *not yet registered*, returns without raising —
      ``register_or_update_endpoint`` will then store the bcrypt hash of
      ``provided_key`` so subsequent ingests can authenticate.
    * If the endpoint *is* registered and either no header was sent or
      the provided key does not match the stored hash, raises 401.

    Audit ref: docs/AUDIT_2026-05-21.md#C1. Fixes the "bcrypt is theatre"
    finding by tying per-endpoint key rotation to actual auth.
    """
    row = db.execute(
        text("SELECT api_key_hash FROM endpoints WHERE hostname = :hostname"),
        {"hostname": hostname},
    ).fetchone()

    if row is None:
        if not provided_key:
            raise HTTPException(401, "Missing X-Endpoint-Key for registration")
        return

    stored_hash = row[0]
    if not provided_key:
        raise HTTPException(401, "Missing X-Endpoint-Key header")

    try:
        ok = bcrypt.checkpw(provided_key.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # Malformed hash on disk: fail closed.
        ok = False
    if not ok:
        raise HTTPException(401, "Invalid endpoint key")
