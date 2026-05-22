"""Regression tests for AUDIT C1.

The control-plane bcrypts a per-endpoint API key on first registration
and stores the hash on ``endpoints.api_key_hash``. Before this fix, no
code path ever verified that hash on subsequent ingests; every endpoint
was effectively authenticated by the fleet-wide ``CP_API_KEY`` only and
the bcrypt work was theatre.

These tests pin the new contract:
* ``/api/v1/ingest`` requires both ``X-API-Key`` (fleet) and
  ``X-Endpoint-Key`` (per-endpoint) for already-registered endpoints.
* The per-endpoint key is verified against the stored bcrypt hash.
* The stored hash uses ``bcrypt.gensalt(rounds=12)`` minimum.
* Re-registering with the same plaintext key yields a different hash
  (salt is unique per endpoint).
"""

from __future__ import annotations

import bcrypt
import pytest

from tests.conftest import empty_ingest_payload, fetch_api_key_hash

FLEET_KEY = "fleet-secret"


def _register(client, hostname: str, endpoint_key: str):
    """Drive the first-time registration path that stores api_key_hash."""
    return client.post(
        "/api/v1/ingest",
        json=empty_ingest_payload(hostname),
        headers={
            "X-API-Key": FLEET_KEY,
            "X-Endpoint-Key": endpoint_key,
        },
    )


def test_ingest_rejects_missing_x_endpoint_key(cp_app):
    """Subsequent ingests without X-Endpoint-Key must be 401."""
    endpoint_key = "client-secret-aaaa"
    reg = _register(cp_app, "host-a", endpoint_key)
    assert reg.status_code == 202, reg.text

    response = cp_app.post(
        "/api/v1/ingest",
        json=empty_ingest_payload("host-a"),
        headers={"X-API-Key": FLEET_KEY},
    )
    assert response.status_code == 401
    assert "endpoint" in response.json().get("detail", "").lower()


def test_ingest_rejects_wrong_x_endpoint_key(cp_app, monkeypatch):
    """A garbage X-Endpoint-Key must fail bcrypt verification and 401.

    We monkeypatch ``bcrypt.checkpw`` with a spy to prove the production
    code calls bcrypt — i.e. the verification isn't a string compare
    masquerading as bcrypt.
    """
    endpoint_key = "client-secret-bbbb"
    reg = _register(cp_app, "host-b", endpoint_key)
    assert reg.status_code == 202, reg.text

    calls: list[tuple[bytes, bytes]] = []
    real_checkpw = bcrypt.checkpw

    def spy_checkpw(password, hashed):
        calls.append((password, hashed))
        return real_checkpw(password, hashed)

    monkeypatch.setattr("cp.auth.bcrypt.checkpw", spy_checkpw)

    response = cp_app.post(
        "/api/v1/ingest",
        json=empty_ingest_payload("host-b"),
        headers={
            "X-API-Key": FLEET_KEY,
            "X-Endpoint-Key": "garbage-not-the-real-one",
        },
    )
    assert response.status_code == 401
    assert calls, "bcrypt.checkpw was not called on the wrong-key path"
    provided, stored = calls[0]
    assert provided == b"garbage-not-the-real-one"
    assert stored.startswith(b"$2")


def test_ingest_accepts_correct_x_endpoint_key(cp_app):
    """The plaintext key returned by the first registration must work."""
    endpoint_key = "client-secret-cccc"
    reg = _register(cp_app, "host-c", endpoint_key)
    assert reg.status_code == 202, reg.text

    response = cp_app.post(
        "/api/v1/ingest",
        json=empty_ingest_payload("host-c"),
        headers={
            "X-API-Key": FLEET_KEY,
            "X-Endpoint-Key": endpoint_key,
        },
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["endpoint_id"]
    assert body["stored"]["sessions"] == 0


def test_password_hash_uses_minimum_12_rounds(cp_app):
    """Stored bcrypt hash must use cost >= 12. Format: ``$2b$NN$...``."""
    endpoint_key = "client-secret-dddd"
    reg = _register(cp_app, "host-d", endpoint_key)
    assert reg.status_code == 202, reg.text

    stored = fetch_api_key_hash(cp_app._engine, "host-d")
    parts = stored.split("$")
    assert len(parts) >= 4, f"unexpected bcrypt format: {stored!r}"
    assert parts[1].startswith("2"), f"not a bcrypt 2x hash: {stored!r}"
    cost = int(parts[2])
    assert cost >= 12, f"bcrypt cost rounds {cost} below required minimum 12"


def test_password_hash_salt_is_unique_per_user(cp_app):
    """Two endpoints registered with the same plaintext key must hash differently."""
    shared_key = "same-plaintext-everywhere"
    reg_a = _register(cp_app, "host-e", shared_key)
    reg_b = _register(cp_app, "host-f", shared_key)
    assert reg_a.status_code == 202, reg_a.text
    assert reg_b.status_code == 202, reg_b.text

    hash_a = fetch_api_key_hash(cp_app._engine, "host-e")
    hash_b = fetch_api_key_hash(cp_app._engine, "host-f")
    assert hash_a != hash_b, "salt was reused across endpoints"
    assert bcrypt.checkpw(shared_key.encode(), hash_a.encode())
    assert bcrypt.checkpw(shared_key.encode(), hash_b.encode())


@pytest.mark.parametrize(
    "bad_key",
    ["", "x", "wrong-key-1", "a" * 1024],
)
def test_ingest_rejects_various_wrong_keys(cp_app, bad_key):
    """A range of bad keys all 401."""
    endpoint_key = "client-secret-gggg"
    reg = _register(cp_app, "host-g", endpoint_key)
    assert reg.status_code == 202, reg.text

    response = cp_app.post(
        "/api/v1/ingest",
        json=empty_ingest_payload("host-g"),
        headers={
            "X-API-Key": FLEET_KEY,
            "X-Endpoint-Key": bad_key,
        },
    )
    assert response.status_code == 401
