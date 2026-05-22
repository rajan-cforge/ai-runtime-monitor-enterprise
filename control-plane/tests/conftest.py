"""Shared fixtures for control-plane tests.

The production control-plane runs on Postgres. For unit/integration
tests we swap the SQLAlchemy engine for an in-process SQLite database
created from a Postgres-compatible-subset schema. The audit-finding
regression tests only touch the ``endpoints`` table and the ingest
endpoint with empty payloads, so the schema below is intentionally
minimal — it mirrors ``migrations/001_initial_schema.sql`` for the
columns those tests touch.
"""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

SCHEMA_SQL = [
    """CREATE TABLE endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id TEXT NOT NULL UNIQUE,
        hostname TEXT NOT NULL,
        ip_address TEXT,
        os TEXT,
        monitor_version TEXT,
        api_key_hash TEXT NOT NULL,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        last_heartbeat TEXT,
        status TEXT DEFAULT 'active',
        metadata TEXT DEFAULT '{}'
    )""",
    """CREATE TABLE fleet_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id TEXT NOT NULL,
        client_session_id TEXT NOT NULL,
        start_time TEXT,
        cwd TEXT,
        model TEXT,
        agent_type TEXT,
        title TEXT,
        total_cost REAL DEFAULT 0,
        total_input_tokens INTEGER DEFAULT 0,
        total_output_tokens INTEGER DEFAULT 0,
        total_turns INTEGER DEFAULT 0,
        last_activity TEXT,
        UNIQUE(endpoint_id, client_session_id)
    )""",
    """CREATE TABLE fleet_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id TEXT NOT NULL,
        client_event_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        event_type TEXT NOT NULL,
        source_layer TEXT NOT NULL,
        data_json TEXT NOT NULL,
        UNIQUE(endpoint_id, client_event_id)
    )""",
    """CREATE TABLE fleet_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id TEXT NOT NULL,
        client_event_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        severity TEXT NOT NULL,
        patterns TEXT,
        context TEXT,
        snippet TEXT,
        validated INTEGER DEFAULT 0,
        confidence TEXT,
        dismissed INTEGER DEFAULT 0,
        dismissed_at TEXT,
        UNIQUE(endpoint_id, client_event_id)
    )""",
    """CREATE TABLE fleet_api_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        endpoint_id TEXT NOT NULL,
        client_call_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        session_id TEXT,
        model TEXT,
        destination_service TEXT,
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        cache_read_tokens INTEGER DEFAULT 0,
        cache_write_tokens INTEGER DEFAULT 0,
        estimated_cost_usd REAL DEFAULT 0,
        latency_ms INTEGER DEFAULT 0,
        UNIQUE(endpoint_id, client_call_id)
    )""",
    """CREATE TABLE sync_watermarks (
        endpoint_id TEXT NOT NULL,
        table_name TEXT NOT NULL,
        last_client_id INTEGER DEFAULT 0,
        last_sync TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(endpoint_id, table_name)
    )""",
]


@pytest.fixture
def cp_app(monkeypatch, tmp_path):
    """Return a FastAPI TestClient with a SQLite-backed control-plane.

    Patches ``cp.db.get_db`` to yield an in-memory SQLite session, sets
    ``CP_API_KEY`` to a known value, and rewrites the ``now()`` /
    ``CURRENT_TIMESTAMP`` shim used by ``process_ingest``.
    """
    monkeypatch.setenv("CP_API_KEY", "fleet-secret")

    db_path = tmp_path / "cp_test.sqlite"
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        for stmt in SCHEMA_SQL:
            conn.execute(text(stmt))

    SessionLocal = sessionmaker(bind=engine, autoflush=False)

    def _get_db_override():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    import cp.app as app_module
    from cp.db import get_db

    app_module.app.dependency_overrides[get_db] = _get_db_override
    try:
        client = TestClient(app_module.app)
        client._engine = engine  # expose for assertions
        yield client
    finally:
        app_module.app.dependency_overrides.pop(get_db, None)


def empty_ingest_payload(hostname: str = "host-a") -> dict:
    return {
        "endpoint": {
            "hostname": hostname,
            "os": "macOS",
            "ip": "127.0.0.1",
            "monitor_version": "0.1.0",
        },
        "sessions": [],
        "events": [],
        "api_calls": [],
        "alerts": [],
        "watermarks": {},
    }


def fetch_api_key_hash(engine, hostname: str) -> str:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT api_key_hash FROM endpoints WHERE hostname = :h"),
            {"h": hostname},
        ).fetchone()
    assert row is not None, f"endpoint {hostname!r} not registered"
    return row[0]


def make_endpoint_id() -> str:
    return str(uuid.uuid4())


# Expose helpers on the conftest module so test files can import them.
os.environ.setdefault("PYTHONUTF8", "1")
