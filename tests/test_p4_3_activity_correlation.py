"""TDD red-phase tests for P4.3 runtime activity correlation.

Pins the contract Rajan ratified 2026-06-12:
  * Q8 Path A — host-based correlation (spec §7.1.1 amendment downscopes
    PID-JOIN to destination-host aggregation; the spec's `process_id`
    column never existed).
  * Q8 rider — TWO distinct no-data states (NEVER collapsed):
      - `"asset_has_no_runtime_correlation"` (structural n/a — python
        packages, MCP config-only)
      - `"correlatable_type_no_activity"` (meaningful negative — chrome
        ext correlatable but no captures in window)
    Amendment-C discipline: different facts, different renderings.
  * Q9 — `activity_recency` factor (spec §6.1) wired from real
    last-seen timestamps. Bucketing: 100/80/60/30/0 by recency.
  * Endpoint `/api/asset/<id>/activity?window=24h|7d|30d` with envelope
    `{last_seen, top_destinations, anomalies, data_status}`.
  * Auth gate inherited from `_check_auth` (covered by
    test_security_hardening).
"""

from __future__ import annotations

import json
import threading
import time
from http.server import HTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from claude_monitoring.db import init_db

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_NOW = 1734000000.0  # fixed test clock
_24H_AGO = _NOW - 24 * 3600
_3DAYS_AGO = _NOW - 3 * 86400
_7DAYS_AGO = _NOW - 7 * 86400
_8DAYS_AGO = _NOW - 8 * 86400


def _setup_activity_db(tmp_path):
    """Build a temp DB with assets + api_calls covering every render state."""
    db_path = tmp_path / "test.db"
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    conn = init_db(db_path)

    # ---- assets ----
    assets = [
        # (id, name, source, type) — covering structural + correlatable cases
        # Correlatable types (expected_hosts entry will exist):
        ("ext-claude-ok", "Claude", "chromium-extensions", "browser_extension"),
        ("ext-claude-noact", "Claude-noact", "chromium-extensions", "browser_extension"),
        ("ollama-llama3", "llama3", "ollama-models", "ai_model"),
        # Structural-noncorrelatable types (no expected_hosts entry):
        ("pkg-requests", "requests", "python-packages", "python_package"),
        ("mcp-cfg", "config-only-mcp", "mcp-servers", "mcp_server"),
    ]
    for aid, name, source, atype in assets:
        conn.execute(
            """INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (aid, atype, name, source, _NOW - 86400, _NOW, _NOW, "{}"),
        )

    # ---- api_calls ----
    # Chrome extension correlate via host = "api.anthropic.com" and "claude.ai"
    # ext-claude-ok: has recent hits → ok
    # ext-claude-noact: NO hits at all → correlatable_type_no_activity
    # ollama: has hits to localhost:11434 in prior-7d but not last-24h
    rows = [
        # (timestamp_iso, dest_host, dest_service, bytes_in, bytes_out)
        # ext-claude-ok: 5 hits last 24h on api.anthropic.com + 1 new host
        (_NOW - 3600, "api.anthropic.com", "anthropic_api", 1000, 5000),
        (_NOW - 3600, "api.anthropic.com", "anthropic_api", 1500, 4000),
        (_NOW - 7200, "api.anthropic.com", "anthropic_api", 2000, 3000),
        (_NOW - 10800, "claude.ai", "claude_web", 500, 100),
        (_NOW - 14400, "api.anthropic.com", "anthropic_api", 800, 2000),
        # New-host anomaly: prior 7d had only api.anthropic.com, last-24h adds claude.ai
        (_3DAYS_AGO, "api.anthropic.com", "anthropic_api", 1000, 2000),
        (_3DAYS_AGO, "api.anthropic.com", "anthropic_api", 1000, 2000),
        # ollama: hits on localhost:11434 in prior 7d (3-8 days) but NOT last-24h
        (_3DAYS_AGO, "localhost:11434", "ollama", 100, 5000),
        (_3DAYS_AGO, "localhost:11434", "ollama", 100, 6000),
    ]
    for ts, host, svc, bytes_in, bytes_out in rows:
        ts_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        conn.execute(
            """INSERT INTO api_calls (timestamp, session_id, destination_host, destination_service,
                                       request_size_bytes, response_size_bytes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (ts_iso, "test-sess", host, svc, bytes_in, bytes_out),
        )

    conn.commit()
    conn.close()
    return db_path, output_dir


@pytest.fixture()
def api_server(tmp_path, monkeypatch):
    monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
    db_path, output_dir = _setup_activity_db(tmp_path)
    # Freeze "now" for deterministic windowing
    monkeypatch.setattr(
        "claude_monitoring.attack_surface.activity.correlator._now",
        lambda: _NOW,
    )
    # Default the heartbeat to fresh so `capture_ok=True` in the handler.
    # CI runners have no live daemon → `heartbeat_age_seconds()` returns
    # None → the handler would collapse every response to `capture_off`.
    # Individual tests that need `capture_off` re-patch this to `None`.
    monkeypatch.setattr(
        "claude_monitoring.lifecycle.heartbeat_age_seconds",
        lambda: 5.0,
    )
    with (
        patch("claude_monitoring.monitor.DB_PATH", db_path),
        patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir),
        patch("claude_monitoring.config.get_db_path", return_value=db_path),
        patch("claude_monitoring.config.get_output_dir", return_value=output_dir),
        patch("claude_monitoring.db.get_db_path", return_value=db_path),
        patch("claude_monitoring.db.get_output_dir", return_value=output_dir),
    ):
        from claude_monitoring.monitor import DashboardHandler

        server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{port}"
        server.shutdown()


# ---------------------------------------------------------------------------
# Endpoint envelope
# ---------------------------------------------------------------------------


class TestActivityEndpointEnvelope:
    def test_route_exists_and_returns_json(self, api_server):
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        assert resp.status == 200
        data = json.loads(resp.read())
        for key in ("last_seen", "top_destinations", "anomalies", "data_status"):
            assert key in data, f"envelope must carry `{key}`"

    def test_unknown_asset_returns_404(self, api_server):
        with pytest.raises(HTTPError) as exc:
            urlopen(f"{api_server}/api/asset/does-not-exist/activity")
        assert exc.value.code == 404

    def test_invalid_window_param_returns_400(self, api_server):
        """Defense-in-depth: only 24h/7d/30d accepted. Arbitrary windows
        rejected so an attacker can't probe arbitrary time bounds."""
        with pytest.raises(HTTPError) as exc:
            urlopen(f"{api_server}/api/asset/ext-claude-ok/activity?window=garbage")
        assert exc.value.code == 400

    def test_window_param_24h_default(self, api_server):
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        data = json.loads(resp.read())
        assert data.get("window") == "24h"

    def test_window_param_7d_respected(self, api_server):
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity?window=7d")
        data = json.loads(resp.read())
        assert data["window"] == "7d"


# ---------------------------------------------------------------------------
# Five data_status states — Q8 rider: TWO distinct no-data states
# ---------------------------------------------------------------------------


class TestActivityDataStatus:
    """Per Rajan Q8 rider (2026-06-12): `asset_has_no_runtime_correlation`
    (structural n/a) and `correlatable_type_no_activity` (meaningful
    negative) must NEVER share a label or hint payload. Same Amendment-C
    discipline as cve_status."""

    def test_ok_state_correlatable_with_data(self, api_server):
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        data = json.loads(resp.read())
        assert data["data_status"] == "ok"
        assert len(data["top_destinations"]) > 0

    def test_correlatable_type_no_activity_state(self, api_server):
        """Host-based correlation per spec §7.1 / §7.1.1 attributes traffic
        by destination_host, so ext-claude-ok and ext-claude-noact (both
        chromium-extensions) share the same destination signature. The
        "meaningful negative" state surfaces when a correlatable source
        has matches OUTSIDE the requested window but not within it —
        e.g., ollama: 2 captures at 3 days ago, zero in the last 24h."""
        resp = urlopen(f"{api_server}/api/asset/ollama-llama3/activity?window=24h")
        data = json.loads(resp.read())
        assert data["data_status"] == "correlatable_type_no_activity"
        assert data["top_destinations"] == []

    def test_asset_has_no_runtime_correlation_state(self, api_server):
        """python-packages is a structural n/a — packages aren't runtime
        processes with destination signatures we can pin to."""
        resp = urlopen(f"{api_server}/api/asset/pkg-requests/activity")
        data = json.loads(resp.read())
        assert data["data_status"] == "asset_has_no_runtime_correlation"
        assert data["top_destinations"] == []

    def test_mcp_config_only_is_structural_n_a(self, api_server):
        resp = urlopen(f"{api_server}/api/asset/mcp-cfg/activity")
        data = json.loads(resp.read())
        assert data["data_status"] == "asset_has_no_runtime_correlation"

    def test_http_path_surfaces_capture_off_when_heartbeat_dead(self, monkeypatch, api_server):
        """Architect/code-reviewer 2026-06-12 BLOCKING: the handler must
        read heartbeat status to surface `capture_off` from the HTTP
        surface, otherwise the 5-state Q8 contract collapses to 4 in
        production. Force heartbeat_age_seconds → None (no heartbeat
        file) and verify the endpoint returns capture_off for a
        correlatable asset."""
        monkeypatch.setattr(
            "claude_monitoring.lifecycle.heartbeat_age_seconds",
            lambda: None,
        )
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        data = json.loads(resp.read())
        assert data["data_status"] == "capture_off"

    def test_q8_rider_two_no_data_states_distinct(self, api_server):
        """Q8 rider invariant: the two no-data states must produce
        DIFFERENT payloads. Same Amendment-C ('doesn't apply' and
        'observed nothing' must never share a label).

        pkg-requests = python-packages = structural n/a
        ollama @ 24h = correlatable (ollama-models has expected_hosts)
                       but no captures in last 24h (ollama traffic is in
                       prior 7d only)"""
        a = json.loads(urlopen(f"{api_server}/api/asset/pkg-requests/activity").read())
        b = json.loads(urlopen(f"{api_server}/api/asset/ollama-llama3/activity?window=24h").read())
        assert a["data_status"] != b["data_status"], "structural-n/a and correlatable-no-activity MUST never collapse"


# ---------------------------------------------------------------------------
# Aggregation correctness — top-N destinations sorted by hits
# ---------------------------------------------------------------------------


class TestTopDestinationsAggregation:
    def test_top_destinations_sorted_by_hits_desc(self, api_server):
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        data = json.loads(resp.read())
        hits = [d["hits"] for d in data["top_destinations"]]
        assert hits == sorted(hits, reverse=True)

    def test_top_destinations_include_host_hits_bytes(self, api_server):
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        data = json.loads(resp.read())
        for d in data["top_destinations"]:
            for k in ("host", "hits", "bytes"):
                assert k in d

    def test_only_expected_hosts_for_asset_aggregate(self, api_server):
        """The ollama asset's expected hosts include `localhost:11434`;
        but NOT `api.anthropic.com`. The aggregator must filter by the
        per-source expected-hosts whitelist, not return cross-asset
        traffic."""
        resp = urlopen(f"{api_server}/api/asset/ollama-llama3/activity?window=7d")
        data = json.loads(resp.read())
        hosts = {d["host"] for d in data["top_destinations"]}
        # Anthropic traffic exists in fixture but belongs to chrome ext
        assert "api.anthropic.com" not in hosts
        assert "localhost:11434" in hosts

    def test_last_seen_reflects_most_recent_match(self, api_server):
        """`last_seen` = max timestamp across the asset's expected-hosts
        captures (any window). Used by §6.1 activity_recency."""
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        data = json.loads(resp.read())
        assert data["last_seen"] is not None


# ---------------------------------------------------------------------------
# New-host anomaly (set-diff: last-24h ∖ prior-7d)
# ---------------------------------------------------------------------------


class TestNewHostAnomaly:
    def test_new_host_in_last_24h_flagged(self, api_server):
        """ext-claude-ok prior-7d hits api.anthropic.com only; last-24h
        adds claude.ai → new-host anomaly fires for claude.ai."""
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        data = json.loads(resp.read())
        new_host_anomalies = [a for a in data["anomalies"] if a["kind"] == "new_host"]
        assert len(new_host_anomalies) >= 1
        assert any(a["value"] == "claude.ai" for a in new_host_anomalies)

    def test_no_anomaly_when_host_appeared_in_prior_window(self, api_server):
        """api.anthropic.com appears in both windows — not a new host."""
        resp = urlopen(f"{api_server}/api/asset/ext-claude-ok/activity")
        data = json.loads(resp.read())
        new_host_hosts = {a["value"] for a in data["anomalies"] if a["kind"] == "new_host"}
        assert "api.anthropic.com" not in new_host_hosts


# ---------------------------------------------------------------------------
# Activity_recency factor wiring (Q9 ratified, §6.1)
# ---------------------------------------------------------------------------


class TestActivityRecencyFactorWiring:
    """Q9 ratified: `_compute_activity_recency` now reads last-seen
    timestamps from the activity correlator instead of the empty
    Phase 2 stub. Bucketing per spec §6.1: 100/80/60/30/0."""

    def test_recency_100_for_last_hour(self):
        from claude_monitoring.attack_surface.risk.scoring import (
            _compute_activity_recency,
        )

        # last_seen 1h ago → bucket 100 (within last hour)
        recency = _compute_activity_recency({"last_seen_seconds": 3600, "recency_score": None})
        assert recency == 100.0

    def test_recency_80_for_last_24h(self):
        from claude_monitoring.attack_surface.risk.scoring import (
            _compute_activity_recency,
        )

        recency = _compute_activity_recency({"last_seen_seconds": 12 * 3600, "recency_score": None})
        assert recency == 80.0

    def test_recency_60_for_last_7days(self):
        from claude_monitoring.attack_surface.risk.scoring import (
            _compute_activity_recency,
        )

        recency = _compute_activity_recency({"last_seen_seconds": 5 * 86400, "recency_score": None})
        assert recency == 60.0

    def test_recency_30_for_last_30days(self):
        from claude_monitoring.attack_surface.risk.scoring import (
            _compute_activity_recency,
        )

        recency = _compute_activity_recency({"last_seen_seconds": 20 * 86400, "recency_score": None})
        assert recency == 30.0

    def test_recency_0_when_no_data(self):
        from claude_monitoring.attack_surface.risk.scoring import (
            _compute_activity_recency,
        )

        assert _compute_activity_recency(None) == 0.0
        assert _compute_activity_recency({}) == 0.0


# ---------------------------------------------------------------------------
# Source → expected hosts contract
# ---------------------------------------------------------------------------


class TestExpectedHostsContract:
    def test_chromium_extensions_correlate_to_anthropic_hosts(self):
        from claude_monitoring.attack_surface.activity.expected_hosts import (
            expected_hosts_for_source,
        )

        hosts = expected_hosts_for_source("chromium-extensions")
        assert hosts is not None
        assert "api.anthropic.com" in hosts

    def test_ollama_models_correlate_to_localhost_port(self):
        from claude_monitoring.attack_surface.activity.expected_hosts import (
            expected_hosts_for_source,
        )

        hosts = expected_hosts_for_source("ollama-models")
        assert hosts is not None
        assert any("11434" in h for h in hosts)

    def test_python_packages_returns_none_structural_n_a(self):
        from claude_monitoring.attack_surface.activity.expected_hosts import (
            expected_hosts_for_source,
        )

        # None signals "this source has no runtime correlation contract"
        assert expected_hosts_for_source("python-packages") is None

    def test_mcp_servers_returns_none_structural_n_a(self):
        from claude_monitoring.attack_surface.activity.expected_hosts import (
            expected_hosts_for_source,
        )

        # MCP servers run inside the host tool; their traffic is the host
        # tool's traffic, not directly attributable.
        assert expected_hosts_for_source("mcp-servers") is None

    def test_unknown_source_returns_none(self):
        from claude_monitoring.attack_surface.activity.expected_hosts import (
            expected_hosts_for_source,
        )

        assert expected_hosts_for_source("future-unknown-source") is None


# ---------------------------------------------------------------------------
# Route registration pin
# ---------------------------------------------------------------------------


class TestRouteRegistration:
    def test_activity_handler_method_exists_on_dashboard_handler(self):
        from claude_monitoring.monitor import DashboardHandler

        assert hasattr(DashboardHandler, "_api_asset_activity"), (
            "DashboardHandler must expose _api_asset_activity handler method"
        )


# ---------------------------------------------------------------------------
# Production-timestamp-format regression (judge p4.3.a1 APPROVE-WITH-FIX)
# ---------------------------------------------------------------------------


class TestProductionTimestampFormatContract:
    """The lexicographic window comparison + `_parse_capture_ts` must hold
    against the EXACT timestamp format `watch.py` writes into
    `api_calls.timestamp`, not the sanitized seconds+Z form the other
    tests use to match the correlator's internal `_iso()` boundary
    generator.

    **Load-bearing format dependency:** production writes
    ``datetime.now(timezone.utc).isoformat()`` →
    ``"2026-06-12T12:34:56.789012+00:00"`` (microseconds + ``+00:00``).
    The activity window relies on lexicographic ordering of this TEXT
    column. The fixed-width ``YYYY-MM-DDTHH:MM:SS`` prefix governs
    ordering for any ≥1s separation — same-second boundary records
    may be excluded (the conservative direction), never silently
    included from outside the window. If `watch.py`'s timestamp
    writing or `api_calls`'s schema ever changes (epoch float, drops
    the offset, etc.), this test breaks and the window filter needs
    re-verification.
    """

    def test_production_iso_format_included_in_window(self, tmp_path, monkeypatch):
        """Insert a row with the production timestamp format at a known
        offset inside the 24h window; assert it appears in
        `top_destinations` and `last_seen` parses correctly through
        `_parse_capture_ts`, producing the expected `activity_recency`
        bucket."""
        import datetime as _dt

        from claude_monitoring.attack_surface.activity.correlator import (
            _parse_capture_ts,
            correlate_asset_activity,
        )

        db_path = tmp_path / "monitor.db"
        conn = init_db(db_path)

        # Two timestamps in production format. Anchor "now" to a real
        # wall-clock value so `correlate_asset_activity`'s internal
        # window math (which uses real time.time()) compares correctly.
        now_dt = _dt.datetime.now(_dt.timezone.utc)
        in_window_dt = now_dt - _dt.timedelta(minutes=30)  # 30 min ago
        in_window_iso = in_window_dt.isoformat()
        # Sanity-check the format we're asserting: microseconds + +00:00
        assert "+00:00" in in_window_iso, f"production format expected, got {in_window_iso}"
        assert "." in in_window_iso, "production format includes microseconds"

        # Insert an asset (chrome ext → correlates to api.anthropic.com)
        conn.execute(
            """INSERT INTO assets (id, type, source, name, first_seen, last_seen,
                                    last_scanned, current_state)
               VALUES ('chrome-test', 'browser_extension', 'chromium-extensions',
                       'Test', ?, ?, ?, '{}')""",
            (now_dt.timestamp(), now_dt.timestamp(), now_dt.timestamp()),
        )
        # Insert api_calls row with the PRODUCTION timestamp format
        conn.execute(
            """INSERT INTO api_calls (timestamp, session_id, destination_host,
                                       destination_service, request_size_bytes,
                                       response_size_bytes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (in_window_iso, "test-sess", "api.anthropic.com", "anthropic_api", 1000, 2000),
        )
        conn.commit()

        # (a) `_parse_capture_ts` correctly handles the production format
        parsed = _parse_capture_ts(in_window_iso)
        assert parsed is not None, "production isoformat must parse"
        assert abs(parsed - in_window_dt.timestamp()) < 1.0, (
            f"parsed epoch {parsed} should match input {in_window_dt.timestamp()}"
        )

        # (b) the row is included in the 24h window aggregation
        result = correlate_asset_activity(conn, "chrome-test", window="24h", capture_ok=True)
        assert result.data_status == "ok", (
            f"row in production format must be aggregated; got data_status={result.data_status!r}"
        )
        hosts = [d["host"] for d in result.top_destinations]
        assert "api.anthropic.com" in hosts, f"production-format row must appear in top_destinations; got {hosts!r}"

        # (c) last_seen reflects the production-format row
        assert result.last_seen is not None
        assert abs(result.last_seen - in_window_dt.timestamp()) < 1.0

        conn.close()
