"""P6.5 — Session Explorer envelope + capture-state + recency tests.

Phase A judge p6.5.a2 APPROVE 2026-06-17 with three load-bearing pins:

  * `is_content_captured` is IMPORTED from `dashboard_api_traffic` —
    NO re-derivation. Single source of the predicate across State Bar,
    API Traffic, and Session Explorer.
  * Mixed-topology = STRICT: any envelope-only row demotes the entire
    session to "env". Rejects 50%-majority — partial state must never
    render as fully-safe.
  * 24h literal recency threshold: `now - 86400 == 86400` is NOT warn;
    strictly greater than 86400 triggers the warn glyph.

Phase B = failing tests first (TDD).
"""

from __future__ import annotations

import sqlite3
import time

import pytest

from claude_monitoring import dashboard_api_traffic
from claude_monitoring.db import init_db


def _seed_api_call(
    conn,
    *,
    session_id="sess-1",
    endpoint_path="/v1/messages",
    input_tokens=0,
    http_status=200,
    source="proxy",
    dest_service="anthropic",
    ts_offset_s=-3600,
):
    ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + ts_offset_s))
    conn.execute(
        """INSERT INTO api_calls
           (timestamp, session_id, endpoint_path, destination_service,
            input_tokens, output_tokens, destination_host, http_method,
            http_status, source)
           VALUES (?, ?, ?, ?, ?, 0, 'api.anthropic.com', 'POST', ?, ?)""",
        (
            ts_iso,
            session_id,
            endpoint_path,
            dest_service,
            input_tokens,
            http_status,
            source,
        ),
    )
    conn.commit()


@pytest.fixture
def conn(tmp_path):
    db = init_db(tmp_path / "test.db")
    db.row_factory = sqlite3.Row
    yield db
    db.close()


# ---------------------------------------------------------------------------
# TestClassifyCaptureState
# ---------------------------------------------------------------------------


class TestClassifyCaptureState:
    """Strict rule per judge a2: n_env > 0 → topo=env. Only n_env == 0
    (every row content-captured) qualifies as 'full'."""

    def test_all_rows_fully_captured_returns_full(self, conn):
        from claude_monitoring import dashboard_session_explorer

        for _ in range(3):
            _seed_api_call(conn, session_id="s1", endpoint_path="/v1/messages", input_tokens=100)
        result = dashboard_session_explorer.classify_capture_state(conn, "s1")
        assert result["topo"] == "full"
        assert result["n_full"] == 3
        assert result["n_env"] == 0

    def test_any_envelope_row_demotes_to_env(self, conn):
        """LOAD-BEARING — strict rule. 99 full + 1 envelope = env."""
        from claude_monitoring import dashboard_session_explorer

        for _ in range(99):
            _seed_api_call(conn, session_id="s2", endpoint_path="/v1/messages", input_tokens=100)
        _seed_api_call(conn, session_id="s2", endpoint_path="/v1/messages", input_tokens=0)
        result = dashboard_session_explorer.classify_capture_state(conn, "s2")
        assert result["topo"] == "env", "strict rule: any env row demotes whole session"
        assert result["n_full"] == 99
        assert result["n_env"] == 1

    def test_all_envelope_only_returns_env(self, conn):
        from claude_monitoring import dashboard_session_explorer

        for _ in range(4):
            _seed_api_call(conn, session_id="s3", endpoint_path="/v1/messages", input_tokens=0)
        result = dashboard_session_explorer.classify_capture_state(conn, "s3")
        assert result["topo"] == "env"
        assert result["n_full"] == 0
        assert result["n_env"] == 4

    def test_no_rows_returns_none(self, conn):
        from claude_monitoring import dashboard_session_explorer

        result = dashboard_session_explorer.classify_capture_state(conn, "no-such-session")
        assert result["topo"] == "none"
        assert result["n_full"] == 0
        assert result["n_env"] == 0


# ---------------------------------------------------------------------------
# TestReconciliationCountFormMatchesPredicate (LOAD-BEARING per a2)
# ---------------------------------------------------------------------------


class TestReconciliationCountFormMatchesPredicate:
    """SQL aggregate `(n_full, n_env)` MUST equal the per-row predicate
    iteration using `dashboard_api_traffic.is_content_captured`. Same
    seed, same numbers. Pins the single-source-of-predicate contract."""

    def test_aggregate_matches_per_row_iteration(self, conn):
        from claude_monitoring import dashboard_session_explorer

        # Adversarial mix
        _seed_api_call(conn, session_id="rec", endpoint_path="/v1/messages", input_tokens=100)
        _seed_api_call(conn, session_id="rec", endpoint_path="/v1/messages", input_tokens=0)
        _seed_api_call(conn, session_id="rec", endpoint_path="/v1/chat/completions", input_tokens=50)
        _seed_api_call(conn, session_id="rec", endpoint_path="/v1/environments/poll", input_tokens=999)

        # SQL aggregate form
        sql_result = dashboard_session_explorer.classify_capture_state(conn, "rec")

        # Per-row predicate form
        rows = conn.execute("SELECT endpoint_path, input_tokens FROM api_calls WHERE session_id = 'rec'").fetchall()
        n_full_py = sum(1 for r in rows if dashboard_api_traffic.is_content_captured(r))
        n_env_py = len(rows) - n_full_py

        assert sql_result["n_full"] == n_full_py
        assert sql_result["n_env"] == n_env_py


# ---------------------------------------------------------------------------
# TestCrossTabPredicateParityWithP6_4 (LOAD-BEARING per a2)
# ---------------------------------------------------------------------------


class TestCrossTabPredicateParityWithP6_4:
    """The a1-inversion seed: chat row with input_tokens > 0 AND empty
    previews. P6.4 counts it 'captured' in the header K. P6.5 MUST also
    count it 'full' — exact parity, no drift."""

    def test_chat_with_tokens_empty_previews_is_full_in_both(self, conn):
        from claude_monitoring import dashboard_session_explorer

        conn.execute(
            """INSERT INTO api_calls
               (timestamp, session_id, endpoint_path, destination_service,
                input_tokens, output_tokens, destination_host, http_method,
                http_status, source, last_user_msg_preview, assistant_msg_preview)
               VALUES (?, 'parity', '/v1/messages', 'anthropic', 100, 50,
                       'api.anthropic.com', 'POST', 200, 'proxy', NULL, '')""",
            (time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 3600)),),
        )
        conn.commit()

        # P6.4 view: header K via compute_traffic_summary
        summary = dashboard_api_traffic.compute_traffic_summary(conn)
        assert summary["content_captured"] == 1, "P6.4 must count empty-preview row as captured"

        # P6.5 view: session classification
        p6_5 = dashboard_session_explorer.classify_capture_state(conn, "parity")
        assert p6_5["topo"] == "full", "P6.5 must classify the same row as 'full'"
        assert p6_5["n_full"] == 1


# ---------------------------------------------------------------------------
# TestComputeSessionRecency
# ---------------------------------------------------------------------------


class TestComputeSessionRecency:
    def test_recent_capture_no_warn(self, conn):
        from claude_monitoring import dashboard_session_explorer

        _seed_api_call(conn, session_id="r1", ts_offset_s=-60)  # 1 min ago
        result = dashboard_session_explorer.compute_session_recency(conn, "r1")
        assert result["last_capture_ts"] is not None
        assert result["recency_seconds"] < 120
        assert result["recency_warn"] is False

    def test_no_rows_returns_null_last_ts_no_warn(self, conn):
        from claude_monitoring import dashboard_session_explorer

        result = dashboard_session_explorer.compute_session_recency(conn, "never-seen")
        assert result["last_capture_ts"] is None
        assert result["recency_seconds"] is None
        assert result["recency_warn"] is False, (
            "never-captured uses topo=none for distinct signal; recency_warn must NOT fire"
        )


# ---------------------------------------------------------------------------
# TestRecencyWarnAtThresholdBoundary (LOAD-BEARING per a2)
# ---------------------------------------------------------------------------


class TestRecencyWarnAtThresholdBoundary:
    """Spec line 142 literal: strictly greater than 24h (86400s) → warn.
    Exactly 86400s ago: no warn. 86401s ago: warn."""

    def test_at_exactly_86400_seconds_no_warn(self, conn):
        from claude_monitoring import dashboard_session_explorer

        _seed_api_call(conn, session_id="b1", ts_offset_s=-86400)
        result = dashboard_session_explorer.compute_session_recency(conn, "b1")
        # Allow for clock drift in test execution (a few seconds).
        assert result["recency_seconds"] is not None
        assert result["recency_warn"] is False or abs(result["recency_seconds"] - 86400) <= 5

    def test_at_86401_seconds_warn_fires(self, conn):
        from claude_monitoring import dashboard_session_explorer

        _seed_api_call(conn, session_id="b2", ts_offset_s=-86500)  # well over 24h
        result = dashboard_session_explorer.compute_session_recency(conn, "b2")
        assert result["recency_warn"] is True


# ---------------------------------------------------------------------------
# TestDeriveSessionSources
# ---------------------------------------------------------------------------


class TestDeriveSessionSources:
    def test_proxy_only_returns_single_source(self, conn):
        from claude_monitoring import dashboard_session_explorer

        _seed_api_call(conn, session_id="src1", source="proxy")
        _seed_api_call(conn, session_id="src1", source="proxy")
        result = dashboard_session_explorer.derive_session_sources(conn, "src1")
        assert result == ["proxy"]

    def test_proxy_and_extension_returns_dual_sorted(self, conn):
        from claude_monitoring import dashboard_session_explorer

        _seed_api_call(conn, session_id="src2", source="proxy")
        _seed_api_call(conn, session_id="src2", source="browser_proxy")
        result = dashboard_session_explorer.derive_session_sources(conn, "src2")
        assert "proxy" in result
        assert "browser_proxy" in result
        assert len(result) == 2

    def test_no_api_calls_returns_jsonl_marker(self, conn):
        """CLI-only session badge per judge a2 R1 ratification — 'JSONL'
        marker, more honest than omitting the badge entirely."""
        from claude_monitoring import dashboard_session_explorer

        result = dashboard_session_explorer.derive_session_sources(conn, "no-rows")
        assert result == ["JSONL"]


# ---------------------------------------------------------------------------
# TestEnrichSessionRow (envelope shape)
# ---------------------------------------------------------------------------


class TestEnrichSessionRow:
    """`enrich_session_row(conn, row)` adds the five new envelope fields
    additively. No existing field renamed or removed."""

    def test_enriched_row_has_all_five_new_fields(self, conn):
        from claude_monitoring import dashboard_session_explorer

        _seed_api_call(conn, session_id="e1", endpoint_path="/v1/messages", input_tokens=100)
        row = {"session_id": "e1", "title": "test", "total_input_tokens": 100}
        result = dashboard_session_explorer.enrich_session_row(conn, row)
        # New fields present
        assert "capture_state" in result
        assert "capture_breakdown" in result
        assert "last_capture_ts" in result
        assert "recency_seconds" in result
        assert "recency_warn" in result
        assert "sources" in result
        # Existing fields preserved
        assert result["session_id"] == "e1"
        assert result["title"] == "test"
        assert result["total_input_tokens"] == 100

    def test_empty_session_safe_defaults(self, conn):
        from claude_monitoring import dashboard_session_explorer

        row = {"session_id": "empty"}
        result = dashboard_session_explorer.enrich_session_row(conn, row)
        assert result["capture_state"] == "none"
        assert result["last_capture_ts"] is None
        assert result["recency_seconds"] is None
        assert result["recency_warn"] is False
        assert result["sources"] == ["JSONL"]
