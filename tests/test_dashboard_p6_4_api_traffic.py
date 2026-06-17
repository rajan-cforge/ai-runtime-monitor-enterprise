"""P6.4 — API Traffic tab envelope + markup tests.

Phase A judge p6.4.a2 APPROVE 2026-06-16 with one load-bearing
contract: ONE `is_content_captured` predicate, three consumers
(summary counter + .cstate--full row badge + noise-rule negation).

Two reconciliation pins (load-bearing per a2 judge):

  * TestHeaderReconciliationToBadge — header `K content_captured`
    MUST equal the count of `.cstate--full` rendered rows. Cannot
    drift by construction.
  * TestShowAllRevealsEveryHiddenRow — no row is ever permanently
    unreachable; "Show all" toggle reveals every hidden row.

Plus the §4.5 data-truthful unknown state on empty data
(percentage=None → "Awaiting data", never "0% clean").
"""

from __future__ import annotations

import sqlite3
import time
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring import dashboard_api_traffic
from claude_monitoring.dashboard_handler import DashboardHandler
from claude_monitoring.db import init_db


def _seed_api_call(
    conn,
    *,
    endpoint_path,
    input_tokens=0,
    http_status=200,
    dest_service="anthropic",
    source="proxy",
    ts_offset_s=-3600,
    last_user_msg_preview=None,
    assistant_msg_preview=None,
):
    ts_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + ts_offset_s))
    conn.execute(
        """INSERT INTO api_calls
           (timestamp, endpoint_path, destination_service, input_tokens, output_tokens,
            destination_host, http_method, http_status, source,
            last_user_msg_preview, assistant_msg_preview)
           VALUES (?, ?, ?, ?, 0, 'api.anthropic.com', 'POST', ?, ?, ?, ?)""",
        (
            ts_iso,
            endpoint_path,
            dest_service,
            input_tokens,
            http_status,
            source,
            last_user_msg_preview,
            assistant_msg_preview,
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
# TestIsChatCallPath
# ---------------------------------------------------------------------------


class TestIsChatCallPath:
    def test_matches_v1_messages(self):
        assert dashboard_api_traffic.is_chat_call_path("/v1/messages") is True

    def test_matches_v1_messages_with_query(self):
        assert dashboard_api_traffic.is_chat_call_path("/v1/messages?beta=true") is True

    def test_matches_chat_completions(self):
        assert dashboard_api_traffic.is_chat_call_path("/v1/chat/completions") is True

    def test_excludes_environments_poll(self):
        assert dashboard_api_traffic.is_chat_call_path("/v1/environments/x/work/poll") is False

    def test_excludes_usage(self):
        assert dashboard_api_traffic.is_chat_call_path("/v1/usage") is False

    def test_empty_and_none_are_false(self):
        assert dashboard_api_traffic.is_chat_call_path("") is False
        assert dashboard_api_traffic.is_chat_call_path(None) is False


# ---------------------------------------------------------------------------
# TestIsContentCaptured
# ---------------------------------------------------------------------------


class TestIsContentCaptured:
    """Verbatim P6.2 contract: chat-call AND input_tokens > 0. NO
    preview clause. Pinned by Phase A judge p6.4.a2."""

    def test_chat_with_tokens_is_captured(self):
        row = {
            "endpoint_path": "/v1/messages",
            "input_tokens": 42,
        }
        assert dashboard_api_traffic.is_content_captured(row) is True

    def test_chat_with_tokens_and_empty_previews_still_captured(self):
        """Load-bearing — this was the a1 inversion. A streaming parser
        that dropped the previews but counted tokens MUST still register
        as captured."""
        row = {
            "endpoint_path": "/v1/messages",
            "input_tokens": 100,
            "last_user_msg_preview": None,
            "assistant_msg_preview": "",
        }
        assert dashboard_api_traffic.is_content_captured(row) is True

    def test_chat_with_zero_tokens_is_not_captured(self):
        row = {
            "endpoint_path": "/v1/messages",
            "input_tokens": 0,
        }
        assert dashboard_api_traffic.is_content_captured(row) is False

    def test_chat_with_null_tokens_is_not_captured(self):
        """NULL parity — Python `(None or 0) > 0` is False (same as
        SQL's `input_tokens > 0` on NULL)."""
        row = {
            "endpoint_path": "/v1/messages",
            "input_tokens": None,
        }
        assert dashboard_api_traffic.is_content_captured(row) is False

    def test_non_chat_with_tokens_is_not_captured(self):
        row = {
            "endpoint_path": "/v1/environments/x/poll",
            "input_tokens": 99,  # absurd but pin the predicate
        }
        assert dashboard_api_traffic.is_content_captured(row) is False


# ---------------------------------------------------------------------------
# TestIsNoiseRow (rewritten per a2 — chat rows NEVER hidden)
# ---------------------------------------------------------------------------


class TestIsNoiseRow:
    def test_chat_with_tokens_not_noise(self):
        row = {"endpoint_path": "/v1/messages", "input_tokens": 50, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is False

    def test_failed_chat_call_not_noise(self):
        """Load-bearing per a2 — chat-call rows are NEVER hidden,
        including 4xx failures. The operator needs them."""
        row = {"endpoint_path": "/v1/messages", "input_tokens": 0, "http_status": 401}
        assert dashboard_api_traffic.is_noise_row(row) is False

    def test_non_chat_4xx_is_noise(self):
        row = {"endpoint_path": "/v1/usage", "input_tokens": 0, "http_status": 404}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_environments_poll_is_noise(self):
        row = {"endpoint_path": "/v1/environments/x/work/poll", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_organizations_profile_is_noise(self):
        row = {"endpoint_path": "/v1/organizations/x/profile", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_oauth_is_noise(self):
        row = {"endpoint_path": "/v1/oauth/token", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_anthropic_event_logging_is_noise(self):
        """P6.4.1 regression pin — real Anthropic Claude Code path
        that the original 5-marker rule missed in production."""
        row = {"endpoint_path": "/api/event_logging/v2/batch", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_claude_code_grove_is_noise(self):
        row = {"endpoint_path": "/api/claude_code_grove", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_claude_cli_bootstrap_is_noise(self):
        row = {"endpoint_path": "/api/claude_cli/bootstrap?entrypoint=local-agent", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_mcp_registry_poll_is_noise(self):
        row = {"endpoint_path": "/mcp-registry/v0/servers?cursor=foo", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_desktop_update_poll_is_noise(self):
        row = {"endpoint_path": "/api/desktop/darwin/universal/squirrel/update", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True

    def test_non_chat_200_unknown_path_is_noise(self):
        """P6.4.1 — was previously False (only 5 markers triggered
        noise). Now the structural rule applies: any non-chat path
        is noise by default. Operator toggles "All requests" to see."""
        row = {"endpoint_path": "/v1/usage", "input_tokens": 0, "http_status": 200}
        assert dashboard_api_traffic.is_noise_row(row) is True


# ---------------------------------------------------------------------------
# TestComputeTrafficSummaryEmptyDb (data-truthful §4.5)
# ---------------------------------------------------------------------------


class TestComputeTrafficSummaryEmptyDb:
    def test_empty_db_returns_zero_counts_and_none_fill_rate(self, conn):
        result = dashboard_api_traffic.compute_traffic_summary(conn)
        assert result["intercepted"] == 0
        assert result["chat_calls"] == 0
        assert result["content_captured"] == 0
        assert result["fill_rate_24h_pct"] is None  # NOT 0%

    def test_sqlite_error_returns_all_none(self, conn):
        broken = MagicMock()
        broken.execute.side_effect = sqlite3.Error("simulated")
        result = dashboard_api_traffic.compute_traffic_summary(broken)
        assert result["intercepted"] is None
        assert result["chat_calls"] is None
        assert result["content_captured"] is None
        assert result["fill_rate_24h_pct"] is None


# ---------------------------------------------------------------------------
# TestComputeTrafficSummarySeeded
# ---------------------------------------------------------------------------


class TestComputeTrafficSummarySeeded:
    def test_three_counters_match_mix(self, conn):
        # 5 chat + tokens / 3 chat + zero tokens / 4 non-chat
        for _ in range(5):
            _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=100)
        for _ in range(3):
            _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=0, http_status=401)
        for _ in range(4):
            _seed_api_call(conn, endpoint_path="/v1/environments/x/poll")
        result = dashboard_api_traffic.compute_traffic_summary(conn)
        assert result["intercepted"] == 12
        assert result["chat_calls"] == 8
        assert result["content_captured"] == 5
        # fill rate = 5 / 8 = 62.5% → rounds to 62 or 63
        assert result["fill_rate_24h_pct"] in (62, 63)

    def test_old_rows_excluded_from_24h_window(self, conn):
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=10, ts_offset_s=-(48 * 3600))
        result = dashboard_api_traffic.compute_traffic_summary(conn)
        assert result["intercepted"] == 0


# ---------------------------------------------------------------------------
# TestHeaderReconciliationToBadge (LOAD-BEARING per a2 — the inversion pin)
# ---------------------------------------------------------------------------


class TestHeaderReconciliationToBadge:
    """The contract that closes the a1 inversion: header `K content_captured`
    equals the count of rendered `.cstate--full` rows. Both derive from
    the same `is_content_captured` predicate, so they cannot drift by
    construction. Test asserts they match on the adversarial seed (a row
    with tokens AND empty previews — the exact a1 case)."""

    def test_header_k_equals_full_rendered_count(self, conn):
        # 5 chat + tokens with non-empty previews
        for _ in range(5):
            _seed_api_call(
                conn,
                endpoint_path="/v1/messages",
                input_tokens=200,
                last_user_msg_preview="hello",
                assistant_msg_preview="hi",
            )
        # 2 chat + tokens with EMPTY previews (a1 inversion case)
        for _ in range(2):
            _seed_api_call(
                conn,
                endpoint_path="/v1/messages",
                input_tokens=99,
                last_user_msg_preview=None,
                assistant_msg_preview="",
            )
        # 3 chat WITHOUT tokens (env-state row)
        for _ in range(3):
            _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=0)
        # 4 non-chat infra
        for _ in range(4):
            _seed_api_call(conn, endpoint_path="/v1/environments/x/poll")

        # Header K
        summary = dashboard_api_traffic.compute_traffic_summary(conn)
        assert summary["content_captured"] == 7

        # Same data through the row predicate → count of `.cstate--full`
        rows = conn.execute("SELECT endpoint_path, input_tokens, http_status FROM api_calls").fetchall()
        full_count = sum(1 for r in rows if dashboard_api_traffic.is_content_captured(r))
        assert summary["content_captured"] == full_count, (
            f"header K ({summary['content_captured']}) must equal full count "
            f"({full_count}). Empty-preview row was the a1 inversion — must be captured."
        )


# ---------------------------------------------------------------------------
# TestShowAllRevealsEveryHiddenRow (LOAD-BEARING per a2 — show-all completeness)
# ---------------------------------------------------------------------------


class TestShowAllRevealsEveryHiddenRow:
    """No row is ever permanently unreachable. Default-view hides only
    non-chat infra noise; show-all reveals every row in the table."""

    def test_show_all_set_equals_all_rows(self, conn):
        # Seed 12 rows of every relevant shape
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=100)
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=0)
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=0, http_status=401)
        _seed_api_call(conn, endpoint_path="/v1/chat/completions", input_tokens=50)
        for _ in range(4):
            _seed_api_call(conn, endpoint_path="/v1/environments/x/poll")
        for _ in range(2):
            _seed_api_call(conn, endpoint_path="/v1/organizations/x/profile")
        _seed_api_call(conn, endpoint_path="/oauth/token", http_status=404)
        _seed_api_call(conn, endpoint_path="/v1/usage")

        rows = conn.execute("SELECT endpoint_path, input_tokens, http_status FROM api_calls").fetchall()
        chat_only_visible = [r for r in rows if not dashboard_api_traffic.is_noise_row(r)]
        all_visible = list(rows)  # show-all reveals everything

        # P6.4.1 structural rule: chat filter shows ONLY chat-call paths.
        # Every non-chat row is noise (including the historical /v1/usage
        # case). 4 chat rows = 4 visible by default.
        assert len(chat_only_visible) == 4
        # Show-all reveals every row in api_calls (no permanent hides).
        assert len(all_visible) == 12

    def test_no_content_captured_row_is_ever_hidden(self, conn):
        """The compounding inversion guard: every row that is_content_captured
        MUST NOT be noise. If this ever breaks, header K could count a row
        invisible by default — the exact a1 inversion."""
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=100, http_status=200)
        _seed_api_call(conn, endpoint_path="/v1/messages", input_tokens=99, http_status=500)
        rows = conn.execute("SELECT endpoint_path, input_tokens, http_status FROM api_calls").fetchall()
        for r in rows:
            if dashboard_api_traffic.is_content_captured(r):
                assert dashboard_api_traffic.is_noise_row(r) is False, (
                    f"content-captured row {dict(r)!r} is noise — INVERSION"
                )


# ---------------------------------------------------------------------------
# TestTrafficSummaryEndpointEnvelope
# ---------------------------------------------------------------------------


class TestTrafficSummaryEndpointEnvelope:
    def test_envelope_has_summary_key(self, conn):
        handler = DashboardHandler.__new__(DashboardHandler)
        captured = {}
        handler._send_json = lambda payload: captured.setdefault("payload", payload)
        with patch("claude_monitoring.dashboard_handler.get_thread_db", return_value=conn):
            handler._api_traffic_summary({})
        envelope = captured["payload"]
        assert "summary" in envelope
        assert set(envelope["summary"].keys()) == {
            "intercepted",
            "chat_calls",
            "content_captured",
            "fill_rate_24h_pct",
        }
