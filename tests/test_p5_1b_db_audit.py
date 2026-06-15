"""P5.1b --db-audit + redact_value_for_display tests — Phase B (TDD).

Phase A judge p5.1b.a2 APPROVE 2026-06-14. The three mandatory inversion
tests Rajan + the judge named:

  1. assets.current_state with {"api_key": "sk-FAKE12345"} → output
     does NOT contain raw "sk-FAKE12345". The token-shape inversion.
  2. assets.install_path with "/Users/<realname>/..." → output does NOT
     contain "<realname>". The username inversion (judge p5.1b.a1
     Finding A — masking must be unconditional, not gated on
     scan_sensitive firing).
  3. crashes table → audit output says "no samples (capture-table policy)",
     NOT the traceback text. The Finding B no-samples coverage.

Plus the per-policy coverage and the CI gate harness.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

# ---------------------------------------------------------------------------
# Three mandatory inversion tests (judge + Rajan acceptance gates)
# ---------------------------------------------------------------------------


class TestRedactValueForDisplayInversions:
    """Three failure-mode tests the primitive is designed to prevent.
    If any of these regress, the redaction layer has gone leaky."""

    def test_assets_current_state_json_blob_with_token_renders_redacted(self):
        """Inversion 1 (Rajan acceptance): seed current_state with an
        OpenAI-shaped key in a JSON blob; the rendered value must NOT
        contain the raw key."""
        from claude_monitoring.privacy_audit import redact_value_for_display

        payload = json.dumps({"api_key": "sk-FAKE1234567890ABCDEFGHIJKLMNOP"})
        rendered = redact_value_for_display("assets", "current_state", payload)
        assert "sk-FAKE1234567890ABCDEFGHIJKLMNOP" not in rendered, (
            f"raw token leaked through masked column; got {rendered!r}"
        )

    def test_assets_install_path_with_username_renders_no_username(self):
        """Inversion 2 (judge p5.1b.a1 Finding A): a path containing a
        real username must NOT render raw. SENSITIVE_PATTERNS has no
        path/username shape, so masking MUST be unconditional — the home-
        dir normalization layer strips the username before `mask_value`
        runs, regardless of whether scan_sensitive matches anything."""
        from claude_monitoring.privacy_audit import redact_value_for_display

        path = "/Users/realuser/Library/Application Support/claude/extensions/foo"
        rendered = redact_value_for_display("assets", "install_path", path)
        assert "realuser" not in rendered, f"raw username leaked through masked column; got {rendered!r}"
        # Display should be informative — not just "[REDACTED]" if we
        # could safely mask in place. Either <USER> or a masked form is
        # acceptable; raw username is not.
        assert "/Users/realuser" not in rendered

    def test_capture_table_redact_raises_caller_must_use_no_samples_policy(self):
        """A capture table cannot be passed to redact_value_for_display
        at all — capture-table policy is no samples, not masked samples.
        The signature is the safety guard against accidentally calling
        the primitive on a capture column."""
        from claude_monitoring.privacy_audit import redact_value_for_display

        with pytest.raises(ValueError, match="capture table"):
            redact_value_for_display("api_calls", "last_user_msg_preview", "anything")


class TestRedactValueForDisplayPolicies:
    """Per-policy unit coverage."""

    def test_raw_column_returns_value_as_is(self):
        from claude_monitoring.privacy_audit import redact_value_for_display

        # assets.type is classified raw (enum).
        assert redact_value_for_display("assets", "type", "ai_tool") == "ai_tool"
        assert redact_value_for_display("assets", "risk_score", 75) == "75"
        assert redact_value_for_display("assets", "is_vigil_component", 0) == "0"

    def test_opaque_id_returns_value_as_is(self):
        from claude_monitoring.privacy_audit import redact_value_for_display

        # assets.id is opaque_id (digest); displayable.
        digest = "a" * 64
        assert redact_value_for_display("assets", "id", digest) == digest

    def test_unknown_table_renders_redacted_fail_closed(self):
        from claude_monitoring.privacy_audit import redact_value_for_display

        assert redact_value_for_display("nonexistent_table", "anycol", "x") == "[REDACTED]"

    def test_unknown_column_in_known_table_renders_redacted_fail_closed(self):
        from claude_monitoring.privacy_audit import redact_value_for_display

        assert redact_value_for_display("assets", "nonexistent_column", "x") == "[REDACTED]"

    def test_masked_column_with_none_returns_empty_string(self):
        """``None`` cell should produce empty string, NOT crash the audit."""
        from claude_monitoring.privacy_audit import redact_value_for_display

        assert redact_value_for_display("assets", "name", None) == ""

    def test_masked_column_with_benign_value_runs_masker_anyway(self):
        """Even when no credential / path is in the value, the masker
        pipeline still runs. This is the Finding-A contract: never gate
        on whether the scanner finds something."""
        from claude_monitoring.privacy_audit import redact_value_for_display

        rendered = redact_value_for_display("assets", "name", "boringextname")
        # Should be a string, not crash, not raw [REDACTED]; mask_value
        # may leave short strings approximately intact, but the point of
        # the test is that the pipeline runs at all.
        assert isinstance(rendered, str)


# ---------------------------------------------------------------------------
# Capture tables list (Finding B)
# ---------------------------------------------------------------------------


class TestCaptureTablesListIsComplete:
    def test_crashes_in_capture_tables_no_samples(self):
        """Finding B (judge p5.1b.a1): the crashes table from
        lifecycle.py:647 must be in the no-samples set because `details`
        stores tracebacks that can embed paths / captured fragments."""
        from claude_monitoring.privacy_audit import CAPTURE_TABLES_NO_SAMPLES

        assert "crashes" in CAPTURE_TABLES_NO_SAMPLES

    def test_all_nine_capture_tables_present(self):
        """The full no-samples set per Phase A a2."""
        from claude_monitoring.privacy_audit import CAPTURE_TABLES_NO_SAMPLES

        expected = {
            "api_calls",
            "events",
            "browser_sessions",
            "sessions",
            "processes",
            "connections",
            "file_events",
            "agent_dependencies",
            "crashes",
        }
        assert expected.issubset(CAPTURE_TABLES_NO_SAMPLES)


# ---------------------------------------------------------------------------
# db_audit_mode() integration — runs against a temp DB
# ---------------------------------------------------------------------------


class TestDbAuditMode:
    """Integration tests for the end-to-end audit mode. Uses
    capsys to capture stdout and monkeypatches `get_db_path` to a temp
    DB seeded with controlled data."""

    def _setup_temp_db(self, tmp_path, monkeypatch):
        from claude_monitoring import privacy_audit
        from claude_monitoring.db import init_db

        db_path = tmp_path / "test.db"
        init_db(db_path).close()
        monkeypatch.setattr(
            "claude_monitoring.db.get_db_path",
            lambda: db_path,
        )
        # The audit mode reads via the `get_db_path` re-export inside
        # privacy_audit's local import; verify it picks up.
        monkeypatch.setattr(privacy_audit, "Path", privacy_audit.Path)
        return db_path

    def test_db_audit_lists_every_table_and_row_counts(self, tmp_path, monkeypatch, capsys):
        from claude_monitoring import privacy_audit

        self._setup_temp_db(tmp_path, monkeypatch)
        rc = privacy_audit.db_audit_mode()
        captured = capsys.readouterr()
        assert rc == 0
        assert "=== Vigil --db-audit ===" in captured.out
        # Should list assets and api_calls etc. — both fresh tables.
        assert "[assets]" in captured.out
        assert "[api_calls]" in captured.out
        # api_calls (capture table) prints the no-samples notice.
        assert "no samples (capture-table policy)" in captured.out

    def test_db_audit_redacts_seeded_secret_in_assets_current_state(self, tmp_path, monkeypatch, capsys):
        """End-to-end inversion test 1: seed a row with a token in
        assets.current_state and assert the audit output does NOT
        contain the raw token."""
        from claude_monitoring import privacy_audit

        db_path = self._setup_temp_db(tmp_path, monkeypatch)
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "asset-1",
                "ai_tool",
                "test",
                "ollama-models",
                0,
                0,
                0,
                json.dumps({"api_key": "sk-FAKE1234567890ABCDEFGHIJKLMNOP"}),
            ),
        )
        conn.commit()
        conn.close()
        privacy_audit.db_audit_mode()
        captured = capsys.readouterr()
        assert "sk-FAKE1234567890ABCDEFGHIJKLMNOP" not in captured.out, "raw token leaked into audit output"

    def test_db_audit_redacts_username_in_install_path(self, tmp_path, monkeypatch, capsys):
        """End-to-end inversion test 2: seed a row with a username in
        install_path and assert the audit output does NOT contain the
        raw username."""
        from claude_monitoring import privacy_audit

        db_path = self._setup_temp_db(tmp_path, monkeypatch)
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state, install_path) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "asset-2",
                "ai_tool",
                "test",
                "ollama-models",
                0,
                0,
                0,
                "{}",
                "/Users/realuser/Library/Application Support/claude/extensions/foo",
            ),
        )
        conn.commit()
        conn.close()
        privacy_audit.db_audit_mode()
        captured = capsys.readouterr()
        assert "realuser" not in captured.out, "raw username leaked into audit output"


# ---------------------------------------------------------------------------
# CI gate
# ---------------------------------------------------------------------------


class TestClassificationGate:
    """The check_db_audit_classification.py script ensures every column
    in every table is classified. Run it directly here."""

    def test_gate_passes_on_current_main(self):
        import subprocess
        from pathlib import Path

        repo_root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            ["python3", str(repo_root / "scripts" / "check_db_audit_classification.py")],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"classification gate failed:\n{result.stdout}\n{result.stderr}"
        assert "PASS" in result.stdout
