# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for Section 7 (cleanup), Section 8 (setup wizard), and Section 9 (purge).

These three features form the lifecycle bookends around `ai-monitor --start`:
the wizard runs once on first launch, cleanup runs on demand to dedup, and
purge tears everything down for uninstall.
"""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from claude_monitoring import cleanup as cleanup_mod
from claude_monitoring import wizard as wizard_mod

# ─────────────────────────────────────────────────────────────
# Section 7: cleanup
# ─────────────────────────────────────────────────────────────


@pytest.fixture()
def db_with_cruft(tmp_path):
    """Build a database with known duplicates, empty sessions, and NULL hashes."""
    from claude_monitoring.db import init_db

    db_path = tmp_path / "monitor.db"
    conn = init_db(db_path)
    try:
        # 3 extension captures with the same hash + conv_id + type → 2 dupes
        for ts in ("2026-04-01T00:00:00Z", "2026-04-01T00:00:01Z", "2026-04-01T00:00:02Z"):
            conn.execute(
                """INSERT INTO browser_sessions
                   (service, url, title, conversation_id, visit_time, source,
                    event_type, content_text, content_hash)
                   VALUES ('Claude Web', 'https://claude.ai/chat/1', 'Test',
                           'conv1', ?, 'extension', 'user_prompt', 'hello world', 'abc123')""",
                (ts,),
            )
        # 2 chrome history visits same URL same minute → 1 dupe
        for ts in ("2026-04-01T00:01:00Z", "2026-04-01T00:01:30Z"):
            conn.execute(
                """INSERT INTO browser_sessions
                   (service, url, title, visit_time, source)
                   VALUES ('ChatGPT', 'https://chatgpt.com', 'Home', ?, 'chrome_history')""",
                (ts,),
            )
        # 1 empty session
        conn.execute(
            "INSERT INTO sessions (session_id, start_time, total_turns, total_input_tokens, total_output_tokens) VALUES (?, ?, ?, ?, ?)",
            ("empty-1", "2026-04-01T00:00:00Z", 0, 0, 0),
        )
        # 1 real session that should be kept
        conn.execute(
            "INSERT INTO sessions (session_id, start_time, total_turns, title, last_activity) VALUES (?, ?, ?, ?, ?)",
            ("real-1", "2026-04-01T00:00:00Z", 5, "Real chat", "2026-04-01T01:00:00Z"),
        )
        # 1 browser_sessions row with NULL content_hash but populated content_text
        conn.execute(
            """INSERT INTO browser_sessions
               (service, url, title, visit_time, source, event_type, content_text, content_hash)
               VALUES ('Claude Web', 'https://claude.ai/chat/2', 'Other',
                       '2026-04-02T00:00:00Z', 'extension', 'user_prompt',
                       'unique content here', NULL)""",
        )
        conn.commit()
        yield conn, db_path
    finally:
        conn.close()


class TestCleanupCounts:
    def test_count_duplicate_captures(self, db_with_cruft):
        conn, _ = db_with_cruft
        assert cleanup_mod.count_duplicate_captures(conn) == 2

    def test_count_duplicate_visits(self, db_with_cruft):
        conn, _ = db_with_cruft
        assert cleanup_mod.count_duplicate_visits(conn) == 1

    def test_count_empty_sessions(self, db_with_cruft):
        conn, _ = db_with_cruft
        assert cleanup_mod.count_empty_sessions(conn) == 1

    def test_count_null_hashes(self, db_with_cruft):
        conn, _ = db_with_cruft
        assert cleanup_mod.count_null_hashes(conn) == 1


class TestCleanupDryRun:
    def test_dry_run_does_not_modify_db(self, db_with_cruft, monkeypatch):
        conn, db_path = db_with_cruft
        monkeypatch.setattr(cleanup_mod, "get_db_path", lambda: db_path)
        before_browser = conn.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()[0]
        before_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

        summary = cleanup_mod.run_cleanup(dry_run=True)
        assert summary["ok"] is True
        assert summary["dry_run"] is True
        assert summary["duplicate_captures"] == 2
        assert summary["duplicate_visits"] == 1
        assert summary["empty_sessions"] == 1
        assert summary["backup_path"] is None  # no backup on dry run

        after_browser = conn.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()[0]
        after_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        assert after_browser == before_browser
        assert after_sessions == before_sessions


class TestCleanupExecute:
    def test_real_run_removes_duplicates(self, db_with_cruft, monkeypatch):
        conn, db_path = db_with_cruft
        monkeypatch.setattr(cleanup_mod, "get_db_path", lambda: db_path)

        summary = cleanup_mod.run_cleanup(dry_run=False)
        assert summary["ok"] is True
        assert summary["duplicate_captures"] == 2
        assert summary["duplicate_visits"] == 1
        assert summary["empty_sessions"] == 1
        assert summary["hashes_backfilled"] == 1
        assert summary["backup_path"] is not None
        assert Path(summary["backup_path"]).exists()

        # Reopen — close + reopen so we see what was committed
        conn.close()
        conn2 = sqlite3.connect(str(db_path))
        try:
            # Real session preserved
            (s,) = conn2.execute("SELECT COUNT(*) FROM sessions WHERE session_id='real-1'").fetchone()
            assert s == 1
            # Empty session gone
            (e,) = conn2.execute("SELECT COUNT(*) FROM sessions WHERE session_id='empty-1'").fetchone()
            assert e == 0
            # Only one extension capture for the duplicated content
            (cap,) = conn2.execute(
                "SELECT COUNT(*) FROM browser_sessions WHERE source='extension' AND content_hash='abc123'"
            ).fetchone()
            assert cap == 1
            # Hash was backfilled
            (null_hashes,) = conn2.execute(
                "SELECT COUNT(*) FROM browser_sessions WHERE content_hash IS NULL AND content_text IS NOT NULL"
            ).fetchone()
            assert null_hashes == 0
        finally:
            conn2.close()

    def test_missing_db_returns_error(self, tmp_path, monkeypatch):
        nonexistent = tmp_path / "nope.db"
        monkeypatch.setattr(cleanup_mod, "get_db_path", lambda: nonexistent)
        summary = cleanup_mod.run_cleanup()
        assert summary["ok"] is False
        assert "not found" in summary["error"].lower()


class TestCleanupSummaryPrint:
    def test_dry_run_summary(self, capsys):
        summary = {
            "ok": True,
            "dry_run": True,
            "duplicate_captures": 5,
            "duplicate_visits": 3,
            "empty_sessions": 2,
            "hashes_backfilled": 4,
            "backup_path": None,
            "remaining_sessions": 0,
            "remaining_browser": 0,
        }
        cleanup_mod.print_cleanup_summary(summary)
        out = capsys.readouterr().out
        assert "DRY RUN" in out
        assert "Would remove: 10 rows" in out
        assert "Would backfill: 4" in out

    def test_real_run_summary(self, capsys):
        summary = {
            "ok": True,
            "dry_run": False,
            "duplicate_captures": 5,
            "duplicate_visits": 3,
            "empty_sessions": 2,
            "hashes_backfilled": 4,
            "backup_path": "/tmp/backup",
            "remaining_sessions": 100,
            "remaining_browser": 50,
        }
        cleanup_mod.print_cleanup_summary(summary)
        out = capsys.readouterr().out
        assert "Backup: /tmp/backup" in out
        assert "100 sessions" in out
        assert "50 browser entries" in out


# ─────────────────────────────────────────────────────────────
# Section 8: setup wizard
# ─────────────────────────────────────────────────────────────


class TestFirstRunDetection:
    def test_first_run_when_marker_missing(self, tmp_path, monkeypatch):
        # wizard.py imports get_setup_marker_path by name at module load,
        # so we patch the binding inside the wizard module too.
        def marker_fn():
            return tmp_path / ".setup_complete"

        monkeypatch.setattr("claude_monitoring.security.get_setup_marker_path", marker_fn)
        monkeypatch.setattr(wizard_mod, "get_setup_marker_path", marker_fn)
        assert wizard_mod.is_first_run() is True

    def test_not_first_run_when_marker_exists(self, tmp_path, monkeypatch):
        marker = tmp_path / ".setup_complete"
        marker.write_text("{}")

        def marker_fn():
            return marker

        monkeypatch.setattr("claude_monitoring.security.get_setup_marker_path", marker_fn)
        monkeypatch.setattr(wizard_mod, "get_setup_marker_path", marker_fn)
        assert wizard_mod.is_first_run() is False


class TestSetupWizard:
    def test_wizard_writes_marker(self, tmp_path, monkeypatch):
        # Stub everything that touches the system
        monkeypatch.setattr("claude_monitoring.security.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.security.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "monitor.db")

        # Skip the cert generation so we don't burn 2s of CPU
        cert = tmp_path / "certs" / "ai-monitor-ca.pem"
        cert.parent.mkdir(parents=True)
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")

        # Stub all interactive bits. verify_ca_trusted is now the source of
        # truth for "is the CA actually trusted as a root anchor"; stub it
        # to report verified-trusted so the wizard's Step 2 takes the
        # happy path. _is_cert_trusted is kept for callers that still
        # import the status helper.
        monkeypatch.setattr(wizard_mod, "_is_cert_trusted", lambda: True)
        monkeypatch.setattr(wizard_mod, "verify_ca_trusted", lambda *a, **kw: (True, "trusted"))
        monkeypatch.setattr(wizard_mod, "_is_system_proxy_configured", lambda: True)
        monkeypatch.setattr(wizard_mod, "get_ca_info", lambda: {"common_name": "Test CA"})

        buf = io.StringIO()
        with redirect_stdout(buf):
            assert wizard_mod.run_setup_wizard() is True

        out = buf.getvalue()
        assert "Setup complete" in out
        assert "Test CA" in out

        marker = tmp_path / ".setup_complete"
        assert marker.exists()
        state = json.loads(marker.read_text())
        assert state["version"] == wizard_mod.WIZARD_VERSION
        assert state["cert_trusted"] is True
        assert state["proxy_enabled"] is True
        assert "dashboard_token" in state

    def test_wizard_blocks_proxy_if_trust_verification_fails(self, tmp_path, monkeypatch):
        """The defect this PR fixes: trust_ca_cert() returns True from
        osascript exit, but admin trust settings aren't actually applied
        (user cancelled the dialog mid-way, Touch ID timed out, etc.).
        verify_ca_trusted() catches it. Step 3 (system proxy) must be
        skipped entirely — enabling the system proxy without trust
        breaks browsers and captures nothing useful."""
        monkeypatch.setattr("claude_monitoring.security.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.security.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "monitor.db")

        cert = tmp_path / "certs" / "ai-monitor-ca.pem"
        cert.parent.mkdir(parents=True)
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")

        # osascript "succeeds" but verify says trust isn't actually applied.
        # Pass the literal code; the wizard maps it to a human message
        # via trust_reason_message().
        monkeypatch.setattr(wizard_mod, "trust_ca_cert", lambda *a, **kw: True)
        monkeypatch.setattr(
            wizard_mod,
            "verify_ca_trusted",
            lambda *a, **kw: (False, "in_keychain_but_not_trusted"),
        )
        monkeypatch.setattr(wizard_mod, "get_ca_info", lambda: {"common_name": "Test CA"})
        # User answers "yes" to the trust prompt — we want to verify the
        # post-trust verification rejects despite the user opting in.
        monkeypatch.setattr(wizard_mod, "_prompt", lambda *a, **kw: True)

        buf = io.StringIO()
        with redirect_stdout(buf):
            result = wizard_mod.run_setup_wizard()

        out = buf.getvalue()
        # Wizard returns False so monitor.py:run_setup_wizard caller exits 1
        assert result is False
        # Step 2 must report the failure
        assert "Certificate trust step appeared to succeed, but verification failed" in out
        # Step 3 must be the skipped-due-to-trust message, NOT the
        # interactive proxy-enable prompt
        assert "System proxy skipped" in out
        assert "CA trust verification failed" in out
        # The final summary must reflect the caveat
        assert "Setup completed with caveats" in out
        # Marker still written so --status can read trust_ca state
        marker = tmp_path / ".setup_complete"
        assert marker.exists()
        state = json.loads(marker.read_text())
        assert state["steps"]["trust_ca"] == "manual_required"
        assert state["steps"]["system_proxy"] == "skipped_trust_required"

    def test_wizard_prints_actionable_manual_command_if_trust_fails(self, tmp_path, monkeypatch):
        """When trust verification fails, the user must be told exactly
        what to run to recover. Generic 'something went wrong' isn't
        actionable. We assert the exact `security add-trusted-cert`
        invocation and the cert path appear in the output."""
        monkeypatch.setattr("claude_monitoring.security.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.security.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "monitor.db")

        cert = tmp_path / "certs" / "ai-monitor-ca.pem"
        cert.parent.mkdir(parents=True)
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")

        monkeypatch.setattr(wizard_mod, "trust_ca_cert", lambda *a, **kw: False)
        monkeypatch.setattr(
            wizard_mod,
            "verify_ca_trusted",
            lambda *a, **kw: (False, "trust_settings_export_failed"),
        )
        monkeypatch.setattr(wizard_mod, "get_ca_info", lambda: {"common_name": "Test CA"})
        monkeypatch.setattr(wizard_mod, "_prompt", lambda *a, **kw: True)

        buf = io.StringIO()
        with redirect_stdout(buf):
            wizard_mod.run_setup_wizard()

        out = buf.getvalue()
        # The exact recovery command, plus the cert path, must appear.
        assert "sudo security add-trusted-cert -d -r trustRoot" in out
        assert "/Library/Keychains/System.keychain" in out
        assert str(cert) in out
        assert "Then re-run: ai-monitor --setup" in out
        # trust_reason_message("trust_settings_export_failed") is what
        # gets printed; the message must mention the export step so
        # the user understands what failed.
        assert "trust-settings export" in out or "trust settings export" in out.lower()

    def test_wizard_enables_system_proxy_when_trust_verified_and_user_accepts(self, tmp_path, monkeypatch):
        """Step 3 happy path: trust is verified, the system proxy isn't
        already enabled, the user accepts the prompt, and
        _enable_system_proxy returns True. Records 'ok' in the state
        marker. Closes a coverage gap in the verification-passes +
        proxy-enable-accepted branch."""
        monkeypatch.setattr("claude_monitoring.security.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.security.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "monitor.db")

        cert = tmp_path / "certs" / "ai-monitor-ca.pem"
        cert.parent.mkdir(parents=True)
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")

        # Trust prompt path: cert not yet trusted, user accepts, trust
        # succeeds and verifies. Then system proxy isn't enabled yet;
        # the user accepts the enable prompt; _enable_system_proxy
        # returns True.
        verify_calls = {"n": 0}

        def verify_after_trust(*a, **kw):
            verify_calls["n"] += 1
            # First call: pre-trust check at top of Step 2 — not trusted.
            # Second call: post-trust verification — trusted. Return
            # the literal codes the new contract expects.
            return (True, "trusted") if verify_calls["n"] >= 2 else (False, "not_in_keychain")

        monkeypatch.setattr(wizard_mod, "verify_ca_trusted", verify_after_trust)
        monkeypatch.setattr(wizard_mod, "trust_ca_cert", lambda *a, **kw: True)
        monkeypatch.setattr(wizard_mod, "_is_system_proxy_configured", lambda: False)
        monkeypatch.setattr(wizard_mod, "_enable_system_proxy", lambda: True)
        monkeypatch.setattr(wizard_mod, "get_ca_info", lambda: {"common_name": "Test CA"})
        monkeypatch.setattr(wizard_mod, "_prompt", lambda *a, **kw: True)

        buf = io.StringIO()
        with redirect_stdout(buf):
            result = wizard_mod.run_setup_wizard()

        out = buf.getvalue()
        assert result is True
        assert "Certificate trusted (verified in admin trust settings)" in out
        assert "System proxy enabled" in out
        marker = tmp_path / ".setup_complete"
        state = json.loads(marker.read_text())
        assert state["steps"]["trust_ca"] == "ok"
        assert state["steps"]["system_proxy"] == "ok"

    def test_wizard_skips_system_proxy_when_user_declines_trust(self, tmp_path, monkeypatch):
        """When the user answers 'no' to the trust prompt, Step 3 must
        NOT offer the system proxy — enabling it without trust would
        route AI traffic through an untrusted CA and break browsers
        with zero useful capture. The wizard still returns True because
        the decline was an intentional user choice (not a verification
        failure), but the runtime behavior of Step 3 is the same."""
        monkeypatch.setattr("claude_monitoring.security.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.security.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "monitor.db")

        cert = tmp_path / "certs" / "ai-monitor-ca.pem"
        cert.parent.mkdir(parents=True)
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")

        # Cert not trusted, user declines the trust prompt.
        # verify_ca_trusted returns a literal code; for the decline
        # path the code never gets read (we set state to 'skipped').
        monkeypatch.setattr(wizard_mod, "verify_ca_trusted", lambda *a, **kw: (False, "not_in_keychain"))
        monkeypatch.setattr(wizard_mod, "get_ca_info", lambda: {"common_name": "Test CA"})
        monkeypatch.setattr(wizard_mod, "_prompt", lambda *a, **kw: False)

        buf = io.StringIO()
        with redirect_stdout(buf):
            result = wizard_mod.run_setup_wizard()

        out = buf.getvalue()
        # User's intentional decline → wizard exit code is success.
        assert result is True
        # But Step 3 must still be blocked from prompting for the system proxy.
        assert "System proxy skipped" in out
        assert "CA trust was declined" in out
        # No interactive system-proxy prompt should appear; assert by
        # absence of the prompt's distinctive opener phrasing.
        assert "Enable AI traffic monitoring for desktop apps" not in out
        # Marker reflects both intentional decline and blocked step.
        marker = tmp_path / ".setup_complete"
        state = json.loads(marker.read_text())
        assert state["steps"]["trust_ca"] == "skipped"
        assert state["steps"]["system_proxy"] == "skipped_trust_required"

    def test_wizard_skips_already_present_cert(self, tmp_path, monkeypatch):
        monkeypatch.setattr("claude_monitoring.security.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.security.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: tmp_path / "monitor.db")
        monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: tmp_path)
        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "monitor.db")

        cert = tmp_path / "certs" / "ai-monitor-ca.pem"
        cert.parent.mkdir(parents=True)
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")

        monkeypatch.setattr(wizard_mod, "_is_cert_trusted", lambda: True)
        monkeypatch.setattr(wizard_mod, "verify_ca_trusted", lambda *a, **kw: (True, "trusted"))
        monkeypatch.setattr(wizard_mod, "_is_system_proxy_configured", lambda: True)
        monkeypatch.setattr(wizard_mod, "get_ca_info", lambda: {"common_name": "Existing"})

        gen_called = {"count": 0}

        def fake_gen(*args, **kwargs):
            gen_called["count"] += 1

        monkeypatch.setattr(wizard_mod, "generate_custom_ca", fake_gen)

        buf = io.StringIO()
        with redirect_stdout(buf):
            wizard_mod.run_setup_wizard()
        # Cert already present, should NOT have called generate
        assert gen_called["count"] == 0


# ─────────────────────────────────────────────────────────────
# Section 9: purge
# ─────────────────────────────────────────────────────────────


class TestPurge:
    def _stub_paths(self, tmp_path, monkeypatch):
        """wizard.py imports config helpers at module load — patch the
        wizard-module bindings AND the config bindings so both code paths
        see the temp dir."""

        def out():
            return tmp_path

        def db():
            return tmp_path / "monitor.db"

        monkeypatch.setattr(wizard_mod, "get_output_dir", out)
        monkeypatch.setattr(wizard_mod, "get_db_path", db)
        monkeypatch.setattr("claude_monitoring.security.get_output_dir", out)
        monkeypatch.setattr("claude_monitoring.security.get_db_path", db)
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", out)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", db)

    def test_purge_requires_DELETE_token(self, tmp_path, monkeypatch):
        self._stub_paths(tmp_path, monkeypatch)
        (tmp_path / "monitor.db").write_text("data")
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = wizard_mod.run_purge(confirm_token="not-the-magic-word")
        assert result is False
        assert (tmp_path / "monitor.db").exists()
        assert "Cancelled" in buf.getvalue()

    def test_purge_removes_data_dir(self, tmp_path, monkeypatch):
        self._stub_paths(tmp_path, monkeypatch)
        (tmp_path / "monitor.db").write_text("secret data" * 100)
        (tmp_path / ".dashboard_token").write_text("tok")

        # Stub the side-effecting parts so the test doesn't touch the keychain
        monkeypatch.setattr(wizard_mod, "_disable_system_proxy", lambda: True)
        monkeypatch.setattr(wizard_mod, "untrust_ca_cert", lambda *_a, **_k: True)

        buf = io.StringIO()
        with redirect_stdout(buf):
            result = wizard_mod.run_purge(confirm_token="DELETE")
        assert result is True
        out = buf.getvalue()
        assert "completely removed" in out
        assert not tmp_path.exists()  # whole dir gone

    def test_purge_with_no_db_still_succeeds(self, tmp_path, monkeypatch):
        def out():
            return tmp_path

        def db():
            return tmp_path / "missing.db"

        monkeypatch.setattr(wizard_mod, "get_output_dir", out)
        monkeypatch.setattr(wizard_mod, "get_db_path", db)
        monkeypatch.setattr("claude_monitoring.security.get_output_dir", out)
        monkeypatch.setattr("claude_monitoring.security.get_db_path", db)
        monkeypatch.setattr("claude_monitoring.config.get_output_dir", out)
        monkeypatch.setattr("claude_monitoring.config.get_db_path", db)
        monkeypatch.setattr(wizard_mod, "_disable_system_proxy", lambda: True)
        monkeypatch.setattr(wizard_mod, "untrust_ca_cert", lambda *_a, **_k: True)

        buf = io.StringIO()
        with redirect_stdout(buf):
            result = wizard_mod.run_purge(confirm_token="DELETE")
        assert result is True
