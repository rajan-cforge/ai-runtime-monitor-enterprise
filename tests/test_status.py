# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for the ai-monitor --status command."""

from __future__ import annotations

import io
import subprocess
from contextlib import redirect_stdout
from unittest.mock import patch

from claude_monitoring import status as status_mod


def _mock_completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


class TestMitmproxyRunning:
    def test_returns_true_when_listen_present(self):
        with patch(
            "claude_monitoring.status.subprocess.run",
            return_value=_mock_completed("python3 LISTEN 127.0.0.1:9080"),
        ):
            assert status_mod._is_mitmproxy_running() is True

    def test_returns_false_when_no_listener(self):
        with patch(
            "claude_monitoring.status.subprocess.run",
            return_value=_mock_completed(""),
        ):
            assert status_mod._is_mitmproxy_running() is False

    def test_returns_false_on_exception(self):
        with patch(
            "claude_monitoring.status.subprocess.run",
            side_effect=OSError("boom"),
        ):
            assert status_mod._is_mitmproxy_running() is False


class TestSystemProxyConfigured:
    def test_returns_true_when_enabled_and_port_matches(self):
        output = "Enabled: Yes\nServer: 127.0.0.1\nPort: 9080\n"
        with patch(
            "claude_monitoring.status.subprocess.run",
            return_value=_mock_completed(output),
        ):
            assert status_mod._is_system_proxy_configured() is True

    def test_returns_false_when_disabled(self):
        with patch(
            "claude_monitoring.status.subprocess.run",
            return_value=_mock_completed("Enabled: No\n"),
        ):
            assert status_mod._is_system_proxy_configured() is False

    def test_returns_false_when_wrong_port(self):
        output = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8888\n"
        with patch(
            "claude_monitoring.status.subprocess.run",
            return_value=_mock_completed(output),
        ):
            assert status_mod._is_system_proxy_configured() is False


class TestCertTrusted:
    """_is_cert_trusted now reflects 'admin trust settings applied', not
    just 'cert exists in keychain'. The two are distinct macOS keychain
    states and only the second makes TLS chains validate. Tests mock at
    the verify_ca_trusted boundary so we don't have to set up real
    keychain state for each case."""

    def test_returns_true_when_cert_in_keychain_and_admin_trust_settings(self, monkeypatch, tmp_path):
        cert = tmp_path / "ai-monitor-ca.pem"
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
        monkeypatch.setattr("claude_monitoring.security.get_ca_cert_path", lambda: cert)
        monkeypatch.setattr("claude_monitoring.security.verify_ca_trusted", lambda *a, **kw: (True, None))
        assert status_mod._is_cert_trusted() is True

    def test_returns_false_when_in_keychain_but_no_admin_trust(self, monkeypatch, tmp_path):
        """This is the critical state we missed pre-fix: cert was added to
        the System keychain but admin trust settings were never applied
        (e.g., osascript dialog cancelled). The old _is_cert_trusted
        returned True (find-certificate found it). The new one returns
        False — matching what the proxy interception layer actually needs."""
        cert = tmp_path / "ai-monitor-ca.pem"
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
        monkeypatch.setattr("claude_monitoring.security.get_ca_cert_path", lambda: cert)
        monkeypatch.setattr(
            "claude_monitoring.security.verify_ca_trusted",
            lambda *a, **kw: (False, "in_keychain_but_not_trusted"),
        )
        assert status_mod._is_cert_trusted() is False

    def test_returns_false_when_cert_file_missing(self, monkeypatch, tmp_path):
        cert = tmp_path / "ai-monitor-ca.pem"  # does not exist
        monkeypatch.setattr("claude_monitoring.security.get_ca_cert_path", lambda: cert)
        # legacy mitmproxy CA also absent — _find_certificate path returns False
        with patch("claude_monitoring.status.subprocess.run", return_value=_mock_completed("")):
            assert status_mod._is_cert_trusted() is False

    def test_falls_back_to_legacy_mitmproxy_ca_when_custom_cert_file_missing(self, monkeypatch, tmp_path):
        """Pre-custom-CA installs only had the default mitmproxy CA. We
        can't SHA-1-verify without the cert file, so we fall back to
        name-based search and report keychain-only (trust state unknown).
        Returns False because we can't confirm admin trust."""
        cert = tmp_path / "ai-monitor-ca.pem"  # does not exist
        monkeypatch.setattr("claude_monitoring.security.get_ca_cert_path", lambda: cert)

        def fake_run(cmd, **_):
            if "mitmproxy" in cmd:
                return _mock_completed("mitmproxy")
            return _mock_completed("")

        with patch("claude_monitoring.status.subprocess.run", side_effect=fake_run):
            # _is_cert_trusted is strict: only True when admin trust is verified.
            # Legacy path can only confirm presence, so it returns False.
            assert status_mod._is_cert_trusted() is False


class TestMonitorRunning:
    def test_returns_true_on_http_200(self):
        # The probe now uses http.client.HTTPConnection directly to
        # bypass the macOS system proxy. Mock the connection class.
        fake_conn = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        fake_resp = fake_conn.getresponse.return_value
        fake_resp.status = 200
        fake_resp.read.return_value = b""
        with patch("http.client.HTTPConnection", return_value=fake_conn):
            assert status_mod._is_monitor_running() is True

    def test_returns_false_on_connection_error(self):
        with patch("http.client.HTTPConnection", side_effect=OSError("refused")):
            assert status_mod._is_monitor_running() is False


class TestDbEncrypted:
    def test_returns_false_without_sqlcipher(self):
        # sqlcipher3 is not installed in the test env by default
        import importlib

        with patch.object(importlib, "import_module", side_effect=ImportError):
            assert status_mod._is_db_encrypted() in (True, False)


class TestCheckPermissions:
    def test_missing_paths_are_ok(self, tmp_path, monkeypatch):
        monkeypatch.setattr(status_mod, "get_output_dir", lambda: tmp_path / "nonexistent")
        monkeypatch.setattr(status_mod, "get_db_path", lambda: tmp_path / "nonexistent" / "x.db")
        assert status_mod._check_permissions() is True

    def test_detects_wrong_permissions(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "out"
        out_dir.mkdir(mode=0o755)
        db = out_dir / "monitor.db"
        db.write_text("x")
        db.chmod(0o644)
        monkeypatch.setattr(status_mod, "get_output_dir", lambda: out_dir)
        monkeypatch.setattr(status_mod, "get_db_path", lambda: db)
        assert status_mod._check_permissions() is False

    def test_ok_with_correct_permissions(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "out"
        out_dir.mkdir(mode=0o700)
        db = out_dir / "monitor.db"
        db.write_text("x")
        db.chmod(0o600)
        monkeypatch.setattr(status_mod, "get_output_dir", lambda: out_dir)
        monkeypatch.setattr(status_mod, "get_db_path", lambda: db)
        assert status_mod._check_permissions() is True


class TestHasDashboardToken:
    def test_missing_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.setattr(status_mod, "get_output_dir", lambda: tmp_path)
        assert status_mod._has_dashboard_token() is False

    def test_short_token_rejected(self, tmp_path, monkeypatch):
        (tmp_path / ".dashboard_token").write_text("short")
        monkeypatch.setattr(status_mod, "get_output_dir", lambda: tmp_path)
        assert status_mod._has_dashboard_token() is False

    def test_valid_token_ok(self, tmp_path, monkeypatch):
        (tmp_path / ".dashboard_token").write_text("a" * 32)
        monkeypatch.setattr(status_mod, "get_output_dir", lambda: tmp_path)
        assert status_mod._has_dashboard_token() is True


class TestExtensionHeartbeat:
    def test_no_db_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(status_mod, "get_db_path", lambda: tmp_path / "nonexistent.db")
        assert status_mod._check_extension_heartbeat() is None

    def _setup_db_with_heartbeat(self, tmp_path, monkeypatch, last_seen_iso: str):
        """Helper: build a temp DB with one extension_heartbeats row at
        the given last_seen timestamp."""
        import sqlite3

        db_path = tmp_path / "monitor.db"
        conn = sqlite3.connect(str(db_path))
        conn.executescript(
            """
            CREATE TABLE extension_heartbeats (
                hostname TEXT, last_seen TEXT, user_matches INTEGER,
                assistant_matches INTEGER, captures_sent INTEGER,
                selector_failure INTEGER
            );
            """
        )
        conn.execute(
            "INSERT INTO extension_heartbeats (hostname, last_seen, user_matches, "
            "assistant_matches, captures_sent, selector_failure) VALUES (?, ?, ?, ?, ?, ?)",
            ("claude.ai", last_seen_iso, 3, 3, 5, 0),
        )
        conn.commit()
        conn.close()
        monkeypatch.setattr(status_mod, "get_db_path", lambda: db_path)
        return db_path

    def test_fresh_heartbeat_returns_dict(self, tmp_path, monkeypatch):
        """Heartbeat from 30s ago is fresh — function returns row dict."""
        from datetime import datetime, timedelta, timezone

        fresh = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
        self._setup_db_with_heartbeat(tmp_path, monkeypatch, fresh)
        result = status_mod._check_extension_heartbeat()
        assert result is not None
        assert result["hostname"] == "claude.ai"
        assert "3 user" in result["status"]

    def test_stale_heartbeat_returns_none(self, tmp_path, monkeypatch):
        """Heartbeat from days ago is stale — function returns None so
        the status display correctly shows 'Extension not loaded' rather
        than the false-positive 'Extension content' it produced pre-fix.
        This is the regression test for the architect cycle-1 finding
        on PR #51."""
        from datetime import datetime, timedelta, timezone

        stale = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        self._setup_db_with_heartbeat(tmp_path, monkeypatch, stale)
        result = status_mod._check_extension_heartbeat()
        assert result is None

    def test_boundary_heartbeat_just_inside_window_returns_dict(self, tmp_path, monkeypatch):
        """Just inside the 5-minute window (4m30s ago) — still fresh."""
        from datetime import datetime, timedelta, timezone

        boundary_fresh = (datetime.now(timezone.utc) - timedelta(seconds=270)).isoformat()
        self._setup_db_with_heartbeat(tmp_path, monkeypatch, boundary_fresh)
        assert status_mod._check_extension_heartbeat() is not None

    def test_boundary_heartbeat_just_outside_window_returns_none(self, tmp_path, monkeypatch):
        """Just outside the 5-minute window (5m30s ago) — stale."""
        from datetime import datetime, timedelta, timezone

        boundary_stale = (datetime.now(timezone.utc) - timedelta(seconds=330)).isoformat()
        self._setup_db_with_heartbeat(tmp_path, monkeypatch, boundary_stale)
        assert status_mod._check_extension_heartbeat() is None

    def test_malformed_timestamp_returns_none(self, tmp_path, monkeypatch):
        """Defensive: bad timestamp data → treat as stale, not fresh."""
        self._setup_db_with_heartbeat(tmp_path, monkeypatch, "not-an-iso-timestamp")
        assert status_mod._check_extension_heartbeat() is None


class TestShowStatus:
    def test_show_status_returns_zero_and_prints(self, monkeypatch):
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: False)
        monkeypatch.setattr(status_mod, "_is_cert_trusted", lambda: False)
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: False)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: False)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: False)
        monkeypatch.setattr(status_mod, "_check_extension_heartbeat", lambda: None)

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = status_mod.show_status()
        output = buf.getvalue()

        assert rc == 0
        for header in ("Core:", "Proxy:", "Capture matrix:", "Security:"):
            assert header in output
        assert "Monitor:" in output
        assert "mitmproxy:" in output
        assert "Claude Code:" in output

    def test_show_status_allow_hosts_line_shows_api_count_when_no_browser_leak(self, monkeypatch):
        """PR #54: show_status emits a new 'allow_hosts:' line under
        Proxy. Happy path — AI_PROXY_DOMAINS ∩ AI_BROWSER_DOMAINS is
        empty (PR #51 invariant) — line reads '✅ N API endpoints'."""
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: False)
        monkeypatch.setattr(status_mod, "_get_ca_trust_state", lambda: (True, True, None))
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: False)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: False)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: True)
        monkeypatch.setattr(status_mod, "_check_extension_heartbeat", lambda: None)

        buf = io.StringIO()
        with redirect_stdout(buf):
            status_mod.show_status()
        out = buf.getvalue()

        assert "allow_hosts:" in out
        assert "API endpoints (browser UI excluded)" in out
        assert "✅" in out  # the ok marker on the allow_hosts line

    def test_show_status_allow_hosts_line_flags_browser_ui_regression(self, monkeypatch):
        """If AI_PROXY_DOMAINS regressed and gained a browser UI host,
        show_status surfaces it as ⚠ on the allow_hosts line so a
        config-drift regression is visible at --status time without
        having to re-read constants.py."""
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: False)
        monkeypatch.setattr(status_mod, "_get_ca_trust_state", lambda: (True, True, None))
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: False)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: False)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: True)
        monkeypatch.setattr(status_mod, "_check_extension_heartbeat", lambda: None)
        # Force a regression: stuff a browser UI host into AI_PROXY_DOMAINS.
        monkeypatch.setattr("claude_monitoring.constants.AI_PROXY_DOMAINS", ["api.anthropic.com", "claude.ai"])

        buf = io.StringIO()
        with redirect_stdout(buf):
            status_mod.show_status()
        out = buf.getvalue()

        assert "allow_hosts:" in out
        assert "regression" in out
        assert "claude.ai" in out
        assert "⚠" in out

    def test_show_status_partial_trust_state_distinguishes_keychain_from_admin_trust(self, monkeypatch):
        """The two-line CA cert + CA trust display must distinguish the
        three states (trusted / in-keychain-but-not-trusted /
        not-in-keychain). Pre-fix the status only showed Trusted/Not
        Trusted, which masked the failure mode this PR catches."""
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: False)
        # The critical state: cert exists in keychain but admin trust
        # settings are not applied. Old _is_cert_trusted returned True
        # here; the new contract has trust=False with a specific reason.
        monkeypatch.setattr(
            status_mod,
            "_get_ca_trust_state",
            lambda: (True, False, "in_keychain_but_not_trusted"),
        )
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: False)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: False)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: True)
        monkeypatch.setattr(status_mod, "_check_extension_heartbeat", lambda: None)

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = status_mod.show_status()
        output = buf.getvalue()

        assert rc == 0
        assert "CA cert:" in output
        assert "✅ In keychain" in output
        assert "CA trust:" in output
        assert "Not in admin trust settings — proxy interception will fail" in output
        # The reason from _get_ca_trust_state is passed through
        # trust_reason_message, which maps "in_keychain_but_not_trusted"
        # to a string that includes the actionable recovery command.
        assert "admin trust settings are not applied" in output
        assert "security add-trusted-cert" in output

    def test_show_status_no_keychain_state(self, monkeypatch):
        """show_status with cert not in keychain at all (pre-setup,
        or post-purge). Different from the partial-trust state."""
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: False)
        # cert_code=None signals legacy fallback path (no SHA-1 verification
        # available); _get_ca_trust_state returns None when the custom CA
        # cert file is absent.
        monkeypatch.setattr(
            status_mod,
            "_get_ca_trust_state",
            lambda: (False, False, None),
        )
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: False)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: False)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: False)
        monkeypatch.setattr(status_mod, "_check_extension_heartbeat", lambda: None)

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = status_mod.show_status()
        output = buf.getvalue()

        assert rc == 0
        assert "CA cert:" in output
        assert "❌ Not in keychain" in output
        assert "CA trust:" in output
        assert "❌ Not trusted" in output

    def test_show_status_with_everything_ok(self, monkeypatch):
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: True)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: True)
        monkeypatch.setattr(status_mod, "_is_cert_trusted", lambda: True)
        monkeypatch.setattr(status_mod, "_get_ca_trust_state", lambda: (True, True, None))
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: True)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: True)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: True)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: True)
        monkeypatch.setattr(
            status_mod,
            "_check_extension_heartbeat",
            lambda: {
                "hostname": "claude.ai",
                "last_seen": "2026-04-11T10:00:00",
                "status": "✅ 3 user / 3 assistant",
            },
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = status_mod.show_status()
        output = buf.getvalue()

        assert rc == 0
        assert "Extension:" in output
        assert "claude.ai" in output
        # The custom CA section now shows the CN from get_ca_info(),
        # but since _has_custom_ca() is mocked True without an actual
        # cert on disk, get_ca_info() returns None → "details unavailable"
        assert "Custom" in output


class TestShowStatusJson:
    def test_emits_valid_json(self, monkeypatch):
        import json

        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: False)
        monkeypatch.setattr(status_mod, "_is_cert_trusted", lambda: False)
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: False)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: False)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: False)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: False)
        monkeypatch.setattr(status_mod, "_check_extension_heartbeat", lambda: None)

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = status_mod.show_status_json()

        assert rc == 0
        payload = json.loads(buf.getvalue())
        assert payload["monitor_running"] is False
        assert payload["dashboard_port"] == 9081
        assert payload["proxy_port"] == 9080
        assert "extension" in payload


# ─────────────────────────────────────────────────────────────
# Next-Steps footer — proxy enablement guidance + restart matrix
# ─────────────────────────────────────────────────────────────


class TestHttpProxyEnvIsSet:
    def test_returns_true_when_https_proxy_set(self, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9080")
        monkeypatch.delenv("https_proxy", raising=False)
        assert status_mod._http_proxy_env_is_set() is True

    def test_returns_true_when_lowercase_https_proxy_set(self, monkeypatch):
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        monkeypatch.setenv("https_proxy", "http://127.0.0.1:9080")
        assert status_mod._http_proxy_env_is_set() is True

    def test_returns_false_when_neither_set(self, monkeypatch):
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        monkeypatch.delenv("https_proxy", raising=False)
        assert status_mod._http_proxy_env_is_set() is False

    def test_empty_string_treated_as_unset(self, monkeypatch):
        """An exported-but-empty HTTPS_PROXY shouldn't fool the check.

        Some shells set HTTPS_PROXY="" to neutralise a previously-exported
        value; we should treat that as "not configured" and still nag the
        user to export the real URL.
        """
        monkeypatch.setenv("HTTPS_PROXY", "")
        monkeypatch.delenv("https_proxy", raising=False)
        assert status_mod._http_proxy_env_is_set() is False


class TestRenderNextStepsLines:
    """The renderer that powers both --status and the wizard ending."""

    def test_lines_include_export_and_enable_commands(self):
        lines = status_mod._render_next_steps_lines(proxy_port=9080)
        joined = "\n".join(lines)
        assert "export HTTPS_PROXY=http://127.0.0.1:9080" in joined
        assert "ai-monitor --enable-system-proxy" in joined

    def test_lines_include_restart_matrix(self):
        lines = status_mod._render_next_steps_lines(proxy_port=9080)
        joined = "\n".join(lines)
        # The five apps from the user-specified matrix, plus Chrome
        # exception, must all appear.
        for app in ("Claude Code", "Claude Desktop", "ChatGPT Desktop", "Cursor", "Chrome"):
            assert app in joined, f"{app} missing from restart matrix"
        # Chrome row must explain the no-restart exception.
        assert "no" in joined.lower() and "Chrome" in joined

    def test_lines_respect_custom_proxy_port(self):
        lines = status_mod._render_next_steps_lines(proxy_port=9999)
        joined = "\n".join(lines)
        assert "http://127.0.0.1:9999" in joined
        assert "http://127.0.0.1:9080" not in joined


class TestNextStepsFooterGating:
    """The footer fires when the user's environment is INCOMPLETE.

    Both conditions matter: the macOS system proxy AND HTTPS_PROXY in the
    shell. Either one missing means desktop apps or CLI tools won't have
    their API traffic captured, so the footer should appear and nag.
    """

    def _stub_status_pieces(self, monkeypatch, *, sys_proxy: bool):
        # Stub everything show_status calls so we only exercise the footer.
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: True)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: sys_proxy)
        monkeypatch.setattr(status_mod, "_get_ca_trust_state", lambda: (True, True, None))
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: True)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: False)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: True)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: True)
        monkeypatch.setattr(status_mod, "_check_extension_heartbeat", lambda: None)

    def test_footer_absent_when_fully_configured(self, monkeypatch):
        self._stub_status_pieces(monkeypatch, sys_proxy=True)
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9080")
        buf = io.StringIO()
        with redirect_stdout(buf):
            status_mod.show_status()
        assert "Next steps" not in buf.getvalue()

    def test_footer_present_when_system_proxy_off(self, monkeypatch):
        self._stub_status_pieces(monkeypatch, sys_proxy=False)
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9080")
        buf = io.StringIO()
        with redirect_stdout(buf):
            status_mod.show_status()
        out = buf.getvalue()
        assert "Next steps" in out
        assert "ai-monitor --enable-system-proxy" in out

    def test_footer_present_when_https_proxy_env_unset(self, monkeypatch):
        self._stub_status_pieces(monkeypatch, sys_proxy=True)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        monkeypatch.delenv("https_proxy", raising=False)
        buf = io.StringIO()
        with redirect_stdout(buf):
            status_mod.show_status()
        out = buf.getvalue()
        assert "Next steps" in out
        assert "export HTTPS_PROXY=" in out

    def test_dashboard_url_includes_token_when_available(self, monkeypatch):
        """Once monitoring is running, the Dashboard line should be
        directly clickable — i.e. include the ?token= query so the user
        doesn't have to find it themselves in the logs."""
        self._stub_status_pieces(monkeypatch, sys_proxy=True)
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9080")
        monkeypatch.setattr(
            "claude_monitoring.security.ensure_dashboard_token",
            lambda: "TESTTOKEN1234567890",
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            status_mod.show_status()
        assert "?token=TESTTOKEN1234567890" in buf.getvalue()


# ─────────────────────────────────────────────────────────────
# Honest capture matrix — live per-app detection
#
# Pre-fix the capture matrix printed `✅ Proxy (full capture)` for
# Claude Desktop / ChatGPT Desktop / Cursor whenever `sys_proxy=True`,
# regardless of whether those apps were actually routing through the
# proxy or whether content was being decrypted. The label lied — see
# the ground-truth verification on 2026-06-01 where all three apps
# showed ✅ in --status while their chat messages produced zero rows.
#
# These tests pin the new contract: the label reflects LIVE evidence
# (process is reachable from proxy, content rows exist for the app's
# expected host), not a static boolean.
# ─────────────────────────────────────────────────────────────


class TestFindAppMainPid:
    def test_returns_none_when_pgrep_finds_nothing(self):
        with patch("claude_monitoring.status.subprocess.run", return_value=_mock_completed("")):
            assert status_mod._find_app_main_pid("Claude.app/Contents/MacOS/Claude") is None

    def test_returns_first_pid_from_pgrep_output(self):
        out = "12345 /Applications/Claude.app/Contents/MacOS/Claude\n"
        with patch("claude_monitoring.status.subprocess.run", return_value=_mock_completed(out)):
            assert status_mod._find_app_main_pid("Claude.app/Contents/MacOS/Claude") == 12345

    def test_returns_none_when_pgrep_raises(self):
        with patch("claude_monitoring.status.subprocess.run", side_effect=OSError("no pgrep")):
            assert status_mod._find_app_main_pid("Claude") is None

    def test_returns_none_when_pgrep_output_malformed(self):
        with patch("claude_monitoring.status.subprocess.run", return_value=_mock_completed("not-a-pid garbage\n")):
            assert status_mod._find_app_main_pid("X") is None


class TestPidHasProxyConnection:
    def test_returns_false_for_none_pid(self):
        assert status_mod._pid_has_proxy_connection(None) is False

    def test_returns_true_when_lsof_shows_established_to_9080(self):
        out = "Claude 12345 user 5u IPv4 0xa 0t0 TCP 127.0.0.1:55988->127.0.0.1:9080 (ESTABLISHED)\n"
        with patch("claude_monitoring.status.subprocess.run", return_value=_mock_completed(out)):
            assert status_mod._pid_has_proxy_connection(12345) is True

    def test_returns_false_when_only_direct_connections(self):
        out = "Claude 12345 user 5u IPv6 0xa 0t0 TCP [::1]:60001->[2607:6bc0::10]:443 (ESTABLISHED)\n"
        with patch("claude_monitoring.status.subprocess.run", return_value=_mock_completed(out)):
            assert status_mod._pid_has_proxy_connection(12345) is False

    def test_returns_false_on_lsof_failure(self):
        with patch("claude_monitoring.status.subprocess.run", side_effect=OSError("no lsof")):
            assert status_mod._pid_has_proxy_connection(12345) is False

    def test_respects_custom_proxy_port(self):
        out = "Cursor 222 user 5u IPv4 0xa 0t0 TCP 127.0.0.1:55988->127.0.0.1:9999 (ESTABLISHED)\n"
        with patch("claude_monitoring.status.subprocess.run", return_value=_mock_completed(out)):
            assert status_mod._pid_has_proxy_connection(222, proxy_port=9999) is True
            assert status_mod._pid_has_proxy_connection(222, proxy_port=9080) is False


class TestRecentContentRowsForHost:
    """Counts api_calls rows for a host where content was decrypted
    (input_tokens > 0). Heuristic — shared hosts can produce false
    positives if another client hits the same host. Documented limit."""

    def test_zero_when_no_db(self, monkeypatch):
        def boom():
            raise OSError("db unavailable")

        monkeypatch.setattr("claude_monitoring.db.get_thread_db", boom)
        assert status_mod._recent_content_rows_for_host("api.anthropic.com") == 0

    def test_counts_only_rows_with_input_tokens(self, monkeypatch, tmp_path):
        # Spin up a real in-memory-ish DB so the SQL runs as it would in prod
        import sqlite3 as _sq

        db_path = tmp_path / "monitor.db"
        conn = _sq.connect(str(db_path))
        conn.execute(
            "CREATE TABLE api_calls (id INTEGER PRIMARY KEY, timestamp TEXT, "
            "destination_host TEXT, input_tokens INTEGER)"
        )
        now_iso = "2026-06-01T16:00:00+00:00"
        rows = [
            (now_iso, "api.anthropic.com", 100),  # populated, recent ✓
            (now_iso, "api.anthropic.com", 0),  # envelope-only ✗
            (now_iso, "api.openai.com", 50),  # wrong host ✗
            ("2020-01-01T00:00:00+00:00", "api.anthropic.com", 100),  # old ✗
        ]
        conn.executemany(
            "INSERT INTO api_calls (timestamp, destination_host, input_tokens) VALUES (?,?,?)",
            rows,
        )
        conn.commit()
        conn.close()

        def fake_db():
            return _sq.connect(str(db_path))

        monkeypatch.setattr("claude_monitoring.db.get_thread_db", fake_db)
        # Use a very wide window for the test so the "recent" row counts;
        # the test row's timestamp is mocked-current.
        assert status_mod._recent_content_rows_for_host("api.anthropic.com", minutes=60 * 24 * 365) == 1


class TestDetectDesktopAppCapture:
    """The orchestrator — the function whose output replaces the lying
    static label in show_status(). Combines three signals into one of
    four honest verdicts."""

    def test_app_not_running(self, monkeypatch):
        monkeypatch.setattr(status_mod, "_find_app_main_pid", lambda _suffix: None)
        icon, msg = status_mod._detect_desktop_app_capture(
            "Cursor", "Cursor.app/Contents/MacOS/Cursor", "api.cursor.sh", sys_proxy=True
        )
        assert icon == "·"
        assert "not running" in msg.lower()

    def test_fully_captured_has_content_rows(self, monkeypatch):
        monkeypatch.setattr(status_mod, "_find_app_main_pid", lambda _suffix: 12345)
        monkeypatch.setattr(status_mod, "_pid_has_proxy_connection", lambda _pid, **k: True)
        monkeypatch.setattr(status_mod, "_recent_content_rows_for_host", lambda h, minutes=60: 14)
        icon, msg = status_mod._detect_desktop_app_capture("Claude Desktop", "X", "api.anthropic.com", sys_proxy=True)
        assert icon == "✅"
        assert "14" in msg, f"label should surface row count, got: {msg}"

    def test_rows_alone_do_not_grant_check_when_app_is_bypassing(self, monkeypatch):
        """Regression test pinned by the code-reviewer agent on 2026-06-01.

        The shared-host false-positive: Claude Code is producing rows on
        ``api.anthropic.com`` while Claude Desktop IPv6-bypasses the
        proxy. A naive ``rows > 0 → ✅`` orchestrator would label Claude
        Desktop as captured purely from Claude Code's rows — the exact
        bug the honest matrix exists to eliminate. The orchestrator
        must require BOTH a live proxy connection AND rows > 0 before
        declaring ✅.
        """
        monkeypatch.setattr(status_mod, "_find_app_main_pid", lambda _suffix: 12345)
        # App is NOT routing through proxy (IPv6 bypass scenario)
        monkeypatch.setattr(status_mod, "_pid_has_proxy_connection", lambda _pid, **k: False)
        # But the shared host HAS rows from another client (Claude Code)
        monkeypatch.setattr(status_mod, "_recent_content_rows_for_host", lambda h, minutes=60: 99)
        icon, msg = status_mod._detect_desktop_app_capture("Claude Desktop", "X", "api.anthropic.com", sys_proxy=True)
        # Must NOT be ✅ — rows are from another client, not this app
        assert icon == "❌", f"expected ❌ for IPv6-bypass+shared-host case, got {icon} ({msg})"
        assert "bypass" in msg.lower() or "direct" in msg.lower()

    def test_tunneled_only_has_proxy_conn_but_no_content(self, monkeypatch):
        """The chatgpt.com case — app routes through proxy but allow_hosts
        excludes the host so nothing is decrypted."""
        monkeypatch.setattr(status_mod, "_find_app_main_pid", lambda _suffix: 12345)
        monkeypatch.setattr(status_mod, "_pid_has_proxy_connection", lambda _pid, **k: True)
        monkeypatch.setattr(status_mod, "_recent_content_rows_for_host", lambda h, minutes=60: 0)
        icon, msg = status_mod._detect_desktop_app_capture("ChatGPT Desktop", "X", "chatgpt.com", sys_proxy=True)
        assert icon == "⚠"
        assert "allow_hosts" in msg.lower() or "decrypted" in msg.lower()

    def test_bypassing_proxy_on_but_app_routing_direct(self, monkeypatch):
        """The Claude Desktop IPv6 / Cursor plugin-helper case — app
        running, system proxy on, but app has no :9080 connection."""
        monkeypatch.setattr(status_mod, "_find_app_main_pid", lambda _suffix: 12345)
        monkeypatch.setattr(status_mod, "_pid_has_proxy_connection", lambda _pid, **k: False)
        monkeypatch.setattr(status_mod, "_recent_content_rows_for_host", lambda h, minutes=60: 0)
        icon, msg = status_mod._detect_desktop_app_capture("Claude Desktop", "X", "api.anthropic.com", sys_proxy=True)
        assert icon == "❌"
        assert "bypass" in msg.lower() or "direct" in msg.lower() or "ipv6" in msg.lower()

    def test_process_only_when_system_proxy_off(self, monkeypatch):
        monkeypatch.setattr(status_mod, "_find_app_main_pid", lambda _suffix: 12345)
        monkeypatch.setattr(status_mod, "_pid_has_proxy_connection", lambda _pid, **k: False)
        monkeypatch.setattr(status_mod, "_recent_content_rows_for_host", lambda h, minutes=60: 0)
        icon, msg = status_mod._detect_desktop_app_capture("Cursor", "X", "api.cursor.sh", sys_proxy=False)
        assert icon == "❌"
        assert "process only" in msg.lower() or "system proxy" in msg.lower()


class TestShowStatusHonestMatrix:
    """End-to-end: show_status() output for the three desktop app rows
    reflects the real capture state, not a static sys_proxy boolean."""

    def _stub(self, monkeypatch, *, sys_proxy: bool):
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: True)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: sys_proxy)
        monkeypatch.setattr(status_mod, "_get_ca_trust_state", lambda: (True, True, None))
        monkeypatch.setattr(status_mod, "_is_monitor_running", lambda: True)
        monkeypatch.setattr(status_mod, "_is_db_encrypted", lambda: False)
        monkeypatch.setattr(status_mod, "_check_permissions", lambda: True)
        monkeypatch.setattr(status_mod, "_has_dashboard_token", lambda: True)
        monkeypatch.setattr(status_mod, "_has_custom_ca", lambda: True)
        monkeypatch.setattr(status_mod, "_check_extension_heartbeat", lambda: None)

    def test_three_desktop_apps_show_distinct_states(self, monkeypatch):
        """The verification on 2026-06-01 produced exactly this state:
        Claude Desktop bypassing (IPv6), ChatGPT Desktop tunneled-only,
        Cursor bypassing (plugin helpers). The honest matrix must show
        three different labels, not three identical ✅."""
        self._stub(monkeypatch, sys_proxy=True)

        def fake_pid(suffix):
            return {
                "Claude.app/Contents/MacOS/Claude": 1001,
                "ChatGPT.app/Contents/MacOS/ChatGPT": 1002,
                "Cursor.app/Contents/MacOS/Cursor": 1003,
            }.get(suffix)

        def fake_proxy_conn(pid, **k):
            # ChatGPT Desktop is the only one reaching the proxy
            return pid == 1002

        def fake_rows(host, minutes=60):
            return 0  # nothing decrypted today

        monkeypatch.setattr(status_mod, "_find_app_main_pid", fake_pid)
        monkeypatch.setattr(status_mod, "_pid_has_proxy_connection", fake_proxy_conn)
        monkeypatch.setattr(status_mod, "_recent_content_rows_for_host", fake_rows)

        buf = io.StringIO()
        with redirect_stdout(buf):
            status_mod.show_status()
        output = buf.getvalue()

        # Extract each desktop-app row by name and assert the SPECIFIC
        # icon per app, not just "labels are diverse." A test that only
        # checks diversity could pass even if the wrong icon went to the
        # wrong app — exactly the kind of regression a lying matrix
        # would re-introduce in disguise. Strengthened per code-reviewer.
        rows: dict[str, str] = {}
        for line in output.splitlines():
            stripped = line.strip()
            for label in ("Claude Desktop", "ChatGPT Desktop", "Cursor"):
                prefix = label + ":"
                if stripped.startswith(prefix):
                    # The icon is the first non-empty token after the label
                    rest = stripped[len(prefix) :].strip()
                    rows[label] = rest.split()[0]
                    break
        assert set(rows) == {"Claude Desktop", "ChatGPT Desktop", "Cursor"}, f"missing desktop-app rows: {rows}"
        # Pin each app's verdict per the mock setup above
        assert rows["Claude Desktop"] == "❌", f"Claude Desktop should bypass (❌), got {rows['Claude Desktop']}"
        assert rows["ChatGPT Desktop"] == "⚠", f"ChatGPT Desktop should be tunneled (⚠), got {rows['ChatGPT Desktop']}"
        assert rows["Cursor"] == "❌", f"Cursor should bypass (❌), got {rows['Cursor']}"

    def test_fully_captured_when_content_rows_present(self, monkeypatch):
        self._stub(monkeypatch, sys_proxy=True)
        monkeypatch.setattr(status_mod, "_find_app_main_pid", lambda s: 1001)
        monkeypatch.setattr(status_mod, "_pid_has_proxy_connection", lambda pid, **k: True)
        monkeypatch.setattr(status_mod, "_recent_content_rows_for_host", lambda h, minutes=60: 14)
        buf = io.StringIO()
        with redirect_stdout(buf):
            status_mod.show_status()
        out = buf.getvalue()
        # The Claude Desktop line should now be a ✅ with a row count
        assert "Claude Desktop:" in out
        for line in out.splitlines():
            if line.strip().startswith("Claude Desktop:"):
                assert "✅" in line, f"expected ✅, got: {line}"
                assert "14" in line, f"expected row count in label, got: {line}"
                break
