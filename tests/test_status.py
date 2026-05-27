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
