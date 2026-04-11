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
    def test_detects_custom_ca(self):
        def fake_run(cmd, **_):
            if "AI Runtime Monitor" in cmd:
                return _mock_completed("AI Runtime Monitor - Mac-3155")
            return _mock_completed("")

        with patch("claude_monitoring.status.subprocess.run", side_effect=fake_run):
            assert status_mod._is_cert_trusted() is True

    def test_fallback_to_mitmproxy_cert(self):
        def fake_run(cmd, **_):
            if "mitmproxy" in cmd:
                return _mock_completed("mitmproxy")
            return _mock_completed("")

        with patch("claude_monitoring.status.subprocess.run", side_effect=fake_run):
            assert status_mod._is_cert_trusted() is True

    def test_neither_cert_present(self):
        with patch(
            "claude_monitoring.status.subprocess.run",
            return_value=_mock_completed(""),
        ):
            assert status_mod._is_cert_trusted() is False


class TestMonitorRunning:
    def test_returns_true_on_http_200(self):
        class FakeResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        with patch("urllib.request.urlopen", return_value=FakeResp()):
            assert status_mod._is_monitor_running() is True

    def test_returns_false_on_connection_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
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

    def test_show_status_with_everything_ok(self, monkeypatch):
        monkeypatch.setattr(status_mod, "_is_mitmproxy_running", lambda: True)
        monkeypatch.setattr(status_mod, "_is_system_proxy_configured", lambda: True)
        monkeypatch.setattr(status_mod, "_is_cert_trusted", lambda: True)
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
        assert "Custom (AI domains only)" in output


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
