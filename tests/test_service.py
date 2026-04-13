"""Tests for the macOS LaunchAgent service (Phase 3)."""

from __future__ import annotations

import plistlib
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring import lifecycle


@pytest.fixture()
def tmp_output_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, "get_output_dir", lambda: tmp_path)
    monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
    # Redirect the plist path into tmp too so we never touch ~/Library
    fake_la = tmp_path / "LaunchAgents"
    fake_la.mkdir()
    monkeypatch.setattr(lifecycle, "get_plist_path", lambda: fake_la / f"{lifecycle.LAUNCH_AGENT_LABEL}.plist")
    # Reset logger cache so tests get fresh handlers
    lifecycle._LOGGER_CACHE = None
    import logging as _logging

    _logging.getLogger("ai-runtime-monitor").handlers.clear()
    return tmp_path


class TestPlistGeneration:
    def test_contains_required_keys(self, tmp_output_dir):
        xml = lifecycle.generate_plist(python_path="/usr/bin/python3")
        parsed = plistlib.loads(xml.encode())
        assert parsed["Label"] == lifecycle.LAUNCH_AGENT_LABEL
        assert parsed["RunAtLoad"] is True
        assert parsed["KeepAlive"]["SuccessfulExit"] is False
        assert parsed["ThrottleInterval"] == 10
        assert parsed["ProcessType"] == "Background"
        assert "ProgramArguments" in parsed

    def test_program_args_include_daemon(self, tmp_output_dir):
        xml = lifecycle.generate_plist(python_path="/usr/bin/python3", with_proxy=True)
        parsed = plistlib.loads(xml.encode())
        args = parsed["ProgramArguments"]
        assert "/usr/bin/python3" in args
        assert "--start" in args
        assert "--with-proxy" in args
        assert "--daemon" in args

    def test_without_proxy(self, tmp_output_dir):
        xml = lifecycle.generate_plist(python_path="/usr/bin/python3", with_proxy=False)
        parsed = plistlib.loads(xml.encode())
        args = parsed["ProgramArguments"]
        assert "--with-proxy" not in args
        assert "--daemon" in args

    def test_log_paths_in_plist(self, tmp_output_dir):
        xml = lifecycle.generate_plist(python_path="/usr/bin/python3")
        parsed = plistlib.loads(xml.encode())
        assert "service-stdout.log" in parsed["StandardOutPath"]
        assert "service-stderr.log" in parsed["StandardErrorPath"]


class TestInstallService:
    def test_writes_plist(self, tmp_output_dir):
        with patch("claude_monitoring.lifecycle.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            ok, msg = lifecycle.install_service()
        assert ok is True
        assert lifecycle.get_plist_path().exists()
        parsed = plistlib.loads(lifecycle.get_plist_path().read_bytes())
        assert parsed["Label"] == lifecycle.LAUNCH_AGENT_LABEL

    def test_stores_preference_when_with_system_proxy(self, tmp_output_dir):
        with patch("claude_monitoring.lifecycle.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            lifecycle.install_service(with_system_proxy=True)
        prefs = lifecycle.read_preferences()
        assert prefs.get("auto_enable_system_proxy") is True

    def test_default_does_not_set_proxy_pref(self, tmp_output_dir):
        with patch("claude_monitoring.lifecycle.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            lifecycle.install_service(with_system_proxy=False)
        prefs = lifecycle.read_preferences()
        assert prefs.get("auto_enable_system_proxy") is False

    def test_launchctl_failure_returns_false(self, tmp_output_dir):
        with patch("claude_monitoring.lifecycle.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="bad plist")
            ok, msg = lifecycle.install_service()
        assert ok is False
        assert "bad plist" in msg


class TestUninstallService:
    def test_removes_plist(self, tmp_output_dir):
        lifecycle.get_plist_path().write_text("stub")
        with patch("claude_monitoring.lifecycle.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            ok, msg = lifecycle.uninstall_service()
        assert ok is True
        assert not lifecycle.get_plist_path().exists()

    def test_no_plist_still_succeeds(self, tmp_output_dir):
        with patch("claude_monitoring.lifecycle.disable_system_proxy") as mock_disable:
            ok, msg = lifecycle.uninstall_service()
        assert ok is True
        assert "not installed" in msg.lower()
        mock_disable.assert_called_once()


class TestIsServiceInstalled:
    def test_false_when_missing(self, tmp_output_dir):
        assert lifecycle.is_service_installed() is False

    def test_true_when_plist_present(self, tmp_output_dir):
        lifecycle.get_plist_path().write_text("stub")
        assert lifecycle.is_service_installed() is True


class TestGetServiceState:
    def test_not_installed(self, tmp_output_dir):
        state = lifecycle.get_service_state()
        assert state["installed"] is False
        assert state["loaded"] is False

    def test_installed_but_not_loaded(self, tmp_output_dir):
        lifecycle.get_plist_path().write_text("stub")
        with patch("claude_monitoring.lifecycle.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            state = lifecycle.get_service_state()
        assert state["installed"] is True
        assert state["loaded"] is False

    def test_loaded_with_pid(self, tmp_output_dir):
        lifecycle.get_plist_path().write_text("stub")
        output = '{\n\t"PID" = 12345;\n\t"LastExitStatus" = 0;\n}'
        with patch("claude_monitoring.lifecycle.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output)
            state = lifecycle.get_service_state()
        assert state["installed"] is True
        assert state["loaded"] is True
        assert state["pid"] == 12345
        assert state["last_exit_code"] == 0
