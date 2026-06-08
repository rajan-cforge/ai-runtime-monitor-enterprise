"""P2.6 reputation runtime configuration — kill-switch + dormant flag + budget."""

from __future__ import annotations

import pytest

from claude_monitoring.attack_surface.reputation import config


class TestKillSwitch:
    def test_disabled_when_VIGIL_NO_REPUTATION_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VIGIL_NO_REPUTATION", "1")
        assert config.reputation_disabled() is True

    def test_disabled_when_NO_NETWORK_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Spec §8.3 air-gapped mode also short-circuits reputation."""
        monkeypatch.setenv("NO_NETWORK", "1")
        assert config.reputation_disabled() is True

    def test_enabled_when_no_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        assert config.reputation_disabled() is False

    def test_truthy_variants_recognized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for val in ["1", "true", "TRUE", "yes", "on"]:
            monkeypatch.setenv("VIGIL_NO_REPUTATION", val)
            assert config.reputation_disabled() is True

    def test_falsy_variants_not_disabling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_NETWORK", raising=False)
        for val in ["0", "false", "no", "off", ""]:
            monkeypatch.setenv("VIGIL_NO_REPUTATION", val)
            assert config.reputation_disabled() is False


class TestChromeVSCodeDormantFlag:
    """Item 3 ratified — default False; flipped only by P3.1/P3.2."""

    def test_default_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VIGIL_REPUTATION_CHROME_VSCODE_ENABLED", raising=False)
        assert config.chrome_vscode_enabled() is False

    def test_env_override_can_enable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dev/test override path — production default still off."""
        monkeypatch.setenv("VIGIL_REPUTATION_CHROME_VSCODE_ENABLED", "1")
        assert config.chrome_vscode_enabled() is True

    def test_env_falsy_keeps_dormant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VIGIL_REPUTATION_CHROME_VSCODE_ENABLED", "0")
        assert config.chrome_vscode_enabled() is False


class TestRatifiedConstants:
    def test_pypistats_budget_is_25(self) -> None:
        """Addendum ratification 2026-06-08."""
        assert config.PYPISTATS_PER_SCAN_BUDGET == 25

    def test_request_timeout_matches_existing_pattern(self) -> None:
        """10s matches threat_intel.py."""
        assert config.REQUEST_TIMEOUT_SECONDS == 10
