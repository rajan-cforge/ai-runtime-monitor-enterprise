"""P2.6 reputation dispatcher — per-asset routing, kill-switch, dormant gate."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.reputation.dispatcher import (
    MODIFIER_WEIGHTS,
    ReputationDispatcher,
    reputation_modifier_for,
)
from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)


def _asset(*, source: str, name: str = "pkg", current_state: dict | None = None) -> Asset:
    return Asset(
        id="x",
        type=source,
        parent_asset_id=None,
        name=name,
        version=None,
        install_path=f"/tmp/{name}",
        source=source,
        current_state=current_state or {},
        discovered_at=time.time(),
    )


@pytest.fixture
def dispatcher_with_mock_clients(tmp_path: Path):
    """Build a dispatcher where every per-registry client is a mock so
    tests can pin the dispatcher's behavior without touching the
    network."""
    npm = MagicMock()
    pypi = MagicMock()
    chrome = MagicMock()
    vscode = MagicMock()
    mcp_author = MagicMock()
    dispatcher = ReputationDispatcher(
        cache_path=tmp_path / "rep.json",
        npm_client=npm,
        pypi_client=pypi,
        chrome_client=chrome,
        vscode_client=vscode,
        mcp_author_client=mcp_author,
    )
    return dispatcher, npm, pypi, chrome, vscode, mcp_author


class TestPerSourceRouting:
    def test_npm_source_routes_to_npm_client(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        dispatcher, npm, *_ = dispatcher_with_mock_clients
        npm.lookup.return_value = ReputationResult(
            signal=ReputationSignal.NPM_LOW_DOWNLOADS,
            present=True,
            downloads=1_000_000,
        )
        result = dispatcher.lookup(_asset(source="node-packages", name="left-pad"))
        npm.lookup.assert_called_once_with("left-pad")
        assert result is not None
        assert result.signal is ReputationSignal.NPM_LOW_DOWNLOADS

    def test_pip_source_routes_to_pypi_client(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        dispatcher, _npm, pypi, *_ = dispatcher_with_mock_clients
        pypi.lookup.return_value = ReputationResult(
            signal=ReputationSignal.PIP_LOW_DOWNLOADS,
            present=True,
            downloads=500_000,
        )
        result = dispatcher.lookup(_asset(source="python-packages", name="requests"))
        pypi.lookup.assert_called_once_with("requests")
        assert result is not None

    def test_mcp_source_passes_command_and_first_arg(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        dispatcher, _npm, _pypi, _chrome, _vscode, mcp_author = dispatcher_with_mock_clients
        mcp_author.lookup.return_value = ReputationResult(
            signal=ReputationSignal.MCP_AUTHOR_UNVERIFIED,
            present=True,
        )
        asset = _asset(
            source="mcp-servers",
            name="filesystem",
            current_state={"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]},
        )
        dispatcher.lookup(asset)
        mcp_author.lookup.assert_called_once_with("npx", "@modelcontextprotocol/server-filesystem")

    def test_unrelated_source_returns_none(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        dispatcher, npm, pypi, *_ = dispatcher_with_mock_clients
        # claude-code-skills has no reputation signal in P2.6
        result = dispatcher.lookup(_asset(source="claude-code-skills"))
        assert result is None
        npm.lookup.assert_not_called()
        pypi.lookup.assert_not_called()


class TestKillSwitchShortCircuits:
    """``VIGIL_NO_REPUTATION=1`` → every applicable asset gets
    unavailable-with-reason; clients are never called."""

    def test_kill_switch_returns_unavailable_no_client_call(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VIGIL_NO_REPUTATION", "1")
        dispatcher, npm, *_ = dispatcher_with_mock_clients
        result = dispatcher.lookup(_asset(source="node-packages", name="left-pad"))
        assert result is not None
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED
        npm.lookup.assert_not_called()

    def test_kill_switch_returns_None_for_non_participating_source(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Kill switch + asset type that doesn't participate → still None."""
        monkeypatch.setenv("VIGIL_NO_REPUTATION", "1")
        dispatcher, *_ = dispatcher_with_mock_clients
        result = dispatcher.lookup(_asset(source="claude-code-skills"))
        assert result is None

    def test_NO_NETWORK_also_kills(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.setenv("NO_NETWORK", "1")
        dispatcher, npm, *_ = dispatcher_with_mock_clients
        result = dispatcher.lookup(_asset(source="node-packages", name="x"))
        assert result is not None
        assert result.reason is UnavailableReason.LOOKUP_FAILED


class TestDormantGate:
    """Chrome/VSCode signals return DORMANT until the flag flips."""

    def test_chrome_returns_dormant_by_default(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        monkeypatch.delenv("VIGIL_REPUTATION_CHROME_VSCODE_ENABLED", raising=False)
        dispatcher, _npm, _pypi, chrome, *_ = dispatcher_with_mock_clients
        result = dispatcher.lookup(_asset(source="chrome-extensions", name="abc"))
        assert result is not None
        assert result.present is None
        assert result.reason is UnavailableReason.DORMANT
        chrome.lookup.assert_not_called()

    def test_vscode_returns_dormant_by_default(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        monkeypatch.delenv("VIGIL_REPUTATION_CHROME_VSCODE_ENABLED", raising=False)
        dispatcher, _npm, _pypi, _chrome, vscode, *_ = dispatcher_with_mock_clients
        result = dispatcher.lookup(_asset(source="vscode-extensions", name="x.y"))
        assert result is not None
        assert result.reason is UnavailableReason.DORMANT
        vscode.lookup.assert_not_called()

    def test_chrome_calls_client_when_flag_flipped(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        monkeypatch.setenv("VIGIL_REPUTATION_CHROME_VSCODE_ENABLED", "1")
        dispatcher, _npm, _pypi, chrome, *_ = dispatcher_with_mock_clients
        chrome.lookup.return_value = ReputationResult(
            signal=ReputationSignal.CHROME_NOT_IN_STORE, present=True
        )
        result = dispatcher.lookup(_asset(source="chrome-extensions", name="abc"))
        chrome.lookup.assert_called_once_with("abc")
        assert result is not None
        assert result.present is True


class TestCacheFirst:
    def test_cache_hit_skips_client_call(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        dispatcher, npm, *_ = dispatcher_with_mock_clients
        npm.lookup.return_value = ReputationResult(
            signal=ReputationSignal.NPM_LOW_DOWNLOADS, present=True, downloads=200
        )
        dispatcher.lookup(_asset(source="node-packages", name="left-pad"))
        dispatcher.lookup(_asset(source="node-packages", name="left-pad"))
        # Only one network call — the second is cache-served
        assert npm.lookup.call_count == 1


class TestPerItemIsolationOnException:
    """Per memory project_v022_per_item_isolation.md: a client raising
    must not crash the dispatcher."""

    def test_exception_translates_to_LOOKUP_FAILED(
        self, dispatcher_with_mock_clients, monkeypatch: pytest.MonkeyPatch, caplog
    ) -> None:
        monkeypatch.delenv("VIGIL_NO_REPUTATION", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        dispatcher, npm, *_ = dispatcher_with_mock_clients
        npm.lookup.side_effect = RuntimeError("kaboom")
        with caplog.at_level("WARNING"):
            result = dispatcher.lookup(_asset(source="node-packages", name="x"))
        assert result is not None
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED
        # Warning logged for observability
        assert any("kaboom" in r.message for r in caplog.records)


class TestReputationModifierMapping:
    """``reputation_modifier_for`` is the int the scoring layer adds.

    Only ``present is False`` fires the modifier. Everything else is 0
    — including unavailable + dormant + present True. Silence is never
    all-clear in SCORE terms either."""

    def test_present_true_returns_zero(self) -> None:
        r = ReputationResult(signal=ReputationSignal.NPM_LOW_DOWNLOADS, present=True, downloads=200)
        assert reputation_modifier_for(r) == 0

    def test_unavailable_returns_zero(self) -> None:
        r = ReputationResult(
            signal=ReputationSignal.PIP_LOW_DOWNLOADS,
            present=None,
            reason=UnavailableReason.RATE_LIMITED,
        )
        assert reputation_modifier_for(r) == 0

    def test_dormant_returns_zero(self) -> None:
        r = ReputationResult(
            signal=ReputationSignal.CHROME_NOT_IN_STORE,
            present=None,
            reason=UnavailableReason.DORMANT,
        )
        assert reputation_modifier_for(r) == 0

    def test_present_false_fires_npm_15(self) -> None:
        r = ReputationResult(signal=ReputationSignal.NPM_LOW_DOWNLOADS, present=False, downloads=50)
        assert reputation_modifier_for(r) == 15

    def test_present_false_fires_pip_15(self) -> None:
        r = ReputationResult(signal=ReputationSignal.PIP_LOW_DOWNLOADS, present=False, downloads=50)
        assert reputation_modifier_for(r) == 15

    def test_present_false_fires_chrome_20(self) -> None:
        r = ReputationResult(signal=ReputationSignal.CHROME_NOT_IN_STORE, present=False)
        assert reputation_modifier_for(r) == 20

    def test_present_false_fires_vscode_20(self) -> None:
        r = ReputationResult(signal=ReputationSignal.VSCODE_NOT_IN_MARKETPLACE, present=False)
        assert reputation_modifier_for(r) == 20

    def test_present_false_fires_mcp_10(self) -> None:
        r = ReputationResult(signal=ReputationSignal.MCP_AUTHOR_UNVERIFIED, present=False)
        assert reputation_modifier_for(r) == 10

    def test_modifier_weight_table_matches_ratified_values(self) -> None:
        """Ratification item 1 numerical lockdown."""
        assert MODIFIER_WEIGHTS[ReputationSignal.NPM_LOW_DOWNLOADS] == 15
        assert MODIFIER_WEIGHTS[ReputationSignal.PIP_LOW_DOWNLOADS] == 15
        assert MODIFIER_WEIGHTS[ReputationSignal.CHROME_NOT_IN_STORE] == 20
        assert MODIFIER_WEIGHTS[ReputationSignal.VSCODE_NOT_IN_MARKETPLACE] == 20
        assert MODIFIER_WEIGHTS[ReputationSignal.MCP_AUTHOR_UNVERIFIED] == 10

    def test_none_result_returns_zero(self) -> None:
        assert reputation_modifier_for(None) == 0
