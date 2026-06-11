"""TDD red-phase tests for P4.1 dispatcher.

Phase B test surface for `attack_surface/cves/dispatcher.py`. Pins:
  * per-scan orchestration: queries → cache → batch → detail-fetch
  * per-item isolation (one asset's failure doesn't poison others)
  * 50-call vuln-detail budget (Phase A §3)
  * kill-switch (VIGIL_NO_CVE_FEED / NO_NETWORK)
  * tri-state result (None / [] / [...])
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def fake_caches(tmp_path, monkeypatch):
    """Point both cache files at tmp_path so the dispatcher uses fresh
    empty caches."""
    monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
    return tmp_path


class _PackageAsset:
    """Minimal duck-typed Asset for tests."""

    def __init__(self, asset_id: str, source: str, package: str, version: str, ecosystem: str):
        self.id = asset_id
        self.source = source
        self.current_state = {
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
        }


class TestCVEDispatcherKillSwitch:
    """When the kill-switch is set, every asset gets cves=None reason=KILL_SWITCH;
    no network calls are made."""

    def test_kill_switch_returns_kill_switch_reason_for_all_assets(self, fake_caches, monkeypatch):
        monkeypatch.setenv("VIGIL_NO_CVE_FEED", "1")
        from claude_monitoring.attack_surface.cves.dispatcher import CVEDispatcher
        from claude_monitoring.attack_surface.cves.types import UnavailableReason

        client = MagicMock()
        dispatcher = CVEDispatcher(client=client)
        assets = [
            _PackageAsset("a", "python-packages", "requests", "2.18.0", "PyPI"),
        ]
        out = dispatcher.scan(assets)
        assert out["a"].cves is None
        assert out["a"].reason == UnavailableReason.KILL_SWITCH
        client.querybatch.assert_not_called()
        client.vuln_detail.assert_not_called()


class TestCVEDispatcherCachedHits:
    """When all assets' querybatch + vuln-detail entries are cached, no
    network calls are made; results come straight from the caches."""

    def test_warm_cache_uses_no_network(self, fake_caches):
        from claude_monitoring.attack_surface.cves import config
        from claude_monitoring.attack_surface.cves.dispatcher import CVEDispatcher
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )
        from claude_monitoring.attack_surface.cves.vulns_cache import VulnsCache

        qb = QuerybatchCache(config.get_querybatch_cache_path())
        qb.set("PyPI", "requests", "2.18.0", vuln_ids=["GHSA-x"])
        vc = VulnsCache(config.get_vulns_cache_path())
        vc.set(
            "GHSA-x",
            record={
                "id": "GHSA-x",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            },
        )

        client = MagicMock()
        dispatcher = CVEDispatcher(client=client)
        assets = [
            _PackageAsset("a", "python-packages", "requests", "2.18.0", "PyPI"),
        ]
        out = dispatcher.scan(assets)
        client.querybatch.assert_not_called()
        client.vuln_detail.assert_not_called()
        # Asset gets at least one CVSS entry; scoring layer uses max().
        assert out["a"].cves is not None
        assert len(out["a"].cves) == 1
        assert "cvss" in out["a"].cves[0]


class TestCVEDispatcherFreshQuery:
    """Cold cache → dispatcher makes 1 querybatch call + N detail calls."""

    def test_cold_cache_calls_querybatch_and_caches_result(self, fake_caches):
        from claude_monitoring.attack_surface.cves.dispatcher import CVEDispatcher

        client = MagicMock()
        client.querybatch.return_value = [["GHSA-x"]]
        client.vuln_detail.return_value = {
            "id": "GHSA-x",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }
        dispatcher = CVEDispatcher(client=client)
        assets = [
            _PackageAsset("a", "python-packages", "requests", "2.18.0", "PyPI"),
        ]
        out = dispatcher.scan(assets)
        client.querybatch.assert_called_once()
        client.vuln_detail.assert_called_once_with("GHSA-x")
        assert out["a"].cves is not None
        assert len(out["a"].cves) == 1

    def test_clean_package_returns_empty_list(self, fake_caches):
        from claude_monitoring.attack_surface.cves.dispatcher import CVEDispatcher

        client = MagicMock()
        client.querybatch.return_value = [[]]  # no vulns
        dispatcher = CVEDispatcher(client=client)
        assets = [_PackageAsset("a", "python-packages", "clean", "1.0", "PyPI")]
        out = dispatcher.scan(assets)
        assert out["a"].cves == []
        client.vuln_detail.assert_not_called()


class TestCVEDispatcherEcosystemFilter:
    """Only PyPI + npm package-type sources get CVE lookups; skipped sources
    return CVEResult(cves=None, reason=None)."""

    def test_skipped_source_gets_cves_none_no_reason(self, fake_caches):
        from claude_monitoring.attack_surface.cves.dispatcher import CVEDispatcher

        client = MagicMock()
        dispatcher = CVEDispatcher(client=client)
        assets = [
            _PackageAsset("a", "homebrew-ai-tools", "ollama", "1.0", "homebrew"),
            _PackageAsset("b", "vscode-extensions", "ms-python.python", "1.0", "vscode"),
        ]
        out = dispatcher.scan(assets)
        assert out["a"].cves is None and out["a"].reason is None
        assert out["b"].cves is None and out["b"].reason is None
        client.querybatch.assert_not_called()


class TestCVEDispatcherPerItemIsolation:
    """A failed vuln_detail call for one ID MUST NOT poison other assets'
    results."""

    def test_one_vuln_detail_error_isolates_to_its_asset(self, fake_caches):
        from claude_monitoring.attack_surface.cves.client import OSVNetworkError
        from claude_monitoring.attack_surface.cves.dispatcher import CVEDispatcher

        client = MagicMock()
        # Two distinct queries → two distinct vuln IDs
        client.querybatch.return_value = [["GHSA-bad"], ["GHSA-good"]]

        def fake_detail(vuln_id):
            if vuln_id == "GHSA-bad":
                raise OSVNetworkError("simulated")
            return {
                "id": vuln_id,
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            }

        client.vuln_detail.side_effect = fake_detail
        dispatcher = CVEDispatcher(client=client)
        assets = [
            _PackageAsset("a", "python-packages", "bad-pkg", "1.0", "PyPI"),
            _PackageAsset("b", "python-packages", "good-pkg", "1.0", "PyPI"),
        ]
        out = dispatcher.scan(assets)
        # asset 'a' partial-failed (the only vuln couldn't be fetched)
        assert out["a"].cves == [] or out["a"].cves is None
        # asset 'b' succeeded
        assert out["b"].cves is not None and len(out["b"].cves) == 1


class TestCVEDispatcherBudgetCap:
    """Per-scan vuln-detail budget caps how many `/v1/vulns/{id}` calls
    we make. Beyond the cap, remaining vulns get reason=BUDGET_EXHAUSTED."""

    def test_budget_caps_detail_fetches(self, fake_caches, monkeypatch):
        from claude_monitoring.attack_surface.cves import config
        from claude_monitoring.attack_surface.cves.dispatcher import CVEDispatcher
        from claude_monitoring.attack_surface.cves.types import UnavailableReason

        # Patch the budget down so the test stays fast.
        monkeypatch.setattr(config, "VULN_DETAIL_CALLS_PER_SCAN_BUDGET", 2)
        client = MagicMock()
        # 4 assets each with 1 unique vuln → 4 detail calls would be needed;
        # budget=2 caps it.
        client.querybatch.return_value = [["GHSA-1"], ["GHSA-2"], ["GHSA-3"], ["GHSA-4"]]
        client.vuln_detail.return_value = {
            "id": "X",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }
        dispatcher = CVEDispatcher(client=client)
        assets = [_PackageAsset(f"a{i}", "python-packages", f"p{i}", "1.0", "PyPI") for i in range(4)]
        out = dispatcher.scan(assets)
        # First 2 assets get their vuln-detail; remaining 2 get BUDGET_EXHAUSTED.
        budget_exhausted = sum(1 for r in out.values() if r.reason == UnavailableReason.BUDGET_EXHAUSTED)
        assert budget_exhausted == 2
        assert client.vuln_detail.call_count == 2
