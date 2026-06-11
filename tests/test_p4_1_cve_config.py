"""TDD red-phase tests for P4.1 CVE feed config.

Phase B test surface for `attack_surface/cves/config.py`. Pins the
env-var kill-switches + TTL + budget constants per Phase A §3, §4, §6.
"""

from __future__ import annotations


class TestKillSwitches:
    """Phase A §6: env-var kill switches; default ENABLED (different from
    reputation's default-OFF for chrome/vscode, because CVE data is
    universally useful + API is privacy-safe)."""

    def test_kill_switch_env_var_name(self):
        from claude_monitoring.attack_surface.cves import config

        assert config.VIGIL_NO_CVE_FEED_ENV == "VIGIL_NO_CVE_FEED"

    def test_no_network_env_var_name(self):
        from claude_monitoring.attack_surface.cves import config

        assert config.NO_NETWORK_ENV == "NO_NETWORK"

    def test_is_disabled_when_vigil_kill_switch_set(self, monkeypatch):
        monkeypatch.setenv("VIGIL_NO_CVE_FEED", "1")
        from claude_monitoring.attack_surface.cves import config

        assert config.cve_feed_disabled() is True

    def test_is_disabled_when_no_network_set(self, monkeypatch):
        monkeypatch.setenv("NO_NETWORK", "1")
        from claude_monitoring.attack_surface.cves import config

        assert config.cve_feed_disabled() is True

    def test_default_enabled(self, monkeypatch):
        monkeypatch.delenv("VIGIL_NO_CVE_FEED", raising=False)
        monkeypatch.delenv("NO_NETWORK", raising=False)
        from claude_monitoring.attack_surface.cves import config

        assert config.cve_feed_disabled() is False

    def test_kill_switch_truthy_values(self, monkeypatch):
        from claude_monitoring.attack_surface.cves import config

        for value in ("1", "true", "yes", "on"):
            monkeypatch.setenv("VIGIL_NO_CVE_FEED", value)
            assert config.cve_feed_disabled() is True, f"value {value!r} should disable"


class TestCacheTTLs:
    """Phase A §4 — TTLs corrected from the original wrong values
    (7d negative → 24h; symmetry between positive/negative for querybatch).
    Vuln-details near-immutable → 7d."""

    def test_querybatch_negative_ttl_24h(self):
        from claude_monitoring.attack_surface.cves import config

        assert config.QUERYBATCH_NEGATIVE_TTL_SECONDS == 24 * 3600

    def test_querybatch_positive_ttl_24h(self):
        from claude_monitoring.attack_surface.cves import config

        assert config.QUERYBATCH_POSITIVE_TTL_SECONDS == 24 * 3600

    def test_vulns_detail_ttl_7d(self):
        from claude_monitoring.attack_surface.cves import config

        assert config.VULNS_DETAIL_TTL_SECONDS == 7 * 24 * 3600


class TestPerScanBudget:
    """Phase A §3 — cap at 50 vuln-detail calls per scan (soft-fail beyond)."""

    def test_vuln_detail_budget_per_scan(self):
        from claude_monitoring.attack_surface.cves import config

        assert config.VULN_DETAIL_CALLS_PER_SCAN_BUDGET == 50


class TestAPIBase:
    """Allowlist host is `api.osv.dev` only (§1)."""

    def test_api_base_is_https_api_osv_dev(self):
        from claude_monitoring.attack_surface.cves import config

        assert config.OSV_API_BASE == "https://api.osv.dev"


class TestCachePaths:
    """Two cache files — separate TTL semantics."""

    def test_querybatch_cache_path(self, tmp_path, monkeypatch):
        from claude_monitoring.attack_surface.cves import config

        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        assert config.get_querybatch_cache_path() == tmp_path / "osv-querybatch-cache.json"

    def test_vulns_cache_path(self, tmp_path, monkeypatch):
        from claude_monitoring.attack_surface.cves import config

        monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: tmp_path)
        assert config.get_vulns_cache_path() == tmp_path / "osv-vulns-cache.json"
