"""TDD red-phase tests for P4.1 vulns cache.

Phase B test surface for `attack_surface/cves/vulns_cache.py`. Pins
the vuln-ID → full record persistence + 7-day TTL.
"""

from __future__ import annotations


class TestVulnsCacheReadWrite:
    def test_set_and_get_roundtrip(self, tmp_path):
        from claude_monitoring.attack_surface.cves.vulns_cache import VulnsCache

        cache = VulnsCache(tmp_path / "v.json")
        record = {
            "id": "GHSA-x",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/...:H"}],
        }
        cache.set("GHSA-x", record=record)
        assert cache.get("GHSA-x") == record

    def test_get_missing_returns_none(self, tmp_path):
        from claude_monitoring.attack_surface.cves.vulns_cache import VulnsCache

        cache = VulnsCache(tmp_path / "v.json")
        assert cache.get("GHSA-x") is None


class TestVulnsCacheTTL:
    """Phase A §4: vuln-detail records get 7-day TTL (near-immutable)."""

    def test_default_ttl_is_7_days(self, tmp_path, monkeypatch):
        from claude_monitoring.attack_surface.cves import config
        from claude_monitoring.attack_surface.cves.vulns_cache import VulnsCache

        now = [1_000_000.0]
        monkeypatch.setattr(
            "claude_monitoring.attack_surface.cves.vulns_cache.time.time",
            lambda: now[0],
        )
        cache = VulnsCache(tmp_path / "v.json")
        cache.set("GHSA-x", record={"id": "GHSA-x"})
        now[0] += config.VULNS_DETAIL_TTL_SECONDS - 1
        assert cache.get("GHSA-x") == {"id": "GHSA-x"}
        now[0] += 2  # past 7 days
        assert cache.get("GHSA-x") is None


class TestVulnsCachePersistence:
    def test_set_writes_chmod_600(self, tmp_path):
        from claude_monitoring.attack_surface.cves.vulns_cache import VulnsCache

        path = tmp_path / "v.json"
        cache = VulnsCache(path)
        cache.set("GHSA-x", record={"id": "GHSA-x"})
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_persistence_across_instances(self, tmp_path):
        from claude_monitoring.attack_surface.cves.vulns_cache import VulnsCache

        path = tmp_path / "v.json"
        VulnsCache(path).set("GHSA-x", record={"id": "GHSA-x", "summary": "..."})
        assert VulnsCache(path).get("GHSA-x") == {"id": "GHSA-x", "summary": "..."}

    def test_corrupted_file_is_cache_miss_not_raise(self, tmp_path):
        from claude_monitoring.attack_surface.cves.vulns_cache import VulnsCache

        path = tmp_path / "v.json"
        path.write_text("{not valid json")
        cache = VulnsCache(path)
        assert cache.get("GHSA-x") is None
        # Writes still work
        cache.set("GHSA-x", record={"id": "GHSA-x"})
        assert cache.get("GHSA-x") == {"id": "GHSA-x"}
