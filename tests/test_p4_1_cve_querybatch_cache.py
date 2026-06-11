"""TDD red-phase tests for P4.1 querybatch cache.

Phase B test surface for `attack_surface/cves/querybatch_cache.py`.
Pins the persistence shape + TTL semantics + chmod 600 + atomic write
contract per Phase A §4 + the project pattern from
`attack_surface/reputation/cache.py`.
"""

from __future__ import annotations

import json
import os
import time


class TestQuerybatchCacheReadWrite:
    """Round-trip a (ecosystem, package, version) → vuln-ID-list entry."""

    def test_set_and_get_roundtrip(self, tmp_path):
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        cache = QuerybatchCache(tmp_path / "qb.json")
        cache.set("PyPI", "requests", "2.18.0", vuln_ids=["GHSA-x", "PYSEC-1"])
        assert cache.get("PyPI", "requests", "2.18.0") == ["GHSA-x", "PYSEC-1"]

    def test_get_missing_returns_none(self, tmp_path):
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        cache = QuerybatchCache(tmp_path / "qb.json")
        assert cache.get("PyPI", "requests", "2.18.0") is None

    def test_empty_list_is_preserved_as_no_vulns(self, tmp_path):
        """Phase A: `vuln_ids=[]` (clean package) is a CACHEABLE positive
        answer, not the same as "no entry yet"."""
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        cache = QuerybatchCache(tmp_path / "qb.json")
        cache.set("PyPI", "clean-pkg", "1.0.0", vuln_ids=[])
        assert cache.get("PyPI", "clean-pkg", "1.0.0") == []


class TestQuerybatchCacheTTL:
    """Phase A §4: positive AND negative TTL = 24h (symmetric — the
    clean→vulnerable transition is the catch case)."""

    def test_expired_entry_returns_none(self, tmp_path, monkeypatch):
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        # Freeze time, set an entry with a 1-second TTL, fast-forward past it.
        now = [1_000_000.0]
        monkeypatch.setattr(
            "claude_monitoring.attack_surface.cves.querybatch_cache.time.time",
            lambda: now[0],
        )
        cache = QuerybatchCache(tmp_path / "qb.json")
        cache.set("PyPI", "requests", "2.18.0", vuln_ids=["GHSA-x"], ttl_seconds=1)
        assert cache.get("PyPI", "requests", "2.18.0") == ["GHSA-x"]
        now[0] += 2  # 2 seconds later → expired
        assert cache.get("PyPI", "requests", "2.18.0") is None

    def test_default_ttl_is_phase_a_value(self, tmp_path, monkeypatch):
        """When the caller omits ttl_seconds, the entry gets the Phase A
        default (24h, same for positive + negative)."""
        from claude_monitoring.attack_surface.cves import config
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        now = [1_000_000.0]
        monkeypatch.setattr(
            "claude_monitoring.attack_surface.cves.querybatch_cache.time.time",
            lambda: now[0],
        )
        cache = QuerybatchCache(tmp_path / "qb.json")
        cache.set("PyPI", "requests", "2.18.0", vuln_ids=["GHSA-x"])
        # Just before 24h: still cached
        now[0] += config.QUERYBATCH_POSITIVE_TTL_SECONDS - 1
        assert cache.get("PyPI", "requests", "2.18.0") == ["GHSA-x"]
        # Just after 24h: expired
        now[0] += 2
        assert cache.get("PyPI", "requests", "2.18.0") is None


class TestQuerybatchCachePersistence:
    """Persistence + chmod 600 + atomic write (parity with reputation cache)."""

    def test_set_writes_chmod_600(self, tmp_path):
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        path = tmp_path / "qb.json"
        cache = QuerybatchCache(path)
        cache.set("PyPI", "requests", "2.18.0", vuln_ids=["GHSA-x"])
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_persistence_across_instances(self, tmp_path):
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        path = tmp_path / "qb.json"
        QuerybatchCache(path).set("PyPI", "requests", "2.18.0", vuln_ids=["GHSA-x"])
        # New instance — must read the persisted state.
        assert QuerybatchCache(path).get("PyPI", "requests", "2.18.0") == ["GHSA-x"]

    def test_corrupted_file_is_cache_miss_not_raise(self, tmp_path, caplog):
        """Per-item isolation rider: a malformed cache file MUST NOT raise.
        Log a warning + treat as cold cache (matches reputation pattern)."""
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        path = tmp_path / "qb.json"
        path.write_text("{not valid json")
        cache = QuerybatchCache(path)
        assert cache.get("PyPI", "requests", "2.18.0") is None
        # New writes still succeed.
        cache.set("PyPI", "requests", "2.18.0", vuln_ids=["GHSA-x"])
        assert cache.get("PyPI", "requests", "2.18.0") == ["GHSA-x"]

    def test_missing_file_is_cache_miss_not_raise(self, tmp_path):
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        cache = QuerybatchCache(tmp_path / "does-not-exist.json")
        assert cache.get("PyPI", "requests", "2.18.0") is None


class TestQuerybatchCacheKeying:
    """Cache key is (ecosystem, package, version) tuple. Same package
    + different ecosystem are independent entries (e.g., a `requests`
    package may exist on PyPI AND npm with different vulns)."""

    def test_different_ecosystems_are_independent(self, tmp_path):
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        cache = QuerybatchCache(tmp_path / "qb.json")
        cache.set("PyPI", "axios", "1.0.0", vuln_ids=["PYSEC-A"])
        cache.set("npm", "axios", "1.0.0", vuln_ids=["GHSA-B"])
        assert cache.get("PyPI", "axios", "1.0.0") == ["PYSEC-A"]
        assert cache.get("npm", "axios", "1.0.0") == ["GHSA-B"]

    def test_different_versions_are_independent(self, tmp_path):
        from claude_monitoring.attack_surface.cves.querybatch_cache import (
            QuerybatchCache,
        )

        cache = QuerybatchCache(tmp_path / "qb.json")
        cache.set("PyPI", "requests", "2.18.0", vuln_ids=["GHSA-old"])
        cache.set("PyPI", "requests", "2.31.0", vuln_ids=[])
        assert cache.get("PyPI", "requests", "2.18.0") == ["GHSA-old"]
        assert cache.get("PyPI", "requests", "2.31.0") == []
