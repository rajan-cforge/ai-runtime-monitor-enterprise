"""P4.5 CVE-poll scheduler tests — Phase B (TDD).

Phase A judge p4.5.a3 APPROVE. D-cve: separate cve_poll thread per spec
§8.3 ("Separate from asset discovery. Runs daily."). Carry-forward:
poll failure leaves cache untouched (authoritative staleness renderer is
the merged cve_status_hints).
"""

from __future__ import annotations

import pytest


class TestCvePollOnceSkipsNonPackageSources:
    """Assets whose `source` doesn't map to an OSV ecosystem are skipped."""

    def test_ollama_source_yields_zero_refreshed(self, tmp_path, monkeypatch):
        from claude_monitoring.cve_poll_scheduler import cve_poll_once
        from claude_monitoring.db import init_db

        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "test.db")
        conn = init_db(tmp_path / "test.db")
        # ollama-models has no _SOURCE_TO_ECOSYSTEM entry → skipped.
        conn.execute(
            "INSERT INTO assets (id, type, name, source, version, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("ollama-1", "ai_tool", "llama3", "ollama-models", "0.5.0", 0, 0, 0, "{}"),
        )
        conn.commit()
        conn.close()
        refreshed = cve_poll_once()
        assert refreshed == 0


class TestCvePollOnceWalksPyPI:
    """python-packages → PyPI ecosystem. Mock OSVClient.querybatch to
    verify the call shape and the cache write-through."""

    def test_pypi_assets_produce_querybatch_call(self, tmp_path, monkeypatch):
        from claude_monitoring.cve_poll_scheduler import cve_poll_once
        from claude_monitoring.db import init_db

        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "test.db")
        # Point cache to tmp_path so production cache file isn't touched.
        cache_path = tmp_path / "cache.json"
        monkeypatch.setattr(
            "claude_monitoring.attack_surface.cves.config.get_querybatch_cache_path",
            lambda: cache_path,
        )
        conn = init_db(tmp_path / "test.db")
        conn.execute(
            "INSERT INTO assets (id, type, name, source, version, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("req-1", "ai_tool", "requests", "python-packages", "2.18.0", 0, 0, 0, "{}"),
        )
        conn.commit()
        conn.close()

        captured_queries = []

        class _MockClient:
            def __init__(self, *args, **kwargs):
                pass

            def querybatch(self, queries):
                captured_queries.extend(queries)
                # One vuln per query (matching the request shape).
                return [[f"GHSA-{i}"] for i, _ in enumerate(queries)]

        monkeypatch.setattr("claude_monitoring.attack_surface.cves.client.OSVClient", _MockClient)
        refreshed = cve_poll_once()
        assert refreshed == 1
        assert len(captured_queries) == 1
        assert captured_queries[0]["package"]["name"] == "requests"
        assert captured_queries[0]["package"]["ecosystem"] == "PyPI"
        assert captured_queries[0]["version"] == "2.18.0"


class TestCvePollFailureNeverTouchesCache:
    """Judge p4.5.a3 carry-forward: on poll failure, the cache file must
    NOT be created/modified. The authoritative staleness renderer is the
    merged cve_status_hints (off assets.last_scanned), and the cache is
    allowed to age — but never get a fresh timestamp on a failed poll.
    """

    def test_querybatch_exception_leaves_cache_file_absent(self, tmp_path, monkeypatch):
        from claude_monitoring.cve_poll_scheduler import cve_poll_once
        from claude_monitoring.db import init_db

        monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: tmp_path / "test.db")
        cache_path = tmp_path / "cache.json"
        monkeypatch.setattr(
            "claude_monitoring.attack_surface.cves.config.get_querybatch_cache_path",
            lambda: cache_path,
        )
        conn = init_db(tmp_path / "test.db")
        conn.execute(
            "INSERT INTO assets (id, type, name, source, version, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("req-1", "ai_tool", "requests", "python-packages", "2.18.0", 0, 0, 0, "{}"),
        )
        conn.commit()
        conn.close()

        class _FailingClient:
            def __init__(self, *args, **kwargs):
                pass

            def querybatch(self, queries):
                raise RuntimeError("simulated OSV.dev outage")

        monkeypatch.setattr("claude_monitoring.attack_surface.cves.client.OSVClient", _FailingClient)
        with pytest.raises(RuntimeError):
            cve_poll_once()
        # Cache file must NOT exist after a failed batch — never stamp
        # a fresh timestamp on a failed poll.
        assert not cache_path.exists()


class TestCvePollObservableCounters:
    def test_get_poll_count_is_readable(self):
        from claude_monitoring.cve_poll_scheduler import get_failure_count, get_poll_count

        # Just verify the readers exist + return non-negative ints.
        assert get_poll_count() >= 0
        assert get_failure_count() >= 0
