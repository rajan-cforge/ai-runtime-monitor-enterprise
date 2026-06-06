"""P1.3 Files 2/3/5/6/7/8 — orchestrator + concurrency + persistence + audit + registry + telemetry.

Consolidated test file covering the Phase B surface for the
`DiscoveryOrchestrator` outside the contract layer (which lives in
File 1 — `test_p1_3_last_run_outcome.py`).

Per Rajan's 2026-06-05 ratifications:
- Trigger vocabulary: `{"scheduled", "on_demand", "cli"}`
- `max_workers = min(8, len(sources))`
- `MAX_TOTAL_SCAN_SEC = 300` (mark-not-cancel)
- Concatenate, no in-memory de-dupe (UPSERT is last-write-wins; cross-source MERGE deferred to Phase 2)
- Orchestrator-internal exceptions propagate; `ScanLock` released in `finally`
- Audit: observable stubs (Option β); DEBUG log lines with literal `"P1.5 stub — no DB write yet"`
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import (
    DiscoverySource,
    LastRunOutcome,
)
from claude_monitoring.attack_surface.orchestrator import (
    DiscoveryOrchestrator,
    ScanLock,
    ScanResult,
    default_sources,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_asset(name: str, source: str = "test-source") -> Asset:
    return Asset(
        id=f"id-{name}-{source}",
        type="ai_tool",
        parent_asset_id=None,
        name=name,
        version=None,
        install_path=None,
        source=source,
        current_state={},
        discovered_at=0.0,
    )


class _HappySource(DiscoverySource):
    """Returns a fixed asset list cleanly."""

    def __init__(self, assets: list[Asset] | None = None, src_name: str = "happy") -> None:
        self._assets = assets or [_make_asset("a", "happy"), _make_asset("b", "happy")]
        self._name = src_name

    def name(self) -> str:
        return self._name

    def requires_auth(self) -> bool:
        return False

    def discover(self) -> list[Asset]:
        return list(self._assets)


class _CleanZeroSource(DiscoverySource):
    """Cleanly returns []."""

    def name(self) -> str:
        return "clean-zero"

    def requires_auth(self) -> bool:
        return False

    def discover(self) -> list[Asset]:
        return []


class _CrashingSource(DiscoverySource):
    """Raises RuntimeError in discover()."""

    def name(self) -> str:
        return "crashing"

    def requires_auth(self) -> bool:
        return False

    def discover(self) -> list[Asset]:
        raise RuntimeError("source crash")


class _TimingOutSource(DiscoverySource):
    """Sleeps longer than DEFAULT_TIMEOUT_SEC."""

    DEFAULT_TIMEOUT_SEC = 0.1

    def name(self) -> str:
        return "timing-out"

    def requires_auth(self) -> bool:
        return False

    def discover(self) -> list[Asset]:
        time.sleep(2.0)
        return []


class _ThreadIDCapturingSource(DiscoverySource):
    """Records the worker thread ID."""

    captured_tid: int = 0

    def name(self) -> str:
        return "tid-capture"

    def requires_auth(self) -> bool:
        return False

    def discover(self) -> list[Asset]:
        self.captured_tid = threading.get_ident()
        return [_make_asset("tid", "tid-capture")]


# ---------------------------------------------------------------------------
# File 2 — TestDiscoveryOrchestratorSurface (7) + TestOrchestratorFailureIsolation (4)
# ---------------------------------------------------------------------------


class TestDiscoveryOrchestratorSurface:
    def test_scan_trigger_kwarg_only(self, tmp_path: Path) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[], lock=lock)
        # Positional trigger rejected (kwarg-only)
        with pytest.raises(TypeError):
            o.scan("on_demand")  # type: ignore[misc]
        # Kwarg form works
        o.scan(trigger="on_demand")

    def test_scan_returns_scan_result(self, tmp_path: Path) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[], lock=lock)
        result = o.scan(trigger="on_demand")
        assert isinstance(result, ScanResult)
        assert result.trigger == "on_demand"
        assert result.lock_acquired is True
        assert result.total_duration_sec >= 0.0

    @pytest.mark.parametrize("trigger", ["scheduled", "on_demand", "cli"])
    def test_scan_accepts_all_three_trigger_values(self, tmp_path: Path, trigger: str) -> None:
        """Trigger vocabulary lock per ratification 2 — all three required."""
        lock = ScanLock(lock_path=tmp_path / f".lock-{trigger}")
        o = DiscoveryOrchestrator(sources=[], lock=lock)
        result = o.scan(trigger=trigger)
        assert result.trigger == trigger

    def test_scan_invalid_trigger_raises_value_error(self, tmp_path: Path) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[], lock=lock)
        with pytest.raises(ValueError, match="trigger"):
            o.scan(trigger="bogus")

    def test_scan_empty_registry_returns_empty_result(self, tmp_path: Path) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[], lock=lock)
        result = o.scan(trigger="on_demand")
        assert result.assets == []
        assert result.per_source == ()

    def test_scan_single_source_happy_path(self, tmp_path: Path) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[_HappySource()], lock=lock)
        result = o.scan(trigger="on_demand")
        assert len(result.assets) == 2
        assert len(result.per_source) == 1
        assert result.per_source[0].name == "happy"
        assert result.per_source[0].asset_count == 2
        assert result.per_source[0].last_run_outcome == LastRunOutcome.SUCCESS

    def test_scan_multiple_sources_concatenates_assets(self, tmp_path: Path) -> None:
        """Concatenate, no in-memory de-dupe. UPSERT (Phase 2 MERGE deferred)."""
        s1 = _HappySource(
            assets=[_make_asset("a", "s1"), _make_asset("b", "s1")],
            src_name="s1",
        )
        s2 = _HappySource(
            assets=[_make_asset("c", "s2"), _make_asset("d", "s2")],
            src_name="s2",
        )
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[s1, s2], lock=lock)
        result = o.scan(trigger="on_demand")
        assert len(result.assets) == 4
        assert len(result.per_source) == 2


class TestOrchestratorFailureIsolation:
    def test_one_source_failing_does_not_affect_another(self, tmp_path: Path) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(
            sources=[_HappySource(), _CrashingSource()],
            lock=lock,
        )
        result = o.scan(trigger="on_demand")
        # Happy assets present
        assert len(result.assets) == 2
        # Both sources reported
        assert len(result.per_source) == 2
        by_name = {t.name: t for t in result.per_source}
        assert by_name["happy"].last_run_outcome == LastRunOutcome.SUCCESS
        assert by_name["crashing"].last_run_outcome == LastRunOutcome.ERROR
        assert by_name["crashing"].asset_count == 0

    def test_per_source_telemetry_distinguishes_clean_zero_from_failure(self, tmp_path: Path) -> None:
        """The whole point of the last_run_outcome extension."""
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(
            sources=[_CleanZeroSource(), _TimingOutSource()],
            lock=lock,
        )
        result = o.scan(trigger="on_demand")
        by_name = {t.name: t for t in result.per_source}
        assert by_name["clean-zero"].last_run_outcome == LastRunOutcome.SUCCESS
        assert by_name["clean-zero"].asset_count == 0
        assert by_name["timing-out"].last_run_outcome == LastRunOutcome.TIMEOUT
        assert by_name["timing-out"].asset_count == 0

    def test_orchestrator_internal_exception_propagates_and_releases_lock(self, tmp_path: Path) -> None:
        """Persistence/lock errors propagate. Lock released in finally."""

        class _BadConn:
            def execute(self, *args, **kw):
                raise sqlite3.DatabaseError("write fail")

            def commit(self):
                pass

        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(
            sources=[_HappySource()],
            lock=lock,
            persistence_connection=_BadConn(),  # type: ignore[arg-type]
        )
        with pytest.raises(sqlite3.DatabaseError):
            o.scan(trigger="on_demand")
        # Lock file gone
        assert not (tmp_path / ".lock").exists()

    def test_concurrent_scan_returns_empty_when_lock_held(self, tmp_path: Path) -> None:
        """Second scan while lock is held by another invocation returns empty result, lock_acquired=False."""
        lock_path = tmp_path / ".lock"
        lock = ScanLock(lock_path=lock_path)
        # Pretend a different process holds the lock
        lock.acquire("on_demand")
        try:
            o = DiscoveryOrchestrator(sources=[_HappySource()], lock=ScanLock(lock_path=lock_path))
            result = o.scan(trigger="on_demand")
            assert result.lock_acquired is False
            assert result.assets == []
        finally:
            lock.release()


# ---------------------------------------------------------------------------
# File 3 — TestConcurrency
# ---------------------------------------------------------------------------


class TestConcurrency:
    def test_max_workers_cap_constant_locked_at_8(self) -> None:
        assert DiscoveryOrchestrator.MAX_WORKER_CAP == 8

    def test_max_total_scan_sec_constant_locked_at_300(self) -> None:
        assert DiscoveryOrchestrator.MAX_TOTAL_SCAN_SEC == 300.0

    def test_worker_thread_invokes_run_with_safety(self, tmp_path: Path) -> None:
        src = _ThreadIDCapturingSource()
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[src], lock=lock)
        o.scan(trigger="on_demand")
        assert src.captured_tid != 0
        assert src.captured_tid != threading.get_ident()

    def test_one_source_hanging_does_not_block_others(self, tmp_path: Path) -> None:
        """The timing-out source has a short DEFAULT_TIMEOUT_SEC, so it
        returns within ~0.1s. The happy source doesn't wait."""
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(
            sources=[_TimingOutSource(), _HappySource()],
            lock=lock,
        )
        t0 = time.monotonic()
        result = o.scan(trigger="on_demand")
        elapsed = time.monotonic() - t0
        # Happy assets present even though TimingOut was hanging
        assert any(a.source == "happy" for a in result.assets)
        # Total scan well under sleep(2.0)
        assert elapsed < 1.0, f"scan took {elapsed:.2f}s — should have unblocked early"

    def test_max_total_scan_sec_stops_waiting_and_marks_stragglers_timeout(self, tmp_path: Path) -> None:
        """Mark-not-cancel: Python can't kill threads. When the
        orchestrator wall-clock ceiling fires, in-flight workers are
        abandoned (they keep running) and their telemetry is marked
        TIMEOUT."""

        class _SlowButLongTimeoutSource(DiscoverySource):
            DEFAULT_TIMEOUT_SEC = 10.0  # per-source timeout much larger than orchestrator's

            def __init__(self, sleep_for: float, src_name: str) -> None:
                self._sleep = sleep_for
                self._n = src_name

            def name(self) -> str:
                return self._n

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                time.sleep(self._sleep)
                return []

        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(
            sources=[_SlowButLongTimeoutSource(2.0, "slow-1"), _SlowButLongTimeoutSource(2.0, "slow-2")],
            lock=lock,
        )
        o.MAX_TOTAL_SCAN_SEC = 0.2  # type: ignore[misc]
        t0 = time.monotonic()
        result = o.scan(trigger="on_demand")
        elapsed = time.monotonic() - t0
        # Returned well before either source's sleep(2.0)
        assert elapsed < 1.5, f"orchestrator did not stop waiting; elapsed={elapsed:.2f}s"
        # At least one source marked TIMEOUT in telemetry
        outcomes = [t.last_run_outcome for t in result.per_source]
        assert LastRunOutcome.TIMEOUT in outcomes


# ---------------------------------------------------------------------------
# File 5 — TestPersistenceUpsert (drift dispositions)
# ---------------------------------------------------------------------------


def _setup_assets_db(tmp_path: Path) -> sqlite3.Connection:
    """Apply the P0.2 migration to a fresh sqlite DB so the orchestrator
    can UPSERT against the real schema."""
    from claude_monitoring.persistence.migrations import apply_migrations

    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    apply_migrations(conn)
    return conn


class TestPersistenceUpsert:
    def test_first_insert_sets_all_three_timestamps_from_scan_time(self, tmp_path: Path) -> None:
        """Drift 2 — insert sets first_seen = last_seen = last_scanned = scan_time."""
        conn = _setup_assets_db(tmp_path)
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(
            sources=[_HappySource(assets=[_make_asset("first", "happy")], src_name="happy")],
            lock=lock,
            persistence_connection=conn,
        )
        result = o.scan(trigger="on_demand")
        rows = list(conn.execute("SELECT id, first_seen, last_seen, last_scanned FROM assets"))
        assert len(rows) == 1
        _id, first_seen, last_seen, last_scanned = rows[0]
        assert first_seen == last_seen == last_scanned == result.started_at

    def test_reobservation_preserves_first_seen_updates_last_seen(self, tmp_path: Path) -> None:
        """Drift 2 — `ON CONFLICT` preserves first_seen; updates last_seen + last_scanned."""
        conn = _setup_assets_db(tmp_path)
        lock_path = tmp_path / ".lock"
        src = _HappySource(assets=[_make_asset("re-obs", "happy")], src_name="happy")
        # First scan
        o1 = DiscoveryOrchestrator(sources=[src], lock=ScanLock(lock_path=lock_path), persistence_connection=conn)
        r1 = o1.scan(trigger="on_demand")
        time.sleep(0.05)
        # Second scan — same asset
        o2 = DiscoveryOrchestrator(sources=[src], lock=ScanLock(lock_path=lock_path), persistence_connection=conn)
        r2 = o2.scan(trigger="on_demand")
        assert r2.started_at > r1.started_at  # sanity
        rows = list(conn.execute("SELECT first_seen, last_seen FROM assets"))
        first_seen, last_seen = rows[0]
        assert first_seen == r1.started_at, "drift 2: first_seen MUST be preserved by ON CONFLICT"
        assert last_seen == r2.started_at, "drift 2: last_seen MUST be updated on re-observation"

    def test_is_vigil_component_bool_to_integer_adapter(self, tmp_path: Path) -> None:
        """Drift 4 — bool ↔ INTEGER 0/1."""
        conn = _setup_assets_db(tmp_path)
        a = Asset(
            id="vigil-1",
            type="ai_tool",
            parent_asset_id=None,
            name="Vigil",
            version=None,
            install_path=None,
            source="happy",
            current_state={},
            discovered_at=0.0,
            is_vigil_component=True,
        )
        o = DiscoveryOrchestrator(
            sources=[_HappySource(assets=[a], src_name="happy")],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        o.scan(trigger="on_demand")
        rows = list(conn.execute("SELECT is_vigil_component FROM assets"))
        assert rows[0][0] == 1

    def test_current_state_json_round_trip(self, tmp_path: Path) -> None:
        """current_state TEXT stores json.dumps(dict); read back via json.loads."""
        import json as _json

        conn = _setup_assets_db(tmp_path)
        state = {"permissions": ["read", "write"], "nested": {"x": 1, "y": None}}
        a = Asset(
            id="state-1",
            type="ai_tool",
            parent_asset_id=None,
            name="X",
            version=None,
            install_path=None,
            source="happy",
            current_state=state,
            discovered_at=0.0,
        )
        o = DiscoveryOrchestrator(
            sources=[_HappySource(assets=[a], src_name="happy")],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        o.scan(trigger="on_demand")
        rows = list(conn.execute("SELECT current_state FROM assets"))
        assert _json.loads(rows[0][0]) == state

    def test_empty_source_string_rejected_at_persistence(self, tmp_path: Path) -> None:
        """Drift 1 — `source` non-empty enforced at persistence boundary
        (defensive dual-layer with dataclass `__post_init__`)."""
        conn = _setup_assets_db(tmp_path)
        # Create an asset bypassing __post_init__ via direct __dict__ surgery
        # — simulates corruption arriving at persistence (worst case).
        a = _make_asset("bad", "happy")
        object.__setattr__(a, "source", "")  # break the contract artificially
        o = DiscoveryOrchestrator(
            sources=[_HappySource(assets=[a], src_name="happy")],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        with pytest.raises(ValueError, match="source"):
            o.scan(trigger="on_demand")

    def test_orchestrator_does_not_write_phase2_owned_columns(self, tmp_path: Path) -> None:
        """Drift 3 — ontology_tags / risk_score / risk_band / risk_factors
        NOT touched by the orchestrator's UPSERT (Phase 2 owns them)."""
        conn = _setup_assets_db(tmp_path)
        o = DiscoveryOrchestrator(
            sources=[_HappySource()],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        o.scan(trigger="on_demand")
        rows = list(conn.execute("SELECT ontology_tags, risk_score, risk_band, risk_factors FROM assets"))
        for row in rows:
            assert all(v is None for v in row)

    def test_parameterized_sql_via_qmark_placeholders(self, tmp_path: Path) -> None:
        """CLAUDE.md mandatory: parameterized SQL. Asset with quote chars
        in `name` round-trips intact (string-concat would either fail or
        corrupt)."""
        conn = _setup_assets_db(tmp_path)
        a = _make_asset("'; DROP TABLE assets; --", "happy")
        o = DiscoveryOrchestrator(
            sources=[_HappySource(assets=[a], src_name="happy")],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        o.scan(trigger="on_demand")
        rows = list(conn.execute("SELECT name FROM assets"))
        assert rows[0][0] == "'; DROP TABLE assets; --"
        # Table still exists (the SQL injection didn't fire)
        list(conn.execute("SELECT COUNT(*) FROM assets"))


# ---------------------------------------------------------------------------
# File 6 — TestAuditStubObservability (Option β observable refinement)
# ---------------------------------------------------------------------------


class TestTelemetrySeededWithAllRegisteredSources:
    """#155 fix (Rajan 2026-06-05): every registered source appears in
    `per_source` even if its future never resolved (cancelled by the
    wall-clock budget) — seeded UNCALLED up front, updated in place."""

    def test_telemetry_size_matches_registered_source_count(self, tmp_path: Path) -> None:
        """3 registered sources → exactly 3 PerSourceTelemetry entries,
        in source-registration order, regardless of completion order."""
        s1 = _HappySource(src_name="s1")
        s2 = _CleanZeroSource()  # name = "clean-zero"
        s3 = _HappySource(src_name="s3")
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[s1, s2, s3], lock=lock)
        result = o.scan(trigger="on_demand")
        assert len(result.per_source) == 3
        # Order preserved by source-registration order
        assert [t.name for t in result.per_source] == ["s1", "clean-zero", "s3"]

    def test_straggler_source_appears_as_timeout_not_missing(self, tmp_path: Path) -> None:
        """When wall-clock budget fires with stragglers still running,
        the straggler appears in telemetry as TIMEOUT (NOT silently absent)."""

        class _SlowSource(DiscoverySource):
            DEFAULT_TIMEOUT_SEC = 10.0  # well above orchestrator budget

            def __init__(self, name: str) -> None:
                self._n = name

            def name(self) -> str:
                return self._n

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                time.sleep(2.0)
                return []

        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(
            sources=[_SlowSource("slow-1"), _SlowSource("slow-2")],
            lock=lock,
        )
        o.MAX_TOTAL_SCAN_SEC = 0.2  # type: ignore[misc]
        result = o.scan(trigger="on_demand")
        # Both sources MUST appear, both marked TIMEOUT
        assert len(result.per_source) == 2
        outcomes = {t.name: t.last_run_outcome for t in result.per_source}
        assert outcomes == {"slow-1": LastRunOutcome.TIMEOUT, "slow-2": LastRunOutcome.TIMEOUT}


class TestPersistAssetsAtomicTransaction:
    """#156 fix (Rajan 2026-06-05): `_persist_assets` wraps its UPSERT
    loop in `with self.conn:` so a mid-loop failure ROLLS BACK in-flight
    inserts rather than leaving the connection mid-transaction for the
    caller to clean up."""

    def test_mid_loop_failure_rolls_back_prior_inserts(self, tmp_path: Path) -> None:
        """If the 2nd asset's UPSERT raises mid-loop, the 1st asset's
        UPSERT (which succeeded) is rolled back atomically."""
        from claude_monitoring.persistence.migrations import apply_migrations

        db_path = tmp_path / "atomic.db"
        conn = sqlite3.connect(str(db_path))
        apply_migrations(conn)

        a_good = _make_asset("good-1", "happy")
        a_bad = _make_asset("bad-2", "happy")
        # Corrupt a_bad's source to trigger the drift-1 ValueError mid-loop
        object.__setattr__(a_bad, "source", "")

        source = _HappySource(assets=[a_good, a_bad], src_name="happy")
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[source], lock=lock, persistence_connection=conn)

        with pytest.raises(ValueError, match="source"):
            o.scan(trigger="on_demand")

        # a_good's UPSERT was rolled back — assets table is empty
        rows = list(conn.execute("SELECT COUNT(*) FROM assets"))
        assert rows[0][0] == 0, "transaction did not roll back — a_good leaked into assets table"


class TestAuditIntegration:
    """Post-P1.5 integration — the orchestrator's audit calls now write
    real `discovery_runs` rows (Option β stubs filled in P1.5).

    The transitional "stub DEBUG phrase emitted" tests were retired
    when P1.5 landed; `tests/test_p1_5_discovery_runs_audit.py` now
    pins the write path directly + the `TestStubPhraseAbsent` group
    pins that the stub phrase is GONE from production code paths."""

    def test_orchestrator_scan_writes_discovery_runs_row(self, tmp_path: Path) -> None:
        """Happy-path scan with a real connection writes one row with
        completed_at populated."""
        conn = _setup_assets_db(tmp_path)
        o = DiscoveryOrchestrator(
            sources=[_HappySource()],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=conn,
        )
        o.scan(trigger="on_demand")
        rows = list(conn.execute("SELECT trigger, completed_at, assets_discovered FROM discovery_runs"))
        assert len(rows) == 1
        assert rows[0][0] == "on_demand"
        assert rows[0][1] is not None
        assert rows[0][2] == 2  # _HappySource emits 2 assets

    def test_orchestrator_scan_on_failure_marks_run_crashed(self, tmp_path: Path) -> None:
        """Orchestrator-internal failure → row updated with crashed status."""
        conn = _setup_assets_db(tmp_path)

        # Inject a persistence-time failure by passing a wrapper that blows up
        class _BadOnUpsert:
            def __init__(self, real):
                self.real = real
                self.upsert_count = 0

            def execute(self, *args, **kwargs):
                # Allow audit INSERTs but fail on the assets UPSERT
                if args and "INSERT INTO assets" in args[0]:
                    raise sqlite3.DatabaseError("upsert failure")
                return self.real.execute(*args, **kwargs)

            def commit(self):
                return self.real.commit()

            def __enter__(self):
                return self.real.__enter__()

            def __exit__(self, exc_type, exc, tb):
                return self.real.__exit__(exc_type, exc, tb)

        bad_conn = _BadOnUpsert(conn)  # type: ignore[arg-type]
        o = DiscoveryOrchestrator(
            sources=[_HappySource()],
            lock=ScanLock(lock_path=tmp_path / ".lock"),
            persistence_connection=bad_conn,  # type: ignore[arg-type]
        )
        with pytest.raises(sqlite3.DatabaseError):
            o.scan(trigger="on_demand")
        # discovery_runs row has status=crashed in the errors JSON
        import json as _json

        rows = list(conn.execute("SELECT errors FROM discovery_runs"))
        assert len(rows) == 1
        assert _json.loads(rows[0][0])["status"] == "crashed"


# ---------------------------------------------------------------------------
# File 7 — TestSourceRegistry (factory, no module-level mutable state)
# ---------------------------------------------------------------------------


class TestSourceRegistry:
    def test_default_sources_returns_list(self) -> None:
        result = default_sources()
        assert isinstance(result, list)

    def test_default_sources_returns_fresh_list_per_call(self) -> None:
        """No module-level mutable state — factory returns a NEW list.
        Mutating one return value MUST NOT affect a subsequent call."""
        a = default_sources()
        original_len = len(a)
        a.append("contaminant")  # type: ignore[arg-type]
        b = default_sources()
        assert len(b) == original_len
        assert "contaminant" not in b

    def test_default_sources_registers_p1_4_minimal_sources(self) -> None:
        """P1.4-minimal adds Ollama models + AI tool versions. Empty at
        P1.3 merge time; 2 sources after P1.4-minimal merge."""
        sources = default_sources()
        names = {s.name() for s in sources}
        assert "ollama-models" in names
        assert "ai-tool-versions" in names


# ---------------------------------------------------------------------------
# File 8 — TestFailureModeTelemetryLogging
# ---------------------------------------------------------------------------


class TestFailureModeTelemetryLogging:
    def test_clean_zero_logs_info_not_warning(self, tmp_path: Path, caplog) -> None:
        """Clean zero (SUCCESS + empty) is INFO. WARNING would falsely
        signal a failure that didn't happen."""
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[_CleanZeroSource()], lock=lock)
        with caplog.at_level("INFO"):
            o.scan(trigger="on_demand")
        info_msgs = [r for r in caplog.records if "clean-zero" in r.message and "SUCCESS" in r.message]
        warn_msgs = [r for r in caplog.records if "clean-zero" in r.message and r.levelname == "WARNING"]
        assert info_msgs, "clean zero should log INFO with SUCCESS"
        assert not warn_msgs, "clean zero must NOT log WARNING"

    def test_timeout_logs_warning(self, tmp_path: Path, caplog) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[_TimingOutSource()], lock=lock)
        with caplog.at_level("WARNING"):
            o.scan(trigger="on_demand")
        assert any("timing-out" in r.message and r.levelname == "WARNING" for r in caplog.records)

    def test_error_logs_warning(self, tmp_path: Path, caplog) -> None:
        lock = ScanLock(lock_path=tmp_path / ".lock")
        o = DiscoveryOrchestrator(sources=[_CrashingSource()], lock=lock)
        with caplog.at_level("WARNING"):
            o.scan(trigger="on_demand")
        assert any("crashing" in r.message and r.levelname == "WARNING" for r in caplog.records)
