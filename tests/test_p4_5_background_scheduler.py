"""P4.5 background-scheduler concurrency tests — Phase B (TDD).

Phase A judge p4.5.a3 APPROVE. D-conc: scheduler gates solely on
``ScanLock.acquire(trigger="scheduled")``; on failure reads
``ScanLock.read_holder_trigger()`` and emits the verbatim §8.6 / L585
log line when the holder is on-demand/cli; ScanLock's ``_is_stale``
self-heals a crashed holder after 600s.

The judge-mandated regression: a stale ``discovery_runs`` row with
``completed_at = NULL`` (simulating a crashed ``vigil --discover``)
must NOT cause the scheduler to defer. The scheduler must RUN.
"""

from __future__ import annotations

import logging
import time

from claude_monitoring.attack_surface.orchestrator import ScanLock


class TestScanLockHolderTriggerReader:
    """D-conc carry-forward: lock.py exposes a public reader of the
    holder trigger. Used by the scheduler to differentiate the §8.6
    log line from the generic 'lock contention' case."""

    def test_returns_trigger_when_lock_exists_with_payload(self, tmp_path):
        lock = ScanLock(lock_path=tmp_path / ".lock")
        assert lock.acquire(trigger="on_demand") is True
        try:
            # A SEPARATE ScanLock instance pointing to the same file
            # reads the holder trigger — that's the scheduler use-case.
            reader = ScanLock(lock_path=tmp_path / ".lock")
            assert reader.read_holder_trigger() == "on_demand"
        finally:
            lock.release()

    def test_returns_none_when_no_lock_file(self, tmp_path):
        lock = ScanLock(lock_path=tmp_path / ".missing.lock")
        assert lock.read_holder_trigger() is None

    def test_returns_none_when_lock_file_corrupt(self, tmp_path):
        path = tmp_path / "bad.lock"
        path.write_text("not json {{{")
        lock = ScanLock(lock_path=path)
        assert lock.read_holder_trigger() is None


class TestSchedulerDeferralLog:
    """Defer-iff-on-demand-in-progress contract per spec §8.6 / L585.
    The log message must be verbatim per judge p4.5.a3."""

    def test_deferral_log_verbatim_for_on_demand_holder(self, caplog):
        from claude_monitoring.discovery_scheduler import _emit_deferral_log

        logger = logging.getLogger("ai-runtime-monitor.test")
        with caplog.at_level(logging.INFO, logger="ai-runtime-monitor.test"):
            _emit_deferral_log("on_demand", logger)
        # Verbatim string per directive line 585
        # (`v022-implementation-directive-v1-LOCKED.md`).
        assert any(
            "Scheduled scan deferred — on-demand scan in progress" in record.message for record in caplog.records
        )

    def test_deferral_log_verbatim_for_cli_holder(self, caplog):
        from claude_monitoring.discovery_scheduler import _emit_deferral_log

        logger = logging.getLogger("ai-runtime-monitor.test")
        with caplog.at_level(logging.INFO, logger="ai-runtime-monitor.test"):
            _emit_deferral_log("cli", logger)
        assert any(
            "Scheduled scan deferred — on-demand scan in progress" in record.message for record in caplog.records
        )

    def test_deferral_log_warning_when_another_scheduler_holds(self, caplog):
        from claude_monitoring.discovery_scheduler import _emit_deferral_log

        logger = logging.getLogger("ai-runtime-monitor.test")
        with caplog.at_level(logging.WARNING, logger="ai-runtime-monitor.test"):
            _emit_deferral_log("scheduled", logger)
        # WARNING (surprising case), NOT INFO with the §8.6 message.
        assert any(record.levelno == logging.WARNING for record in caplog.records)
        assert not any(
            "Scheduled scan deferred — on-demand scan in progress" in record.message for record in caplog.records
        )

    def test_deferral_increments_counter(self):
        # Read-only counter — verify monotonic increase.
        from claude_monitoring.discovery_scheduler import _emit_deferral_log, get_deferral_count

        before = get_deferral_count()
        logger = logging.getLogger("ai-runtime-monitor.test")
        _emit_deferral_log("on_demand", logger)
        assert get_deferral_count() == before + 1


class TestSchedulerSurvivesStaleNullDiscoveryRow:
    """Judge p4.5.a3 mandatory regression test (a2 finding).

    Reproduction: a crashed ``vigil --discover`` process leaves a
    ``discovery_runs`` row with ``trigger='cli', completed_at=NULL``.
    The original a2 pre-check would silently skip every scheduled cycle
    forever (until daemon restart sweeps it). The a3 fix drops the DB
    pre-check; ScanLock's stale-self-heal is the sole gate.

    This test asserts: a stale NULL ``discovery_runs`` row does NOT
    cause the scheduler to defer. The scheduler RUNS.
    """

    def test_stale_null_cli_row_does_not_block_scheduled_scan(self, tmp_path, monkeypatch):
        from claude_monitoring.attack_surface.orchestrator import (
            DiscoveryOrchestrator,
            ScanLock,
        )
        from claude_monitoring.db import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        # Simulate a crashed --discover: trigger='cli', completed_at=NULL,
        # started_at = 1h ago.
        crashed_started = time.time() - 3600
        conn.execute(
            "INSERT INTO discovery_runs (started_at, trigger, completed_at, errors) VALUES (?, ?, NULL, '{}')",
            (crashed_started, "cli"),
        )
        conn.commit()

        # NO lock file → ScanLock.acquire("scheduled") will succeed.
        # This is exactly the point: the scheduler gates on ScanLock
        # alone, NOT on the stale discovery_runs row.
        lock = ScanLock(lock_path=tmp_path / ".lock")
        orchestrator = DiscoveryOrchestrator(
            sources=[],
            lock=lock,
            persistence_connection=conn,
        )
        result = orchestrator.scan(trigger="scheduled")
        # Critical assertion: the scheduler RAN. lock_acquired must be True.
        assert result.lock_acquired is True, (
            "Scheduler must RUN with a stale NULL discovery_runs row present — "
            "the a2 inversion would have it defer instead."
        )
        conn.close()


class TestSchedulerDefersToRealInProgressOnDemand:
    """Positive path: a genuinely-running on-demand scan holds the
    ScanLock; the scheduler defers + emits the §8.6 log line."""

    def test_scheduler_defers_when_real_on_demand_holds_lock(self, tmp_path):
        from claude_monitoring.attack_surface.orchestrator import (
            DiscoveryOrchestrator,
            ScanLock,
        )
        from claude_monitoring.db import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        on_demand_lock = ScanLock(lock_path=tmp_path / ".lock")
        assert on_demand_lock.acquire(trigger="on_demand") is True
        try:
            # Now the scheduler attempts its scan. ScanLock is held by
            # the on-demand caller → acquire fails → orchestrator returns
            # lock_acquired=False.
            scheduled_lock = ScanLock(lock_path=tmp_path / ".lock")
            orchestrator = DiscoveryOrchestrator(
                sources=[],
                lock=scheduled_lock,
                persistence_connection=conn,
            )
            result = orchestrator.scan(trigger="scheduled")
            assert result.lock_acquired is False
            # And the reader-side holder trigger gives us "on_demand" so
            # the scheduler can emit the §8.6 message.
            assert scheduled_lock.read_holder_trigger() == "on_demand"
        finally:
            on_demand_lock.release()
            conn.close()
