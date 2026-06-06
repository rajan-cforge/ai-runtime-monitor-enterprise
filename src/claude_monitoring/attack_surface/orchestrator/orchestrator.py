"""`DiscoveryOrchestrator` — coordinates scans across registered sources.

Per the v0.2.2 P1.3 architect-pass + Rajan's 2026-06-05 ratifications:

- Concurrency: `ThreadPoolExecutor(max_workers=min(8, len(sources)))`
- Wall-clock ceiling: `MAX_TOTAL_SCAN_SEC = 300` ("stop waiting for
  stragglers and mark them TIMEOUT" — Python cannot kill running threads)
- Per-source: invokes ``run_with_safety()`` (NEVER ``discover()`` directly)
- Failure isolation: one source's crash does not affect another; the
  `last_run_outcome` extension distinguishes clean-zero from crash
- Cross-source assets: **concatenate, do not de-dupe** (UPSERT at
  persistence resolves identity collisions as deterministic
  last-write-wins; cross-source MERGE semantics deferred to Phase 2
  ontology)
- Trigger vocabulary: `"scheduled"` / `"on_demand"` / `"cli"` — `cli`
  is required for the CLI-dump milestone
- Orchestrator-internal exceptions: PROPAGATE out of `scan()`; the
  `ScanLock` is released in a `finally`
- Audit: calls the observable `audit.*` stubs (Option β); P1.5 fills
  the bodies
"""

from __future__ import annotations

import concurrent.futures
import logging
import sqlite3
import time
from dataclasses import dataclass, field

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import (
    DiscoverySource,
    LastRunOutcome,
)
from claude_monitoring.attack_surface.orchestrator import audit
from claude_monitoring.attack_surface.orchestrator.lock import VALID_TRIGGERS, ScanLock

logger = logging.getLogger("ai-runtime-monitor.attack_surface.orchestrator")


# ---------------------------------------------------------------------------
# Result value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PerSourceTelemetry:
    """Per-source telemetry recorded in a ScanResult.

    `last_run_outcome` is the source's outcome state after
    `run_with_safety` resolved. The audit layer (P1.5) reads
    ``last_run_outcome.value`` for the `failure_kind` JSON field.
    """

    name: str
    asset_count: int
    elapsed_sec: float
    last_run_outcome: LastRunOutcome


@dataclass(frozen=True)
class ScanResult:
    """Return value of `DiscoveryOrchestrator.scan()`."""

    assets: list[Asset]
    per_source: tuple[PerSourceTelemetry, ...]
    started_at: float
    completed_at: float
    trigger: str
    lock_acquired: bool
    total_duration_sec: float = field(default=0.0)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class DiscoveryOrchestrator:
    """Coordinates scans across registered DiscoverySource subclasses.

    Args:
        sources: Iterable of DiscoverySource instances. May be empty
            (orchestrator still works; returns an empty ScanResult).
        lock: Optional `ScanLock` instance. Default constructs one
            at the standard location.
        persistence_connection: Optional sqlite3.Connection for asset
            UPSERTs and audit calls. When None, persistence is skipped
            (useful for the CLI-dump milestone where you just want
            the asset list).
    """

    MAX_TOTAL_SCAN_SEC: float = 300.0
    """Orchestrator-level wall-clock ceiling. **Mark-not-cancel:** Python
    cannot kill a running thread, so when this ceiling is hit the
    orchestrator stops waiting for stragglers and marks their telemetry
    `TIMEOUT`. The leaked workers keep running until they return on their
    own. Per-source timeouts (`DEFAULT_TIMEOUT_SEC`) are the primary
    bound; this is a defense-in-depth ceiling."""

    MAX_WORKER_CAP: int = 8

    def __init__(
        self,
        sources: list[DiscoverySource] | None = None,
        lock: ScanLock | None = None,
        persistence_connection: sqlite3.Connection | None = None,
    ) -> None:
        self.sources = list(sources) if sources is not None else []
        self.lock = lock if lock is not None else ScanLock()
        self.conn = persistence_connection

    def scan(self, *, trigger: str) -> ScanResult:
        """Run all registered sources once and return a `ScanResult`.

        Args:
            trigger: One of `"scheduled"` / `"on_demand"` / `"cli"`
                (keyword-only). Invalid values raise `ValueError`.

        Returns:
            `ScanResult` with concatenated assets across all sources +
            per-source telemetry.

        Raises:
            ValueError: on bad trigger.
            Exception: any orchestrator-internal exception (persistence,
                lock failure) propagates. Per-source `discover()`
                exceptions are absorbed by `run_with_safety` to `[]`
                and surfaced via `PerSourceTelemetry.last_run_outcome`.
        """
        if trigger not in VALID_TRIGGERS:
            raise ValueError(
                f"DiscoveryOrchestrator.scan: trigger must be one of {sorted(VALID_TRIGGERS)}, got {trigger!r}"
            )

        started_at = time.time()
        lock_acquired = self.lock.acquire(trigger)
        if not lock_acquired:
            logger.warning("scan: lock held by another invocation; returning empty result")
            return ScanResult(
                assets=[],
                per_source=(),
                started_at=started_at,
                completed_at=time.time(),
                trigger=trigger,
                lock_acquired=False,
                total_duration_sec=0.0,
            )

        run_id: int = 0
        try:
            if self.conn is not None:
                run_id = audit.record_run_started(self.conn, trigger=trigger, source_count=len(self.sources))

            assets, per_source = self._run_sources()

            if self.conn is not None:
                self._persist_assets(assets, scan_time=started_at)
                audit.record_run_finished(
                    self.conn,
                    run_id,
                    assets_discovered=len(assets),
                    per_source=per_source,
                )

            completed_at = time.time()
            return ScanResult(
                assets=assets,
                per_source=per_source,
                started_at=started_at,
                completed_at=completed_at,
                trigger=trigger,
                lock_acquired=True,
                total_duration_sec=completed_at - started_at,
            )
        except Exception as exc:
            if self.conn is not None:
                # NOTE: P1.5 stubs may return 0 for run_id; we still call
                # the crash hook because the observable-stub DEBUG line
                # is the entire point of Option β. P1.5 will gate on a
                # truthy run_id once the real INSERT lands.
                audit.record_run_crashed(
                    self.conn,
                    run_id,
                    exception_type=type(exc).__name__,
                    exception_message=str(exc),
                )
            raise
        finally:
            self.lock.release()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_sources(self) -> tuple[list[Asset], tuple[PerSourceTelemetry, ...]]:
        """Execute all sources concurrently; collect assets + telemetry.

        **Mark-not-cancel:** Python cannot kill a running thread. When
        the orchestrator's wall-clock budget (``MAX_TOTAL_SCAN_SEC``)
        elapses, ``concurrent.futures.as_completed(timeout=remaining)``
        raises ``TimeoutError`` and we stop waiting; in-flight worker
        threads keep running until their ``discover()`` returns. Their
        telemetry is marked ``LastRunOutcome.TIMEOUT``.
        """
        if not self.sources:
            return [], ()

        worker_count = min(self.MAX_WORKER_CAP, len(self.sources))
        deadline = time.time() + self.MAX_TOTAL_SCAN_SEC
        assets: list[Asset] = []
        telemetry: list[PerSourceTelemetry] = []

        # Manual lifecycle (NOT the context-manager form) — the
        # context-manager's __exit__ calls shutdown(wait=True), which
        # would block on leaked workers when the wall-clock budget fires.
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=worker_count)
        future_to_source: dict[concurrent.futures.Future, tuple[DiscoverySource, float]] = {}
        try:
            for src in self.sources:
                future_to_source[pool.submit(src.run_with_safety)] = (src, time.time())

            try:
                for future in concurrent.futures.as_completed(
                    future_to_source, timeout=max(0.001, deadline - time.time())
                ):
                    src, started = future_to_source[future]
                    src_assets = future.result()
                    elapsed = time.time() - started
                    outcome = src.last_run_outcome()
                    if outcome == LastRunOutcome.SUCCESS or outcome == LastRunOutcome.CAPPED:
                        assets.extend(src_assets)
                        self._log_source_result(src, outcome, len(src_assets))
                    else:
                        self._log_source_result(src, outcome, 0)
                    telemetry.append(
                        PerSourceTelemetry(
                            name=src.name(),
                            asset_count=len(src_assets),
                            elapsed_sec=elapsed,
                            last_run_outcome=outcome,
                        )
                    )
            except concurrent.futures.TimeoutError:
                # Wall-clock budget exceeded. Mark every unfinished
                # source TIMEOUT; abandon their futures (mark-not-cancel).
                self._collect_stragglers(future_to_source, telemetry)
        finally:
            # Don't wait — leaked workers run to completion on their own;
            # the orchestrator returns control to the caller now.
            pool.shutdown(wait=False, cancel_futures=True)

        return assets, tuple(telemetry)

    def _collect_stragglers(
        self,
        future_to_source: dict[concurrent.futures.Future, tuple[DiscoverySource, float]],
        telemetry: list[PerSourceTelemetry],
        skip_future: concurrent.futures.Future | None = None,
    ) -> None:
        """Mark unfinished sources TIMEOUT when the orchestrator wall-clock
        ceiling fires. **Mark-not-cancel:** the in-flight thread keeps
        running; the orchestrator simply stops waiting."""
        recorded_names = {t.name for t in telemetry}
        for future, (src, started) in future_to_source.items():
            if future is skip_future:
                continue
            if future.done():
                continue
            if src.name() in recorded_names:
                continue
            telemetry.append(self._telemetry_for(src, started, asset_count=0, force_outcome=LastRunOutcome.TIMEOUT))
            logger.warning(
                "orchestrator wall-clock ceiling exceeded; source %s marked TIMEOUT (worker thread leaked, will run to completion)",
                src.name(),
            )

    def _telemetry_for(
        self,
        src: DiscoverySource,
        started: float,
        *,
        asset_count: int,
        force_outcome: LastRunOutcome,
    ) -> PerSourceTelemetry:
        return PerSourceTelemetry(
            name=src.name(),
            asset_count=asset_count,
            elapsed_sec=time.time() - started,
            last_run_outcome=force_outcome,
        )

    def _log_source_result(self, src: DiscoverySource, outcome: LastRunOutcome, count: int) -> None:
        if outcome == LastRunOutcome.SUCCESS and count == 0:
            # Clean zero is INFO, not WARNING — empty + SUCCESS = "no
            # assets on this machine," a valid result.
            logger.info("source %s produced 0 assets (SUCCESS)", src.name())
        elif outcome == LastRunOutcome.SUCCESS:
            logger.info("source %s produced %d assets (SUCCESS)", src.name(), count)
        elif outcome == LastRunOutcome.CAPPED:
            logger.warning("source %s capped at %d assets (truncated)", src.name(), count)
        elif outcome == LastRunOutcome.TIMEOUT:
            logger.warning("source %s timed out; 0 assets", src.name())
        elif outcome == LastRunOutcome.ERROR:
            logger.warning("source %s errored; 0 assets", src.name())
        # UNCALLED should not happen here — outcome is read AFTER run_with_safety resolves.

    # ------------------------------------------------------------------
    # Persistence (drift-2 disposition)
    # ------------------------------------------------------------------

    _UPSERT_SQL: str = """
INSERT INTO assets (
    id, type, parent_asset_id, name, version, install_path, source,
    first_seen, last_seen, last_scanned, current_state, is_vigil_component
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
ON CONFLICT(id) DO UPDATE SET
    type = excluded.type,
    parent_asset_id = excluded.parent_asset_id,
    name = excluded.name,
    version = excluded.version,
    install_path = excluded.install_path,
    source = excluded.source,
    last_seen = excluded.last_seen,
    last_scanned = excluded.last_scanned,
    current_state = excluded.current_state,
    is_vigil_component = excluded.is_vigil_component
;
"""

    def _persist_assets(self, assets: list[Asset], scan_time: float) -> None:
        """UPSERT assets into the `assets` table.

        Drift dispositions (P1.1 architect-pass §3):
        - **Drift 1** — `source` non-empty enforced at dataclass + here
          (defensive duplicate; raises ValueError before SQL).
        - **Drift 2** — first INSERT sets `first_seen = last_seen =
          last_scanned = scan_time`. `ON CONFLICT` preserves `first_seen`
          (column NOT in the SET clause); updates only `last_seen` /
          `last_scanned`.
        - **Drift 3** — orchestrator-owned columns (`ontology_tags`,
          `risk_score`, `risk_band`, `risk_factors`) NOT touched.
        - **Drift 4** — `is_vigil_component bool → INTEGER 0/1` adapted
          via `int(asset.is_vigil_component)`.
        """
        import json as _json

        if self.conn is None:
            return

        for asset in assets:
            if not asset.source or not asset.source.strip():
                raise ValueError(f"asset {asset.id!r}: source must be non-empty for persistence (drift 1)")
            current_state_json = _json.dumps(asset.current_state)
            self.conn.execute(
                self._UPSERT_SQL,
                (
                    asset.id,
                    asset.type,
                    asset.parent_asset_id,
                    asset.name,
                    asset.version,
                    asset.install_path,
                    asset.source,
                    scan_time,
                    scan_time,
                    scan_time,
                    current_state_json,
                    int(asset.is_vigil_component),
                ),
            )
        self.conn.commit()


# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------


def default_sources() -> list[DiscoverySource]:
    """Return a fresh list of registered EASY-tier sources for the orchestrator.

    **Factory pattern** per Rajan's 2026-06-05 source-registry ratification:
    returns a NEW list per call (no module-level mutable state — avoids
    the CLAUDE.md forbidden pattern + lets tests mutate without leaking
    state between runs).

    **P1.4-minimal registered sources** (pure C2 enumeration):

    - :class:`OllamaModelsSource` — ``ollama list`` text-row parse
    - :class:`AIToolVersionsSource` — CLI ``--version`` probes for known
      AI tools (Info.plist and npm package.json strategies deferred to
      the later C3 batch)

    C3 sources (MCP servers, Claude Code skills, OpenClaw skills, AI
    apps Info.plist) will be added in a later batch.
    """
    from claude_monitoring.attack_surface.discovery.sources.ai_tool_versions import (
        AIToolVersionsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.ollama_models import (
        OllamaModelsSource,
    )

    return [OllamaModelsSource(), AIToolVersionsSource()]


__all__ = [
    "DiscoveryOrchestrator",
    "PerSourceTelemetry",
    "ScanResult",
    "default_sources",
]
