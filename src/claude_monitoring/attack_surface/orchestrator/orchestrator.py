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
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any

from claude_monitoring.attack_surface.activity import (
    correlate_asset_activity,
    expected_hosts_for_source,
)
from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.cves.dispatcher import CVEDispatcher
from claude_monitoring.attack_surface.cves.types import CVEResult
from claude_monitoring.attack_surface.discovery.base import (
    DiscoverySource,
    LastRunOutcome,
)
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.ontology.mapping import map_asset
from claude_monitoring.attack_surface.orchestrator import audit
from claude_monitoring.attack_surface.orchestrator.lock import VALID_TRIGGERS, ScanLock
from claude_monitoring.attack_surface.reputation.composition import (
    score_asset_with_rules_and_reputation,
)
from claude_monitoring.attack_surface.reputation.config import get_reputation_cache_path
from claude_monitoring.attack_surface.reputation.dispatcher import ReputationDispatcher
from claude_monitoring.attack_surface.risk.rules import (
    DEFAULT_RULES_PATH,
    load_curated_rules,
)
from claude_monitoring.attack_surface.risk.scoring import RiskScoreResult

logger = logging.getLogger("ai-runtime-monitor.attack_surface.orchestrator")


# ---------------------------------------------------------------------------
# Risk-factors JSON serialization (spec §10 v1 schema — see Rajan
# ratification 2026-06-11; Amendments C+D + the C/D riders)
# ---------------------------------------------------------------------------

RISK_FACTORS_SCHEMA_VERSION: int = 1
"""Bump when the JSON schema for `risk_factors` changes incompatibly.
v1 keys: schema_version, contributions, weights, applied_rules,
applied_reputation, cves, cve_status, cve_unavailable_reason."""


def _factors_payload(score_result: RiskScoreResult, cve_result: CVEResult | None) -> dict:
    """Serialize a `RiskScoreResult` + matching `CVEResult` into the
    `risk_factors` JSON blob persisted on the asset row.

    Tri-state `cve_status` rules — None and [] NEVER collapse:

      * ``cve_result is None`` OR ``cve_result.cves is None`` with
        ``reason is None``  →  ``cve_status="not_applicable"``,
        ``cves=null``. Non-PyPI/non-npm sources (Ollama, MCP, etc.).
      * ``cve_result.cves is None`` with ``reason is set``  →
        ``cve_status="unavailable"``,
        ``cve_unavailable_reason=reason.value``, ``cves=null``.
      * ``cve_result.cves == []``  →  ``cve_status="ok"``, ``cves=[]``.
      * ``cve_result.cves == [...]``  →  ``cve_status="ok"``,
        ``cves=[...]``.

    The ``weights`` dict is included so the P7.9 popover stays
    self-contained — operator sees the weights that produced THIS row
    even after future weight tuning (audit-trail rationale per Rajan
    D rider 2026-06-11)."""
    if cve_result is None or (cve_result.cves is None and cve_result.reason is None):
        cve_status = "not_applicable"
        cve_unavailable_reason: str | None = None
        cves_payload: list | None = None
    elif cve_result.cves is None:
        cve_status = "unavailable"
        # cve_result.reason is set here (the `is None` case is handled above).
        # mypy can't narrow that, hence the cast.
        cve_unavailable_reason = cve_result.reason.value if cve_result.reason is not None else None
        cves_payload = None
    else:
        cve_status = "ok"
        cve_unavailable_reason = None
        cves_payload = list(cve_result.cves)
    return {
        "schema_version": RISK_FACTORS_SCHEMA_VERSION,
        "contributions": dict(score_result.contributions),
        "weights": dict(score_result.weights),
        "applied_rules": list(score_result.applied_rules),
        "applied_reputation": list(score_result.applied_reputation),
        "cves": cves_payload,
        "cve_status": cve_status,
        "cve_unavailable_reason": cve_unavailable_reason,
    }


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
                # scan-scoring-callsite (2026-06-11): score assets BEFORE
                # persistence so the UPSERT writes risk_score / risk_band /
                # risk_factors / ontology_tags atomically with the asset
                # row itself. Per-item isolation lives inside _score_assets;
                # an exception there does NOT propagate.
                score_results = self._score_assets(assets)
                self._persist_assets(
                    assets,
                    scan_time=started_at,
                    score_results=score_results,
                    discovery_run_id=run_id,
                )
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

        **Seed telemetry up front** (follow-up #155 per Rajan 2026-06-05):
        every registered source is seeded with ``LastRunOutcome.UNCALLED``
        BEFORE submitting to the pool. As sources resolve, entries are
        updated in place. A source whose future is cancelled (wall-clock
        budget fires before it runs) or whose telemetry write is otherwise
        skipped STILL appears in the result as UNCALLED — the audit can
        never silently lose a source.
        """
        if not self.sources:
            return [], ()

        worker_count = min(self.MAX_WORKER_CAP, len(self.sources))
        deadline = time.time() + self.MAX_TOTAL_SCAN_SEC
        assets: list[Asset] = []

        # Seed telemetry by source name with UNCALLED up front (#155 fix).
        # Sources are then UPDATED in place by their resolved outcome.
        telemetry_by_name: dict[str, PerSourceTelemetry] = {
            src.name(): PerSourceTelemetry(
                name=src.name(),
                asset_count=0,
                elapsed_sec=0.0,
                last_run_outcome=LastRunOutcome.UNCALLED,
            )
            for src in self.sources
        }

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
                    telemetry_by_name[src.name()] = PerSourceTelemetry(
                        name=src.name(),
                        asset_count=len(src_assets),
                        elapsed_sec=elapsed,
                        last_run_outcome=outcome,
                    )
            except concurrent.futures.TimeoutError:
                # Wall-clock budget exceeded. Mark every unfinished
                # source TIMEOUT; abandon their futures (mark-not-cancel).
                self._collect_stragglers(future_to_source, telemetry_by_name)
        finally:
            # Don't wait — leaked workers run to completion on their own;
            # the orchestrator returns control to the caller now.
            pool.shutdown(wait=False, cancel_futures=True)

        # Preserve source-registration order in the returned tuple.
        ordered = tuple(telemetry_by_name[src.name()] for src in self.sources)
        return assets, ordered

    def _collect_stragglers(
        self,
        future_to_source: dict[concurrent.futures.Future, tuple[DiscoverySource, float]],
        telemetry_by_name: dict[str, PerSourceTelemetry],
        skip_future: concurrent.futures.Future | None = None,
    ) -> None:
        """Mark unfinished sources TIMEOUT when the orchestrator wall-clock
        ceiling fires. **Mark-not-cancel:** the in-flight thread keeps
        running; the orchestrator simply stops waiting.

        Updates ``telemetry_by_name`` in place (per #155 seeded-up-front
        pattern) so the source still appears in the result even though
        its worker never reported back.
        """
        for future, (src, started) in future_to_source.items():
            if future is skip_future:
                continue
            if future.done():
                continue
            # Only override UNCALLED — if the entry was already populated
            # by a resolved future, leave it alone.
            existing = telemetry_by_name.get(src.name())
            if existing is not None and existing.last_run_outcome != LastRunOutcome.UNCALLED:
                continue
            telemetry_by_name[src.name()] = PerSourceTelemetry(
                name=src.name(),
                asset_count=0,
                elapsed_sec=time.time() - started,
                last_run_outcome=LastRunOutcome.TIMEOUT,
            )
            logger.warning(
                "orchestrator wall-clock ceiling exceeded; source %s marked TIMEOUT (worker thread leaked, will run to completion)",
                src.name(),
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
    # Scoring (scan-scoring-callsite 2026-06-11)
    # ------------------------------------------------------------------

    def _score_assets(self, assets: list[Asset]) -> dict[str, tuple[RiskScoreResult, CVEResult | None]]:
        """Compose per-asset risk score from CVE feed + curated rules + reputation.

        Per architect-pass APPROVE-WITH-AMENDMENTS verdict 2026-06-11:

        - **Amendment A:** ``ReputationDispatcher`` is constructed
          FRESH per scan inside this method (NOT held on
          ``self``). Cross-scan reuse would silently zero the
          `PyPIScanBudget` after the first scan.
        - **Amendment B:** Each successful asset yields a
          ``(RiskScoreResult, CVEResult | None, frozenset[OntologyCategory])``
          tuple — the ``CVEResult`` is threaded through to
          ``_persist_assets`` so ``_factors_payload`` can serialize
          ``cve_status`` from the original tri-state; the tags are
          threaded through so persistence does NOT call ``map_asset``
          a second time (avoids the double-call divergence flagged by
          code-reviewer).
        - **Per-item isolation:** any per-asset exception (in
          ``map_asset`` or in the composition call) is caught + logged;
          the asset is omitted from the return dict and ALL four
          orchestrator-owned columns (`ontology_tags`, `risk_score`,
          `risk_band`, `risk_factors`) stay NULL on persistence —
          distinct from "scored with risk_score=0".
        """
        # Per-scan CVE dispatcher — budget counter resets every scan.
        cves_by_asset = CVEDispatcher().scan(assets)
        # Per-scan reputation dispatcher — class docstring says "One
        # instance per scan" (file-backed cache survives across instances).
        rep_dispatcher = ReputationDispatcher(cache_path=get_reputation_cache_path())
        # Rules: reload from YAML every scan so operator edits take
        # effect immediately (Phase A Q4 option (a) ratified).
        rules = load_curated_rules(DEFAULT_RULES_PATH)
        # P4.3 Q9 wiring: per-asset runtime activity correlation, fed
        # into `activity_recency` factor. Only attempts correlation for
        # assets whose source is in the expected-hosts whitelist;
        # structural-n/a sources (packages, MCP configs) skip the
        # correlator entirely. Architect-pass + code-reviewer 2026-06-12
        # caught the missing integration — without this block the
        # `_compute_activity_recency` wiring is unreachable from the
        # scheduled scan path even though scoring.py is internally
        # correct.
        runtime_activity_by_asset = self._correlate_activity(assets)
        out: dict[str, tuple[RiskScoreResult, CVEResult | None, frozenset[OntologyCategory]]] = {}
        for asset in assets:
            try:
                tags = map_asset(asset)
                cve_result = cves_by_asset.get(asset.id)
                cves = cve_result.cves if cve_result is not None else None
                runtime_activity = runtime_activity_by_asset.get(asset.id)
                score_result = score_asset_with_rules_and_reputation(
                    asset,
                    tags,
                    rules,
                    rep_dispatcher,
                    cves=cves,
                    runtime_activity=runtime_activity,
                )
                out[asset.id] = (score_result, cve_result, tags)
            except Exception as exc:
                # Architect Q11: per-item isolation. risk_score stays NULL
                # → distinguishable in the dashboard from "scored=0".
                logger.warning(
                    "score_asset failed for %s: %s — risk_score will be NULL",
                    asset.id,
                    exc,
                )
        return out

    def _correlate_activity(self, assets: list[Asset]) -> dict[str, dict | None]:
        """Per-asset runtime activity correlation for the scoring path.

        Calls `correlate_asset_activity` for assets whose source has an
        expected-hosts whitelist; returns
        `{asset.id: {"last_seen_seconds": float}}` for assets with
        observed activity, omitting structural-n/a + capture-off cases
        (scoring will see `runtime_activity=None` → 0 recency).

        Per-item isolation: a correlation failure on asset X must not
        affect asset Y (`project_v022_per_item_isolation`). Each
        correlation call is wrapped in try/except.
        """
        out: dict[str, dict | None] = {}
        if self.conn is None:
            return out
        # Activity_recency cap-time clock — single now() per scan so
        # all per-asset bucketing aligns to the same moment.
        scan_clock = time.time()
        for asset in assets:
            if expected_hosts_for_source(asset.source) is None:
                continue  # Structural n/a — leaves runtime_activity=None.
            try:
                result = correlate_asset_activity(self.conn, asset.id, window="24h")
                if result.last_seen is not None:
                    seconds_ago = max(0.0, scan_clock - result.last_seen)
                    out[asset.id] = {"last_seen_seconds": seconds_ago}
            except Exception as exc:
                logger.warning("activity correlation failed for %s: %s", asset.id, exc)
        return out

    # ------------------------------------------------------------------
    # Persistence (drift-2 + drift-3 disposition)
    # ------------------------------------------------------------------

    _UPSERT_SQL: str = """
INSERT INTO assets (
    id, type, parent_asset_id, name, version, install_path, source,
    first_seen, last_seen, last_scanned, current_state, is_vigil_component,
    ontology_tags, risk_score, risk_band, risk_factors
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
    is_vigil_component = excluded.is_vigil_component,
    ontology_tags = excluded.ontology_tags,
    risk_score = excluded.risk_score,
    risk_band = excluded.risk_band,
    risk_factors = excluded.risk_factors
;
"""

    def _persist_assets(
        self,
        assets: list[Asset],
        scan_time: float,
        *,
        score_results: dict[str, tuple[RiskScoreResult, CVEResult | None, frozenset[OntologyCategory]]] | None = None,
        discovery_run_id: int = 0,
    ) -> None:
        """UPSERT assets into the `assets` table.

        Drift dispositions (P1.1 architect-pass §3):
        - **Drift 1** — `source` non-empty enforced at dataclass + here
          (defensive duplicate; raises ValueError before SQL).
        - **Drift 2** — first INSERT sets `first_seen = last_seen =
          last_scanned = scan_time`. `ON CONFLICT` preserves `first_seen`
          (column NOT in the SET clause); updates only `last_seen` /
          `last_scanned`.
        - **Drift 3 (REVERSED 2026-06-11, scan-scoring-callsite):**
          orchestrator-owned columns (`ontology_tags`, `risk_score`,
          `risk_band`, `risk_factors`) ARE now written. Assets where
          scoring failed (absent from ``score_results``) have NULL
          values for all four — distinguishable in the dashboard from
          ``risk_score = 0`` ("scored, no factors fired"). Tags used
          for ``ontology_tags`` are the SAME ``frozenset`` that
          ``_score_assets`` fed into the composition call (threaded via
          ``score_results[asset.id][2]``) — persistence never calls
          ``map_asset`` itself, so a future non-deterministic mapper
          cannot create scored-vs-persisted tag divergence.
        - **Drift 4** — `is_vigil_component bool → INTEGER 0/1` adapted
          via `int(asset.is_vigil_component)`.

        Q11 cap guard: any persisted ``risk_score > 100`` (or < 0)
        raises ``ValueError`` at the persistence boundary. The
        composition function clamps at [0, 100]; this guard is the
        last-line defense against a future scorer change that drops
        the clamp. **Validated BEFORE entering the
        ``with self.conn:`` transaction** so a single corrupt score
        does not roll back the entire batch — per-item isolation must
        hold at persistence too, not just at scoring.
        """
        if self.conn is None:
            return

        score_results = score_results or {}

        # Pre-validate score range BEFORE the transaction. A ValueError
        # raised mid-loop inside ``with self.conn:`` would roll back
        # every prior asset's UPSERT, violating the per-item isolation
        # contract (`project_v022_per_item_isolation`).
        for _asset_id, (score_result, _cve, _tags) in score_results.items():
            if score_result.final_score > 100 or score_result.final_score < 0:
                raise ValueError(
                    f"asset {_asset_id!r}: risk_score {score_result.final_score} "
                    "out of [0,100] — composition guard breach"
                )

        # Atomic commit/rollback per #156 (Rajan 2026-06-05): wrap the
        # UPSERT loop in `with self.conn:` so a mid-loop failure rolls
        # back the in-flight transaction rather than leaving the
        # connection in a mid-transaction state for the caller to clean
        # up.
        with self.conn:
            for asset in assets:
                if not asset.source or not asset.source.strip():
                    raise ValueError(f"asset {asset.id!r}: source must be non-empty for persistence (drift 1)")
                current_state_json = json.dumps(asset.current_state)
                scored = score_results.get(asset.id)
                if scored is not None:
                    score_result, cve_result, tags = scored
                    ontology_tags_json: str | None = json.dumps(sorted(t.value for t in tags))
                    risk_score: int | None = score_result.final_score
                    risk_band: str | None = score_result.band.value
                    risk_factors_json: str | None = json.dumps(_factors_payload(score_result, cve_result))
                else:
                    ontology_tags_json = None
                    risk_score = None
                    risk_band = None
                    risk_factors_json = None
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
                        ontology_tags_json,
                        risk_score,
                        risk_band,
                        risk_factors_json,
                    ),
                )
                # P4.4: append to asset_history when state actually changed
                # since the last scan. Per-item isolated — a history-write
                # failure on one asset MUST NOT abort the rest of the loop
                # (`project_v022_per_item_isolation`).
                try:
                    self._record_history(
                        self.conn,
                        asset,
                        scan_time=scan_time,
                        discovery_run_id=discovery_run_id,
                        ontology_tags_json=ontology_tags_json,
                        risk_score=risk_score,
                        risk_band=risk_band,
                        risk_factors_json=risk_factors_json,
                    )
                except Exception as exc:
                    logger.warning("asset_history write failed for %s: %s", asset.id, exc)

    def _record_history(
        self,
        conn: sqlite3.Connection,
        asset: Asset,
        *,
        scan_time: float,
        discovery_run_id: int,
        ontology_tags_json: str | None,
        risk_score: int | None,
        risk_band: str | None,
        risk_factors_json: str | None,
    ) -> None:
        """Append one asset_history row when state changed since last scan.

        State for diff purposes (D1, judge p4.4.a3 APPROVE):
        {current_state, ontology_tags, risk_score, risk_band,
        risk_factors, version}. Excludes last_seen/last_scanned which
        change every scan — including them would defeat "only on change".

        Diff shape (D2): per-field {old, new}; special token
        `_kind: "first_seen"` for the initial discovery row.

        Snapshot (D3): full materialized state dict.

        Run attribution (D4): integer FK to discovery_runs.id, not a
        float-equality timestamp join.
        """
        snapshot = {
            "current_state": asset.current_state,
            "ontology_tags": json.loads(ontology_tags_json) if ontology_tags_json else None,
            "risk_score": risk_score,
            "risk_band": risk_band,
            "risk_factors": json.loads(risk_factors_json) if risk_factors_json else None,
            "version": asset.version,
        }
        prev_row = conn.execute(
            "SELECT state_snapshot FROM asset_history WHERE asset_id = ? ORDER BY scan_timestamp DESC LIMIT 1",
            (asset.id,),
        ).fetchone()
        if prev_row is None:
            diff: dict[str, Any] = {"_kind": "first_seen"}
        else:
            prev_snapshot = json.loads(prev_row[0])
            diff = {}
            for field_name, value in snapshot.items():
                if prev_snapshot.get(field_name) != value:
                    diff[field_name] = {"old": prev_snapshot.get(field_name), "new": value}
            if not diff:
                return  # No-op: nothing changed since last scan.
        conn.execute(
            "INSERT INTO asset_history (asset_id, scan_timestamp, discovery_run_id, "
            "state_snapshot, changes_from_previous) VALUES (?, ?, ?, ?, ?)",
            (
                asset.id,
                scan_time,
                discovery_run_id or None,
                json.dumps(snapshot),
                json.dumps(diff),
            ),
        )


# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------


def default_sources() -> list[DiscoverySource]:
    """Return a fresh list of all 13 registered discovery sources.

    **Factory pattern** per Rajan's 2026-06-05 source-registry ratification:
    returns a NEW list per call (no module-level mutable state — avoids
    the CLAUDE.md forbidden pattern + lets tests mutate without leaking
    state between runs).

    Source set mirrors
    :data:`claude_monitoring.attack_surface.ontology.mapping.REGISTERED_SOURCES`
    (13 entries). The test
    ``TestSourceRegistry.test_default_sources_registers_all_thirteen_sources``
    pins set-equality; drift in either direction fails CI.

    Phase 3 ratified intent (P3.8): real mapper bodies reachable by scans.
    This factory is the load-bearing entry point — without an entry here,
    a mapper body is dead code. Sources fall into the four families
    catalogued in :mod:`mapping`: identity-only (3), skills (2), MCP
    scored (1), Phase-3 wired (7).
    """
    from claude_monitoring.attack_surface.discovery.sources.ai_apps_info_plist import (
        AiAppsInfoPlistSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.ai_tool_versions import (
        AIToolVersionsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.chromium_extensions import (
        ChromiumExtensionsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.claude_code_skills import (
        ClaudeCodeSkillsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.claude_desktop_integrations import (
        ClaudeDesktopIntegrationsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.homebrew_ai_tools import (
        HomebrewAiToolsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.mcp_servers import (
        McpServersSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.node_packages import (
        NodePackagesSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.ollama_models import (
        OllamaModelsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.openclaw_skills import (
        OpenClawSkillsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.python_packages import (
        PythonPackagesSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.python_project_deps import (
        PythonProjectDepsSource,
    )
    from claude_monitoring.attack_surface.discovery.sources.vscode_cursor_extensions import (
        VscodeCursorExtensionsSource,
    )

    return [
        OllamaModelsSource(),
        AIToolVersionsSource(),
        AiAppsInfoPlistSource(),
        ClaudeCodeSkillsSource(),
        OpenClawSkillsSource(),
        McpServersSource(),
        VscodeCursorExtensionsSource(),
        ChromiumExtensionsSource(),
        PythonPackagesSource(),
        PythonProjectDepsSource(),
        NodePackagesSource(),
        HomebrewAiToolsSource(),
        ClaudeDesktopIntegrationsSource(),
    ]


__all__ = [
    "DiscoveryOrchestrator",
    "PerSourceTelemetry",
    "ScanResult",
    "default_sources",
]
