"""Attack-surface assets dashboard API — `/api/assets` + `/api/asset/<id>`.

Lifted from `monitor.py` so the new endpoint logic does not bloat the
already-near-ceiling DashboardHandler module. The handler methods
themselves stay in monitor.py as 1–2 line wrappers that delegate to
these free functions.

Per the dashboard-asset-view PR (2026-06-11, judge-queued + Rajan-
ratified as the condition of the scan-scoring-callsite C-rider
deferral). Server-side cve_status / risk_score hints come from
`attack_surface/rendering/cve_status_hints` — the ONE load-bearing call
site per Amendment C.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from claude_monitoring.attack_surface.rendering import (
    UNKNOWN_PENDING_RESCAN_HINT,
    cve_status_hint,
    risk_score_hint,
)

# Hot-path DoS guard. `do_GET` is hot per CLAUDE.md; an authenticated caller
# requesting `?limit=10000000` would `fetchall()` the entire table into
# memory + double-`json.loads` every row. Clamping at 1000 covers the
# largest realistic dev-machine population (~1k assets per the
# scan-scoring-callsite empirical scan) with headroom; values above this
# silently snap down.
_MAX_LIMIT = 1000


# ---------------------------------------------------------------------------
# Row projection — shared by list + detail
# ---------------------------------------------------------------------------


def render_asset_row(row: sqlite3.Row) -> dict[str, Any]:
    """Project a `sqlite3.Row` from the `assets` table to the API
    payload shape. Parses the JSON columns and renders the
    cve_status_hint / risk_score_hint via the rules layer."""
    risk_factors_raw = row["risk_factors"]
    risk_factors_parsed: dict | None = None
    if risk_factors_raw:
        try:
            parsed = json.loads(risk_factors_raw)
            if isinstance(parsed, dict):
                risk_factors_parsed = parsed
        except (json.JSONDecodeError, TypeError):
            risk_factors_parsed = None

    ontology_tags_raw = row["ontology_tags"]
    ontology_tags_list: list[str] = []
    if ontology_tags_raw:
        try:
            parsed_tags = json.loads(ontology_tags_raw)
            if isinstance(parsed_tags, list):
                ontology_tags_list = [str(t) for t in parsed_tags]
        except (json.JSONDecodeError, TypeError):
            ontology_tags_list = []

    # Server-side cve_status_hint — the ONE load-bearing call site.
    if risk_factors_parsed is not None:
        hint = cve_status_hint(
            risk_factors_parsed.get("cve_status", "not_applicable"),
            risk_factors_parsed.get("cves"),
            risk_factors_parsed.get("cve_unavailable_reason"),
        )
    else:
        # No risk_factors → score-pipeline didn't run for this asset.
        # Distinct from not_applicable (= no ecosystem to query): we
        # do NOT know whether the feed applies. Verdict
        # dashboard-asset-view.a1 Finding 4 — borrowing
        # "CVE feed does not apply" was data-truthfulness-wrong for
        # python-packages assets that have an ecosystem but whose
        # scoring failed last scan.
        hint = UNKNOWN_PENDING_RESCAN_HINT

    risk_score = row["risk_score"]
    rs_hint = risk_score_hint(risk_score)

    return {
        "id": row["id"],
        "type": row["type"],
        "name": row["name"],
        "version": row["version"],
        "source": row["source"],
        "last_scanned": row["last_scanned"],
        "risk_score": risk_score,
        "risk_band": row["risk_band"],
        "ontology_tags": ontology_tags_list,
        # P7-C Q1 fold (Rajan-ratified 2026-07-04): project current_state
        # so the drill-down can render the raw manifest permissions block
        # per LOCKED §Phase 7:259 ("native permission text + ontology
        # tags"). Column was already SELECTed in _ASSET_COLUMNS; only the
        # projection was missing.
        "current_state": row["current_state"],
        "cve_status_hint": {"label": hint.label, "severity": hint.severity, "tooltip": hint.tooltip},
        "risk_score_hint": (
            {"label": rs_hint.label, "severity": rs_hint.severity, "tooltip": rs_hint.tooltip}
            if rs_hint is not None
            else None
        ),
        "risk_factors": risk_factors_parsed,
    }


# ---------------------------------------------------------------------------
# List endpoint
# ---------------------------------------------------------------------------


_ASSET_COLUMNS = (
    "id, type, parent_asset_id, name, version, install_path, source, "
    "first_seen, last_seen, last_scanned, current_state, ontology_tags, "
    "risk_score, risk_band, risk_factors, is_vigil_component"
)


def list_assets(db: sqlite3.Connection, params: dict[str, list[str]]) -> dict[str, Any]:
    """Asset list — `risk_score DESC NULLS LAST, last_scanned DESC`.

    Query params (all optional):
      * `limit` (default 200; Rajan Q1 ratification 2026-06-11)
      * `offset` (default 0)
      * `risk_band` — exact match against `assets.risk_band`.
      * `source` — exact match against `assets.source`.

    Response envelope:
      * `rows` — projected row payloads (see `render_asset_row`), with
        `risk_factors` stripped to keep list rows narrow.
      * `total` — post-filter pre-pagination row count.
      * `limit` / `offset` — echo of the params.
      * `unscored_count` — global count of NULL-risk_score assets (the
        NULLS LAST rider — operators must see how many assets sit
        below the score-sorted tail, regardless of filter state).
    """
    try:
        limit = int(params.get("limit", ["200"])[0])
    except (ValueError, TypeError):
        limit = 200
    limit = max(1, min(limit, _MAX_LIMIT))
    try:
        offset = int(params.get("offset", ["0"])[0])
    except (ValueError, TypeError):
        offset = 0
    offset = max(0, offset)
    risk_band_filter = params.get("risk_band", [""])[0]
    source_filter = params.get("source", [""])[0]

    where_clauses: list[str] = []
    where_args: list[Any] = []
    if risk_band_filter:
        where_clauses.append("risk_band = ?")
        where_args.append(risk_band_filter)
    if source_filter:
        where_clauses.append("source = ?")
        where_args.append(source_filter)
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # bandit B608: `where_sql` is built from literal fragments above —
    # never from `params`. Filter VALUES are bound via `?` placeholders
    # in `where_args`. `_ASSET_COLUMNS` is a module-level literal.
    # CLAUDE.md mandatory pattern (parameterized SQL) satisfied.
    total_row = db.execute(f"SELECT COUNT(*) FROM assets {where_sql}", where_args).fetchone()  # nosec B608
    total = total_row[0] if total_row else 0

    # `unscored_count` is the global tail (no filters) — operators
    # need a stable signal "N assets sitting below page 1" regardless
    # of filter state. If we filtered, this would lie at filter time.
    unscored_row = db.execute("SELECT COUNT(*) FROM assets WHERE risk_score IS NULL").fetchone()
    unscored_count = unscored_row[0] if unscored_row else 0

    sql = (
        f"SELECT {_ASSET_COLUMNS} FROM assets {where_sql} "  # nosec B608
        "ORDER BY (risk_score IS NULL), risk_score DESC, last_scanned DESC "
        "LIMIT ? OFFSET ?"
    )
    rows = db.execute(sql, [*where_args, limit, offset]).fetchall()

    projected: list[dict] = []
    for r in rows:
        payload = render_asset_row(r)
        payload.pop("risk_factors", None)
        projected.append(payload)

    # feat/daemon-discovery-scheduler: surface in-flight scan so the UI
    # can render "Scan running…" instead of an empty table.
    # `discovery_runs.completed_at IS NULL` is the durable signal — set
    # by `audit.record_run_started`, cleared on `record_run_finished`.
    # The startup-sweep in monitor.py closes stale NULL rows from a
    # SIGKILLed mid-scan, so this query never returns ghost rows.
    in_flight_row = db.execute(
        "SELECT trigger, started_at FROM discovery_runs WHERE completed_at IS NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    scan_in_progress = (
        None
        if in_flight_row is None
        else {
            "trigger": in_flight_row["trigger"],
            "started_at": in_flight_row["started_at"],
        }
    )

    return {
        "rows": projected,
        "total": total,
        "limit": limit,
        "offset": offset,
        "unscored_count": unscored_count,
        "scan_in_progress": scan_in_progress,
    }


# ---------------------------------------------------------------------------
# Detail endpoint
# ---------------------------------------------------------------------------


def get_asset_detail(db: sqlite3.Connection, params: dict[str, list[str]]) -> tuple[dict[str, Any], int]:
    """Asset detail — full row including parsed `risk_factors` for the
    §6.4 transparency-mandate breakdown popover.

    Returns `(payload, status_code)`. `400` if `id` is missing, `404`
    if the asset is not found, `200` otherwise.
    """
    asset_id = params.get("id", [""])[0]
    if not asset_id:
        return {"error": "missing id"}, 400
    # bandit B608: `_ASSET_COLUMNS` is a module-level literal — never
    # user-controlled. `asset_id` is bound via `?`. Parameterized.
    row = db.execute(
        f"SELECT {_ASSET_COLUMNS} FROM assets WHERE id = ?",  # nosec B608
        (asset_id,),
    ).fetchone()
    if row is None:
        return {"error": "not found", "id": asset_id}, 404
    return render_asset_row(row), 200


def get_asset_history(db: sqlite3.Connection, asset_id: str) -> tuple[dict[str, Any], int]:
    """P4.4 temporal audit trail. Returns reverse-chronological history
    rows for ``asset_id`` joined to ``discovery_runs`` for trigger
    attribution. LEFT JOIN renders orphan-FK rows with
    ``trigger="unknown"`` so the endpoint never 500s on a half-consistent
    DB.

    Returns ``(payload, status_code)``. ``404`` if the asset itself
    doesn't exist; ``200`` with ``{"history": []}`` if the asset exists
    but has no history rows yet (just discovered, or pre-P4.4 DB).
    """
    if not asset_id:
        return {"error": "missing id"}, 400
    exists = db.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if exists is None:
        return {"error": "not found", "id": asset_id}, 404
    rows = db.execute(
        "SELECT h.scan_timestamp, h.discovery_run_id, h.state_snapshot, "
        "h.changes_from_previous, COALESCE(r.trigger, 'unknown') AS trigger "
        "FROM asset_history h "
        "LEFT JOIN discovery_runs r ON r.id = h.discovery_run_id "
        "WHERE h.asset_id = ? "
        "ORDER BY h.scan_timestamp DESC",
        (asset_id,),
    ).fetchall()
    history = []
    for r in rows:
        history.append(
            {
                "scan_timestamp": r["scan_timestamp"] if hasattr(r, "keys") else r[0],
                "discovery_run_id": r["discovery_run_id"] if hasattr(r, "keys") else r[1],
                "state_snapshot": r["state_snapshot"] if hasattr(r, "keys") else r[2],
                "changes_from_previous": r["changes_from_previous"] if hasattr(r, "keys") else r[3],
                "trigger": r["trigger"] if hasattr(r, "keys") else r[4],
            }
        )
    return {"history": history}, 200


def get_new_in_24h(db: sqlite3.Connection) -> tuple[dict[str, Any], int]:
    """Count of assets with ``first_seen`` within the last 24 hours.

    Q1 data-truthfulness condition (judge p4.4.a3 ratification): distinguish
    ``no_runs`` (zero discovery_runs rows) from ``no_new`` (runs exist
    but zero assets are new in window) from ``ok`` (positive count).
    The UI MUST render distinct copy per state so an operator never
    sees a bare ``0`` that conflates "never ran" with "ran, found
    nothing new".
    """
    import time as _t

    runs_count = db.execute("SELECT COUNT(*) FROM discovery_runs").fetchone()[0]
    if runs_count == 0:
        return {"count": 0, "status": "no_runs"}, 200
    cutoff = _t.time() - 24 * 3600
    new_count = db.execute("SELECT COUNT(*) FROM assets WHERE first_seen >= ?", (cutoff,)).fetchone()[0]
    if new_count == 0:
        return {"count": 0, "status": "no_new"}, 200
    return {"count": new_count, "status": "ok"}, 200


def get_overview(db: sqlite3.Connection) -> dict[str, Any]:
    """P7-A State C composite payload (judge Ask #4 ratified 2026-07-01).

    Single endpoint returning everything State C needs to render the
    Overview pane, so the frontend makes ONE request instead of 4-5:
      - total: overall asset count
      - by_band: distribution across 5 scored bands + explicit "unscored"
        bucket (CF-5: unscored MUST stay distinct — never folds into
        info/low; sum of scored bands ≤ total, gap = unscored)
      - top_5: top-5 by risk_score (list row shape, risk_factors stripped)
      - new_assets_24h: {count, status} per judge p4.4.a3 truthfulness
      - new_cves_24h: {count:0, status:"unavailable"} in v0.2.2 (§4.5 fix
        M9: `asset_cves` table is empty; CVEs inline in
        assets.risk_factors.cves JSON; rendering 0 without the flag would
        imply "clean" when the truth is "unknown")
      - last_scan_ts: MAX(completed_at) across all completed discovery_runs
      - scan_in_progress: same shape as list_assets — in-flight signal
    """
    total_row = db.execute("SELECT COUNT(*) FROM assets").fetchone()
    total = total_row[0] if total_row else 0

    # by_band: per-band histogram + explicit unscored bucket (CF-5).
    # Aggregation over scored assets by risk_band column; scored total
    # + unscored bucket exactly reconstructs `total`.
    band_rows = db.execute(
        "SELECT risk_band, COUNT(*) FROM assets WHERE risk_band IS NOT NULL GROUP BY risk_band"
    ).fetchall()
    by_band: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unscored": 0,
    }
    for row in band_rows:
        band = row[0]
        if band in by_band:
            by_band[band] = row[1]
    unscored_row = db.execute("SELECT COUNT(*) FROM assets WHERE risk_band IS NULL").fetchone()
    by_band["unscored"] = unscored_row[0] if unscored_row else 0

    # top_5: reuse list_assets sort semantics (risk_score DESC NULLS LAST).
    top_5_rows = db.execute(
        f"SELECT {_ASSET_COLUMNS} FROM assets "  # nosec B608
        "ORDER BY (risk_score IS NULL), risk_score DESC, last_scanned DESC "
        "LIMIT 5"
    ).fetchall()
    top_5: list[dict] = []
    for r in top_5_rows:
        payload = render_asset_row(r)
        payload.pop("risk_factors", None)
        top_5.append(payload)

    # new_assets_24h delegates to the truthfulness-hardened helper.
    new_assets_payload, _ = get_new_in_24h(db)

    # M9 (Ask #2 ratified): CVE data path unavailable in v0.2.2.
    new_cves_24h = {"count": 0, "status": "unavailable"}

    # last_scan_ts: MAX completed_at across ALL triggers (per D-no-trigger-filter
    # from p4.5 state-bar precedent — --discover + scheduled scans both count).
    last_scan_row = db.execute("SELECT MAX(completed_at) FROM discovery_runs WHERE completed_at IS NOT NULL").fetchone()
    last_scan_ts = last_scan_row[0] if last_scan_row else None

    # scan_in_progress: reuse list_assets in-flight signal.
    in_flight_row = db.execute(
        "SELECT trigger, started_at FROM discovery_runs WHERE completed_at IS NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    scan_in_progress = (
        None
        if in_flight_row is None
        else {"trigger": in_flight_row["trigger"], "started_at": in_flight_row["started_at"]}
    )

    return {
        "total": total,
        "by_band": by_band,
        "top_5": top_5,
        "new_assets_24h": new_assets_payload,
        "new_cves_24h": new_cves_24h,
        "last_scan_ts": last_scan_ts,
        "scan_in_progress": scan_in_progress,
    }


def get_recent_activity(db: sqlite3.Connection, capture_ok: bool) -> dict[str, Any]:
    """P7-B Recent Activity Tool Section — 3-state truthful envelope.

    Judge Ask #2 ratified 2026-07-02. Aggregates last-24h api_calls across
    all assets via per-source ``expected_hosts`` mapping. Rendered by the
    ``_renderRecentActivitySection`` frontend renderer.

    Args:
        db: sqlite3 connection (read-only OK).
        capture_ok: caller-supplied capture-health gate. When ``False``
            (heartbeat dead / never), returns ``capture_status='off'``
            regardless of DB rows — we cannot truthfully say "no activity"
            if the capture layer wasn't recording. Mirrors the
            ``correlate_asset_activity`` contract at
            ``activity/correlator.py:159``.

    Returns:
        Dict with:
          - ``capture_status``: ``'off' | 'no_captures_yet' | 'ok'`` —
            three visually-distinct render states per Rajan guidance
            2026-07-02 ("no captured calls ≠ idle tool") and judge
            CF-4 truthfulness gate. Empty ``assets`` list combined with
            ``ok`` status means "capture on, discovered tools made no
            observable calls in last 24h" — NOT "no data".
          - ``assets``: reverse-chronologically ordered by
            ``last_call_ts``, capped at 50. Each row: ``id, name, source,
            last_call_ts, call_count_24h``. Empty in ``off`` and
            ``no_captures_yet`` states.

    CF-3 (verdict hard gate): parameterized SQL only. The IN-list uses
    ``?`` placeholders bound from the module-level
    ``expected_hosts_for_source`` frozensets — never string-interpolated
    from caller-controlled data.

    Query-plan verified 2026-07-02 on the 259k-row live DB: SEARCH
    api_calls USING INDEX idx_api_calls_ts (timestamp>?) — the existing
    timestamp index handles the 24h narrowing; ``destination_host IN
    (...)`` filter applies to the post-narrow subset. No new index
    needed.
    """

    from claude_monitoring.attack_surface.activity.expected_hosts import (
        expected_hosts_for_source,
    )

    # off state: heartbeat gate says capture layer isn't recording. Return
    # early — DB row count is not a truthful signal here.
    if not capture_ok:
        return {"capture_status": "off", "assets": []}

    # Build host→source lookup across all sources with expected hosts.
    # Sources with no hosts (structural n/a per Q8) contribute nothing.
    host_to_source: dict[str, str] = {}
    all_hosts: list[str] = []
    source_rows = db.execute("SELECT DISTINCT source FROM assets").fetchall()
    for r in source_rows:
        source = r[0] if isinstance(r, tuple) else r["source"]
        if not source:
            continue
        hosts = expected_hosts_for_source(source)
        if hosts is None:
            continue
        for h in hosts:
            host_to_source[h] = source
            all_hosts.append(h)

    if not all_hosts:
        # No correlatable sources at all — none of the discovered sources
        # have expected_hosts registered. Semantic bootstrap state:
        # capture on but the correlation registry is structurally empty.
        return {"capture_status": "no_captures_yet", "assets": []}

    # Bootstrap distinction: check whether api_calls has EVER captured
    # anything. If empty, the capture layer is running but no rows have
    # been written yet — genuine no_captures_yet. Distinct from "tools
    # idle in the 24h window" (which the correlation query below
    # resolves to 'ok' with an empty assets list, per Rajan guidance
    # 'no captured calls ≠ idle tool').
    any_row = db.execute("SELECT 1 FROM api_calls LIMIT 1").fetchone()
    if any_row is None:
        return {"capture_status": "no_captures_yet", "assets": []}

    # Aggregate api_calls in 24h window by destination_host.
    # ISO-string timestamp compares lexically thanks to fixed-width RFC3339.
    from datetime import datetime, timedelta, timezone

    cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    placeholders = ",".join("?" * len(all_hosts))
    # nosec B608: `placeholders` is a `?,?,?` string built from list
    # length — NEVER user input. All actual values bound via `?` in
    # `params_list` below. CF-3 (verdict hard gate): no f-string SQL
    # interpolation of user data; only the literal `?`-placeholder
    # string is concatenated.
    sql = (
        "SELECT destination_host, MAX(timestamp) AS last_ts, COUNT(*) AS n "  # nosec B608
        "FROM api_calls "
        "WHERE timestamp >= ? AND destination_host IN (" + placeholders + ") "
        "GROUP BY destination_host"
    )
    params_list: list[Any] = [cutoff_iso, *all_hosts]
    host_rows = db.execute(sql, params_list).fetchall()

    if not host_rows:
        # Capture running, correlatable sources present, api_calls has
        # historic rows, but zero matches in the 24h window. This is
        # "capture on, tools currently idle" — the ok+empty state per
        # Rajan guidance "no captured calls ≠ idle tool". Distinct from
        # 'off' (capture down) and from 'no_captures_yet' (bootstrap).
        # R4 code-review Important fold-in 2026-07-02: prior impl
        # returned 'no_captures_yet' here, making 'ok+empty' unreachable
        # and the frontend's dedicated branch dead code — a source-honesty
        # violation per CLAUDE.md ("never silently leave spec and code
        # disagreeing").
        return {"capture_status": "ok", "assets": []}

    # Aggregate per source (there may be N hosts per source).
    source_agg: dict[str, dict[str, Any]] = {}
    for r in host_rows:
        host = r[0] if isinstance(r, tuple) else r["destination_host"]
        last_ts = r[1] if isinstance(r, tuple) else r["last_ts"]
        n = r[2] if isinstance(r, tuple) else r["n"]
        source = host_to_source.get(host)
        if source is None:
            continue
        agg = source_agg.get(source, {"last_ts": None, "n": 0})
        # Latest wins (ISO strings compare lexically).
        if agg["last_ts"] is None or (last_ts and last_ts > agg["last_ts"]):
            agg["last_ts"] = last_ts
        agg["n"] = int(agg["n"]) + int(n or 0)
        source_agg[source] = agg

    # Fetch assets for each source with activity; pick highest-risk
    # representative asset per source (or all, then dedupe by id).
    asset_rows: list[dict[str, Any]] = []
    for source, agg in source_agg.items():
        rows = db.execute(
            "SELECT id, name, source FROM assets WHERE source = ? "
            "ORDER BY (risk_score IS NULL), risk_score DESC LIMIT 5",
            (source,),
        ).fetchall()
        for row in rows:
            asset_rows.append(
                {
                    "id": row[0] if isinstance(row, tuple) else row["id"],
                    "name": row[1] if isinstance(row, tuple) else row["name"],
                    "source": row[2] if isinstance(row, tuple) else row["source"],
                    "last_call_ts": agg["last_ts"],
                    "call_count_24h": agg["n"],
                }
            )

    # Sort reverse-chronologically; cap at 50.
    asset_rows.sort(key=lambda x: x["last_call_ts"] or "", reverse=True)
    asset_rows = asset_rows[:50]

    return {"capture_status": "ok", "assets": asset_rows}
