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

from claude_monitoring.attack_surface.rendering import cve_status_hint, risk_score_hint

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
        # Treat as not_applicable so the row still has a defined hint
        # and never collapses to "missing field" at the renderer.
        hint = cve_status_hint("not_applicable", None, None)

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

    return {
        "rows": projected,
        "total": total,
        "limit": limit,
        "offset": offset,
        "unscored_count": unscored_count,
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
