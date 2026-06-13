"""Per-asset runtime activity correlator.

Aggregates `api_calls` for an asset's expected-destination-host
whitelist (`expected_hosts.py`) over a configurable window. Surfaces:

  * `last_seen` — most recent capture timestamp matching any of the
    asset's expected hosts (any time, not just within `window`).
  * `top_destinations` — top-N by hit count within `window`, each row
    `{host, hits, bytes}`.
  * `anomalies` — currently `new_host` only: hosts that appear in the
    last-24h block but not in the prior 7d block (set-diff against the
    asset's expected hosts). "Unusual time" deferred to v0.3+ per
    spec §7.3.
  * `data_status` — five-state enum (Q8 rider, Amendment-C discipline):
      - `"ok"`            — correlatable + has data in window
      - `"correlatable_type_no_activity"` — correlatable + no captures
                            in window (meaningful negative)
      - `"asset_has_no_runtime_correlation"` — structural n/a
                            (expected_hosts_for_source returned None)
      - `"capture_off"`   — heartbeat dead; cannot meaningfully say
                            whether the asset was active
      - `"asset_not_found"` — surfaced as HTTP 404 by the wrapper,
                              kept in the enum for symmetry

Hot-path: `_api_asset_activity` calls this once per drilldown (NOT
on dashboard refresh). The query budget is **up to 5 SQL statements
per call**: asset-source lookup, in-window aggregation, fallback
last-seen (skipped when in-window returned rows), last-24h distinct
hosts for anomaly, prior-7d distinct hosts for anomaly. All leverage
the existing `idx_api_calls_ts` index. Acceptable at v0.2.2 scale
because the endpoint is invoked only on explicit drilldown.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Literal

from claude_monitoring.attack_surface.activity.expected_hosts import (
    expected_hosts_for_source,
)

DataStatus = Literal[
    "ok",
    "correlatable_type_no_activity",
    "asset_has_no_runtime_correlation",
    "capture_off",
    "asset_not_found",
]

# Window shorthand → seconds. Hot-path defense-in-depth: reject any
# value not in this set so an attacker can't probe arbitrary bounds.
_WINDOW_TO_SECONDS: dict[str, int] = {
    "24h": 24 * 3600,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
}

_TOP_N = 5
"""Top-N destinations rendered. Spec §7.2 mockup uses 5; bigger payload
brings diminishing return + bloats the drilldown response."""


@dataclass(frozen=True)
class ActivityResult:
    """Renderer-agnostic activity payload."""

    last_seen: float | None
    top_destinations: list[dict[str, Any]]
    anomalies: list[dict[str, Any]]
    data_status: DataStatus
    window: str = "24h"

    def to_payload(self) -> dict[str, Any]:
        """Dict shape served by the `/api/asset/<id>/activity` route."""
        return {
            "last_seen": self.last_seen,
            "top_destinations": list(self.top_destinations),
            "anomalies": list(self.anomalies),
            "data_status": self.data_status,
            "window": self.window,
        }


# Monkey-patchable clock for deterministic tests. Production reads
# `time.time()` — same float-seconds source as the rest of the daemon.
def _now() -> float:
    return time.time()


def _parse_capture_ts(ts: str | float | None) -> float:
    """`api_calls.timestamp` is stored as ISO 8601 text. Parse to
    Unix epoch float for windowing math. Tolerant of missing 'Z'."""
    if ts is None:
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
    s = str(ts)
    # 2026-06-11T12:34:56Z → epoch
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        from datetime import datetime

        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return 0.0


def correlate_asset_activity(
    db: sqlite3.Connection,
    asset_id: str,
    window: str = "24h",
    capture_ok: bool = True,
) -> ActivityResult:
    """Run per-asset host-based correlation.

    Args:
        db: sqlite3 connection (read-only OK).
        asset_id: the `assets.id` to correlate.
        window: one of `_WINDOW_TO_SECONDS` keys.
        capture_ok: caller-supplied capture-health gate. When `False`
            (heartbeat dead), the result is `data_status="capture_off"`
            regardless of what the DB returns — we can't truthfully
            say "no activity" if the capture layer wasn't recording.

    Returns:
        `ActivityResult`. Per-state contract pinned in
        `tests/test_p4_3_activity_correlation.py`.
    """
    if window not in _WINDOW_TO_SECONDS:
        raise ValueError(f"window must be one of {sorted(_WINDOW_TO_SECONDS)}, got {window!r}")

    # 1. Look up the asset's source to decide structural-correlatable vs n/a.
    row = db.execute("SELECT source FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if row is None:
        return ActivityResult(
            last_seen=None,
            top_destinations=[],
            anomalies=[],
            data_status="asset_not_found",
            window=window,
        )
    source = row[0] if isinstance(row, tuple) else row["source"]

    expected = expected_hosts_for_source(source)
    if expected is None:
        # Structural n/a — Q8 rider, distinct from correlatable_type_no_activity.
        return ActivityResult(
            last_seen=None,
            top_destinations=[],
            anomalies=[],
            data_status="asset_has_no_runtime_correlation",
            window=window,
        )

    if not capture_ok:
        return ActivityResult(
            last_seen=None,
            top_destinations=[],
            anomalies=[],
            data_status="capture_off",
            window=window,
        )

    # 2. Build the IN-clause from the developer-controlled whitelist.
    #    Values come from `expected_hosts.py` module-level literal —
    #    NEVER from request input — but we still bind them as `?` per
    #    CLAUDE.md mandatory parameterization.
    placeholders = ",".join("?" * len(expected))
    expected_list = list(expected)

    now = _now()
    window_start_iso = _iso(now - _WINDOW_TO_SECONDS[window])

    # 3. In-window aggregation by host.
    # bandit B608: `placeholders` is `,`-joined `?` chars sized to the
    # developer-controlled `_EXPECTED_HOSTS` literal; never from request
    # input. Host VALUES go through `?` binding in `expected_list`.
    rows = db.execute(
        f"""SELECT destination_host AS host,
                   COUNT(*) AS hits,
                   COALESCE(SUM(request_size_bytes), 0) + COALESCE(SUM(response_size_bytes), 0) AS bytes,
                   MAX(timestamp) AS last_ts
            FROM api_calls
            WHERE timestamp >= ?
              AND destination_host IN ({placeholders})
            GROUP BY destination_host
            ORDER BY hits DESC
            LIMIT ?""",  # nosec B608
        [window_start_iso, *expected_list, _TOP_N],
    ).fetchall()

    top_destinations: list[dict[str, Any]] = []
    last_seen: float | None = None
    for r in rows:
        host = r["host"] if hasattr(r, "keys") else r[0]
        hits = r["hits"] if hasattr(r, "keys") else r[1]
        bytes_ = r["bytes"] if hasattr(r, "keys") else r[2]
        last_ts = r["last_ts"] if hasattr(r, "keys") else r[3]
        top_destinations.append({"host": host, "hits": int(hits), "bytes": int(bytes_ or 0)})
        ts_epoch = _parse_capture_ts(last_ts)
        if last_seen is None or ts_epoch > last_seen:
            last_seen = ts_epoch

    # 4. Fallback `last_seen` lookup — beyond the window, in case the
    #    asset has older traffic but nothing in this window. §6.1
    #    `activity_recency` needs the most-recent across all time.
    if last_seen is None:
        # bandit B608: same justification as step 3 — placeholders fixed
        # from developer-controlled literal; values bound.
        fallback = db.execute(
            f"""SELECT MAX(timestamp) FROM api_calls
                WHERE destination_host IN ({placeholders})""",  # nosec B608
            expected_list,
        ).fetchone()
        if fallback and fallback[0]:
            last_seen = _parse_capture_ts(fallback[0])

    # 5. New-host anomaly: set-diff between last-24h block and
    #    prior-7d block, restricted to the asset's expected hosts.
    anomalies: list[dict[str, Any]] = []
    last_24h_start = _iso(now - 24 * 3600)
    prior_7d_start = _iso(now - 8 * 86400)
    prior_7d_end = _iso(now - 24 * 3600)

    # bandit B608 (both queries): same justification — placeholders
    # fixed from developer-controlled literal; values bound.
    last_24h_hosts = {
        r[0]
        for r in db.execute(
            f"""SELECT DISTINCT destination_host FROM api_calls
                WHERE timestamp >= ?
                  AND destination_host IN ({placeholders})""",  # nosec B608
            [last_24h_start, *expected_list],
        ).fetchall()
    }
    prior_hosts = {
        r[0]
        for r in db.execute(
            f"""SELECT DISTINCT destination_host FROM api_calls
                WHERE timestamp >= ? AND timestamp < ?
                  AND destination_host IN ({placeholders})""",  # nosec B608
            [prior_7d_start, prior_7d_end, *expected_list],
        ).fetchall()
    }
    for new_host in sorted(last_24h_hosts - prior_hosts):
        anomalies.append({"kind": "new_host", "value": new_host, "since": last_24h_start})

    if not top_destinations:
        return ActivityResult(
            last_seen=last_seen,
            top_destinations=[],
            anomalies=anomalies,
            data_status="correlatable_type_no_activity",
            window=window,
        )

    return ActivityResult(
        last_seen=last_seen,
        top_destinations=top_destinations,
        anomalies=anomalies,
        data_status="ok",
        window=window,
    )


def _iso(epoch: float) -> str:
    """Render Unix-epoch float → `YYYY-MM-DDTHH:MM:SSZ` to match the
    capture-layer timestamp format in `api_calls.timestamp`."""
    import datetime as _dt

    return _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
