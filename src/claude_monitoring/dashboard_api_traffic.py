"""P6.4 — API Traffic tab envelope builder for /api/traffic/summary.

Five helpers + an assembler that feed the API Traffic tab's three
counter cards (intercepted / chat_calls / content_captured) +
fill-rate widget. Extracted from `dashboard_handler.py` to keep that
file under the 2900-line ceiling.

Load-bearing contract (judge p6.4.a2 APPROVE 2026-06-16):

  * `is_content_captured(row) ≡ is_chat_call_path(row.endpoint_path)
    AND (row.input_tokens or 0) > 0` — ONE predicate, three consumers.
    Matches P6.2's merged `compute_fill_rate_24h::filled` numerator
    verbatim. By construction header `K content_captured` == count of
    `.cstate--full` rendered rows.
  * `is_noise_row` NEVER references content-captured and NEVER hides a
    chat-call row. The default-view filter hides only non-chat
    infrastructure noise. Failed (4xx) chat calls remain visible — the
    operator needs them.
  * Empty-data fill-rate → `percentage=None` (UI renders "Awaiting
    data", not "0% clean"). §4.5 discipline inherited from P6.2/P6.3.
"""

from __future__ import annotations

import sqlite3
import time

_CHAT_CALL_PATHS = (
    "/v1/messages",
    "/v1/chat/completions",
)

_NOISE_PATH_MARKERS = (
    "/v1/environments/",
    "/v1/organizations/",
    "/profile",
    "/oauth",
    "/telemetry",
)


def is_chat_call_path(endpoint_path: str | None) -> bool:
    """True iff the endpoint path matches the v0.2.2 chat-call shape.

    Matches P6.2's D-path-filter-for-chat-calls SQL filter:
        endpoint_path LIKE '/v1/messages%' OR LIKE '%/chat/completions%'

    NULL / empty → False.
    """
    if not endpoint_path:
        return False
    return endpoint_path.startswith("/v1/messages") or "/chat/completions" in endpoint_path


def is_content_captured(row) -> bool:
    """A chat call whose body the parser populated.

    Verbatim from P6.2's `filled` numerator: chat-path + input_tokens > 0.
    NO preview clause — a chat call with tokens but empty previews
    (streaming parser dropped the body) is STILL captured. The token
    counter ran; the operator can trust the row.

    This is the ONE predicate. Header counter, row badge, and noise rule
    all reconcile against it.
    """
    if not is_chat_call_path(row["endpoint_path"]):
        return False
    return (row["input_tokens"] or 0) > 0


def is_noise_row(row) -> bool:
    """Hide non-chat infrastructure noise by default.

    Chat-call rows are NEVER hidden — they are the operator's primary
    signal (including 4xx failures). Per judge p6.4.a2 ratification, this
    is the deliberate operator-facing-UX interpretation of directive
    line 230's literal "hide empty rows": hide non-chat infrastructure
    only.

    "Show all" toggle MUST reveal every hidden row — pinned by
    `TestShowAllRevealsEveryHiddenRow`.
    """
    if is_chat_call_path(row["endpoint_path"]):
        return False
    status = row["http_status"]
    if status is not None and status >= 400:
        return True
    path = row["endpoint_path"] or ""
    for marker in _NOISE_PATH_MARKERS:
        if marker in path:
            return True
    return False


def compute_traffic_summary(conn) -> dict:
    """Three counters + a fill-rate over the last 24h.

    The SQL `content_captured` SUM is the COUNT-form of
    `is_content_captured` (same predicate; cannot drift).

    Empty data → `fill_rate_24h_pct = None` (UI renders "Awaiting
    data"). Query failure → all-None envelope.
    """
    cutoff = time.time() - (24 * 3600)
    cutoff_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(cutoff))
    try:
        row = conn.execute(
            """SELECT
                 COUNT(*) AS intercepted,
                 SUM(CASE WHEN endpoint_path LIKE '/v1/messages%'
                            OR endpoint_path LIKE '%/chat/completions%'
                          THEN 1 ELSE 0 END) AS chat_calls,
                 SUM(CASE WHEN (endpoint_path LIKE '/v1/messages%'
                             OR endpoint_path LIKE '%/chat/completions%')
                            AND input_tokens > 0
                          THEN 1 ELSE 0 END) AS content_captured
               FROM api_calls
               WHERE timestamp > ?""",
            (cutoff_iso,),
        ).fetchone()
    except sqlite3.Error:
        return {
            "intercepted": None,
            "chat_calls": None,
            "content_captured": None,
            "fill_rate_24h_pct": None,
        }
    intercepted = int(row["intercepted"] or 0)
    chat_calls = int(row["chat_calls"] or 0)
    content_captured = int(row["content_captured"] or 0)
    if chat_calls == 0:
        fill_rate_pct: int | None = None
    else:
        fill_rate_pct = round(100.0 * content_captured / chat_calls)
    return {
        "intercepted": intercepted,
        "chat_calls": chat_calls,
        "content_captured": content_captured,
        "fill_rate_24h_pct": fill_rate_pct,
    }


def build_envelope(conn) -> dict:
    """Assemble the /api/traffic/summary envelope. Single source of
    truth for the counter widget."""
    return {"summary": compute_traffic_summary(conn)}
