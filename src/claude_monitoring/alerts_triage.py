"""P9.3 — Alerts triage allowlists + fail-closed verdict/filter helpers.

Sibling of `alerts_pattern.py` (P9.2) and `supply_chain_risk.py` (P9.1).
Single-responsibility module: verdict-taxonomy allowlist, fail-closed
normalization, dataset-wide verdict counts, server-side filter, handler
orchestration. No I/O, no DB, no network — pure Python over already-
fetched alert rows.

Locked by judge p9.3.a2 APPROVE (2026-06-24):

  * LIVE ``_VERDICT_ALLOWLIST`` is the 3-value set
    ``{true_positive, false_positive, dismissed}``. **`muted` is
    REJECTED** at the endpoint until P9.4 lands with its security
    guardrails (CRITICAL-mute ban, expiry, audit, capture-vs-display
    ruling). p9.3.a2 Finding 3.
  * The ``verdict`` COLUMN in ``alert_triage`` remains plain TEXT (no
    schema-level CHECK constraint), so P9.4 lands by ADDING ``"muted"``
    to this set + UI + guardrails. NO re-migration needed.
  * Invalid ``verdict`` or ``triage_filter`` → fail-closed
    (``(None, True)``); handler routes invalid to ``alerts=[]`` +
    explicit invalid flag (inherited p9.2.a2 §4.5 contract).
  * Absent ``triage_filter`` defaults to ``"unresolved"`` — the
    operator's todo is the default landing (p9.3.a2 D-Unresolved-
    default-active).
"""

from __future__ import annotations

_VERDICT_ALLOWLIST: frozenset[str] = frozenset({"true_positive", "false_positive", "dismissed"})
"""LIVE allowlist. `muted` is intentionally absent — P9.4 R0-reserved
capability. The column stays plain TEXT so P9.4 lands without re-
migration; the endpoint validator rejects `muted` fail-closed until
that work ships under Rajan's review."""

_TRIAGE_FILTER_ALLOWLIST: frozenset[str] = frozenset({"unresolved", "all"})
"""Status-filter chip allowlist. Muted variant excluded (P9.4 scope)."""


def _normalize_verdict(value):
    """Allowlist-validate a ``verdict`` POST body value. Returns
    ``(value_or_None, is_invalid)``:

    - Absent (None or empty string) → ``(None, False)``  (no verdict)
    - Valid (in LIVE allowlist)     → ``(value, False)``
    - Invalid (incl. ``"muted"``)   → ``(None, True)``  fail-closed

    The 2-tuple lets the handler distinguish "absent → no verdict set"
    from "invalid → reject the request" (p9.3.a2 F3 LIVE-rejection of
    ``muted``).
    """
    if value is None or value == "":
        return None, False
    if not isinstance(value, str):
        return None, True
    if value in _VERDICT_ALLOWLIST:
        return value, False
    return None, True


def _normalize_triage_filter(value):
    """Allowlist-validate the ``triage_filter`` query param. Returns
    ``(filter_value, is_invalid)``:

    - Absent (None or empty string) → ``("unresolved", False)`` (default;
      p9.3.a2 D-Unresolved-default-active — operator's todo is the
      default landing)
    - Valid (in allowlist)          → ``(value, False)``
    - Invalid                       → ``(None, True)`` fail-closed
    """
    if value is None or value == "":
        return "unresolved", False
    if not isinstance(value, str):
        return None, True
    if value in _TRIAGE_FILTER_ALLOWLIST:
        return value, False
    return None, True


def _aggregate_verdict_counts(alerts):
    """Returns ``{verdict_or_'unresolved': count}`` for the dataset, plus
    ``"all"`` = total. ``verdict_counts["all"]`` MUST equal
    ``len(alerts)`` (NOT sum of triaged-only) so the operator does not
    misread the chip row as Vigil's complete triage state. Mirrors p9.2
    M6 carry-forward.
    """
    counts = {"all": len(alerts), "unresolved": 0}
    for a in alerts:
        v = a.get("verdict")
        if v is None:
            counts["unresolved"] += 1
        else:
            counts[v] = counts.get(v, 0) + 1
    return counts


def apply_triage_filter(alerts, filter_param):
    """Orchestration over the alert dicts. Returns
    ``(filtered_alerts, is_invalid)``:

    - Invalid param   → ``([], True)`` fail-closed
    - ``"unresolved"`` → only verdict-None alerts (operator todo)
    - ``"all"``        → pass-through
    - Absent param    → defaults to ``"unresolved"`` via
      ``_normalize_triage_filter``
    """
    normalized, is_invalid = _normalize_triage_filter(filter_param)
    if is_invalid:
        return [], True
    if normalized == "all":
        return alerts, False
    # "unresolved" — verdict is None
    return [a for a in alerts if a.get("verdict") is None], False


def derive_and_filter_rows(filtered_rows, filter_param):
    """Handler-side orchestration over the alerts API row tuples
    ``(r, data, sev, cats, dismissed, conf, verdict)``. Returns
    ``(filtered_rows_after_triage_filter, verdict_counts, is_invalid)``.

    Counts are aggregated via ``_aggregate_verdict_counts`` (the tested
    dict-API helper, on the production path). Validation routes through
    ``_normalize_triage_filter`` (also tested). The filter PREDICATE is
    applied directly to the tuple's verdict column (``t[6]``) — robust
    against any future maintainer changing ``apply_triage_filter``'s
    return semantics to materialise copies (architect note 2026-06-24
    fold-in: identity-based dict alignment is fragile across module
    boundaries; ``t[6]`` inspection isn't).

    Counts are computed BEFORE the filter is applied so chip badges
    remain truthful even when a chip is active.
    """
    # Project tuples → dicts so the tested aggregator sees the same
    # shape it's tested against. The verdict column is the LAST tuple
    # element (handler tuple shape extended for P9.3).
    data_dicts = [{**(t[1] if t[1] else {}), "verdict": t[6]} for t in filtered_rows]
    verdict_counts = _aggregate_verdict_counts(data_dicts)
    normalized, is_invalid = _normalize_triage_filter(filter_param)
    if is_invalid:
        return [], verdict_counts, True
    if normalized == "all":
        return filtered_rows, verdict_counts, False
    # "unresolved" — filter on verdict column directly (no dict alignment).
    return ([t for t in filtered_rows if t[6] is None], verdict_counts, False)
