"""P9.2 — Alerts pattern derivation + allowlist + fail-closed filter helpers.

Companion to ``supply_chain_risk.py`` (the P9.1 sibling). Single-responsibility
module: pattern-taxonomy allowlist, fail-closed normalization, dataset-wide
aggregation, server-side filter. No I/O, no DB, no network — pure Python
over already-fetched alert rows.

Locked by judge p9.2.a2 APPROVE-WITH-FIX (2026-06-22):

  * Server-side ``pattern_counts`` over the FULL filtered dataset (before
    pagination LIMIT) — fixes the §4.5 page-scoped undercount the existing
    client-side `patternCounts` at dashboard.html:3514-3525 had.
  * ``_PATTERN_ALLOWLIST`` is the FULL 22-key set derived programmatically
    from ``SENSITIVE_PATTERNS.keys()``. NEVER hardcode 22 — the allowlist
    follows whatever set ships, including any future additions.
  * Invalid ``pattern`` query param → ``([], True)`` fail-closed return
    from ``apply_pattern_filter``. The handler routes this to ``alerts=[]
    + pattern_filter_invalid=True`` in the response. Even a frontend that
    ignores the flag CANNOT render the unfiltered set as if filtered (this
    was the §4.5 inversion the verdict's APPROVE-WITH-FIX correction
    closed).
  * The 5 chip ``data-pattern`` values are a curated user-facing SUBSET of
    the 22-key allowlist. The chip subset is in `dashboard.html`, not here.
"""

from __future__ import annotations

from claude_monitoring.constants import SENSITIVE_PATTERNS

# Programmatic — never hardcode the count. Currently 22 keys; future
# additions to SENSITIVE_PATTERNS flow into the allowlist automatically.
_PATTERN_ALLOWLIST: frozenset[str] = frozenset(SENSITIVE_PATTERNS.keys())


def _normalize_pattern_filter(value):
    """Allowlist-validate the ``pattern`` query param. Returns a 2-tuple
    ``(filter_value_or_None, is_invalid)``:

    - Absent (None or empty string) → ``(None, False)`` — no filter, show all.
    - Valid (in allowlist)          → ``(value, False)`` — apply this filter.
    - Invalid (anything else)       → ``(None, True)`` — fail-closed signal.

    The 2-tuple lets the handler distinguish "absent → show all" from
    "invalid → show NONE" (per p9.2.a2 APPROVE-WITH-FIX correction).
    """
    if value is None or value == "":
        return None, False
    if not isinstance(value, str):
        return None, True
    if value in _PATTERN_ALLOWLIST:
        return value, False
    return None, True


def _aggregate_pattern_counts(alerts):
    """Returns ``{pattern: count}`` for every pattern observed in ``alerts``,
    plus an ``"all"`` key counting every alert (regardless of whether it
    matches the chip subset).

    Per p9.2.a2 verdict M6 carry-forward: ``counts["all"]`` MUST equal
    ``len(alerts)`` (not ``sum(5_chip_keys)``) so the operator does not
    misread the curated 5-chip row as Vigil's complete detection set.
    """
    counts = {"all": len(alerts)}
    for a in alerts:
        for p in a.get("patterns") or []:
            counts[p] = counts.get(p, 0) + 1
    return counts


def apply_pattern_filter(alerts, pattern_param):
    """Orchestration helper. Returns ``(filtered_alerts, is_invalid)``:

    - Invalid param → ``([], True)``  (fail-closed; handler wires
      ``alerts=[] + pattern_filter_invalid=True`` into the response).
    - Valid param   → ``(matching, False)`` (Python ``in`` over
      ``a.get("patterns")``).
    - Absent param  → ``(alerts, False)`` (no filter, pass-through).
    """
    normalized, is_invalid = _normalize_pattern_filter(pattern_param)
    if is_invalid:
        return [], True
    if normalized is None:
        return alerts, False
    return [a for a in alerts if normalized in (a.get("patterns") or [])], False


def derive_and_filter_rows(filtered_rows, pattern_param):
    """Handler-side orchestration over the alerts API row tuples
    ``(r, data, sev, cats, dismissed, conf)``. Returns
    ``(filtered_rows_after_pattern_filter, pattern_counts, is_invalid)``.

    Projects each row tuple's ``data`` dict to the dict-API helpers so
    ``_aggregate_pattern_counts`` and ``apply_pattern_filter`` ARE on
    the production path — the test coverage of those helpers therefore
    guards what the handler actually runs (architect-review fix
    2026-06-22: previously the loop was inlined here, leaving the
    tested helpers dead in production).

    NOTE on the "FULL filtered set" claim: the upstream handler caps the
    SQL at ``LIMIT 1000``, so this orchestration is dataset-wide up to
    that cap. P9.3 (Alerts triage with the ``alert_triage`` join) is the
    natural forcing function to push the counts into ``GROUP BY`` SQL
    and remove the cap.
    """
    # Project tuples → dicts so the tested helpers see the same shape
    # they're tested against. Identity-preserving — the projection is
    # only used for the count/filter contract; the original tuples are
    # returned in `out_rows` so the handler's pass-2 enrichment paths
    # are unchanged.
    data_dicts = [t[1] for t in filtered_rows]
    pattern_counts = _aggregate_pattern_counts(data_dicts)
    _filtered_dicts, is_invalid = apply_pattern_filter(data_dicts, pattern_param)
    if is_invalid:
        return [], pattern_counts, True
    if len(_filtered_dicts) == len(data_dicts):
        # No filter applied (absent or 'all' case); pass tuples through.
        return filtered_rows, pattern_counts, False
    # A filter was applied; rebuild the tuple list aligned with the
    # filtered dicts (preserves tuple position for downstream pass-2).
    keep_ids = {id(d) for d in _filtered_dicts}
    return (
        [t for t in filtered_rows if id(t[1]) in keep_ids],
        pattern_counts,
        False,
    )
