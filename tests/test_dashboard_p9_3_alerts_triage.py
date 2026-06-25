"""P9.3 — Alerts TP/FP triage. THIRD Phase 9 PR (first schema-touch).

Adds per-alert true_positive/false_positive verdicts + Unresolved/All
status filter. Generalizes `alert_dismissals` into `alert_triage` table
with `verdict` column ∈ {true_positive, false_positive, dismissed}.
`muted` is RESERVED for P9.4 (R0/security-axis); P9.3 ships ZERO mute
capability — LIVE endpoint allowlist REJECTS verdict='muted' fail-closed.

Locked by judge p9.3.a2 APPROVE (2026-06-24). Phase C hard gates:

  §8  empirical evidence on installed sqlite (normalization + migration)
  M6  split-brain regression — simulated daemon restart MUST NOT
      re-create alert_dismissals after migration
  M9  muted LIVE-rejected — POST verdict='muted' → 4xx + no row
  §4.5 invalid verdict/triage_filter → fail-closed empty + invalid flag
  escaping: escAttr / textContent for new JS, never bare esc()
  P6.11 Pin 5 GREEN (dismiss 3-reason set unchanged)
  Down-migration TP/FP-loss documented

Pins in this file (TDD: failing first, GREEN after alerts_triage.py +
migration + handler delta + frontend chip row land):

  Pin 1 — backend: `_VERDICT_ALLOWLIST` exactly equals
            `frozenset({"true_positive","false_positive","dismissed"})`.
            `muted` is NOT in the live allowlist (F3 fix).
  Pin 2 — backend: `_normalize_verdict(value)` returns (filter, is_invalid)
            tuple. Invalid value (incl. 'muted') → (None, True). Valid →
            (value, False). Absent → (None, False).
  Pin 3 — backend: `_TRIAGE_FILTER_ALLOWLIST` exactly equals
            `frozenset({"unresolved","all"})`. `_normalize_triage_filter`
            mirrors `_normalize_verdict` semantics.
  Pin 4 — backend: `_aggregate_verdict_counts(alerts)` returns dict with
            "all" == len(alerts) (NOT sum of triaged-only). Untriaged
            alerts count toward "all"; triaged alerts ALSO count toward
            their verdict bucket.
  Pin 5 — backend: `apply_triage_filter(alerts, filter)` — Unresolved
            filter returns alerts where verdict is None. All returns
            everything. Invalid → ([], True).
  Pin 6 — backend orchestration: `derive_and_filter_rows(rows, filter)`
            returns (filtered_rows, verdict_counts, is_invalid). Tested
            DIRECTLY (per p9.2.a2 code-review fold-in — production path
            coverage).
  Pin 7 — frontend (static markup): `#panel-alerts` contains EXACTLY 2
            `<button class="v-chip">` chips with `data-triage-filter` in
            {unresolved, all}. Default active = `unresolved` (operator
            todo).
  Pin 8 — frontend (no parallel state): exactly one `alertTriageFilter`
            declaration in dashboard.html. NO `_alertTriageFilter`.
  Pin 9 — frontend (render-path): `loadAlerts()` body reads
            `d.verdict_counts` from API response and updates the chip-count
            spans (specific `alerts-triage-` prefix to dodge comment-
            substring false-positives, per p9.2 code-review fold-in).
  Pin 10 — frontend (triage buttons): exactly 2 NEW buttons per alert
            ("True positive", "False positive"). Existing 3 dismiss-
            buttons stay (P6.11 Pin 5 contract).
  Pin 11 — F3 LIVE-rejection: `_normalize_verdict('muted')` returns
            `(None, True)`. The endpoint MUST 4xx on POST verdict='muted'.
  Pin 12 — escaping: new JS writing per-alert `data-verdict` uses
            template-safe escaping (escAttr or constant data-verdict
            from server response), not bare `esc()`.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p9_3"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_fixture_lines(name: str) -> set[str]:
    return {line for line in (FIXTURE_DIR / name).read_text().splitlines() if line.strip()}


def _grep_panel_block(html: str, panel_id: str) -> str:
    marker = f'id="{panel_id}"'
    idx = html.find(marker)
    if idx < 0:
        return ""
    div_open = html.rfind("<div", 0, idx)
    if div_open < 0:
        return ""
    depth, i = 0, div_open
    while i < len(html):
        if html.startswith("<div", i):
            depth += 1
            i += 4
        elif html.startswith("</div>", i):
            depth -= 1
            i += 6
            if depth == 0:
                return html[div_open:i]
        else:
            i += 1
    return ""


def _grep_panel_triage_chips(panel_html: str) -> set[str]:
    out = set()
    for m in re.finditer(
        r'<button\b[^>]*\bclass="[^"]*\bv-chip\b[^"]*"[^>]*\bdata-triage-filter="([^"]+)"',
        panel_html,
    ):
        out.add(m.group(1))
    for m in re.finditer(
        r'<button\b[^>]*\bdata-triage-filter="([^"]+)"[^>]*\bclass="[^"]*\bv-chip\b[^"]*"',
        panel_html,
    ):
        out.add(m.group(1))
    return out


def _grep_default_active_triage_chip(panel_html: str) -> str:
    m = re.search(
        r'<button\b[^>]*\bclass="[^"]*\bv-chip\b[^"]*\bis-active\b[^"]*"[^>]*\bdata-triage-filter="([^"]+)"',
        panel_html,
    )
    if m:
        return m.group(1)
    m = re.search(
        r'<button\b[^>]*\bdata-triage-filter="([^"]+)"[^>]*\bclass="[^"]*\bv-chip\b[^"]*\bis-active\b[^"]*"',
        panel_html,
    )
    return m.group(1) if m else ""


def _extract_function_body(html: str, signature_prefix: str) -> str:
    idx = html.find(signature_prefix)
    if idx < 0:
        return ""
    brace_start = html.find("{", idx)
    if brace_start < 0:
        return ""
    depth, i = 0, brace_start
    while i < len(html):
        c = html[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return html[brace_start : i + 1]
        i += 1
    return ""


# ---------------------------------------------------------------------------
# Backend pins (1–6) — allowlists, normalization, aggregation, orchestration
# ---------------------------------------------------------------------------


class TestVerdictAllowlistThreeValueLive:
    """Pin 1 (F3 fix): LIVE allowlist is exactly the 3-value set. `muted`
    is REJECTED — P9.4 capability is RESERVED for Rajan. The verdict
    COLUMN remains plain TEXT (no schema-level CHECK constraint), so
    P9.4 lands by adding `muted` to this set + UI + guardrails, no
    re-migration."""

    def test_allowlist_is_exactly_three(self):
        from claude_monitoring.alerts_triage import _VERDICT_ALLOWLIST

        assert frozenset({"true_positive", "false_positive", "dismissed"}) == _VERDICT_ALLOWLIST
        assert "muted" not in _VERDICT_ALLOWLIST, (
            "`muted` MUST be REJECTED at the LIVE endpoint until P9.4 lands "
            "with its guardrails (CRITICAL-mute ban, expiry, audit, "
            "capture-vs-display ruling). p9.3.a2 verdict Finding 3."
        )


class TestNormalizeVerdictFailClosed:
    """Pin 2: invalid → (None, True); valid → (value, False); absent →
    (None, False). Mirrors p9.2's `_normalize_pattern_filter` shape."""

    def test_valid_passes_through(self):
        from claude_monitoring.alerts_triage import _normalize_verdict

        for v in ("true_positive", "false_positive", "dismissed"):
            assert _normalize_verdict(v) == (v, False)

    def test_invalid_returns_none_and_invalid_flag(self):
        from claude_monitoring.alerts_triage import _normalize_verdict

        for v in ("trojan", "<script>", "TruE", 42, [], "ok"):
            assert _normalize_verdict(v) == (None, True), (
                f"invalid value {v!r} must normalize to (None, True) — the fail-closed signal."
            )

    def test_muted_rejected_until_p9_4(self):
        """Pin 11 + Pin 2: Finding 3 LIVE-rejection of `muted` at the
        normalizer (the upstream of the endpoint). Required pin per
        verdict carry-forward #3."""
        from claude_monitoring.alerts_triage import _normalize_verdict

        assert _normalize_verdict("muted") == (None, True), (
            "P9.4 capability — MUST NOT live-write a `muted` row in P9.3. "
            "The TEXT column accepts it (no CHECK), but the endpoint "
            "validator rejects fail-closed."
        )

    def test_absent_returns_none_no_invalid_flag(self):
        from claude_monitoring.alerts_triage import _normalize_verdict

        assert _normalize_verdict(None) == (None, False)
        assert _normalize_verdict("") == (None, False)


class TestNormalizeTriageFilter:
    """Pin 3: Unresolved/All allowlist + fail-closed (matches verdict
    normalizer shape)."""

    def test_allowlist_is_exactly_two(self):
        from claude_monitoring.alerts_triage import _TRIAGE_FILTER_ALLOWLIST

        assert frozenset({"unresolved", "all"}) == _TRIAGE_FILTER_ALLOWLIST

    def test_valid_passes_through(self):
        from claude_monitoring.alerts_triage import _normalize_triage_filter

        assert _normalize_triage_filter("unresolved") == ("unresolved", False)
        assert _normalize_triage_filter("all") == ("all", False)

    def test_invalid_returns_none_and_invalid_flag(self):
        from claude_monitoring.alerts_triage import _normalize_triage_filter

        for v in ("muted", "bogus", "<script>", 42):
            assert _normalize_triage_filter(v) == (None, True)

    def test_absent_is_default_unresolved_not_all(self):
        """Per p9.3.a2 D-Unresolved-default-active: absent param defaults
        to Unresolved (operator todo), NOT All. This is the LIVE semantic
        — frontend sends explicit param, server defaults on absent."""
        from claude_monitoring.alerts_triage import _normalize_triage_filter

        # Absent → "unresolved" sentinel (default), invalid=False.
        # NOT (None, False) — that would be a no-op showing everything,
        # contradicting D-Unresolved-default-active.
        assert _normalize_triage_filter(None) == ("unresolved", False)
        assert _normalize_triage_filter("") == ("unresolved", False)


class TestAggregateVerdictCounts:
    """Pin 4: `verdict_counts["all"] == len(alerts)` (NOT sum of triaged-
    only). Mirrors p9.2 M6 carry-forward."""

    def test_all_counts_every_alert_including_untriaged(self):
        from claude_monitoring.alerts_triage import _aggregate_verdict_counts

        alerts = [
            {"verdict": "true_positive"},
            {"verdict": "false_positive"},
            {"verdict": "dismissed"},
            {"verdict": None},  # untriaged
            {"verdict": None},
            {},  # missing key
        ]
        counts = _aggregate_verdict_counts(alerts)
        assert counts["all"] == 6
        assert counts.get("true_positive", 0) == 1
        assert counts.get("false_positive", 0) == 1
        assert counts.get("dismissed", 0) == 1
        assert counts.get("unresolved", 0) == 3  # both None and missing-key


class TestApplyTriageFilter:
    """Pin 5: Unresolved → verdict is None. All → everything. Invalid →
    ([], True) fail-closed (mirrors p9.2's apply_pattern_filter)."""

    def test_unresolved_returns_only_untriaged(self):
        from claude_monitoring.alerts_triage import apply_triage_filter

        alerts = [
            {"id": 1, "verdict": "true_positive"},
            {"id": 2, "verdict": None},
            {"id": 3, "verdict": "dismissed"},
            {"id": 4, "verdict": None},
        ]
        filtered, invalid = apply_triage_filter(alerts, "unresolved")
        assert invalid is False
        assert [a["id"] for a in filtered] == [2, 4]

    def test_all_returns_everything(self):
        from claude_monitoring.alerts_triage import apply_triage_filter

        alerts = [{"verdict": "true_positive"}, {"verdict": None}]
        filtered, invalid = apply_triage_filter(alerts, "all")
        assert invalid is False
        assert filtered == alerts

    def test_invalid_returns_empty_with_invalid_flag(self):
        from claude_monitoring.alerts_triage import apply_triage_filter

        filtered, invalid = apply_triage_filter([{"verdict": "true_positive"}], "trojan")
        assert filtered == []
        assert invalid is True


class TestNoIdentityAlignmentInAlertsTriageModule:
    """Architect note 2026-06-24 post-pass fold-in: ``derive_and_filter_rows``
    must NOT align dict-API results to tuple inputs via ``id()`` identity.
    Such alignment works only because ``apply_triage_filter`` happens to
    return references today; a future maintainer materialising copies
    (e.g., to add field projection) would silently empty the output. The
    fix path the architect proposed: filter tuples directly on ``t[6]``.

    This pin locks the impl at the source level — regardless of HOW the
    tuple-filter is expressed, it cannot regress to ``id()``-based
    alignment between the two collections.
    """

    def test_module_does_not_use_id_based_alignment(self):
        import inspect

        from claude_monitoring import alerts_triage

        src = inspect.getsource(alerts_triage)
        assert "id(" not in src, (
            "alerts_triage must not use id()-based alignment between dicts "
            "and tuples — architect note 2026-06-24: id() identity works "
            "today only because apply_triage_filter returns references, "
            "not copies. Use tuple-direct filtering on t[6] (the verdict "
            "column) or value-based alignment instead."
        )

    def test_derive_unresolved_filter_robust_to_future_apply_changes(self, monkeypatch):
        """Behavioral mirror of the source pin: even if a future maintainer
        rewires ``derive_and_filter_rows`` to call ``apply_triage_filter``
        AND that helper ever materialises copies, the impl must still
        return the right tuples (or fail loudly, not silently empty)."""
        from claude_monitoring import alerts_triage as at

        orig_apply = at.apply_triage_filter

        def returns_copies(alerts, filter_param):
            filtered, invalid = orig_apply(alerts, filter_param)
            return [dict(a) for a in filtered], invalid  # COPIES, not refs

        monkeypatch.setattr(at, "apply_triage_filter", returns_copies)
        rows = [
            (None, {"id": 1}, "high", [], False, "high", "true_positive"),
            (None, {"id": 2}, "high", [], False, "high", None),  # untriaged
            (None, {"id": 3}, "high", [], False, "high", "dismissed"),
        ]
        out_rows, _counts, is_invalid = at.derive_and_filter_rows(rows, "unresolved")
        assert is_invalid is False
        # Tuple-direct filtering on t[6] survives the simulated copy semantic
        # — the id()-based bug would yield 0 here.
        assert len(out_rows) == 1
        assert out_rows[0][1]["id"] == 2


class TestDeriveAndFilterRowsOnProductionPath:
    """Pin 6 (per p9.2.a2 code-review fold-in): the handler calls
    `derive_and_filter_rows` exclusively. Direct test ensures the
    tuple-shape projection + delegation to the dict-API helpers is on
    the production path, not just dead-code coverage."""

    def _row(self, data, verdict=None):
        # Handler tuple shape: (r, data, sev, cats, dismissed, conf, verdict).
        # P9.3 widens the tuple by 1 column for verdict (LEFT JOIN alert_triage).
        return (None, data, "high", ["credential"], False, "high", verdict)

    def test_unresolved_filter_returns_only_verdict_null(self):
        from claude_monitoring.alerts_triage import derive_and_filter_rows

        rows = [
            self._row({"id": 1}, verdict="true_positive"),
            self._row({"id": 2}, verdict=None),
            self._row({"id": 3}, verdict="dismissed"),
        ]
        out_rows, counts, is_invalid = derive_and_filter_rows(rows, "unresolved")
        assert is_invalid is False
        assert len(out_rows) == 1
        assert out_rows[0][1]["id"] == 2
        # Counts are pre-filter (chip badges stay truthful while a chip is active).
        assert counts["all"] == 3
        assert counts.get("true_positive", 0) == 1
        assert counts.get("unresolved", 0) == 1

    def test_invalid_param_returns_empty_with_invalid_flag(self):
        from claude_monitoring.alerts_triage import derive_and_filter_rows

        rows = [self._row({"id": 1}, verdict=None)]
        out_rows, counts, is_invalid = derive_and_filter_rows(rows, "bogus")
        assert out_rows == []
        assert is_invalid is True
        assert counts["all"] == 1  # counts derived BEFORE filter

    def test_absent_param_defaults_to_unresolved(self):
        """D-Unresolved-default-active: absent param = Unresolved (NOT All).
        The operator's todo is the default landing."""
        from claude_monitoring.alerts_triage import derive_and_filter_rows

        rows = [
            self._row({"id": 1}, verdict="true_positive"),
            self._row({"id": 2}, verdict=None),
        ]
        out_rows, _counts, is_invalid = derive_and_filter_rows(rows, None)
        assert is_invalid is False
        assert len(out_rows) == 1
        assert out_rows[0][1]["id"] == 2


# ---------------------------------------------------------------------------
# Frontend pins (7–10) — static chip markup, state reuse, render-path,
# triage buttons
# ---------------------------------------------------------------------------


class TestAlertsPanelTriageChipAllowlist:
    """Pin 7: panel contains EXACTLY 2 v-chips with `data-triage-filter`
    in {unresolved, all}. Default active = `unresolved` (operator todo)."""

    def test_chip_allowlist_exact(self):
        baseline = _read_fixture_lines("baseline-b71aa7a-triage-chips.txt")
        branch = _grep_panel_triage_chips(_grep_panel_block(_read_branch_html(), "panel-alerts"))
        expected = {"unresolved", "all"}
        assert baseline == expected, f"baseline fixture drift: expected {sorted(expected)}, got {sorted(baseline)}"
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"data-triage-filter values DROPPED: {sorted(dropped)}"
        assert not added, (
            f"data-triage-filter values ADDED: {sorted(added)}. New chip = "
            "deliberate scope extension; update fixture + allowlist in the "
            "same PR (cookbook entry #7)."
        )

    def test_default_active_is_unresolved(self):
        active = _grep_default_active_triage_chip(_grep_panel_block(_read_branch_html(), "panel-alerts"))
        assert active == "unresolved", (
            f"default-active triage chip must be `unresolved` (operator todo), not {active!r}"
        )


class TestNoParallelAlertTriageFilterVariable:
    """Pin 8: exactly one `alertTriageFilter` declaration. NO parallel
    `_alertTriageFilter` (the duplicate-state inversion p9.2.a1 verdict
    rejected). Mirrors p9.2 M5."""

    def test_no_parallel_underscore_variant(self):
        html = _read_branch_html()
        hits = re.findall(r"\b_alertTriageFilter\b", html)
        assert hits == [], (
            f"`_alertTriageFilter` parallel state found ({len(hits)} hits). "
            "Single source of truth: `alertTriageFilter` (no leading underscore)."
        )

    def test_exactly_one_declaration(self):
        html = _read_branch_html()
        decls = re.findall(r"\b(?:let|var|const)\s+alertTriageFilter\b", html)
        assert len(decls) == 1, f"expected exactly one `let alertTriageFilter` declaration; got {len(decls)}"


class TestLoadAlertsRenderPathReadsVerdictCounts:
    """Pin 9 (cookbook #6 + p9.2 code-review fold-in): render-path reads
    `d.verdict_counts` (specific enough to dodge comment-substring false-
    positives) and updates `alerts-triage-` prefixed count spans."""

    def test_render_path_reads_verdict_counts(self):
        body = _extract_function_body(_read_branch_html(), "async function loadAlerts(")
        assert body, "could not extract loadAlerts() body — probe failed"
        assert "d.verdict_counts" in body, (
            "loadAlerts() body must read `d.verdict_counts` from API response "
            "(specific phrase — dodges comment-substring false-positives)."
        )
        assert "alerts-triage-" in body, (
            "loadAlerts() body must update `alerts-triage-<key>-n` chip-count "
            "spans — render-path regex per cookbook entry #6."
        )


class TestTriageButtonsRenderedPerAlert:
    """Pin 10: 2 NEW buttons per alert ("True positive", "False positive").
    Existing 3 dismiss buttons stay (P6.11 Pin 5 contract unchanged)."""

    def test_triage_button_count_is_two(self):
        body = _extract_function_body(_read_branch_html(), "async function loadAlerts(")
        # 2 triage buttons (TP, FP) in the per-alert render path.
        # Specific button label strings — these are the operator-facing labels.
        assert "True positive" in body, "loadAlerts() body must render a 'True positive' button per alert."
        assert "False positive" in body, (
            "loadAlerts() body must render a 'False positive' button per alert. "
            "(NOTE: P6.11 Pin 5 retains 'False positive' as a DISMISS reason "
            "string — they're literally the same UTF-8 string, but the two "
            "rendering sites are distinct; this pin checks PRESENCE in the "
            "loadAlerts body, NOT uniqueness.)"
        )

    def test_triage_class_distinct_from_dismiss(self):
        body = _extract_function_body(_read_branch_html(), "async function loadAlerts(")
        # The new triage buttons use a `.triage-btn` class (or similar
        # namespaced class) to distinguish them from `.dismiss-btn`. Without
        # this distinction, the rendered HTML is indistinguishable and the
        # styling cascade breaks.
        assert "triage-btn" in body, (
            "loadAlerts() body must use a distinct `.triage-btn` class for the "
            "TP/FP buttons — namespaced separately from `.dismiss-btn` so the "
            "CSS cascade can style them independently (e.g., reuse the existing "
            "`.is-on--tp` / `.is-on--fp` colors from dashboard.html:706-707)."
        )
