"""P9.2 — Alerts pattern chips. SECOND Phase 9 PR.

NEW filter UI on the Alerts tab: 5 `<button class="v-chip" data-pattern>`
chips above the alerts list. Reuses existing `alertPatternFilter` state
variable (line 3471 of dashboard.html on 18b48c0) — single source of
truth across the static chip row, per-alert `.badge` chips, and URL
query string.

Architectural revision over P9.1: server-side `pattern_counts` over the
FULL filtered dataset (not paginated page) + server-side `pattern`
filter — replaces the existing page-scoped client-side dynamic
chip-summary + client-side filter. The §4.5 data-truthfulness fix
established in p9.2.a2 verdict (judge APPROVE-WITH-FIX, 2026-06-22).

Cookbook lineage:
  * Refined cookbook entry #6 (judge p6.11 Phase B ruling 2026-06-21):
    static chip markup = static-markup pin; chip-count JS updates =
    render-path regex.
  * Cookbook entry #7 (p9.1.a1 ratified) — this PR repurposes P6.11's
    Pin 6 zero-`v-chip` assertion into a positive 5-chip allowlist in
    the SAME PR (the second worked example of entry #7).

Tests in this file (TDD: written FAILING first per judge APPROVE-WITH-FIX
direction; expected to GREEN once `alerts_pattern.py` + handler delta +
frontend chip row land):

  Pin 1 — backend: `_PATTERN_ALLOWLIST` is exactly `frozenset(
            SENSITIVE_PATTERNS.keys())` — 22 keys, derived programmatically.
  Pin 2 — backend: `_normalize_pattern_filter(value)` returns a 2-tuple
            `(filter, is_invalid)`. Invalid value → `(None, True)`
            (fail-closed signal). Valid value → `(value, False)`. Absent
            → `(None, False)`.
  Pin 3 — backend: `_aggregate_pattern_counts(alerts)` derives counts
            across all 22 patterns; `pattern_counts["all"]` equals total
            alert count (NOT sum of 5-chip subset).
  Pin 4 — backend: when handler receives an INVALID pattern param, the
            response contains `alerts=[]` AND `stats.pattern_filter_invalid
            == True`. NEVER returns the unfiltered set (fail-closed,
            p9.2.a2 verdict APPROVE-WITH-FIX correction).
  Pin 5 — frontend (static markup): `#panel-alerts` contains EXACTLY 5
            `<button class="v-chip">` chips with `data-pattern` in
            {all, aws_key, github_token, api_key_generic, private_key,
            credit_card}. Default active = `all`.
  Pin 6 — frontend (no parallel state): the file contains EXACTLY ONE
            declaration of `alertPatternFilter` (the existing one at
            line 3471). NO `_alertPatternFilter` (the parallel-state
            inversion p9.2.a1 verdict explicitly rejected). Verified
            via grep over the whole dashboard.html.
  Pin 7 — render-path (cookbook #6): `loadAlerts()` body reads
            `stats.pattern_counts` from the API response and updates
            `.v-chip__n` count spans. Body must NOT contain the removed
            client-side filter (`filtered.filter(a => ...)`) or the
            removed dynamic chip-summary (`patternCounts = {}` local).
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p9_2"


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


def _grep_panel_v_chip_data_patterns(panel_html: str) -> set[str]:
    """`data-pattern` values on `<button class="v-chip">` inside the panel."""
    out = set()
    for m in re.finditer(r'<button\b[^>]*\bclass="[^"]*\bv-chip\b[^"]*"[^>]*\bdata-pattern="([^"]+)"', panel_html):
        out.add(m.group(1))
    for m in re.finditer(r'<button\b[^>]*\bdata-pattern="([^"]+)"[^>]*\bclass="[^"]*\bv-chip\b[^"]*"', panel_html):
        out.add(m.group(1))
    return out


def _grep_default_active_chip_value(panel_html: str) -> str:
    m = re.search(
        r'<button\b[^>]*\bclass="[^"]*\bv-chip\b[^"]*\bis-active\b[^"]*"[^>]*\bdata-pattern="([^"]+)"',
        panel_html,
    )
    if m:
        return m.group(1)
    m = re.search(
        r'<button\b[^>]*\bdata-pattern="([^"]+)"[^>]*\bclass="[^"]*\bv-chip\b[^"]*\bis-active\b[^"]*"',
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
# Backend pins (1–4) — derivation, allowlist, fail-closed normalization
# ---------------------------------------------------------------------------


class TestPatternAllowlistIsFullSensitivePatternsKeys:
    """Pin 1: `_PATTERN_ALLOWLIST` is exactly the full 22-key set, derived
    programmatically from `SENSITIVE_PATTERNS.keys()`. NEVER hardcode 22
    (judge p9.2.a2 verdict: "keep it programmatic"). Future keys flow
    in automatically; the 5-chip operator-facing subset is separate."""

    def test_allowlist_equals_sensitive_patterns_keys(self):
        from claude_monitoring.alerts_pattern import _PATTERN_ALLOWLIST
        from claude_monitoring.constants import SENSITIVE_PATTERNS

        assert frozenset(SENSITIVE_PATTERNS.keys()) == _PATTERN_ALLOWLIST, (
            "_PATTERN_ALLOWLIST must be programmatically derived from "
            "SENSITIVE_PATTERNS.keys(); a hardcoded set will drift when new "
            "patterns ship."
        )
        assert len(_PATTERN_ALLOWLIST) >= 22


class TestNormalizePatternFilterFailClosed:
    """Pin 2: invalid values normalize to `(None, True)` — the fail-closed
    signal. Valid values normalize to `(value, False)`. Absent values
    normalize to `(None, False)`. Per p9.2.a2 verdict APPROVE-WITH-FIX:
    the 2-tuple lets the handler route invalid → `alerts=[]` + flag,
    distinct from absent → no filter (show all)."""

    def test_valid_passes_through(self):
        from claude_monitoring.alerts_pattern import _normalize_pattern_filter

        for v in ("aws_key", "github_token", "openai_key", "ssn"):
            assert _normalize_pattern_filter(v) == (v, False)

    def test_invalid_returns_none_and_invalid_flag(self):
        from claude_monitoring.alerts_pattern import _normalize_pattern_filter

        for v in ("'; DROP TABLE", "<script>", "aws-key", "MaLiCiOuS", "muted"):
            assert _normalize_pattern_filter(v) == (None, True), (
                f"invalid value {v!r} must normalize to (None, True) — the "
                "fail-closed signal — never to (None, False) which would "
                "silently render the unfiltered set as if filtered."
            )

    def test_empty_string_is_absent_not_invalid(self):
        """URL `?pattern=` (empty value) is conventionally absent, not
        invalid. Per p9.2.a2 verdict: 'absent = no filter = all is
        unchanged and correct'."""
        from claude_monitoring.alerts_pattern import _normalize_pattern_filter

        assert _normalize_pattern_filter("") == (None, False)

    def test_absent_returns_none_no_invalid_flag(self):
        from claude_monitoring.alerts_pattern import _normalize_pattern_filter

        assert _normalize_pattern_filter(None) == (None, False)


class TestAggregatePatternCountsAllSumsAcrossAll22:
    """Pin 3: `pattern_counts["all"]` counts every alert, including those
    matching ONLY non-chip patterns. p9.2.a2 verdict M6 carry-forward:
    operator must not misread the 5-chip row as Vigil's complete
    detection set."""

    def test_all_equals_total_not_just_chip_subset(self):
        from claude_monitoring.alerts_pattern import _aggregate_pattern_counts

        alerts = [
            {"patterns": ["aws_key"]},
            {"patterns": ["github_token"]},
            {"patterns": ["openai_key"]},  # non-chip pattern
            {"patterns": ["slack_webhook"]},  # non-chip pattern
            {"patterns": ["api_key_generic", "private_key"]},  # multi-pattern
            {"patterns": []},
        ]
        counts = _aggregate_pattern_counts(alerts)
        assert counts["all"] == len(alerts), (
            f"`pattern_counts['all']` must count every alert (={len(alerts)}), "
            f"got {counts['all']}. The 5 chip values are a SUBSET of 22 "
            "patterns; 'all' must sum across the full 22, not just the chips."
        )
        # Confirm specific pattern keys are populated for both chip and non-chip
        assert counts.get("aws_key", 0) == 1
        assert counts.get("openai_key", 0) == 1  # non-chip — still counted
        assert counts.get("slack_webhook", 0) == 1  # non-chip — still counted


class TestDeriveAndFilterRowsOnProductionPath:
    """Pin 4b (code-review conf 88 fold-in 2026-06-22): the production
    handler calls `derive_and_filter_rows` exclusively — direct test
    coverage on it ensures the tuple-shape projection + delegation to
    `apply_pattern_filter` and `_aggregate_pattern_counts` produce the
    fail-closed contract on the actual production line, not just on
    the dict-API helpers."""

    def _make_row(self, data):
        # Mirror the handler's tuple shape (r, data, sev, cats, dismissed, conf).
        return (None, data, "high", ["credential"], False, "high")

    def test_invalid_param_returns_empty_with_invalid_flag(self):
        from claude_monitoring.alerts_pattern import derive_and_filter_rows

        rows = [self._make_row({"patterns": ["aws_key"]}), self._make_row({"patterns": ["openai_key"]})]
        out_rows, counts, is_invalid = derive_and_filter_rows(rows, "bogus_xyz")
        assert out_rows == []
        assert is_invalid is True
        assert counts["all"] == 2  # counts derived BEFORE filter — still reflect dataset

    def test_valid_param_filters_via_tuple_projection(self):
        from claude_monitoring.alerts_pattern import derive_and_filter_rows

        rows = [
            self._make_row({"patterns": ["aws_key"]}),
            self._make_row({"patterns": ["github_token"]}),
            self._make_row({"patterns": ["aws_key", "private_key"]}),
        ]
        out_rows, counts, is_invalid = derive_and_filter_rows(rows, "aws_key")
        assert is_invalid is False
        assert len(out_rows) == 2  # rows 0 and 2 contain aws_key
        # Tuple identity preserved — handler's pass-2 enrichment can still
        # unpack the tuples without re-fetching from DB.
        assert all(isinstance(t, tuple) and len(t) == 6 for t in out_rows)
        assert counts["all"] == 3
        assert counts["aws_key"] == 2

    def test_absent_param_passes_tuples_through(self):
        from claude_monitoring.alerts_pattern import derive_and_filter_rows

        rows = [self._make_row({"patterns": ["aws_key"]})]
        out_rows, _counts, is_invalid = derive_and_filter_rows(rows, None)
        assert is_invalid is False
        assert out_rows == rows  # identity, not just equality


class TestApplyPatternFilterFailsClosed:
    """Pin 4 (judge p9.2.a2 APPROVE-WITH-FIX): the orchestration helper
    enforces the fail-closed contract — invalid pattern param returns
    `([], True)` (empty alerts + invalid flag), NEVER the unfiltered set.
    This is the contract the handler wires into `stats.pattern_filter_invalid`
    + `alerts=[]`. M1 mutation tests this directly."""

    def test_invalid_returns_empty_and_invalid_flag(self):
        from claude_monitoring.alerts_pattern import apply_pattern_filter

        alerts = [{"patterns": ["aws_key"]}, {"patterns": ["github_token"]}]
        filtered, invalid = apply_pattern_filter(alerts, "bogus_xyz")
        assert filtered == [], (
            "fail-closed contract: invalid pattern → alerts=[]. NEVER return "
            "the unfiltered set with just a flag, which a frontend ignoring "
            "the flag would render as 'unfiltered everything' — the §4.5 "
            "inversion p9.2.a2 verdict APPROVE-WITH-FIX corrected."
        )
        assert invalid is True

    def test_valid_filters_correctly(self):
        from claude_monitoring.alerts_pattern import apply_pattern_filter

        alerts = [
            {"id": 1, "patterns": ["aws_key"]},
            {"id": 2, "patterns": ["github_token"]},
            {"id": 3, "patterns": ["aws_key", "private_key"]},
        ]
        filtered, invalid = apply_pattern_filter(alerts, "aws_key")
        assert invalid is False
        assert [a["id"] for a in filtered] == [1, 3]

    def test_absent_returns_unfiltered(self):
        from claude_monitoring.alerts_pattern import apply_pattern_filter

        alerts = [{"patterns": ["aws_key"]}, {"patterns": []}]
        filtered, invalid = apply_pattern_filter(alerts, None)
        assert invalid is False
        assert filtered == alerts


# ---------------------------------------------------------------------------
# Frontend pins (5–7) — static chip markup, state reuse, render-path
# ---------------------------------------------------------------------------


class TestAlertsPanelVChipAllowlist:
    """Pin 5: panel contains EXACTLY 5 v-chips. The 5 chip values land
    EXACTLY as the curated subset; the default-active is `all`. Per
    cookbook #7 the fixture is captured at the PR-creation SHA and the
    pin asserts the BRANCH against it (immutable baseline pattern)."""

    def test_chip_allowlist_exact(self):
        baseline = _read_fixture_lines("baseline-18b48c0-pattern-chips.txt")
        branch = _grep_panel_v_chip_data_patterns(_grep_panel_block(_read_branch_html(), "panel-alerts"))
        expected = {"all", "aws_key", "github_token", "api_key_generic", "private_key", "credit_card"}
        assert baseline == expected, f"baseline fixture drift: expected {sorted(expected)}, got {sorted(baseline)}"
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"data-pattern values DROPPED: {sorted(dropped)}"
        assert not added, (
            f"data-pattern values ADDED: {sorted(added)}. New chip = deliberate "
            "scope extension; update fixture + allowlist in the same PR "
            "(cookbook entry #7)."
        )

    def test_default_active_is_all(self):
        active = _grep_default_active_chip_value(_grep_panel_block(_read_branch_html(), "panel-alerts"))
        assert active == "all", f"default-active chip must be `all` (show-everything default), not {active!r}"


class TestNoParallelAlertPatternFilterVariable:
    """Pin 6: the file contains the EXISTING `alertPatternFilter` declaration
    (line 3471) and NO parallel `_alertPatternFilter` (the duplicate-state
    inversion p9.2.a1 verdict named at §4.4 desync). Whole-file grep —
    a parallel declaration anywhere in the JS would trip this pin."""

    def test_no_parallel_underscore_variant(self):
        html = _read_branch_html()
        # The leading underscore is the inversion shape (matches P9.1's
        # `_scRiskStatusFilter` private prefix).
        hits = re.findall(r"\b_alertPatternFilter\b", html)
        assert hits == [], (
            f"`_alertPatternFilter` found in dashboard.html: {len(hits)} "
            "occurrence(s). The existing `alertPatternFilter` (no leading "
            "underscore) is the single source of truth across the static "
            "chip row, per-alert badge chips, and URL query string. A "
            "parallel `_alertPatternFilter` is the §4.4 desync inversion "
            "p9.2.a1 verdict rejected."
        )

    def test_existing_alertpatternfilter_still_declared(self):
        html = _read_branch_html()
        # Single `let alertPatternFilter` (or `var`/`const`) at exactly one
        # site — keeps the existing variable, doesn't move/shadow it.
        decls = re.findall(r"\b(?:let|var|const)\s+alertPatternFilter\b", html)
        assert len(decls) == 1, (
            f"expected exactly one `let alertPatternFilter` declaration "
            f"(the existing one at line 3471 on 18b48c0); got {len(decls)}. "
            "P9.2 reuses the variable; it does NOT redeclare or shadow it."
        )


class TestLoadAlertsRenderPath:
    """Pin 7: `loadAlerts()` body reads `stats.pattern_counts` from API
    response and updates `.v-chip__n` count spans. The OLD client-side
    filter `filtered.filter(a => (a.patterns||[]).includes(...))` and the
    OLD dynamic chip-summary (`const patternCounts = {}; d.alerts.forEach
    (a => (a.patterns||[]).forEach(...))`) MUST be gone — replaced by the
    server-side derivation."""

    def test_render_path_uses_server_side_pattern_counts(self):
        body = _extract_function_body(_read_branch_html(), "async function loadAlerts(")
        assert body, "could not extract loadAlerts() body — probe failed"
        # Must read the server-side stats key via the API response — specific
        # enough (`d.pattern_counts`) to dodge comment-substring false-positives.
        assert "d.pattern_counts" in body, (
            "loadAlerts() body must read `d.pattern_counts` from API response. "
            "Without it the chip counts cannot reflect the dataset-wide derivation "
            "(§4.5 data-truthfulness)."
        )
        # Must update the chip-count element id family unique to P9.2.
        assert "alerts-pattern-" in body, (
            "loadAlerts() body must update the `alerts-pattern-<key>-n` chip-count "
            "spans (render-path regex per cookbook entry #6)."
        )

    def test_render_path_removed_client_side_filter(self):
        body = _extract_function_body(_read_branch_html(), "async function loadAlerts(")
        # The OLD client-side filter line at 3528-3530:
        #   if (alertPatternFilter) {
        #     filtered = filtered.filter(a => (a.patterns||[]).includes(alertPatternFilter));
        #   }
        # ... must be GONE — replaced by server-side filter.
        assert "filtered = filtered.filter" not in body, (
            "client-side `filtered.filter(...)` still present — server-side "
            "filter via `pattern` query param replaces it. The page-scoped "
            "client filter undercounts the dataset (§4.5 inversion); the fix "
            "is to delete this line, not run both."
        )

    def test_render_path_removed_dynamic_chip_summary(self):
        body = _extract_function_body(_read_branch_html(), "async function loadAlerts(")
        # The OLD dynamic top-15 chip summary at 3514-3525:
        #   const patternCounts = {};
        #   d.alerts.forEach(a => (a.patterns||[]).forEach(p => { ... }));
        # ... must be GONE — replaced by the 5 static chips reading
        # server-side stats.pattern_counts.
        assert "const patternCounts = {}" not in body, (
            "dynamic page-scoped `patternCounts` aggregation still present — "
            "server-side `stats.pattern_counts` (dataset-wide) replaces it. "
            "The page-scoped local undercounts (§4.5 inversion)."
        )
