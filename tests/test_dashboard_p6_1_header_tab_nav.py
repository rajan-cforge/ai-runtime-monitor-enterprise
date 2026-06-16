"""P6.1 — header + tab navigation migration tests (HTML-scrape).

Pins the contract per directive line 221: 10 tabs with Attack Surface
marked "New" + Alerts count badge + 2px accent underline on active.

Mockup-as-visual-reference discipline (directive line 102): we assert
markup structure, not byte-for-byte mockup parity.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_DASHBOARD_HTML = Path(__file__).resolve().parents[1] / "src" / "claude_monitoring" / "dashboard.html"


@pytest.fixture(scope="module")
def dashboard_html() -> str:
    return _DASHBOARD_HTML.read_text()


class TestTopbarReplacesLegacyHeader:
    def test_topbar_element_present(self, dashboard_html):
        assert '<header class="topbar">' in dashboard_html

    def test_legacy_header_div_absent(self, dashboard_html):
        # The legacy `<div class="header">` block is gone — replaced
        # by the semantic <header class="topbar"> shape from the
        # Round 4 mockup. The CSS class `.header` may still exist in
        # other contexts; we pin the legacy *element opening tag*.
        assert '<div class="header">' not in dashboard_html


class TestBrandBlock:
    def test_brand_name(self, dashboard_html):
        assert '<div class="brand__name">Vigil</div>' in dashboard_html

    def test_brand_sub_tagline(self, dashboard_html):
        assert '<div class="brand__sub">Runtime security for AI coding agents</div>' in dashboard_html

    def test_brand_mark_svg(self, dashboard_html):
        assert '<div class="brand__mark">' in dashboard_html
        assert "<svg" in dashboard_html.split('<div class="brand__mark">', 1)[1][:500]


class TestTabNavHasTenVTabsInOrder:
    """Directive line 221: 10 tabs. data-tab attribute kept (NOT renamed
    to mockup's data-view, per Phase A D-preserve-data-tab) so the
    existing switchTab() JS survives unchanged."""

    EXPECTED_DATA_TABS = (
        "explorer",
        "feed",
        "analytics",
        "insights",
        "system",
        "traffic",
        "timeline",
        "supply-chain",
        "assets",
        "alerts",
    )

    def test_vtabs_container_present(self, dashboard_html):
        assert '<nav class="v-tabs">' in dashboard_html

    def test_legacy_tabs_div_container_absent(self, dashboard_html):
        assert '<div class="tabs">' not in dashboard_html

    def test_exactly_ten_v_tabs(self, dashboard_html):
        # Match the opening tag for each .v-tab button.
        matches = re.findall(r'<button class="v-tab(?: is-active)?" data-tab="', dashboard_html)
        assert len(matches) == 10, f"directive line 221 mandates 10 tabs; found {len(matches)}"

    def test_data_tab_attributes_in_mockup_order(self, dashboard_html):
        found = re.findall(r'<button class="v-tab(?: is-active)?" data-tab="([^"]+)"', dashboard_html)
        assert tuple(found) == self.EXPECTED_DATA_TABS

    def test_buttons_not_divs(self, dashboard_html):
        # Semantic upgrade: tabs are <button> elements (focusable, ARIA-
        # friendly) instead of clickable <div>s.
        assert '<div class="tab"' not in dashboard_html


class TestAttackSurfaceTabHasNewBadge:
    """Directive line 221: 'Attack Surface marked "New"'. The tab keeps
    data-tab='assets' (per Phase A D-attack-surface-rename) so backend
    routes + JS handlers stay unchanged; only the visible label + the
    .v-tab__new badge are new."""

    def test_attack_surface_label_present(self, dashboard_html):
        # The data-tab="assets" tab's visible label is now "Attack
        # Surface", not "Assets".
        m = re.search(
            r'data-tab="assets">\s*([^<]+?)\s*<span class="v-tab__new">',
            dashboard_html,
        )
        assert m is not None, "Attack Surface tab + .v-tab__new badge not found together"
        assert m.group(1).strip() == "Attack Surface"

    def test_new_badge_markup(self, dashboard_html):
        assert '<span class="v-tab__new">New</span>' in dashboard_html

    def test_assets_tab_label_removed(self, dashboard_html):
        # Defense-in-depth: ensure the prior 'Assets ' label (with the
        # legacy badge-span trailer) is gone.
        legacy = re.search(
            r'data-tab="assets">\s*Assets\s*<span id="tab-assets-badge"',
            dashboard_html,
        )
        assert legacy is None

    def test_new_badge_rule_exists_in_css(self, dashboard_html):
        # The .v-tab__new style rule MUST exist in dashboard.html (we
        # added it from the mockup since it wasn't already there).
        assert ".v-tab__new {" in dashboard_html
        assert "var(--v-accent)" in dashboard_html.split(".v-tab__new {", 1)[1][:200]


class TestAlertsTabHasRiskCountBadge:
    def test_alerts_badge_uses_v_tab_count_risk_class(self, dashboard_html):
        # The dynamic badge ID stays (id="tab-alerts-badge") so the
        # existing JS that writes the count value still finds it; the
        # className is promoted to the mockup's risk-count styling.
        m = re.search(
            r'id="tab-alerts-badge"\s+class="([^"]+)"',
            dashboard_html,
        )
        assert m is not None, "tab-alerts-badge classed-span not found"
        classes = m.group(1).split()
        assert "v-tab__count" in classes
        assert "v-tab__count--risk" in classes


class TestActiveTabIndicatorIs2pxViaPseudoElement:
    """Directive line 221: 'Active tab gets 2px accent underline.' The
    existing .v-tab.is-active::after rule (already in dashboard.html
    pre-P6.1, came in with P0.1's vigil.css paste) is the source of
    truth — we DON'T author a new rule, we just verify it's still
    there and consume it via the markup."""

    def test_rule_height_is_2px(self, dashboard_html):
        m = re.search(
            r"\.v-tab\.is-active::after\s*\{[^}]*\}",
            dashboard_html,
        )
        assert m is not None, ".v-tab.is-active::after rule not found"
        rule_body = m.group(0)
        assert "height:2px" in rule_body
        assert "background: var(--v-accent)" in rule_body

    def test_legacy_active_rule_removed(self, dashboard_html):
        # The legacy `.tab.active { ... border-bottom-color:var(--blue); }`
        # rule was the pre-P6.1 active-state mechanism — must be gone
        # so the migration is clean.
        assert ".tab.active {" not in dashboard_html

    def test_default_active_tab_is_first(self, dashboard_html):
        # The first tab (Session Explorer) is the initial active state.
        m = re.search(
            r'<button class="v-tab is-active" data-tab="([^"]+)"',
            dashboard_html,
        )
        assert m is not None
        assert m.group(1) == "explorer"


class TestExportMenuStillDispatches:
    """Regression guard — Phase A out-of-scope list explicitly preserves
    the existing Export-dropdown handlers. If the migration silently
    strips them, this test catches it."""

    def test_export_dropdown_anchors_preserved(self, dashboard_html):
        # Spot-check three of the dropdown items by their onclick.
        assert "exportData('sessions','json')" in dashboard_html
        assert "exportData('events','ndjson')" in dashboard_html
        assert "exportData('traffic','csv')" in dashboard_html

    def test_monitoring_status_dot_present(self, dashboard_html):
        # The "Monitoring" status dot moved into topbar__right, but
        # the text label must remain so the operator still sees it.
        assert "Monitoring" in dashboard_html
        assert '<span class="dot"></span>' in dashboard_html.split('class="topbar__right"', 1)[1][:600]


class TestSwitchTabJSUpdated:
    """The Phase A D-preserve-data-tab decision: data-tab attributes
    stay, but switchTab() must use the new .v-tab selector + the
    is-active class. Pin both changes — a regression on either side
    silently breaks tab clicks."""

    def test_switch_tab_queries_v_tab(self, dashboard_html):
        # Locate the switchTab function body and assert it operates on
        # .v-tab, not the legacy .tab.
        m = re.search(
            r"function switchTab\(name\)\s*\{[^}]+?\}",
            dashboard_html,
            re.DOTALL,
        )
        assert m is not None, "switchTab function not found"
        body = m.group(0)
        assert "querySelectorAll('.v-tab')" in body
        assert "querySelector('.v-tab[data-tab=\"'+name+'\"]')" in body
        assert "tab.classList.add('is-active')" in body
        # And the legacy tab class is gone — `tab.classList.add('active')`
        # (with the bare 'active' name on the tab variable) would mean
        # the migration regressed. The panel still uses 'active' — that
        # is in-scope per Phase A out-of-scope #2.
        assert "tab.classList.add('active')" not in body
        assert "querySelectorAll('.tab')" not in body

    def test_panel_active_class_preserved(self, dashboard_html):
        # Phase A out-of-scope: .panel.active is the legacy content-pane
        # display rule and survives unchanged (P6.3+ owns panel migration).
        assert ".panel.active { display:block; }" in dashboard_html

    def test_hash_to_tab_uses_v_tab(self, dashboard_html):
        # Deep-link handler must reach into .v-tab now, not .tab.
        m = re.search(
            r"function _hashToTab\(\)\s*\{[^}]+?\}",
            dashboard_html,
            re.DOTALL,
        )
        assert m is not None
        body = m.group(0)
        assert ".v-tab[data-tab=" in body
        assert ".tab[data-tab=" not in body
