"""P7-C — State D drill-down + risk-score breakdown popover.

BATCHED Phase 7 PR (last one before Phase 8) bundling P7.6 + P7.9.

Rajan-ratified 2026-07-04 (in absence of Claude Desktop judge):
  Q1  Add `current_state` to `render_asset_row` output (native
      permission text projection).
  Q2  Remediation from `applied_rules[*].framework_ref` citations
      (NIST CSF / CIS / MITRE ATT&CK).
  Q3  Scope popover to `.risk-badge` inside `#panel-assets` only —
      NOT Session Explorer / Processes tabs.

Adversarial-pass tightenings surfaced by executor (T-1 through T-5):
  T-1  unknown_capability_floor REPLACEMENT — hide factor rows when
       floor present; base==40, NOT sum of zero-valued factors.
  T-2  max()-of-rules — suppressed rules VISIBLY rendered with
       distinct treatment; never hidden entirely.
  T-3  Reputation state: 4 reason variants (rate_limited /
       budget_exceeded / lookup_failed / dormant) render distinct copy.
  T-4  Scope guard — popover MUST NOT open on Session Explorer /
       Processes badges. DOM containment enforced.
  T-5  All-zero contributions renders distinct from null risk_factors.

11 CF pins (CF-1 through CF-11) — see p7-C.a1.verdict.md.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
HANDLER_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard_handler.py"
DASHBOARD_API_PATH = REPO_ROOT / "src" / "claude_monitoring" / "attack_surface" / "dashboard_api.py"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_handler() -> str:
    return HANDLER_PATH.read_text()


def _read_dashboard_api() -> str:
    return DASHBOARD_API_PATH.read_text()


# ---------------------------------------------------------------------------
# M1 — .bd-* CSS block present
# ---------------------------------------------------------------------------


class TestBdClassCssPresent:
    """M1: .bd-comp/.bd-row/.bd-rule/.bd-sum CSS block from mockup
    vigil.css L256-266."""

    def test_bd_comp_class_defined(self):
        html = _read_branch_html()
        assert ".bd-comp" in html, "M1: .bd-comp CSS class must be defined."

    def test_bd_row_class_defined(self):
        html = _read_branch_html()
        assert ".bd-row" in html, "M1: .bd-row CSS class must be defined."

    def test_bd_rule_class_defined(self):
        html = _read_branch_html()
        assert ".bd-rule" in html, "M1: .bd-rule CSS class must be defined."

    def test_bd_sum_class_defined(self):
        html = _read_branch_html()
        assert ".bd-sum" in html, "M1: .bd-sum CSS class must be defined."

    def test_bd_popover_container_class_defined(self):
        html = _read_branch_html()
        assert ".bd-popover" in html, (
            "M1 (executor add): .bd-popover container class must be defined "
            "for the popover positioning + z-index management."
        )


# ---------------------------------------------------------------------------
# M2 — renderRiskBreakdown function
# ---------------------------------------------------------------------------


class TestRenderRiskBreakdownDefined:
    """M2: renderRiskBreakdown(risk_factors, risk_score, risk_band)
    single-source-of-truth function that produces the breakdown HTML
    for BOTH the popover AND the inline drill-down section."""

    def test_render_function_exists(self):
        html = _read_branch_html()
        assert "function renderRiskBreakdown" in html, (
            "M2: renderRiskBreakdown() must be defined as the single "
            "source of truth for both popover and drill-down inline "
            "breakdown rendering."
        )


# ---------------------------------------------------------------------------
# CF-1 — Auth gate (existing /api/asset/{id} still gated)
# ---------------------------------------------------------------------------


class TestAuthGateNotWeakened:
    """CF-1: /api/asset/{id} is an EXISTING auth-gated endpoint.
    Q1's `current_state` projection is a payload-shape change, not a
    new route. Verify no accidental exemption addition."""

    def test_asset_detail_not_in_open_path_list(self):
        src = _read_handler()
        m = re.search(r"def _check_auth[^)]+\):[^}]*?return True", src, re.DOTALL)
        if m:
            check_auth_body = m.group(0)
            assert "/api/asset/" not in check_auth_body, (
                "CF-1: `/api/asset/*` MUST NOT appear in _check_auth open-path "
                "list. Q1's payload change to render_asset_row must not "
                "prompt anyone to move the endpoint to unauthenticated."
            )


# ---------------------------------------------------------------------------
# T-1 (CF-3) — unknown_capability_floor REPLACEMENT semantic
# ---------------------------------------------------------------------------


class TestFloorReplacementNotAdditive:
    """T-1 / CF-3 (adversarial-pass): unknown_capability_floor is a
    REPLACEMENT semantic in scoring.py:272-278. When floor fires:
      - contributions["unknown_capability_floor"] = 40.0 is set
      - The 4 base factor keys are DROPPED from contributions
    The renderer MUST detect floor presence and switch to floor-only
    rendering. If it iterates over contributions.keys() unconditionally
    and shows the 4 factors as zero-valued rows, that's a §4.5
    truthfulness break — the floor REPLACED the factors."""

    def test_renderer_detects_unknown_capability_floor(self):
        html = _read_branch_html()
        idx = html.find("function renderRiskBreakdown")
        assert idx > 0
        body = html[idx : idx + 6000]
        assert "unknown_capability_floor" in body, (
            "T-1/CF-3: renderRiskBreakdown MUST detect and special-case "
            "the `unknown_capability_floor` contribution key. Rendering "
            "it as a zero-valued factor row is the §4.5 truthfulness "
            "break the adversarial pass surfaced."
        )


# ---------------------------------------------------------------------------
# T-2 (CF-4) — max()-of-rules winner + suppressed VISIBLE
# ---------------------------------------------------------------------------


class TestSuppressedRulesVisible:
    """T-2 / CF-4 (adversarial-pass): rules.py:369 uses
    `max(rule_modifiers)` for the winner. applied_rules contains ALL
    matches, not just the winner. Popover must render suppressed rules
    VISIBLY with distinct treatment — hiding them shows "1 rule
    applied" when 3 patterns actually matched (obscures max() logic
    from the CISO)."""

    def test_renderer_handles_suppressed_rules(self):
        html = _read_branch_html()
        idx = html.find("function renderRiskBreakdown")
        assert idx > 0
        body = html[idx : idx + 6000]
        # Suppressed rules must be rendered — look for the concept in the
        # renderer (grayed / superseded / suppressed / winner marker).
        has_suppressed_handling = any(
            token in body for token in ("suppressed", "superseded", "winner", "is-winner", "not counted")
        )
        assert has_suppressed_handling, (
            "T-2/CF-4: renderRiskBreakdown must handle suppressed rules "
            "visibly (grayed / 'superseded' tag / winner marker). Hiding "
            "them obscures the max() composition from the CISO — same "
            "truthfulness class as T-1."
        )


# ---------------------------------------------------------------------------
# T-3 (CF-5) — Reputation 4 reason variants distinct copy
# ---------------------------------------------------------------------------


class TestReputationReasonVariantsDistinct:
    """T-3 / CF-5 (adversarial-pass): reputation dispatcher (types.py:70-94)
    exposes 4 reason enum values for present=None cases: rate_limited,
    budget_exceeded, lookup_failed, dormant. Each renders distinct copy.
    Silent fall-through to a shared "lookup failed" string hides the
    rate_limited vs budget_exceeded distinction from operators."""

    def test_renderer_handles_all_reputation_reasons(self):
        """Search the whole P7-C block (constant defs may live above
        renderRiskBreakdown)."""
        html = _read_branch_html()
        # The P7-C block starts at the banner comment; take everything
        # from there to end of file for reason-literal search.
        p7c_start = html.find("P7-C: Risk-score breakdown popover")
        assert p7c_start > 0, "P7-C block must be present"
        p7c_region = html[p7c_start:]
        for reason in ("rate_limited", "budget_exceeded", "lookup_failed", "dormant"):
            assert reason in p7c_region, (
                f"T-3/CF-5: P7-C block must handle reputation reason="
                f"{reason!r} with distinct copy. Silent fall-through hides "
                f"operationally-meaningful state."
            )


# ---------------------------------------------------------------------------
# T-4 (CF-6) — Scope guard: NOT session-explorer / processes
# ---------------------------------------------------------------------------


class TestScopeGuardDomContainment:
    """T-4 / CF-6 (adversarial-pass): Session Explorer badge at
    dashboard.html:2248 and Processes badge at :3034 render from unrelated
    scoring pipelines. Popover click-wiring MUST be scoped via DOM
    containment (inside #panel-assets) — literal §6.4 "every risk score"
    interpretation would force nonsense math on those tabs."""

    def test_popover_click_wiring_scoped_to_panel_assets(self):
        """The popover click handler must scope its listener to
        #panel-assets (delegated listener) OR use a data attribute filter
        (e.g., data-breakdown='attack-surface') OR check closest containment."""
        html = _read_branch_html()
        # Look for the scope-guard pattern in the click handler.
        has_panel_scope = "#panel-assets" in html and "risk-badge" in html
        # Any of these approaches satisfies the scope requirement:
        # - delegated listener on #panel-assets
        # - data-breakdown attribute filter
        # - explicit closest() check
        has_scope_marker = any(
            token in html
            for token in (
                'data-breakdown="attack-surface"',
                "data-breakdown='attack-surface'",
                "#panel-assets .risk-badge",
                "#panel-assets').addEventListener",
                '#panel-assets").addEventListener',
                "getElementById('panel-assets')",
                'getElementById("panel-assets")',
            )
        )
        assert has_panel_scope and has_scope_marker, (
            "T-4/CF-6: popover click-wiring MUST be scoped to "
            "`.risk-badge` inside `#panel-assets`. Session Explorer + "
            "Processes badges use unrelated scoring pipelines; forcing "
            "them into the attack-surface breakdown renders nonsense math. "
            "Use delegated listener on #panel-assets OR "
            "data-breakdown='attack-surface' attribute OR closest() check."
        )


# ---------------------------------------------------------------------------
# T-5 (CF-7) — All-zero contributions distinct from null risk_factors
# ---------------------------------------------------------------------------


class TestAllZeroDistinctFromNull:
    """T-5 / CF-7 (adversarial-pass): distinguish 'score-pipeline ran
    but all factors zero' from 'score-pipeline didn't run at all'.
    Existing code has UNKNOWN_PENDING_RESCAN_HINT for null case; the
    renderer must also handle contributions-present-but-all-zero as
    a distinct case."""

    def test_renderer_handles_null_risk_factors_distinctly(self):
        html = _read_branch_html()
        idx = html.find("function renderRiskBreakdown")
        assert idx > 0
        body = html[idx : idx + 6000]
        # Look for null-risk_factors handling — should render distinct
        # copy from the all-zero-contributions case.
        has_null_handling = any(
            token in body
            for token in (
                "!risk_factors",
                "risk_factors == null",
                "risk_factors === null",
                "risk_factors == undefined",
                "!rf",
                "not yet scored",
                "pending rescan",
            )
        )
        assert has_null_handling, (
            "T-5/CF-7: renderRiskBreakdown must handle risk_factors=null "
            "distinctly from all-zero contributions. Both are legitimate "
            "states but represent different data-truth."
        )


# ---------------------------------------------------------------------------
# CF-8 — Q1: current_state projected in render_asset_row
# ---------------------------------------------------------------------------


class TestCurrentStateProjected:
    """Q1 fold: `current_state` column is selected by _ASSET_COLUMNS
    but was NOT projected into render_asset_row output payload. P7-C
    adds it — enables Q1 native permission text rendering."""

    def test_render_asset_row_projects_current_state(self):
        src = _read_dashboard_api()
        idx = src.find("def render_asset_row")
        assert idx > 0
        # Widen the search window since the function body has many keys.
        body = src[idx : idx + 4000]
        assert '"current_state"' in body, (
            "Q1/CF-8: render_asset_row must project `current_state` into "
            "the response payload so the P7-C drill-down can render the "
            "raw manifest permissions block (LOCKED §Phase 7:259 required "
            "native permission text)."
        )


# ---------------------------------------------------------------------------
# Q2 — Remediation from framework_ref citations
# ---------------------------------------------------------------------------


class TestRemediationFromFrameworkRef:
    """Q2 fold: derive remediation guidance from applied_rules[*].framework_ref
    citations (NIST CSF / CIS Controls / MITRE ATT&CK). No hardcoded copy
    invented; no reserved product judgment."""

    def test_renderer_references_framework_citations(self):
        html = _read_branch_html()
        idx = html.find("function renderRiskBreakdown")
        assert idx > 0
        body = html[idx : idx + 6000]
        # Renderer must access framework_ref.
        assert "framework_ref" in body, (
            "Q2: renderRiskBreakdown must derive remediation guidance from applied_rules[*].framework_ref citations."
        )


# ---------------------------------------------------------------------------
# M8/M9 — Popover open + scope guard (integration)
# ---------------------------------------------------------------------------


class TestPopoverOpenClose:
    """M8: click on .risk-badge inside #panel-assets opens popover.
    M10/M11: popover closes on Esc + click-outside."""

    def test_popover_has_close_wiring(self):
        html = _read_branch_html()
        # Look for Esc handler + click-outside pattern near the popover.
        has_esc_handler = (
            "Escape" in html or "keyCode === 27" in html or 'key === "Escape"' in html or "key==='Escape'" in html
        )
        has_close_handler = "closePopover" in html or "closeBreakdown" in html or "bd-popover" in html
        assert has_esc_handler and has_close_handler, (
            "M10/M11: popover must close on Escape key + support programmatic "
            "close (for click-outside handler). Look for closeBreakdown / "
            "closePopover function + Escape key detection."
        )


# ---------------------------------------------------------------------------
# CF-9 — Minimum a11y (ARIA role + return focus)
# ---------------------------------------------------------------------------


class TestPopoverMinimumA11y:
    """CF-9 (adversarial-pass fold): minimum a11y — role='dialog',
    aria-modal='true', return focus to opener badge on close. Focus trap
    deferred to Phase 8 a11y hardening PR."""

    def test_popover_has_role_dialog(self):
        html = _read_branch_html()
        has_role = (
            'role="dialog"' in html
            or "role='dialog'" in html
            or "setAttribute('role', 'dialog')" in html
            or 'setAttribute("role", "dialog")' in html
        )
        assert has_role, (
            "CF-9: popover must have role='dialog' — via literal HTML attribute OR setAttribute('role', 'dialog')."
        )

    def test_popover_has_aria_modal(self):
        html = _read_branch_html()
        has_aria_modal = (
            'aria-modal="true"' in html
            or "aria-modal='true'" in html
            or "setAttribute('aria-modal', 'true')" in html
            or 'setAttribute("aria-modal", "true")' in html
        )
        assert has_aria_modal, "CF-9: popover must have aria-modal='true' — via literal HTML attribute OR setAttribute."


# ---------------------------------------------------------------------------
# CF-11 — P7-A/P7-B inheritance pins stay GREEN
# ---------------------------------------------------------------------------


class TestP7AB_InvariantsPreserved:
    """CF-11: P7-A/P7-B pins must still pass. Specifically:
    - Empty-state hidden-by-default (P7-A M5/M6)
    - LOCKED §3.3:293 empty-state string verbatim
    - AI Tools ordered between all-assets and extensions (P7-B Ask #1)
    - All Assets stays TOP
    - Tool sections default-collapsed (P7-A M10)
    - No new tab (P6.1)"""

    def test_empty_state_still_display_none_default(self):
        html = _read_branch_html()
        m = re.search(
            r'<div\b[^>]*\bid="attack-surface-empty-state"[^>]*>',
            html,
        )
        assert m, "P7.1 empty-state container must exist"
        opening = m.group(0)
        assert "display:none" in opening or "display: none" in opening, (
            "CF-11: p7.1.a2 truthfulness invariant preserved."
        )

    def test_locked_empty_state_string_verbatim(self):
        html = _read_branch_html()
        assert "Vigil hasn't scanned your AI tools yet. Click Discover to begin." in html, (
            "CF-11: LOCKED §3.3:293 verbatim empty-state string preserved."
        )

    def test_ai_tools_shell_still_present(self):
        html = _read_branch_html()
        assert 'data-tool-section="ai-tools"' in html, "CF-11: P7-B AI Tools shell must still exist (verdict Ask #1)."

    def test_tab_button_unchanged(self):
        html = _read_branch_html()
        m = re.search(
            r'<button\b[^>]*\bclass="v-tab\b[^"]*"[^>]*\bdata-tab="assets"[^>]*>([^<]*)<',
            html,
        )
        assert m, "Attack Surface tab button must still exist"
        label = m.group(1).strip()
        assert label == "Attack Surface", f"Tab label unchanged; got {label!r}"


# ---------------------------------------------------------------------------
# M13 — /api/asset/{id} response payload includes current_state (backend)
# ---------------------------------------------------------------------------


class TestApiAssetDetailEnvelope:
    """M13: The /api/asset/{id} response must include current_state
    after Q1 fold. This is the backend contract test."""

    def test_get_asset_detail_returns_current_state(self, tmp_path):
        """Integration test: hit get_asset_detail with a seeded asset
        and verify the response payload includes current_state."""
        import json
        import sqlite3

        from claude_monitoring.attack_surface.dashboard_api import get_asset_detail
        from claude_monitoring.db import init_db

        db_path = tmp_path / "p7c_asset_detail.db"
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        try:
            manifest_permissions = json.dumps({"permissions": ["tabs", "<all_urls>", "storage"]})
            conn.execute(
                "INSERT INTO assets (id, type, name, version, source, first_seen, last_seen, "
                "last_scanned, current_state, ontology_tags, risk_score, risk_band, "
                "risk_factors, is_vigil_component) VALUES (?, 'extension', 'test-ext', '1.0', "
                "'chromium-extensions', 1720123456.0, 1720123456.0, 1720123456.0, ?, "
                "'[\"file_system_read\"]', 55.0, 'medium', NULL, 0)",
                ("asset-1", manifest_permissions),
            )
            conn.commit()
            payload, status = get_asset_detail(conn, {"id": ["asset-1"]})
            assert status == 200, f"Expected 200; got {status}"
            assert "current_state" in payload, (
                "Q1/M13: /api/asset/{id} response envelope must include "
                "`current_state` for the P7-C drill-down native-permission "
                f"text block. Got keys: {sorted(payload.keys())}"
            )
        finally:
            conn.close()
