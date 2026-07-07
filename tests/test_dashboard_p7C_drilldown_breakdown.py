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
# T-1 (CF-3) — unknown_capability_floor ADDS a 5th key (not a replacement)
# ---------------------------------------------------------------------------


class TestFloorReplacementNotAdditive:
    """T-1 / CF-3 (judge p7-C-independent-review.a1 correction 2026-07-05):
    unknown_capability_floor is a REPLACEMENT signal for the SCORE,
    but the 4 factor keys remain in the contributions dict.

    Actual mechanism per `scoring.py:259-282`:
      - contributions is populated with all 4 factor keys with real
        contribution values (line 259-264).
      - base_risk = sum of those 4 contributions (line 265).
      - If floor > base_risk, base_risk is REPLACED with the floor
        (line 280-281) AND contributions["unknown_capability_floor"] is
        added as a 5th key (line 282). The 4 factor keys are NOT removed.

    The renderer MUST branch on presence of the "unknown_capability_floor"
    key and render ONE dedicated row for it (base==floor value), NOT
    sum the 4 factor keys (that would inflate the shown base above
    the floor, contradicting the actual score).

    If the renderer iterates over contributions.keys() unconditionally
    and shows all 5 rows, the popover displays 5 factor contributions
    that sum to more than the final score — §4.5 truthfulness break."""

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


def _run_click_scope_test_via_node(badge_has_attribute: bool, badge_container_id: str = "panel-assets") -> dict:
    """Judge-required-fix #2 + code-reviewer @90 fold-in 2026-07-05:
    exercise the ACTUAL click-handler logic (not source-text grep) with a
    minimal DOM shim. Returns dict with `opened` (bool) indicating whether
    openBreakdownForAsset would have been called on a click."""
    import json
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("node not available; skipping DOM behavioral test")

    html = BRANCH_HTML_PATH.read_text()

    # Extract _wireRiskBadgePopover function body from dashboard.html so
    # the test executes the SHIPPED code, not a re-derivation.
    fn_start = html.find("function _wireRiskBadgePopover")
    assert fn_start > 0, "Could not locate _wireRiskBadgePopover in dashboard.html"
    # Find matching closing brace (function body).
    depth = 0
    brace_start = html.find("{", fn_start)
    i = brace_start
    while i < len(html):
        c = html[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                fn_body = html[fn_start : i + 1]
                break
        i += 1
    else:
        raise AssertionError("Could not locate function body")

    dom_shim = """
// Minimal DOM shim — provides just enough for _wireRiskBadgePopover
// to execute end-to-end (addEventListener + closest + getAttribute +
// dataset + event.stopPropagation).
class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.classList_ = new Set();
    this.attributes = {};
    this.dataset = new Proxy({}, {
      get: (t, k) => t[k],
      set: (t, k, v) => { t[k] = v; return true; },
    });
    this.parentElement = null;
    this.children = [];
    this._listeners = {};
  }
  get id() { return this.attributes.id || ''; }
  set id(v) { this.attributes.id = v; }
  setAttribute(k, v) { this.attributes[k] = v; }
  getAttribute(k) { return this.attributes[k] == null ? null : this.attributes[k]; }
  hasAttribute(k) { return k in this.attributes; }
  get classList() {
    return {
      add: (c) => this.classList_.add(c),
      contains: (c) => this.classList_.has(c),
      remove: (c) => this.classList_.delete(c),
    };
  }
  set className(v) {
    this.classList_ = new Set(v.split(/\\s+/).filter(x => x));
    this.attributes.class = v;
  }
  get className() { return this.attributes.class || ''; }
  appendChild(el) { el.parentElement = this; this.children.push(el); return el; }
  addEventListener(type, fn) {
    if (!this._listeners[type]) this._listeners[type] = [];
    this._listeners[type].push(fn);
  }
  closest(selector) {
    // Support simple '.className' and '[attr]' selectors.
    let cur = this;
    while (cur) {
      if (selector.startsWith('.') && cur.classList_.has(selector.slice(1))) return cur;
      if (selector.startsWith('[') && selector.endsWith(']')) {
        const attrName = selector.slice(1, -1);
        if (cur.attributes && attrName in cur.attributes) return cur;
      }
      cur = cur.parentElement;
    }
    return null;
  }
  dispatchClick(target) {
    // Walk up the DOM firing click listeners at each level.
    const event = {
      target: target,
      _stopped: false,
      stopPropagation() { this._stopped = true; },
    };
    let cur = target;
    while (cur && !event._stopped) {
      if (cur._listeners.click) {
        for (const fn of cur._listeners.click) fn(event);
      }
      cur = cur.parentElement;
    }
    return event;
  }
}

const _byId = {};
const document = {
  getElementById(id) { return _byId[id] || null; },
  addEventListener() { /* stub */ },
  readyState: 'complete',
};

function _mkEl(tag, attrs, parent) {
  const el = new Element(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'id') { el.attributes.id = v; _byId[v] = el; }
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v);
  }
  if (parent) parent.appendChild(el);
  return el;
}

// Spy on openBreakdownForAsset — record calls, don't actually run.
let _spyOpenCalls = [];
function openBreakdownForAsset(assetId, anchorEl) {
  _spyOpenCalls.push({assetId, anchorEl});
}

// Test scenario builder:
const scenario = JSON.parse(process.env.SCENARIO || '{}');
const panel = _mkEl('div', {id: scenario.panel_id || 'panel-assets'});
const row = _mkEl('div', {'data-asset-id': 'asset-test-1'}, panel);
const badgeAttrs = {class: 'risk-badge risk-high'};
if (scenario.badge_has_attribute) badgeAttrs['data-breakdown'] = 'attack-surface';
const badge = _mkEl('span', badgeAttrs, row);

// Wire and fire.
"""
    harness = (
        dom_shim
        + fn_body
        + "\n_wireRiskBadgePopover();\n"
        + "panel.dispatchClick(badge);\n"
        + "process.stdout.write(JSON.stringify({opened: _spyOpenCalls.length > 0}));\n"
    )
    scenario = json.dumps({"badge_has_attribute": badge_has_attribute, "panel_id": badge_container_id})
    result = subprocess.run(
        [node, "-e", harness],
        env={"SCENARIO": scenario, "PATH": subprocess.os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise AssertionError(f"Node subprocess failed: stderr={result.stderr!r}")
    return json.loads(result.stdout)


class TestClickHandlerBehaviorally:
    """Judge-required-fix #2 + code-reviewer @90 (2026-07-05):
    exercise the ACTUAL click handler with a minimal DOM shim. Source-text
    presence checks are not enough — reviewer explicitly required behavior."""

    def test_click_on_badge_WITH_attribute_opens_popover(self):
        """Attack-surface badge (data-breakdown='attack-surface') → popover opens."""
        result = _run_click_scope_test_via_node(badge_has_attribute=True)
        assert result["opened"] is True, (
            "Behavioral pin: click on `.risk-badge[data-breakdown='attack-surface']` "
            "inside #panel-assets MUST call openBreakdownForAsset. Got "
            f"opened={result['opened']!r}."
        )

    def test_click_on_badge_WITHOUT_attribute_does_not_open_popover(self):
        """Judge-required-fix #2 core: badge WITHOUT the attribute inside
        #panel-assets → popover does NOT open (Layer 2 attribute filter
        catches the leak)."""
        result = _run_click_scope_test_via_node(badge_has_attribute=False)
        assert result["opened"] is False, (
            "T-4/CF-6 behavioral pin: click on `.risk-badge` WITHOUT the "
            "data-breakdown='attack-surface' attribute (as if a future refactor "
            "leaked a non-attack-surface badge into #panel-assets) MUST NOT "
            "open the popover. Layer 2 attribute filter is what catches this. "
            f"Got opened={result['opened']!r}."
        )


class TestScopeGuardDualLayer:
    """Judge-required-fix #2 (p7-C-independent-review.a1 2026-07-05):
    D-Q3 planned belt-and-suspenders was silently dropped in a1 impl.
    a2 restores both layers:
      Layer 1 (containment): delegated listener on #panel-assets.
      Layer 2 (attribute filter): badge must carry
        data-breakdown="attack-surface" — future refactor that leaks a
        non-attack-surface badge into #panel-assets is caught by this.
    """

    def test_click_handler_filters_by_data_breakdown_attribute(self):
        html = _read_branch_html()
        # Layer 2 pin: the handler must check data-breakdown attribute.
        assert "getAttribute('data-breakdown')" in html or 'getAttribute("data-breakdown")' in html, (
            "Judge-required-fix #2: click handler must filter by "
            "data-breakdown='attack-surface' attribute (Layer 2 of D-Q3 "
            "belt-and-suspenders). Missing this layer means a future refactor "
            "that leaks a non-attack-surface badge into #panel-assets has "
            "nothing catching it."
        )

    def test_attack_surface_risk_badges_carry_data_breakdown_attribute(self):
        """Every attack-surface `.risk-badge` render site must carry
        `data-breakdown="attack-surface"`. Non-attack-surface sites (session
        explorer, processes) MUST NOT."""
        html = _read_branch_html()
        # Session Explorer badge at ~L2270 — MUST NOT carry the attribute.
        # Find the session badge render — it's in the sessions panel.
        session_badge_match = re.search(
            r"riskBadge\s*=\s*[^;]*risk-badge risk-[^;]*",
            html,
        )
        if session_badge_match:
            snippet = session_badge_match.group(0)
            assert "data-breakdown" not in snippet, (
                "Session Explorer risk badge must NOT carry data-breakdown "
                "attribute — that would leak the popover onto session risk "
                "which uses a different scoring pipeline."
            )
        # At least 3 attack-surface badge sites must carry the attribute
        # (Overview top-5, tool-section, renderAssetRow legacy list).
        attribute_count = html.count('data-breakdown="attack-surface"')
        assert attribute_count >= 3, (
            f"At least 3 attack-surface risk-badge render sites must carry "
            f"data-breakdown='attack-surface'. Found {attribute_count} "
            f"occurrences."
        )


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


# ---------------------------------------------------------------------------
# Judge-required-fix #1 (p7-C-independent-review.a1 CHANGES 2026-07-05):
# Real behavioral test for renderRiskBreakdown via Node subprocess.
# Runs the actual function against a constructed shape that mimics
# real scoring.py output (4 real nonzero factor keys + floor key
# present TOGETHER — the shape my a1 mental model got wrong).
# ---------------------------------------------------------------------------


def _run_render_via_node(risk_factors: dict, risk_score, risk_band: str) -> str:
    """Invoke renderRiskBreakdown against constructed inputs.

    Strategy: extract the P7-C JS block (BD_FACTOR_LABELS + BD_REPUTATION_REASON_COPY +
    renderRiskBreakdown + escHtml/escAttr helpers) from dashboard.html and run it
    in Node.js with a small test harness that receives inputs from JSON.
    """
    import json
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        import pytest

        pytest.skip("node not available; skipping behavioral test")

    html = BRANCH_HTML_PATH.read_text()

    # Extract escHtml / escAttr — small utilities defined in the head.
    # Fall back to a permissive polyfill if they're not extractable
    # (they're pure string transforms; behavior test cares about
    # structural output, not exact escape output).
    esc_polyfill = """
function escHtml(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function escAttr(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;'); }
"""
    # Extract the P7-C block (BD_FACTOR_LABELS -> end of renderRiskBreakdown).
    start_marker = "// P7-C: Risk-score breakdown popover"
    end_marker = "// Popover state machine"
    start = html.find(start_marker)
    end = html.find(end_marker)
    assert start > 0 and end > start, "Could not locate P7-C block in dashboard.html"
    p7c_block = html[start:end]

    harness = (
        esc_polyfill
        + p7c_block
        + "\nlet _stdinBuf = '';\n"
        + "process.stdin.on('data', d => { _stdinBuf += d; });\n"
        + "process.stdin.on('end', () => {\n"
        + "  const input = JSON.parse(_stdinBuf);\n"
        + "  const out = renderRiskBreakdown(input.risk_factors, input.risk_score, input.risk_band);\n"
        + "  process.stdout.write(out);\n"
        + "});\n"
    )
    payload = json.dumps({"risk_factors": risk_factors, "risk_score": risk_score, "risk_band": risk_band})
    result = subprocess.run(
        [node, "-e", harness],
        input=payload,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise AssertionError(f"Node subprocess failed: stderr={result.stderr!r}")
    return result.stdout


class TestFloorRendersOnlyFloorRowWhenFactorsAlsoPresent:
    """Judge-required-fix #1 (2026-07-05): construct the ACTUAL shape
    scoring.py produces when the floor fires (4 nonzero factor keys +
    floor key present TOGETHER) and assert the rendered HTML shows
    ONE floor row, no factor rows, no double-counting."""

    def test_floor_and_factors_present_together_renders_floor_row_only(self):
        # Real shape per scoring.py:259-282: 4 factor keys with real
        # contribution values PLUS unknown_capability_floor added as 5th key.
        risk_factors = {
            "contributions": {
                "max_cve_severity": 8.75,
                "permission_breadth": 6.0,
                "integration_sensitivity": 4.0,
                "activity_recency": 3.0,
                "unknown_capability_floor": 40.0,
            },
            "weights": {
                "max_cve_severity": 0.35,
                "permission_breadth": 0.30,
                "integration_sensitivity": 0.20,
                "activity_recency": 0.15,
            },
            "applied_rules": [],
            "applied_reputation": [],
        }
        html = _run_render_via_node(risk_factors, 40, "medium")

        # The floor row must render:
        assert "Unrecognized package tier" in html, "Floor row must render distinctly"
        assert "bd-row-floor" in html, "Floor row must use bd-row-floor class"

        # The 4 factor row LABELS must NOT appear as separate .bd-row
        # entries — that would double-count and inflate the shown base
        # above the actual final score.
        assert "Max CVE severity" not in html, (
            "Judge-required-fix #1: when floor fires, 4 factor rows MUST "
            "be suppressed. 'Max CVE severity' label appeared in rendered "
            "HTML — factor rows leaked, double-count risk."
        )
        assert "Permission breadth" not in html
        assert "Integration sensitivity" not in html
        assert "Activity recency" not in html

        # Verify sum-line reports base==40 not sum-of-5-keys (which would
        # be 40 + 21.75 = 61.75).
        assert "Base 40.0" in html, (
            "Judge-required-fix #1: base MUST equal floor value (40.0) "
            "when floor fires. Any other base value means sum-of-contributions "
            "was used — the false 'DROPPED keys' mental model."
        )
        # Explicitly guard against the double-count:
        assert "Base 61" not in html, "Double-count catastrophe: floor + 4 factors summed."


class TestFloorAbsentRendersAllFourFactorRows:
    """Complement to the above: when floor is NOT present (normal path),
    all 4 factor rows must render with real values."""

    def test_no_floor_renders_all_four_factor_rows(self):
        risk_factors = {
            "contributions": {
                "max_cve_severity": 28.7,
                "permission_breadth": 18.0,
                "integration_sensitivity": 14.0,
                "activity_recency": 6.3,
            },
            "weights": {
                "max_cve_severity": 0.35,
                "permission_breadth": 0.30,
                "integration_sensitivity": 0.20,
                "activity_recency": 0.15,
            },
            "applied_rules": [],
            "applied_reputation": [],
        }
        html = _run_render_via_node(risk_factors, 67, "high")

        for label in ("Max CVE severity", "Permission breadth", "Integration sensitivity", "Activity recency"):
            assert label in html, f"Normal path: factor row {label!r} must render"
        assert "bd-row-floor" not in html, "Floor row must NOT render when floor key absent"
        assert "Unrecognized package tier" not in html


class TestSuppressedRulesVisiblyRendered:
    """Judge-required-fix #1 companion: real behavioral test of the T-2
    max()-winner + suppressed pin. Multi-rule case must render ALL
    rules; winner marked, suppressed with .bd-rule--suppressed."""

    def test_multiple_rules_winner_and_suppressed_all_rendered(self):
        risk_factors = {
            "contributions": {
                "max_cve_severity": 20.0,
                "permission_breadth": 15.0,
                "integration_sensitivity": 10.0,
                "activity_recency": 5.0,
            },
            "weights": {
                "max_cve_severity": 0.35,
                "permission_breadth": 0.30,
                "integration_sensitivity": 0.20,
                "activity_recency": 0.15,
            },
            "applied_rules": [
                {
                    "id": "rule_shell_network_combo_001",
                    "modifier_applied": 15,
                    "explanation": "shell + network combo",
                    "framework_ref": {"nist_csf": "PR.AC-4"},
                },
                {
                    "id": "rule_secrets_network_001",
                    "modifier_applied": 20,
                    "explanation": "secrets + network combo (higher modifier — wins)",
                    "framework_ref": {"nist_csf": "PR.AC-5"},
                },
                {
                    "id": "rule_filesystem_read_network_001",
                    "modifier_applied": 15,
                    "explanation": "filesystem_read + network combo",
                    "framework_ref": {"nist_csf": "PR.DS-1"},
                },
            ],
            "applied_reputation": [],
        }
        html = _run_render_via_node(risk_factors, 70, "high")

        # All 3 rules must appear
        assert "rule_secrets_network_001" in html, "Winner rule must render"
        assert "rule_shell_network_combo_001" in html, "Suppressed rule must remain visible"
        assert "rule_filesystem_read_network_001" in html, "Suppressed rule must remain visible"

        # Winner marker must appear
        assert "WINNER" in html or "data-winner" in html, "Winner must be marked"

        # Suppressed rules must have the visual distinction
        assert "bd-rule--suppressed" in html, "Suppressed rules must carry .bd-rule--suppressed class"


class TestReputationReasonVariantsRenderDistinctCopy:
    """Judge-required-fix #1 companion: real behavioral test of T-3.
    Each of 4 reason variants renders DIFFERENT string (not silent
    fall-through)."""

    def test_rate_limited_renders_distinct(self):
        html = _run_render_via_node(_reputation_only({"present": None, "reason": "rate_limited"}), 55, "medium")
        assert "rate-limited" in html.lower() or "rate limited" in html.lower(), (
            "T-3: rate_limited reason must render distinctly (not silent fall-through)."
        )

    def test_budget_exceeded_renders_distinct(self):
        html = _run_render_via_node(_reputation_only({"present": None, "reason": "budget_exceeded"}), 55, "medium")
        assert "budget" in html.lower() and "exceeded" in html.lower()

    def test_dormant_renders_distinct(self):
        html = _run_render_via_node(_reputation_only({"present": None, "reason": "dormant"}), 55, "medium")
        assert "dormant" in html.lower()

    def test_lookup_failed_renders_distinct(self):
        html = _run_render_via_node(_reputation_only({"present": None, "reason": "lookup_failed"}), 55, "medium")
        assert "lookup" in html.lower() and "failed" in html.lower()


def _reputation_only(rep_entry: dict) -> dict:
    """Helper: build a risk_factors dict with a specific reputation entry
    and neutral factor values (isolates reputation-rendering behavior)."""
    return {
        "contributions": {
            "max_cve_severity": 20.0,
            "permission_breadth": 15.0,
            "integration_sensitivity": 10.0,
            "activity_recency": 5.0,
        },
        "weights": {
            "max_cve_severity": 0.35,
            "permission_breadth": 0.30,
            "integration_sensitivity": 0.20,
            "activity_recency": 0.15,
        },
        "applied_rules": [],
        "applied_reputation": [{"signal": "npm_low_downloads", **rep_entry}],
    }


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

    def test_popover_a11y_contract_is_consistent(self):
        """Frontend-design N-4 fold-in 2026-07-05: aria-modal='true'
        promises screen readers that background is inert, which requires
        a focus trap. Focus trap is DEFERRED to Phase 8 a11y hardening.
        Truthful contract: role='dialog' alone (non-modal disclosure).

        This test enforces the truthfulness invariant: if aria-modal
        appears without a focus trap, fail — either both ship or neither."""
        html = _read_branch_html()
        has_aria_modal = (
            'aria-modal="true"' in html
            or "aria-modal='true'" in html
            or "setAttribute('aria-modal', 'true')" in html
            or 'setAttribute("aria-modal", "true")' in html
        )
        has_focus_trap = "focus-trap" in html or "trapFocus" in html or "focusTrap" in html
        if has_aria_modal and not has_focus_trap:
            raise AssertionError(
                "CF-9 truthfulness: aria-modal='true' promises inert-background "
                "to screen readers; that promise requires a focus trap. If "
                "focus-trap is deferred to Phase 8, drop aria-modal."
            )


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
