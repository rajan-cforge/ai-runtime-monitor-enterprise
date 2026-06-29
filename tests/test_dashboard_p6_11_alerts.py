"""P6.11 — Alerts tab repaint-only preservation contract (LAST migration in v0.2.2).

Directive line 243 + STATUS.md 2026-06-19 (Rajan REPAINT-ONLY ratification):
strict-scope `.v-*` token migration; live tab controls stay verbatim; the mockup's
new Unresolved/All/Muted status filter, per-alert True/False-positive/Mute triage,
and pattern chips are explicitly Phase 9 scope (P9.2/P9.3/P9.4).

Cookbook inheritance:
  * p6.6.a2 / p6.7.a1 / p6.8.a1 / p6.9.a1 / p6.10.a1 — locked.
  * **Cookbook entry #6, REFINED by judge ruling at p6.11 Phase B (2026-06-21):**
    The no-new-controls guard must cover the **render path**, not just the
    static container. Source-regex over the render path is sufficient when
    control markup is literal (text + class are string literals); a true DOM
    render re-arms as mandatory the moment any control's markup becomes
    data-driven (button text/class built from a variable or loop), where
    source-regex can't enumerate the rendered set. Alerts at c6a91bd is fully
    literal — every rendered button is a literal `<button>...</button>` string
    template — so regex qualifies. R1 test-methodology ruling with a 7-day
    Rajan override window. Recorded in the decision log.

Implementation: the pins below regex over the body of `loadAlerts()`. The
button-allowlist pin asserts the rendered button text set is exactly the
8-button allowlist the judge specified — {False positive, Investigated,
Accept risk, View Advisory, View Session, View Package, Copy Report, Load
More}. The reason-set pin (dismiss reasons) is defense in depth. The v-chip
pin and the triage data-* pin are tag-agnostic zero-presence guards.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p6_11"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_fixture_lines(name: str) -> set[str]:
    text = (FIXTURE_DIR / name).read_text()
    return {line for line in text.splitlines() if line.strip()}


def _grep_panel_block(html: str, panel_id: str) -> str:
    """Balanced-<div> extraction (locked from p6.7.a1 cookbook)."""
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


def _grep_control_ids(panel_html: str) -> set[str]:
    ids = set(re.findall(r'id="([^"]+)"', panel_html))
    ids.discard("panel-alerts")
    return ids


def _grep_alert_item_selectors(html: str) -> set[str]:
    """All `.alert-item*` rule selectors (whole-file scope; repaint scope)."""
    out = set()
    for m in re.finditer(r"^(\.alert-item[^,{]*)\s*\{", html, re.MULTILINE):
        out.add(m.group(1).strip())
    return out


def _grep_alertbar_selectors(html: str) -> set[str]:
    """All `.alertbar*` rule selectors (whole-file scope; sanity-pinned,
    already migrated in an earlier Phase 6 step; consumed cross-tab as a
    top-of-tab callout)."""
    out = set()
    for m in re.finditer(r"^(\.alertbar[^,{]*)\s*\{", html, re.MULTILINE):
        out.add(m.group(1).strip())
    return out


def _extract_load_alerts_body(html: str) -> str:
    """Extract the body of `function loadAlerts(...)`. Bounds the scope of
    the no-new-controls guard to the Alerts renderer specifically — a
    `<button class="v-chip">` anywhere ELSE in the file (e.g., a future
    Supply Chain Phase 9 chip) does not implicate Alerts and should not
    trip Alerts pins.

    Implementation: find `function loadAlerts(`, walk forward counting
    braces from the first `{`."""
    idx = html.find("function loadAlerts(")
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


def _grep_render_path_button_texts(load_alerts_body: str) -> set[str]:
    """Visible button text on EVERY `<button>` in the render path. These are
    literal strings in the JS template; the source of truth for what renders
    into the DOM. Per judge ruling 2026-06-21 (refined lemma #6), the
    allowlist must cover the full render path, not just the dismiss-btn
    subset:
        Dismiss buttons (3):   False positive, Investigated, Accept risk
        Package actions (4):   View Advisory, View Session, View Package,
                               Copy Report
        Load More (1):         Load More
    """
    out = set()
    for m in re.finditer(r"<button\b[^>]*>([^<]+)</button>", load_alerts_body):
        text = m.group(1).strip()
        if text:
            out.add(text)
    return out


def _grep_dismiss_reasons(load_alerts_body: str) -> set[str]:
    """The reason strings passed to `dismissAlert(id, this, 'REASON')`.
    Backing semantics for the dismiss buttons. Phase 9 will add new reasons
    (`true_positive`, `muted`) — this pin fires the moment they land."""
    return set(re.findall(r"dismissAlert\([^,]+,this,\\?'([a-z_]+)\\?'\)", load_alerts_body))


def _grep_v_chip_uses(load_alerts_body: str) -> list[str]:
    """Any element rendered by loadAlerts with `v-chip` in its class list.
    Tag-agnostic per p6.10.a1 lineage."""
    out = []
    for m in re.finditer(r'<\w+\b[^>]*class="([^"]*)"', load_alerts_body):
        classes = m.group(1).split()
        if "v-chip" in classes:
            out.append(m.group(0))
    return out


_TRIAGE_DATA_ATTRS = ("data-action", "data-triage", "data-status", "data-label")


def _grep_triage_data_attrs(load_alerts_body: str) -> dict[str, list[str]]:
    """The 4 Phase 9 triage attribute families. `data-alert-id` is allowlisted
    (already ships at line 3487/3512). These four are NEW for Phase 9."""
    found: dict[str, list[str]] = {}
    for attr in _TRIAGE_DATA_ATTRS:
        hits = re.findall(rf'{attr}="[^"]*"', load_alerts_body)
        if hits:
            found[attr] = hits
    return found


# ---------------------------------------------------------------------------
# TestAlertsControlIds (Pin 1 — static, markup-drift only)
# ---------------------------------------------------------------------------


class TestAlertsControlIds:
    """Pin 1: the 7 ids in static `#panel-alerts` survive. MARKUP-DRIFT only
    per locked cookbook entry #6 — this pin does NOT and cannot guard
    JS-rendered Phase 9 leaks. That coverage lives in
    `TestAlertsRenderedControlSurface` below."""

    def test_panel_scoped_control_ids_preserved(self):
        baseline = _read_fixture_lines("baseline-c6a91bd-control-ids.txt")
        branch = _grep_control_ids(_grep_panel_block(_read_branch_html(), "panel-alerts"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"control ids DROPPED from #panel-alerts: {sorted(dropped)}"
        assert not added, f"control ids ADDED to #panel-alerts: {sorted(added)}"


# ---------------------------------------------------------------------------
# TestAlertItemSelectors (Pin 2 — static, the migration scope)
# ---------------------------------------------------------------------------


class TestAlertItemSelectors:
    """Pin 2: the 12 `.alert-item*` rule selectors survive verbatim. These
    style the JS-rendered `<div class="alert-item">` wrappers and the
    `.dismiss-btn` buttons inside them."""

    def test_alert_item_selectors_preserved(self):
        baseline = _read_fixture_lines("baseline-c6a91bd-alert-item-selectors.txt")
        branch = _grep_alert_item_selectors(_read_branch_html())
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"`.alert-item*` selectors DROPPED: {sorted(dropped)}"
        assert not added, f"`.alert-item*` selectors ADDED in P6.11 scope (forbidden): {sorted(added)}"


# ---------------------------------------------------------------------------
# TestAlertbarSanity (Pin 3 — cross-tab sanity, p6.9 + p6.10 lineage)
# ---------------------------------------------------------------------------


class TestAlertbarSanity:
    """Pin 3: `.alertbar*` rules already migrated in an earlier Phase 6 step
    are still present. Consumed cross-tab as a top-of-tab callout — a future
    drop on any consuming tab fires this pin (FILE-GLOBAL scope per
    p6.10.a1 verdict carry-forward 3)."""

    def test_alertbar_selectors_preserved(self):
        baseline = _read_fixture_lines("baseline-c6a91bd-alertbar-selectors.txt")
        branch = _grep_alertbar_selectors(_read_branch_html())
        dropped = baseline - branch
        assert not dropped, (
            f"`.alertbar*` selectors DROPPED (cross-tab consumed): {sorted(dropped)}. "
            "Any consuming tab's preservation pin should ALSO be firing — "
            "if not, that pin's coverage has rotted."
        )
        # NOTE: asymmetric on purpose (p6.9/p6.10 lineage) — future work is
        # free to ADD .alertbar* rules; this consumer-side sanity pin only
        # guards against DROPS.


# ---------------------------------------------------------------------------
# TestAlertsRenderedControlSurface (Pins 4–7 — the REAL no-new-controls guard)
# ---------------------------------------------------------------------------


class TestAlertsRenderedControlSurface:
    """Pins 4–7 (the REAL no-new-controls guard per locked cookbook entry
    #6). The Alerts panel's controls are JS-injected by `loadAlerts()` into
    `#alerts-list` at runtime. A static-markup pin cannot enforce the
    rendered surface — it would mistake an empty `<div id="alerts-list">`
    for "no controls." These pins read the JS literal-string templates in
    `loadAlerts()` body — the source of truth for what renders.

    Per p6.11.a2 verdict carry-forwards:
      Phase 9 (P9.2/P9.3/P9.4) will add `true_positive` and `muted` dismiss
      reasons (Pin 5 fires), Unresolved/All/Muted status filter (Pin 1
      fires), and `v-chip` pattern chips (Pin 6 fires). These pins exist
      precisely to fire when Phase 9 lands — forcing a deliberate
      scope-extension PR at that point. The DOM-level guard's job is to
      enforce REPAINT-ONLY until Phase 9 deliberately opens the gate."""

    def test_render_path_button_allowlist(self):
        """Pin 4 (judge-specified allowlist 2026-06-21): the rendered button
        text set is EXACTLY the 8-button allowlist — dismiss-btn (3) +
        package action buttons (4) + Load More (1). Catches any Phase 9
        button addition: True positive / Mute / a new action button / etc."""
        body = _extract_load_alerts_body(_read_branch_html())
        texts = _grep_render_path_button_texts(body)
        expected = {
            "False positive",
            "Investigated",
            "Accept risk",
            "View Advisory ↗",  # rendered text includes the ↗ arrow
            "View Session",
            "View Package",
            "Copy Report",
            "Load More",
            # P9.3 scope-extension (cookbook entry #7 third application,
            # judge p9.3.a2 APPROVE 2026-06-24): per-alert TP/FP triage +
            # Unlabel-verdict button (architect post-pass + frontend-design
            # fold-in 2026-06-25, "Unlabel" preferred over "Clear" for
            # precision). Mute DEFERRED to v0.3 per release scope.
            "True positive",
            "Unlabel",
        }
        dropped = expected - texts
        added = texts - expected
        assert not dropped, f"render-path button text DROPPED: {sorted(dropped)}"
        assert not added, (
            f"render-path button text ADDED: {sorted(added)}. "
            "REPAINT-ONLY scope; new buttons (True positive / Mute / new action) "
            "are Phase 9 (P9.2/P9.3/P9.4), not P6.11. They must land as a "
            "deliberate scope-extension PR with the allowlist updated, not silently. "
            "(cookbook entry #6 + judge ruling 2026-06-21 — see module docstring; "
            "update allowlist AND mutation transcript in the scope-extension PR.)"
        )

    def test_dismiss_reason_set_is_exactly_three(self):
        """Pin 5: dismiss reason set passed to `dismissAlert()` is exactly the
        3 known reasons. Defense in depth alongside Pin 4 — catches the case
        where Phase 9 adds a new dismiss reason without changing the visible
        button text. (`false_positive` already ships — NOT Phase 9 net-new.)"""
        body = _extract_load_alerts_body(_read_branch_html())
        reasons = _grep_dismiss_reasons(body)
        expected = {"false_positive", "investigated", "accepted_risk"}
        dropped = expected - reasons
        added = reasons - expected
        assert not dropped, f"dismiss reasons DROPPED: {sorted(dropped)}"
        assert not added, (
            f"dismiss reasons ADDED: {sorted(added)}. "
            "Phase 9 will introduce `true_positive` and `muted` reasons — "
            "they must land as a deliberate scope-extension PR, not silently."
        )

    def test_no_v_chip_elements_rendered_by_load_alerts(self):
        """Pin 6: zero `v-chip` class-bearing elements rendered by
        `loadAlerts()`. The Phase 9 pattern chips will land as
        `<button class="v-chip">` or `<span class="v-chip">`; this pin
        fires the moment any do. Tag-agnostic (p6.10.a1 lineage)."""
        body = _extract_load_alerts_body(_read_branch_html())
        chips = _grep_v_chip_uses(body)
        assert chips == [], (
            f"`v-chip` elements found in loadAlerts() body — REPAINT-ONLY scope "
            f"forbids the Phase 9 pattern chips: {chips}"
        )

    def test_no_triage_data_attrs_rendered_by_load_alerts(self):
        """Pin 7: zero `data-action` / `data-triage` / `data-status` /
        `data-label` attributes rendered by `loadAlerts()`. `data-alert-id`
        is allowlisted (already ships at lines 3487/3512 today). The four
        guarded attribute families are net-new for Phase 9 triage. This pin
        IS the architect's `data-action` pin pattern from the p6.10.a1
        DEFER carry-forward."""
        body = _extract_load_alerts_body(_read_branch_html())
        found = _grep_triage_data_attrs(body)
        assert not found, (
            f"Phase 9 triage `data-*` attributes found in loadAlerts() body: {found}. "
            "REPAINT-ONLY scope; these are Phase 9 (P9.3/P9.4), not P6.11."
        )
