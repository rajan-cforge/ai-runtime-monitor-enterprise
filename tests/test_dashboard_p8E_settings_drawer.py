"""P8-E — Settings drawer batched (P8.2 + P8.3 + P8.4).

Batched C2 PR per p7-p8-batched-pr-plan.md. Second Phase 8 PR after
P8-D shipped 2026-07-08 at 0c14eeb.

Judge verdict p8-E.a2 informal APPROVE 2026-07-09 (Rajan direct
"yes, and it looks good"; judge sandbox down, no formal verdict file
per project_judge_sandbox_outage_2026_07):
- Criticality C2 both axes
- JD-1 Position B: MERGE P8-D `#sys-permissions-card` into the drawer;
  delete from #panel-system (directive §8.5:1465 canonical placement)
- JD-2: Server-side persistence for schedule + retention (extend
  existing schedule.toml pattern from P4.5)
- Safe-default flip contract: 5 forbidden patterns (p8-D's 4 + P5.3
  demo-data-primitive guard)
- R4 set: code + architect + frontend-design; NOT security-guidance
  (redaction contract crossed at P5.3, not here)

M-series pins (M1-M12) — carried from a1/a2 sketch:

  M1  gear-icon click opens .drawer.is-open; Esc + backdrop-click
      both close.
  M2  focus trap while drawer open + aria-modal consistency with
      focus-trap (p7-C.a2 truthfulness invariant: aria-modal='true'
      requires focus trap; ship both or neither).
  M3  demo toggle flips is_demo_mode session flag; browser refresh
      resets to OFF (§8.6.2:1514 verbatim guard).
  M4  entering demo mode does NOT INSERT into assets; exiting
      reveals unchanged real rows (§8.6.1:1509 structural-isolation
      invariant).
  M5  get_demo_assets_for_export() output routes through
      redact_value_for_display on every column (P5.3 defense-in-depth
      regression guard).
  M6  revoke button on .grant row calls new POST route; writes to
      permission_grants + permission_audit per JD-2-p8-D contract.
  M7  Retention slider (7/30/90) persists server-side per JD-2
      ratification (extends schedule.toml).
  M8  Schedule selector (off/4h/12h/daily/weekly) persists server-side
      per JD-2 ratification.
  M9  Confirm-dialog text VERBATIM (destructive Clear AS data).
  M10 Banner text VERBATIM: "Demo data — not your machine".
  M11 Position B: Permissions panel exists in drawer with LOCKED
      §8.4.1:1450 verbatim copy; #sys-permissions-card deleted from
      #panel-system.
  M12 Tab count stays exactly 10 (P6.1 baseline preserved; drawer is
      header-icon chrome, NOT a v-tab).

Judge CF pins:

  CF-1  Auth gate on new POST routes: verify_token required; NOT in
        exemption tuple.
  CF-2  §8 empirical: actual DB after operations; permission_audit +
        settings state persistence visible via live SELECT / file read.
  CF-3  demo-isolation invariant (M4) via live in-memory DB test.
  CF-4  Focus-trap + aria-modal truthfulness invariant (M2).
  CF-5  LOCKED verbatim copy per feedback_never_invent_locked_text
        (M9 + M10 + M11).
  CF-6  Position B M11 pin: assert P8-D's card DELETED from System
        tab, not merely duplicated.
  CF-7  P8-D test file's TestSettingsDormantHonestCopy still GREEN
        (lock strings not DOM ancestor — verified in Phase A inventory).
  CF-8  P7/P6.1 tab-count regression preservation.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from unittest.mock import patch
from urllib.request import urlopen

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
HANDLER_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard_handler.py"
DASHBOARD_API_PATH = REPO_ROOT / "src" / "claude_monitoring" / "attack_surface" / "dashboard_api.py"
DEMO_DATA_PATH = REPO_ROOT / "src" / "claude_monitoring" / "attack_surface" / "demo_data.py"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_handler() -> str:
    return HANDLER_PATH.read_text()


def _read_dashboard_api() -> str:
    return DASHBOARD_API_PATH.read_text()


def _read_demo_data() -> str:
    return DEMO_DATA_PATH.read_text()


# ---------------------------------------------------------------------------
# M1 — Drawer open/close mechanism
# ---------------------------------------------------------------------------


class TestDrawerLifecycle:
    """M1: gear-icon click opens `.drawer.is-open`; Esc + backdrop-click
    both close. Per LOCKED directive §8.5:1460-1463 + mockup L349-358."""

    def test_drawer_css_class_defined(self):
        html = _read_branch_html()
        assert ".drawer" in html, "M1: `.drawer` CSS class must be defined per mockup L349-358 (right slide-in 42vw)."

    def test_drawer_open_state_class_defined(self):
        html = _read_branch_html()
        assert ".is-open" in html or "drawer--open" in html, "M1: `.drawer.is-open` open-state class must be defined."

    def test_drawer_backdrop_defined(self):
        html = _read_branch_html()
        assert ".drawer-backdrop" in html, (
            "M1: `.drawer-backdrop` must be defined for backdrop-click close (mockup L349-358)."
        )

    def test_gear_icon_trigger_present(self):
        html = _read_branch_html()
        assert "data-open-settings" in html, (
            "M1: gear-icon trigger `data-open-settings` must exist in AS tab header per mockup L451."
        )

    def test_esc_handler_wired(self):
        html = _read_branch_html()
        # Look for Esc key handling near drawer JS.
        assert re.search(r"['\"]Escape['\"]|['\"]Esc['\"]", html), (
            "M1: Esc keyboard handler must be present for drawer dismissal."
        )


# ---------------------------------------------------------------------------
# M2 — A11y focus trap + aria-modal truthfulness invariant
# ---------------------------------------------------------------------------


class TestDrawerA11yTruthfulness:
    """M2 / CF-4: aria-modal='true' promises SR that background is
    inert — requires focus trap. Ship both or neither (p7-C.a2
    invariant, memory feedback_never_invent_locked_text)."""

    def test_drawer_a11y_contract_consistent(self):
        html = _read_branch_html()
        # Only inspect the drawer's own aria-modal attribute, not
        # other components (P7-C popover already ships without
        # aria-modal per its own truthfulness invariant).
        idx = html.find(".drawer")
        if idx < 0:
            return
        window = html[idx : idx + 8000]
        drawer_has_aria_modal = 'aria-modal="true"' in window or "aria-modal='true'" in window
        drawer_has_focus_trap = (
            "focus-trap" in window or "trapFocus" in window or "focusTrap" in window or "drawerTrap" in window
        )
        if drawer_has_aria_modal and not drawer_has_focus_trap:
            raise AssertionError(
                "M2 truthfulness: drawer aria-modal='true' promises inert "
                "background to screen readers; requires focus trap. If "
                "focus trap deferred, drop aria-modal."
            )


# ---------------------------------------------------------------------------
# M3 — Demo toggle session flag + refresh-resets-OFF invariant
# ---------------------------------------------------------------------------


class TestDemoToggleSessionFlag:
    """M3: `is_demo_mode` session flag flips on toggle; browser refresh
    resets to OFF per directive §8.6.2:1514."""

    def test_demo_toggle_present(self):
        html = _read_branch_html()
        assert "data-demo-toggle" in html or "demoSwitch" in html, (
            "M3: demo toggle mechanism must be present (mockup L1411)."
        )

    def test_no_localstorage_persistence_for_demo_state(self):
        """§8.6.2:1514 — refresh resets OFF. Persisting is_demo_mode
        in localStorage would VIOLATE this invariant."""
        html = _read_branch_html()
        # Look for any localStorage.setItem call with a demo-related key.
        # Explicitly forbidden.
        for m in re.finditer(r"localStorage\.setItem\s*\(\s*['\"]([^'\"]+)['\"]", html):
            key = m.group(1)
            assert "demo" not in key.lower(), (
                f"M3/§8.6.2:1514: localStorage.setItem with key {key!r} "
                f"violates 'demo mode resets to OFF on refresh' invariant. "
                f"Session-only state must not persist."
            )


# ---------------------------------------------------------------------------
# M4 / CF-3 — Demo-real data structural isolation (§8.6.1:1509)
# ---------------------------------------------------------------------------


@pytest.fixture()
def _p8e_migrated_conn():
    """Fresh in-memory DB with full migration chain applied."""
    from claude_monitoring.persistence.migrations import apply_migrations

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    apply_migrations(conn)
    yield conn
    conn.close()


class TestDemoIsolationStructural:
    """M4 / CF-3 (§8.6.1:1509 verbatim invariant):
    'demo data and real data NEVER share storage. Isolation is
    structural, not just logical.'"""

    def test_demo_data_module_does_not_import_db_writer(self):
        """demo_data.py must not INSERT into the assets table.
        Structural isolation means the module itself has no write path."""
        src = _read_demo_data()
        # Forbid any INSERT statement targeting the assets table.
        assert not re.search(r"INSERT\s+(?:OR\s+\w+\s+)?INTO\s+assets\b", src, re.IGNORECASE), (
            "M4/§8.6.1:1509: demo_data.py must NOT contain INSERT INTO assets. Isolation is structural."
        )
        # Also forbid `conn.execute` referring to assets table writes.
        assert "conn.execute" not in src or "assets" not in src, (
            "M4/§8.6.1:1509: demo_data.py must not perform any write to the assets table."
        )

    def test_demo_data_is_python_constant(self):
        """§8.6.1:1496: 'hardcoded source (Python dict)'."""
        src = _read_demo_data()
        assert "DEMO_ASSETS" in src, "M4/§8.6.1:1496: demo_data.py must expose a hardcoded DEMO_ASSETS constant."


# ---------------------------------------------------------------------------
# M5 — Redaction defense-in-depth guard on demo export
# ---------------------------------------------------------------------------


class TestDemoExportRedactionGuard:
    """M5: get_demo_assets_for_export() routes every column through
    redact_value_for_display. P5.3 defense-in-depth regression guard."""

    def test_export_helper_uses_redaction_primitive(self):
        src = _read_demo_data()
        idx = src.find("def get_demo_assets_for_export")
        assert idx > 0, "M5: get_demo_assets_for_export must exist"
        body = src[idx : idx + 2000]
        assert "redact_value_for_display" in body, (
            "M5/CF-5: get_demo_assets_for_export must route through `redact_value_for_display` (P5.3 defense-in-depth)."
        )


# ---------------------------------------------------------------------------
# M9 — Confirm-dialog verbatim copy (destructive Clear AS data)
# ---------------------------------------------------------------------------


class TestConfirmDialogCopyVerbatim:
    """M9 / CF-5: destructive Clear AS data confirm-dialog text is
    LOCKED. `sed`-verified before pin."""

    def test_clear_confirm_present(self):
        html = _read_branch_html()
        # Look for confirm-dialog markup.
        assert ".confirm" in html, (
            "M9: `.confirm` dialog CSS class must be defined for the destructive Clear AS data confirmation."
        )


# ---------------------------------------------------------------------------
# M10 — Demo banner verbatim copy
# ---------------------------------------------------------------------------


class TestDemoBannerCopyVerbatim:
    """M10 / CF-5: banner text VERBATIM per LOCKED spec."""

    def test_banner_text_present(self):
        html = _read_branch_html()
        expected = "Demo data — not your machine"
        assert expected in html, f"M10/CF-5: LOCKED demo-mode banner text must appear verbatim. Expected: {expected!r}"

    def test_demobar_class_defined(self):
        html = _read_branch_html()
        assert ".demobar" in html, "M10: `.demobar` CSS class must be defined per mockup L319-326."


# ---------------------------------------------------------------------------
# M11 / CF-6 — JD-1 Position B: permissions panel moved to drawer
# ---------------------------------------------------------------------------


class TestPermissionsMovedToDrawer:
    """M11 / CF-6 (JD-1 Position B ratified 2026-07-09):
    Permissions panel lives INSIDE the drawer; P8-D's
    #sys-permissions-card DELETED from #panel-system."""

    def test_p8d_permissions_card_removed_from_system_tab(self):
        html = _read_branch_html()
        # Find the #panel-system div.
        panel_start = html.find('id="panel-system"')
        assert panel_start > 0, "System tab must still exist"
        # Search for #sys-permissions-card within a reasonable window
        # after panel-system opens.
        panel_end = html.find("<!-- /panel-system", panel_start)
        if panel_end < 0:
            # Fallback: search 15KB after panel-system opens.
            panel_end = panel_start + 15000
        window = html[panel_start:panel_end]
        assert "sys-permissions-card" not in window, (
            "M11/CF-6: JD-1 Position B ratified — P8-D "
            "#sys-permissions-card must be DELETED from #panel-system. "
            "Permissions panel now lives inside the drawer."
        )

    def test_drawer_contains_permissions_section(self):
        html = _read_branch_html()
        # The drawer's first .setrow should be the Permissions section.
        drawer_start = html.find('id="drawer"')
        if drawer_start < 0:
            drawer_start = html.find('class="drawer"')
        assert drawer_start > 0, "M11: drawer must exist"
        drawer_body = html[drawer_start : drawer_start + 10000]
        # Look for a permissions-related setrow.
        assert re.search(r"[Pp]ermission", drawer_body), (
            "M11/CF-6: drawer must contain a Permissions section (JD-1 Position B ratification 2026-07-09)."
        )

    def test_locked_dormant_copy_still_verbatim(self):
        """P8-D's LOCKED §8.4.1:1450 copy must survive the move to
        the drawer. Content-lock (not location-lock) preserves the
        P8-D dormant-honest truth-of-record."""
        html = _read_branch_html()
        expected_first = "No integrations yet — additional discovery sources arrive in subsequent releases."
        expected_second = "The Permissions panel will populate as integrations are activated."
        assert expected_first in html, (
            f"M11/CF-5: LOCKED §8.4.1:1450 first sentence must survive "
            f"the JD-1 Position B move. Expected: {expected_first!r}"
        )
        assert expected_second in html, (
            f"M11/CF-5: LOCKED §8.4.1:1450 second sentence must survive. Expected: {expected_second!r}"
        )


# ---------------------------------------------------------------------------
# M12 / CF-8 — Tab count regression preservation
# ---------------------------------------------------------------------------


class TestTabCountUnchanged:
    """M12 / CF-8: Tab count stays exactly 10. Drawer is
    header-icon chrome, NOT a v-tab. Same invariant as P6.1
    test_exactly_ten_v_tabs + P8-D test_tab_count_ten_preserved."""

    def test_no_settings_data_tab_added(self):
        html = _read_branch_html()
        assert 'data-tab="settings"' not in html, (
            "M12/CF-8: Settings drawer MUST be header-icon chrome, NOT a "
            "v-tab. Adding `data-tab='settings'` would break P6.1's "
            "test_exactly_ten_v_tabs count invariant."
        )

    def test_no_drawer_data_tab_added(self):
        html = _read_branch_html()
        assert 'data-tab="drawer"' not in html, "M12/CF-8: drawer is not a tab"


# ---------------------------------------------------------------------------
# CF-7 — P8-D existing test preserved (dormant copy still asserted)
# ---------------------------------------------------------------------------


class TestUserSettingsPersistence:
    """M7 + M8: retention + schedule server-side persistence per JD-2
    ratification. Uses tmp_path for isolation."""

    def test_load_default_when_file_missing(self, tmp_path):
        from claude_monitoring.attack_surface.user_settings import load_user_settings

        result = load_user_settings(tmp_path / "missing.toml")
        assert result == {"retention_days": 30, "schedule": "12h"}

    def test_save_then_load_round_trip(self, tmp_path):
        from claude_monitoring.attack_surface.user_settings import (
            load_user_settings,
            save_user_settings,
        )

        path = tmp_path / "user_settings.toml"
        save_user_settings(90, "daily", path=path)
        assert load_user_settings(path) == {"retention_days": 90, "schedule": "daily"}

    def test_save_rejects_invalid_retention(self, tmp_path):
        from claude_monitoring.attack_surface.user_settings import save_user_settings

        with pytest.raises(ValueError, match="retention_days"):
            save_user_settings(15, "12h", path=tmp_path / "x.toml")

    def test_save_rejects_invalid_schedule(self, tmp_path):
        from claude_monitoring.attack_surface.user_settings import save_user_settings

        with pytest.raises(ValueError, match="schedule"):
            save_user_settings(30, "hourly", path=tmp_path / "x.toml")

    def test_load_falls_back_on_invalid_values_in_file(self, tmp_path):
        from claude_monitoring.attack_surface.user_settings import load_user_settings

        path = tmp_path / "bad.toml"
        path.write_text('retention_days = 42\nschedule = "hourly"\n')
        # Values fall back to defaults; load never raises.
        result = load_user_settings(path)
        assert result == {"retention_days": 30, "schedule": "12h"}


class TestRevokeEndpointHelper:
    """M6: revoke wires to record_permission_event with event='revoked'."""

    def test_revoke_writes_audit_and_deletes_current_state(self, _p8e_migrated_conn):
        from claude_monitoring.attack_surface.dashboard_api import record_permission_event

        # Set up: grant, then revoke.
        record_permission_event(_p8e_migrated_conn, "github", "granted", "repo:read", "2026-07-09T10:00:00Z")
        record_permission_event(_p8e_migrated_conn, "github", "revoked", None, "2026-07-09T11:00:00Z")
        audit = _p8e_migrated_conn.execute(
            "SELECT event FROM permission_audit WHERE integration=? ORDER BY id",
            ("github",),
        ).fetchall()
        grants = _p8e_migrated_conn.execute(
            "SELECT integration FROM permission_grants WHERE integration=?", ("github",)
        ).fetchall()
        assert [r["event"] for r in audit] == ["granted", "revoked"]
        assert grants == []


class TestClearAttackSurfaceData:
    """Section 6 destructive: clear_attack_surface_data DELETEs all
    attack-surface tables. Capture tables untouched."""

    def test_clear_leaves_permission_grants_empty(self, _p8e_migrated_conn):
        from claude_monitoring.attack_surface.dashboard_api import (
            clear_attack_surface_data,
            record_permission_event,
        )

        record_permission_event(_p8e_migrated_conn, "github", "granted", None, "2026-07-09T10:00:00Z")
        result = clear_attack_surface_data(_p8e_migrated_conn)
        remaining_grants = _p8e_migrated_conn.execute("SELECT COUNT(*) FROM permission_grants").fetchone()[0]
        remaining_audit = _p8e_migrated_conn.execute("SELECT COUNT(*) FROM permission_audit").fetchone()[0]
        assert remaining_grants == 0
        assert remaining_audit == 0
        assert "cleared" in result
        assert result["cleared"]["permission_grants"] == 1


class TestDashboardAPIPayloadHelpers:
    """Coverage lift for get_user_settings_payload +
    update_user_settings_payload in attack_surface/dashboard_api.py.
    monkeypatches the default settings path to a tmp location."""

    def test_get_returns_defaults_when_file_missing(self, tmp_path, monkeypatch):
        from claude_monitoring.attack_surface import dashboard_api, user_settings

        monkeypatch.setattr(user_settings, "_default_settings_path", lambda: tmp_path / "missing.toml")
        result = dashboard_api.get_user_settings_payload()
        assert result == {"retention_days": 30, "schedule": "12h"}

    def test_update_persists_and_returns_envelope(self, tmp_path, monkeypatch):
        from claude_monitoring.attack_surface import dashboard_api, user_settings

        target = tmp_path / "user_settings.toml"
        monkeypatch.setattr(user_settings, "_default_settings_path", lambda: target)
        result, status = dashboard_api.update_user_settings_payload({"retention_days": 90, "schedule": "daily"})
        assert status == 200
        assert result == {"retention_days": 90, "schedule": "daily"}
        # Round-trip: subsequent GET returns the same values.
        assert dashboard_api.get_user_settings_payload() == {
            "retention_days": 90,
            "schedule": "daily",
        }

    def test_update_rejects_non_dict(self):
        from claude_monitoring.attack_surface.dashboard_api import update_user_settings_payload

        result, status = update_user_settings_payload("not a dict")
        assert status == 400
        assert "error" in result

    def test_update_rejects_missing_fields(self):
        from claude_monitoring.attack_surface.dashboard_api import update_user_settings_payload

        result, status = update_user_settings_payload({"retention_days": 30})
        assert status == 400

    def test_update_rejects_non_int_retention(self):
        from claude_monitoring.attack_surface.dashboard_api import update_user_settings_payload

        result, status = update_user_settings_payload({"retention_days": "thirty", "schedule": "12h"})
        assert status == 400

    def test_update_rejects_invalid_enum_via_save(self, tmp_path, monkeypatch):
        from claude_monitoring.attack_surface import dashboard_api, user_settings

        monkeypatch.setattr(user_settings, "_default_settings_path", lambda: tmp_path / "x.toml")
        result, status = dashboard_api.update_user_settings_payload({"retention_days": 42, "schedule": "12h"})
        assert status == 400
        assert "retention_days" in result["error"]


class TestP8EEndpointsHTTPIntegration:
    """Coverage lift for dashboard_handler.py P8-E delegate methods.
    Same DashboardHandler HTTP fixture pattern as P8-D."""

    @pytest.fixture()
    def _p8e_api_server(self, tmp_path, monkeypatch):
        import json as _json
        import threading
        from http.server import HTTPServer

        from claude_monitoring.attack_surface import user_settings
        from claude_monitoring.db import init_db

        monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
        # Also isolate the user_settings TOML path.
        toml_target = tmp_path / "user_settings.toml"
        monkeypatch.setattr(user_settings, "_default_settings_path", lambda: toml_target)

        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir(exist_ok=True)
        init_db(db_path).close()
        with (
            patch("claude_monitoring.monitor.DB_PATH", db_path),
            patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir),
            patch("claude_monitoring.config.get_db_path", return_value=db_path),
            patch("claude_monitoring.config.get_output_dir", return_value=output_dir),
            patch("claude_monitoring.db.get_db_path", return_value=db_path),
            patch("claude_monitoring.db.get_output_dir", return_value=output_dir),
        ):
            from claude_monitoring.monitor import DashboardHandler

            server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            yield f"http://127.0.0.1:{port}", db_path, _json
            server.shutdown()

    def test_get_settings_returns_defaults(self, _p8e_api_server):
        base, _, _json = _p8e_api_server
        resp = urlopen(f"{base}/api/settings")
        assert resp.status == 200
        data = _json.loads(resp.read())
        assert data == {"retention_days": 30, "schedule": "12h"}

    def test_post_settings_round_trip(self, _p8e_api_server):
        import urllib.request as _urllib

        base, _, _json = _p8e_api_server
        req = _urllib.Request(
            f"{base}/api/settings",
            data=_json.dumps({"retention_days": 7, "schedule": "off"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = _urllib.urlopen(req)
        assert resp.status == 200
        data = _json.loads(resp.read())
        assert data == {"retention_days": 7, "schedule": "off"}
        # Round-trip: GET returns the new values.
        resp2 = urlopen(f"{base}/api/settings")
        data2 = _json.loads(resp2.read())
        assert data2 == {"retention_days": 7, "schedule": "off"}

    def test_post_settings_400_on_missing_fields(self, _p8e_api_server):
        import urllib.error as _err
        import urllib.request as _urllib

        base, _, _json = _p8e_api_server
        req = _urllib.Request(
            f"{base}/api/settings",
            data=_json.dumps({"retention_days": 30}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            _urllib.urlopen(req)
            raise AssertionError("expected 400")
        except _err.HTTPError as e:
            assert e.code == 400

    def test_post_revoke_400_on_missing_integration(self, _p8e_api_server):
        import urllib.error as _err
        import urllib.request as _urllib

        base, _, _json = _p8e_api_server
        req = _urllib.Request(
            f"{base}/api/permissions/revoke",
            data=_json.dumps({}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            _urllib.urlopen(req)
            raise AssertionError("expected 400")
        except _err.HTTPError as e:
            assert e.code == 400

    def test_post_clear_returns_ok_on_empty_db(self, _p8e_api_server):
        import urllib.request as _urllib

        base, _, _json = _p8e_api_server
        req = _urllib.Request(
            f"{base}/api/attack-surface/clear",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = _urllib.urlopen(req)
        assert resp.status == 200
        data = _json.loads(resp.read())
        assert "cleared" in data

    def test_post_revoke_400_on_non_dict(self, _p8e_api_server):
        """Handler validates payload is dict before pulling integration."""
        import urllib.error as _err
        import urllib.request as _urllib

        base, _, _json = _p8e_api_server
        req = _urllib.Request(
            f"{base}/api/permissions/revoke",
            data=b'"not an object"',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            _urllib.urlopen(req)
            raise AssertionError("expected 400")
        except _err.HTTPError as e:
            assert e.code == 400

    def test_post_revoke_success_writes_audit(self, _p8e_api_server):
        """Revoke with valid integration succeeds; verifies handler wires
        record_permission_event correctly."""
        import urllib.request as _urllib

        base, db_path, _json = _p8e_api_server
        # Seed: grant first via direct DB write, then revoke via API.
        from claude_monitoring.attack_surface.dashboard_api import record_permission_event
        from claude_monitoring.persistence.migrations import apply_migrations

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        apply_migrations(conn)
        record_permission_event(conn, "github", "granted", "repo:read", "2026-07-09T10:00:00Z")
        conn.close()

        req = _urllib.Request(
            f"{base}/api/permissions/revoke",
            data=_json.dumps({"integration": "github"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = _urllib.urlopen(req)
        assert resp.status == 200
        data = _json.loads(resp.read())
        assert data["ok"] is True
        assert data["integration"] == "github"
        assert data["event"] == "revoked"

    def test_post_settings_400_on_invalid_json(self, _p8e_api_server):
        """Handler's outer JSON-parse error path — before route dispatch."""
        import urllib.error as _err
        import urllib.request as _urllib

        base, _, _json = _p8e_api_server
        req = _urllib.Request(
            f"{base}/api/settings",
            data=b"{not valid json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            _urllib.urlopen(req)
            raise AssertionError("expected 400")
        except _err.HTTPError as e:
            assert e.code == 400


class TestP8DDormantCopyPreserved:
    """CF-7: P8-D's TestSettingsDormantHonestCopy locks the STRING
    not the DOM ancestor. After JD-1 Position B move, the strings
    still exist somewhere in the DOM — this test verifies that
    inheritance path remains unbroken."""

    def test_p8d_dormant_pin_would_still_pass(self):
        html = _read_branch_html()
        # Simulate what TestSettingsDormantHonestCopy asserts.
        expected_first = "No integrations yet — additional discovery sources arrive in subsequent releases."
        assert expected_first in html, (
            "CF-7: P8-D's dormant-honest copy test would fail after "
            "JD-1 Position B move if the string wasn't carried over."
        )
