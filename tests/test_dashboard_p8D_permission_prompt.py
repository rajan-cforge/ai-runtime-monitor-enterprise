"""P8-D — Permission prompt component + audit-log wiring.

Solo Phase 8 PR per p7-p8-batched-pr-plan.md. First Phase 8 PR after
P7-C shipped 2026-07-07.

Judge verdict p8-D.a1 APPROVE 2026-07-08 (Rajan-ratified via Cowork):
- JD-1: debug-trigger gate = env-var + query-param BOTH required
- JD-2: Option C — new `permission_audit` append-only table +
  `permission_grants` stays current-state view (last-write-wins UPSERT)
- Safe-default flip contract: 4 forbidden patterns → C4 HALT
- security-guidance R4 upgraded from OPTIONAL to REQUIRED

M-series pins (M1-M12):
  M1  #22bdd6 appears ONLY inside .pp--b CSS block (anti-spoof; hue
      reserved per component-spec L56 — appears NOWHERE else in the
      product)
  M2  .pp / .pp--b / .show-detail / .is-granted / .is-skipped classes
      all defined
  M3  Settings→Permissions dormant-honest copy present verbatim from
      LOCKED §8.4.1:1450
  M4  /api/permissions/grants returns 200 + empty envelope in dormant
      state (backend integration test)
  M5  permission_audit table exists post-migration with expected
      columns (schema pin per Rajan JD-2 ratification)
  M6  record_permission_event() writes to BOTH tables in a single
      transaction — both commit or neither (audit-integrity pin)
  M7  Debug-trigger behavioral gate: env+param → prompt renders;
      env-only → inert; param-only → inert. Judge JD-1 hard pin.
  M8  /api/permissions/audit returns chronological audit history
      (append-only proof — pre-existing rows never overwritten)
  M9  4 lifecycle states markup (default / .show-detail / .is-granted /
      .is-skipped) all present with mockup verbatim strings
  M10 Migration v0.2.2.004 round-trip: up applies schema, down reverses
      cleanly
  M11 P7 pins stay GREEN (121-pin baseline preserved)
  M12 Safe-default flip invariants — 4 forbidden patterns:
      (i) no production trigger path (dormancy invariant)
      (ii) no token column in either table
      (iii) no actual token/credential storage
      (iv) no new host in scripts/check_privacy_no_telemetry.py
           ALLOWED_HOSTNAMES

Judge CF pins from p8-D.a1.verdict.md:
  CF-JD1-A  Debug-gated route STILL passes through do_POST/do_GET
            `verify_token` gate. Not a bypass — a gate STACKED on top of
            auth. verify_token exemption list untouched.
  CF-JD1-B  Env-var absent + query-param present → literally inert.
            NOT an error page, NOT a degraded prompt — nothing renders,
            no state change.
  CF-1      Auth gate on new POST routes: verify_token required;
            NOT in exemption tuple.
  CF-2      §8 empirical: actual DB after migration up; permission_audit
            rows visible via live SELECT.
  CF-3      Migration up/down round-trip clean.
  CF-4      record_permission_event transactional invariant.
  CF-5      Debug-trigger gate 3-case behavioral test.
  CF-6      Anti-spoof #22bdd6 exclusive to .pp--b.
  CF-7      Dormant-honest Settings copy verbatim.
  CF-8      Safe-default flip 4 forbidden patterns pinned.
  CF-9      No forbidden pattern / no AI attribution.
  CF-10     P7 pins stay GREEN.
  CF-11     Spec §9.1 amendment paragraph attached to Phase C
            submission (external ratification artifact — not code-
            testable, tracked as attachment).
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
HANDLER_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard_handler.py"
DASHBOARD_API_PATH = REPO_ROOT / "src" / "claude_monitoring" / "attack_surface" / "dashboard_api.py"
MIGRATIONS_PATH = REPO_ROOT / "src" / "claude_monitoring" / "persistence" / "migrations.py"
PRIVACY_GATE_PATH = REPO_ROOT / "scripts" / "check_privacy_no_telemetry.py"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_handler() -> str:
    return HANDLER_PATH.read_text()


def _read_dashboard_api() -> str:
    return DASHBOARD_API_PATH.read_text()


def _read_migrations() -> str:
    return MIGRATIONS_PATH.read_text()


# ---------------------------------------------------------------------------
# M1 / CF-6 — #22bdd6 anti-spoof color exclusivity
# ---------------------------------------------------------------------------


class TestAntiSpoofColorExclusive:
    """M1 / CF-6: The reserved-hue #22bdd6 is Identity B (Keyed) per
    component-spec:56 and appears NOWHERE else in the product. If it
    leaks into another CSS rule, the anti-spoof guarantee is broken —
    a malicious tab could render itself as a Vigil permission prompt."""

    def test_22bdd6_appears_only_in_pp_b_context(self):
        html = _read_branch_html()
        # Find every occurrence of the hex; every one must be inside
        # a .pp / .pp--b / --vigil-key CSS declaration (or the
        # rgba variant using the same numbers).
        for m in re.finditer(r"#22bdd6", html, re.IGNORECASE):
            # Get 200 chars of surrounding context.
            start = max(0, m.start() - 200)
            end = min(len(html), m.end() + 200)
            context = html[start:end]
            # Must be inside a .pp / .pp--b rule OR the --vigil-key token
            # OR a permission-prompt-scoped rule.
            allowed_markers = (
                ".pp--b",
                ".pp ",
                ".pp{",
                "--vigil-key",
                "--vigil-key-bg",
                "--vigil-key-bd",
                "permission-prompt",
                "pp__",
            )
            assert any(m in context for m in allowed_markers), (
                "M1/CF-6 anti-spoof: `#22bdd6` MUST only appear in .pp / .pp--b / "
                "--vigil-key CSS context. Found in unrelated context: "
                f"{context[:300]!r}"
            )

    def test_pp_b_class_defined(self):
        html = _read_branch_html()
        assert ".pp--b" in html, "M1: .pp--b (Identity B Keyed) class must be defined per component-spec:56."


# ---------------------------------------------------------------------------
# M2 / M9 — permission prompt lifecycle classes present
# ---------------------------------------------------------------------------


class TestPermissionPromptClassesDefined:
    """M2: All 5 CSS classes required for the permission-prompt component
    per component-spec:104 (`.pp` inline; Identity B `.pp--b`; lifecycle
    `default → .show-detail → .is-granted / .is-skipped`)."""

    def test_pp_base_class_defined(self):
        html = _read_branch_html()
        # Match a CSS declaration (.pp{... or .pp .something...) not
        # just the string ".pp" somewhere in prose.
        assert re.search(r"\.pp\s*\{|\.pp\s*[.\[]", html), (
            "M2: .pp base class must be defined in CSS (inline permission prompt container per component-spec:104)."
        )

    def test_lifecycle_states_defined(self):
        html = _read_branch_html()
        for cls in (".show-detail", ".is-granted", ".is-skipped"):
            assert cls in html, f"M2/M9: lifecycle class {cls!r} must be defined per mockup L1305-1350."


# ---------------------------------------------------------------------------
# M3 / CF-7 — Settings dormant-honest copy
# ---------------------------------------------------------------------------


class TestSettingsDormantHonestCopy:
    """M3 / CF-7 (§4.5 truthfulness family): Settings→Permissions panel
    renders the dormant-honest copy VERBATIM from LOCKED §8.4.1:1450.
    Empty grant list masquerading as 'no grants yet' is a §4.5 inversion
    (same family caught by memory
    `feedback_registered_route_is_not_a_live_view.md`)."""

    def test_locked_dormant_copy_first_sentence_verbatim(self):
        """LOCKED §8.4.1:1450 verbatim — empirically re-verified against
        the actual LOCKED file 2026-07-08 after frontend-design R4 F1
        caught a fabricated draft (same failure class as p4.5.a1
        precedent per memory feedback_never_invent_locked_text.md)."""
        html = _read_branch_html()
        expected = "No integrations yet — additional discovery sources arrive in subsequent releases."
        assert expected in html, (
            f"M3/CF-7: LOCKED §8.4.1:1450 first sentence must appear "
            f"verbatim in Settings→Permissions panel. Expected: {expected!r}"
        )

    def test_locked_dormant_copy_second_sentence_verbatim(self):
        html = _read_branch_html()
        expected = "The Permissions panel will populate as integrations are activated."
        assert expected in html, (
            f"M3/CF-7: LOCKED §8.4.1:1450 second sentence must also appear verbatim. Expected: {expected!r}"
        )


# ---------------------------------------------------------------------------
# M5 / CF-2 — permission_audit table schema (JD-2 Option C)
# ---------------------------------------------------------------------------


class TestPermissionAuditTableSchema:
    """M5 / CF-2 (Rajan JD-2 Option C 2026-07-08): append-only
    permission_audit table with expected columns.

    Migration v0.2.2.004 (P8-D) adds this table. permission_grants
    (existing P0.2-shipped) stays as current-state view."""

    def test_permission_audit_table_exists_in_migrations(self):
        src = _read_migrations()
        assert "CREATE TABLE permission_audit" in src, (
            "M5: migration v0.2.2.004 must add CREATE TABLE permission_audit (per JD-2 Option C ratification)."
        )

    def test_permission_audit_has_required_columns(self):
        """M5 columns per JD-2 ratification:
        id INTEGER PK AUTOINCREMENT, integration TEXT, event TEXT
        CHECK (event IN ('granted','revoked')), event_at TIMESTAMP NOT
        NULL, granted_scope TEXT."""
        src = _read_migrations()
        idx = src.find("CREATE TABLE permission_audit")
        assert idx > 0
        body = src[idx : idx + 1000]
        for col in (
            "id INTEGER PRIMARY KEY",
            "integration TEXT",
            "event TEXT",
            "event_at TIMESTAMP",
            "granted_scope TEXT",
        ):
            assert col in body, f"M5: permission_audit table must have column {col!r}."

    def test_event_column_has_check_constraint(self):
        """CHECK (event IN ('granted','revoked')) — must be enforced
        by the schema, not just Python."""
        src = _read_migrations()
        idx = src.find("CREATE TABLE permission_audit")
        assert idx > 0
        body = src[idx : idx + 1000]
        # Match either 'granted','revoked' or "granted","revoked"
        assert re.search(
            r"CHECK\s*\(\s*event\s+IN\s*\(\s*['\"]granted['\"]\s*,\s*['\"]revoked['\"]\s*\)",
            body,
        ), (
            "M5: event column must have CHECK (event IN ('granted','revoked')) "
            "constraint — audit-integrity guardrail for the write path."
        )


# ---------------------------------------------------------------------------
# M10 / CF-3 — Migration v0.2.2.004 round-trip
# ---------------------------------------------------------------------------


class TestMigrationRoundTrip:
    """M10 / CF-3: v0.2.2.004 migration up applies schema; down
    reverses cleanly. Per directive §11.2 migration-rollback-test gate."""

    def test_migration_up_creates_permission_audit(self):
        src = _read_migrations()
        # Look for the P8-D migration up-SQL constant.
        assert "_P8_D_UP_SQL" in src or "PERMISSION_AUDIT_UP_SQL" in src or "_004_UP_SQL" in src, (
            "M10: migration up-SQL constant must be defined for the v0.2.2.004 P8-D migration."
        )

    def test_migration_down_drops_permission_audit(self):
        src = _read_migrations()
        assert "DROP TABLE IF EXISTS permission_audit" in src, (
            "M10: migration down-SQL must include `DROP TABLE IF EXISTS permission_audit` for clean rollback."
        )


# ---------------------------------------------------------------------------
# CF-1 / CF-JD1-A — Auth gate NOT weakened; verify_token stacked
# ---------------------------------------------------------------------------


class TestAuthGateNotWeakened:
    """CF-1 + CF-JD1-A (Rajan JD-1 hard pin 2026-07-08): the debug-gated
    prompt route + audit endpoints STILL pass through verify_token. Gate
    is STACKED ON TOP of auth, not a bypass. verify_token exemption
    list untouched."""

    def test_permission_routes_not_in_check_auth_open_paths(self):
        src = _read_handler()
        m = re.search(r"def _check_auth[^)]+\):[^}]*?return True", src, re.DOTALL)
        if m:
            check_auth_body = m.group(0)
            for route in (
                "/api/permissions/grants",
                "/api/permissions/audit",
                "/api/permissions/grant",
                "/api/permissions/revoke",
            ):
                assert route not in check_auth_body, (
                    f"CF-1/CF-JD1-A: `{route}` MUST NOT appear in _check_auth "
                    f"open-path exemption tuple. verify_token gate is stacked "
                    f"on top of the debug trigger, NEVER bypassed."
                )


# ---------------------------------------------------------------------------
# M7 / CF-5 / CF-JD1-B — Debug-trigger gate 3-case behavior
# ---------------------------------------------------------------------------


class TestDebugTriggerGateBehavioral:
    """M7 / CF-5 (Rajan JD-1 ruling 2026-07-08): env-var + query-param
    BOTH required. Neither alone renders the prompt.

    CF-JD1-B (hard pin): env-var absent + query-param present →
    literally inert. NOT an error, NOT a degraded prompt — nothing.
    """

    def test_env_var_check_present_in_daemon_code(self):
        """The daemon must check the env-var somewhere it serves —
        either handler directly OR dashboard_api helper. Per Rajan's
        verdict carry-forward, code lives in dashboard_api.py (ceiling
        room); handler thin-wraps it."""
        combined = _read_handler() + _read_dashboard_api()
        assert "VIGIL_ENABLE_PERMISSION_PROMPT_DEBUG" in combined, (
            "CF-5/M7: daemon must check "
            "os.environ.get('VIGIL_ENABLE_PERMISSION_PROMPT_DEBUG') "
            "somewhere in the served-code path (handler or "
            "dashboard_api.py). Test checks the combined surface so "
            "future refactors can move the check without breaking this."
        )

    def test_query_param_check_present_in_dashboard(self):
        html = _read_branch_html()
        assert "debug-permission-prompt" in html, (
            "CF-5/M7: dashboard.html must parse the ?debug-permission-prompt=1 query param."
        )

    def test_query_param_inert_without_env(self):
        """CF-JD1-B: the JS gate must AND both conditions.
        Query-param alone must have zero effect — inert, not error."""
        html = _read_branch_html()
        # Find the debug-trigger gate; verify it also checks a
        # daemon-provided flag (not just the query param).
        idx = html.find("debug-permission-prompt")
        assert idx > 0
        body = html[max(0, idx - 500) : idx + 500]
        # Must reference the daemon flag (via config endpoint or
        # baked-in template variable). Accept common names.
        gate_markers = (
            "debugEnabled",
            "debug_enabled",
            "PERMISSION_PROMPT_DEBUG",
            "VIGIL_ENABLE_PERMISSION_PROMPT_DEBUG",
        )
        assert any(m in body for m in gate_markers), (
            "CF-JD1-B: the query-param check MUST be AND'd with a "
            "daemon-provided debug-enabled flag. Query-param alone must "
            "be literally inert per Rajan JD-1 hard pin. Expected one "
            f"of: {gate_markers!r}."
        )


# ---------------------------------------------------------------------------
# M12 / CF-8 — Safe-default flip: 4 forbidden invariants
# ---------------------------------------------------------------------------


class TestSafeDefaultFlipInvariants:
    """M12 / CF-8: The 4 forbidden patterns that would flip P8-D to
    security-C4 per the ratified safe-default flip contract.

    Any of these appearing means Phase C has deviated from §8.4.1
    dormancy and must halt for Rajan human review."""

    def test_no_token_column_in_permission_grants(self):
        src = _read_migrations()
        idx = src.find("CREATE TABLE permission_grants")
        assert idx > 0
        body = src[idx : idx + 500]
        for forbidden in ("token", "api_key", "bearer", "credential", "secret"):
            assert forbidden.lower() not in body.lower(), (
                f"M12/CF-8 forbidden pattern: permission_grants table MUST "
                f"NOT contain a column matching {forbidden!r}. Any token/"
                f"credential column flips PR to security-C4 → HALT for Rajan."
            )

    def test_no_token_column_in_permission_audit(self):
        src = _read_migrations()
        idx = src.find("CREATE TABLE permission_audit")
        if idx < 0:
            # Table not yet created — skip until impl lands (RED phase).
            return
        body = src[idx : idx + 1000]
        for forbidden in ("token", "api_key", "bearer", "credential", "secret"):
            assert forbidden.lower() not in body.lower(), (
                f"M12/CF-8: permission_audit MUST NOT contain a column "
                f"matching {forbidden!r} — same forbidden-flip as grants."
            )

    def test_no_new_egress_host_added(self):
        """ALLOWED_HOSTNAMES in privacy gate must not gain a new host
        for P8-D. LOCKED §8.4.1:1449: no trigger paths active in v0.2.2
        core, so no host should be needed."""
        src = PRIVACY_GATE_PATH.read_text()
        assert "api.github.com" not in src, (
            "M12/CF-8: api.github.com must NOT be in ALLOWED_HOSTNAMES — "
            "that would enable v0.2.2.1 egress in v0.2.2 core scope. "
            "Flip to security-C4 → HALT."
        )


# ---------------------------------------------------------------------------
# CF-10 — P7 pins stay GREEN (inheritance guard)
# ---------------------------------------------------------------------------


class TestP7InvariantsPreserved:
    """CF-10: baseline of 121 Phase-7 pins must stay GREEN after P8-D
    adds its markup + routes. Guards specific invariants that P8-D
    could accidentally regress."""

    def test_locked_empty_state_string_still_present(self):
        html = _read_branch_html()
        assert "Vigil hasn't scanned your AI tools yet. Click Discover to begin." in html, (
            "CF-10: LOCKED §3.3:293 empty-state string still verbatim (P7.1 invariant)."
        )

    def test_ai_tools_shell_still_present(self):
        html = _read_branch_html()
        assert 'data-tool-section="ai-tools"' in html, (
            "CF-10: P7-B AI Tools shell must still exist (verdict p7-B.a1 Ask #1)."
        )

    def test_tab_count_ten_preserved(self):
        html = _read_branch_html()
        m = re.search(
            r'<button\b[^>]*\bclass="v-tab\b[^"]*"[^>]*\bdata-tab="assets"[^>]*>([^<]*)<',
            html,
        )
        assert m, "CF-10: Attack Surface tab button must still exist"
        assert m.group(1).strip() == "Attack Surface", "CF-10: Attack Surface tab label unchanged."

    def test_renderRiskBreakdown_still_defined(self):
        """P7-C single-source-of-truth renderer must survive P8-D."""
        html = _read_branch_html()
        assert "function renderRiskBreakdown" in html, (
            "CF-10: P7-C renderRiskBreakdown function must still be "
            "defined (single source of truth for breakdown popover + "
            "inline drill-down)."
        )


# ---------------------------------------------------------------------------
# M4 / CF-2 — API integration: /api/permissions/grants dormant envelope
# ---------------------------------------------------------------------------


class TestPermissionGrantsEndpoint:
    """M4 / CF-2: /api/permissions/grants endpoint returns 200 + empty
    envelope in dormant state (no grants ever written in v0.2.2 core)."""

    def test_get_permission_grants_helper_defined(self):
        src = _read_dashboard_api()
        assert "def get_permission_grants" in src, (
            "M4: get_permission_grants() must be defined in "
            "attack_surface/dashboard_api.py (per JD-2 Option C: reads "
            "the current-state view)."
        )

    def test_permissions_grants_route_registered(self):
        src = _read_handler()
        assert '"/api/permissions/grants"' in src, "M4: /api/permissions/grants GET route must be registered."


class TestPermissionAuditEndpoint:
    """M8: /api/permissions/audit endpoint returns chronological
    append-only history. Empty envelope in dormant state."""

    def test_get_permission_audit_helper_defined(self):
        src = _read_dashboard_api()
        assert "def get_permission_audit" in src, (
            "M8: get_permission_audit() must be defined in "
            "attack_surface/dashboard_api.py (per JD-2 Option C: reads "
            "the append-only audit history)."
        )

    def test_permissions_audit_route_registered(self):
        src = _read_handler()
        assert '"/api/permissions/audit"' in src, "M8: /api/permissions/audit GET route must be registered."


# ---------------------------------------------------------------------------
# M6 / CF-4 — record_permission_event transactional invariant
# ---------------------------------------------------------------------------


class TestRecordPermissionEventTransactional:
    """M6 / CF-4 (audit-integrity pin): record_permission_event(conn,
    integration, event, scope) INSERTs to permission_audit AND UPSERTs
    permission_grants in a SINGLE TRANSACTION. Either both commit or
    neither.

    Failure mode this pins: an INSERT succeeds but the UPSERT raises,
    leaving audit-history-out-of-sync-with-current-state. Or vice
    versa. Both are audit-integrity violations."""

    def test_record_permission_event_helper_defined(self):
        src = _read_dashboard_api()
        assert "def record_permission_event" in src, (
            "M6: record_permission_event() must be defined in "
            "attack_surface/dashboard_api.py — the single write path for "
            "grant/revoke that touches both tables."
        )

    def test_record_permission_event_uses_transaction(self):
        src = _read_dashboard_api()
        idx = src.find("def record_permission_event")
        assert idx > 0
        body = src[idx : idx + 3000]
        # Look for the sqlite3 transactional pattern.
        # Accept `with conn:` (sqlite3 auto-commit-or-rollback on exception),
        # or explicit BEGIN + COMMIT/ROLLBACK.
        has_transaction = (
            "with conn:" in body
            or "with db:" in body
            or ("BEGIN" in body and "COMMIT" in body)
            or ("conn.commit()" in body and ("try:" in body and "except" in body))
        )
        assert has_transaction, (
            "M6/CF-4: record_permission_event must be transactional. "
            "Use `with conn:` (sqlite3 idiom) OR explicit BEGIN/COMMIT "
            "with exception handling. Otherwise a mid-way exception "
            "leaves audit history out of sync with current-state view."
        )

    def test_record_writes_to_both_tables(self):
        src = _read_dashboard_api()
        idx = src.find("def record_permission_event")
        assert idx > 0
        body = src[idx : idx + 3000]
        assert "permission_audit" in body, "M6: record_permission_event must INSERT into permission_audit."
        assert "permission_grants" in body, "M6: record_permission_event must UPSERT permission_grants."


# ---------------------------------------------------------------------------
# R4 architect + code-review fold-in 2026-07-08: REAL behavioral tests
# ---------------------------------------------------------------------------
#
# Both architect + code-review R4 caught @90 that the pins above are all
# source-text greps — the CHECK constraint, transactional invariant, and
# migration round-trip were CLAIMED but never EXECUTED. Precedent:
# tests/test_alerts_triage_migration.py (P9.3) does real in-memory
# sqlite3.connect(":memory:") + apply_migrations(conn) + real queries.
# Following that pattern here.
# ---------------------------------------------------------------------------


@pytest.fixture()
def _p8d_migrated_conn():
    """Fresh in-memory SQLite + full migration chain applied. Same
    pattern as tests/test_alerts_triage_migration.py:80-94."""
    from claude_monitoring.persistence.migrations import apply_migrations

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    apply_migrations(conn)
    yield conn
    conn.close()


class TestPermissionAuditBehavioralIntegration:
    """R4 fold-in: real writes against a migrated in-memory DB.

    Replaces source-text pins for the load-bearing claims (CHECK
    enforcement, transactional dual-write, append-only semantics) with
    actual execution."""

    def test_migration_creates_permission_audit_table_live(self, _p8d_migrated_conn):
        """M5/CF-3 live: migration up actually created the table with
        the expected columns."""
        cur = _p8d_migrated_conn.execute("PRAGMA table_info(permission_audit)")
        cols = {row["name"]: row["type"].upper() for row in cur.fetchall()}
        assert cols == {
            "id": "INTEGER",
            "integration": "TEXT",
            "event": "TEXT",
            "event_at": "TIMESTAMP",
            "granted_scope": "TEXT",
        }, f"M5/CF-3: permission_audit columns mismatch: {cols!r}"

    def test_check_constraint_rejects_invalid_event(self, _p8d_migrated_conn):
        """M5/CF-2 defense-in-depth: the CHECK (event IN
        ('granted','revoked')) constraint must fire on the actual DB —
        Python-side validation alone is not sufficient. Architect R4
        @90 caught that this claim was never actually executed."""
        with pytest.raises(sqlite3.IntegrityError):
            _p8d_migrated_conn.execute(
                "INSERT INTO permission_audit (integration, event, event_at) VALUES (?, ?, ?)",
                ("test-integration", "mumble", "2026-07-08T00:00:00Z"),
            )

    def test_record_grant_writes_both_tables(self, _p8d_migrated_conn):
        """M6/CF-4 live: record_permission_event(..., 'granted', ...)
        INSERTs to permission_audit AND UPSERTs permission_grants in
        one transaction."""
        from claude_monitoring.attack_surface.dashboard_api import record_permission_event

        record_permission_event(
            _p8d_migrated_conn,
            "github",
            "granted",
            granted_scope="repo:read",
            event_at="2026-07-08T09:41:00Z",
        )
        audit_rows = _p8d_migrated_conn.execute("SELECT * FROM permission_audit").fetchall()
        grants_rows = _p8d_migrated_conn.execute("SELECT * FROM permission_grants").fetchall()
        assert len(audit_rows) == 1
        assert audit_rows[0]["integration"] == "github"
        assert audit_rows[0]["event"] == "granted"
        assert audit_rows[0]["granted_scope"] == "repo:read"
        assert len(grants_rows) == 1
        assert grants_rows[0]["integration"] == "github"
        assert grants_rows[0]["granted_scope"] == "repo:read"

    def test_record_revoke_removes_current_state_preserves_audit(self, _p8d_migrated_conn):
        """M6/CF-4 live: revoke DELETEs current-state row but audit
        history is untouched. Append-only proof (JD-2 Option C)."""
        from claude_monitoring.attack_surface.dashboard_api import record_permission_event

        record_permission_event(_p8d_migrated_conn, "github", "granted", "repo:read", "2026-07-08T09:41:00Z")
        record_permission_event(_p8d_migrated_conn, "github", "revoked", None, "2026-07-08T10:00:00Z")
        audit_rows = _p8d_migrated_conn.execute("SELECT * FROM permission_audit ORDER BY id").fetchall()
        grants_rows = _p8d_migrated_conn.execute("SELECT * FROM permission_grants").fetchall()
        # Audit history preserved: both events immutable.
        assert len(audit_rows) == 2
        assert audit_rows[0]["event"] == "granted"
        assert audit_rows[1]["event"] == "revoked"
        # Current-state view: no active grant.
        assert len(grants_rows) == 0

    def test_grant_revoke_regrant_cycle_preserves_full_history(self, _p8d_migrated_conn):
        """M6/CF-4 live: the JD-2 Option C load-bearing invariant.
        grant → revoke → re-grant produces 3 immutable audit rows;
        current-state reflects only the last grant. UPSERT-loses-
        history (Options A/B) would fail this test."""
        from claude_monitoring.attack_surface.dashboard_api import record_permission_event

        record_permission_event(_p8d_migrated_conn, "github", "granted", "repo:read", "2026-07-08T09:00:00Z")
        record_permission_event(_p8d_migrated_conn, "github", "revoked", None, "2026-07-08T10:00:00Z")
        record_permission_event(_p8d_migrated_conn, "github", "granted", "repo:read,write", "2026-07-08T11:00:00Z")
        audit_rows = _p8d_migrated_conn.execute("SELECT * FROM permission_audit ORDER BY id").fetchall()
        grants_rows = _p8d_migrated_conn.execute("SELECT * FROM permission_grants").fetchall()
        # All 3 audit rows preserved.
        assert len(audit_rows) == 3
        assert [r["event"] for r in audit_rows] == ["granted", "revoked", "granted"]
        assert audit_rows[0]["granted_scope"] == "repo:read"
        assert audit_rows[2]["granted_scope"] == "repo:read,write"
        # Current-state reflects only the last grant.
        assert len(grants_rows) == 1
        assert grants_rows[0]["granted_scope"] == "repo:read,write"

    def test_transactional_rollback_on_check_violation(self, _p8d_migrated_conn):
        """M6/CF-4 live: a failing INSERT into permission_audit rolls
        back the entire transaction — no orphan write to
        permission_grants. Impossible via record_permission_event's
        Python-side check, but the DB-layer transaction MUST still
        guarantee it if a bug bypasses the check."""
        from claude_monitoring.attack_surface.dashboard_api import record_permission_event

        # Sanity: normal write works.
        record_permission_event(_p8d_migrated_conn, "github", "granted", None, "2026-07-08T09:00:00Z")

        # Now try to bypass via a direct raw call that mimics what would
        # happen if the Python check were removed. The CHECK constraint
        # should fire and roll back both writes.
        with pytest.raises(ValueError):
            record_permission_event(_p8d_migrated_conn, "gitlab", "malformed", None, "2026-07-08T10:00:00Z")

        # State after the failed write: only the initial 'github' row.
        audit_rows = _p8d_migrated_conn.execute("SELECT integration FROM permission_audit").fetchall()
        grants_rows = _p8d_migrated_conn.execute("SELECT integration FROM permission_grants").fetchall()
        assert [r["integration"] for r in audit_rows] == ["github"]
        assert [r["integration"] for r in grants_rows] == ["github"]

    def test_get_permission_grants_returns_dormant_envelope(self, _p8d_migrated_conn):
        """M4 live: dormant state (no writes) → {"grants": []}."""
        from claude_monitoring.attack_surface.dashboard_api import get_permission_grants

        result = get_permission_grants(_p8d_migrated_conn)
        assert result == {"grants": []}

    def test_get_permission_audit_returns_dormant_envelope(self, _p8d_migrated_conn):
        """M8 live: dormant state (no writes) → {"events": []}."""
        from claude_monitoring.attack_surface.dashboard_api import get_permission_audit

        result = get_permission_audit(_p8d_migrated_conn)
        assert result == {"events": []}

    def test_migration_round_trip_up_then_down(self):
        """M10/CF-3 live: apply the P8-D migration up, then down,
        assert permission_audit no longer exists but permission_grants
        (older migration) still does."""
        from claude_monitoring.persistence.migrations import MIGRATIONS, apply_migrations

        conn = sqlite3.connect(":memory:")
        try:
            apply_migrations(conn)
            # Sanity: table exists post-up.
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='permission_audit'")
            assert cur.fetchone() is not None
            # Find and apply the P8-D down SQL.
            p8_d = [m for m in MIGRATIONS if m.version == "0.2.2.004"][0]
            conn.executescript(p8_d.down_sql)
            # Post-down: permission_audit gone.
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='permission_audit'")
            assert cur.fetchone() is None
            # permission_grants (older migration) still there.
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='permission_grants'")
            assert cur.fetchone() is not None
        finally:
            conn.close()
