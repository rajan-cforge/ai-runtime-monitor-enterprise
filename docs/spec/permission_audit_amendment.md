# LOCKED §9.1 amendment — `permission_audit` table (P8-D, 2026-07-08)

**Precedent**: `project_v022_phase1_ratifications.md` Decision 5 — spec
amendments inline. This document is the amendment artifact for external
Rajan ratification per CF-11 of the p8-D.a1 judge verdict.

## What changes in LOCKED spec §9.1

Add a new table definition after the existing `permission_grants`
declaration:

```sql
CREATE TABLE permission_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    integration TEXT NOT NULL,
    event TEXT NOT NULL CHECK (event IN ('granted', 'revoked')),
    event_at TIMESTAMP NOT NULL,
    granted_scope TEXT
);
CREATE INDEX idx_permission_audit_integration ON permission_audit(integration);
CREATE INDEX idx_permission_audit_event_at ON permission_audit(event_at);
```

## Rationale

**§4.5.1 requirement 6** ("User-visible audit log") specified that
permission grants must be logged with "timestamp and integration name"
and the user must be able to see what they've granted from a Settings
panel. The existing `permission_grants` table (P0.2-shipped) has
`PRIMARY KEY (integration)` — one row per integration, last-write-wins
semantic. This is the CURRENT STATE.

But "audit log" implies HISTORY: every grant + every revoke must be
recoverable. Under the existing table alone, a `grant → revoke →
re-grant` cycle would be recorded as three separate UPSERTs against the
same row, losing the prior granted_at timestamp on each re-grant.

**Rajan JD-2 ratification 2026-07-08** (verbatim from Cowork chat):
> "Add a separate, append-only history table. Every grant/revoke event
> gets its own permanent row; nothing is ever overwritten. More setup
> work now (one database migration), but it's the only option that
> actually delivers on 'audit log.'"

Load-bearing framing: v0.2.2 core is dormant (§8.4.1:1449); no real
writes ship. But the schema that ships is the schema v0.2.2.1 GitHub
integration writes will use. Committing to UPSERT-only or an additive
`revoked_at` column would lock in a lossy audit primitive at the
moment real production data starts flowing. This amendment is the ONE
chance to get audit-integrity right before that.

## Design decisions embedded in the schema

- **`id INTEGER PRIMARY KEY AUTOINCREMENT`** — surrogate PK, guarantees
  chronological ordering even if two events share `event_at`.
- **`event TEXT CHECK (event IN ('granted', 'revoked'))`** — CHECK
  constraint at the DB layer (not just Python) — defense-in-depth
  against a Python-side bypass; any bad write fails hard with
  `sqlite3.IntegrityError` rather than corrupting the audit.
- **`event_at TIMESTAMP NOT NULL`** — required; audit rows without a
  timestamp are meaningless.
- **`granted_scope TEXT`** — nullable; NULL for revoke events (no scope
  to record).
- **No `user_id` column** — Vigil is single-user localhost; the
  operator is implicit.
- **No FK to `permission_grants`** — the audit history is authoritative
  even if the current-state row is deleted (revoke).
- **Foreign-key clause omitted** — per P0.2 deviation #3, PRAGMA
  foreign_keys is OFF; integration-name orphans are tolerated like
  every other table.
- **Two indexes** — `(integration)` for per-integration history
  queries, `(event_at)` for the reverse-chronological Settings panel
  view.

## Explicitly forbidden columns (safe-default flip contract)

Per p8-D.a1.verdict.md §4 (Rajan-ratified), the following columns
would flip the PR to security-C4 → HALT for Rajan review:

- Any column matching `token`, `api_key`, `bearer`, `credential`, `secret`
- User email, machine ID, external-service correlation ID
- Cryptographic key material, hashes of tokens

Test `TestSafeDefaultFlipInvariants::test_no_token_column_in_permission_audit`
in `tests/test_dashboard_p8D_permission_prompt.py` pins the invariant
in code.

## Write path

`record_permission_event(conn, integration, event, granted_scope=None,
event_at=None)` in
`src/claude_monitoring/attack_surface/dashboard_api.py`. INSERTs to
`permission_audit` and UPSERTs (or DELETEs, for revokes)
`permission_grants` in a single transaction (`with conn:` sqlite3
idiom — auto-commit-or-rollback). Both writes commit or neither.

Live behavioral tests in
`tests/test_dashboard_p8D_permission_prompt.py::TestPermissionAuditBehavioralIntegration`
prove:
- CHECK constraint rejects bad `event` values
- grant → revoke → re-grant cycle produces 3 immutable audit rows +
  current-state reflects only the last grant
- migration up/down round-trip is clean

## Rollback

Migration v0.2.2.004 down-SQL drops `permission_audit`; SQLite drops
the two indexes automatically as part of DROP TABLE.
`permission_grants` (older P0.2 migration) is unaffected. Audit
history is intentionally LOST on down-migration — restoring the
pre-P8-D state means restoring an absence of the audit capability.

## Rajan ratification (external, to be recorded)

This amendment is submitted for Rajan external ratification per
`project_v022_phase1_ratifications.md` Decision 5. On ratification,
the amendment paragraph should be pasted into
`v022-attack-surface-feature-spec-v1-LOCKED.md` §9.1 with attribution
line `— Rajan, 2026-07-08 (p8-D, JD-2 Option C)`.
