"""Persistence layer for v0.2.2+.

This package houses the versioned schema-migration framework introduced in
v0.2.2 P0.0. It coexists with the legacy ``CREATE TABLE IF NOT EXISTS`` +
``try/except ALTER TABLE`` pattern in :mod:`claude_monitoring.db` — see
``docs/spec/MIGRATIONS.md`` for the two-mechanism coexistence contract.

Public surface:

- :class:`~claude_monitoring.persistence.migrations.Migration`
- :class:`~claude_monitoring.persistence.migrations.MigrationError`
- :class:`~claude_monitoring.persistence.migrations.DaemonActiveError`
- :data:`~claude_monitoring.persistence.migrations.MIGRATIONS`
- :func:`~claude_monitoring.persistence.migrations.apply_migrations`
- :func:`~claude_monitoring.persistence.migrations.apply_migration`
"""

from __future__ import annotations

from claude_monitoring.persistence.migrations import (
    DEFAULT_PID_FILE_PATH,
    MIGRATIONS,
    DaemonActiveError,
    Migration,
    MigrationError,
    apply_migration,
    apply_migrations,
)

__all__ = [
    "DEFAULT_PID_FILE_PATH",
    "MIGRATIONS",
    "DaemonActiveError",
    "Migration",
    "MigrationError",
    "apply_migration",
    "apply_migrations",
]
