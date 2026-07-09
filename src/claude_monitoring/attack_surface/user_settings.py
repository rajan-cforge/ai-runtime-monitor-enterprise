"""P8-E user settings persistence — retention + discovery-schedule.

Per JD-2 ratification 2026-07-09 (Rajan direct): server-side
persistence for the Settings drawer's retention + schedule controls.

Storage: ``~/.config/vigil/user_settings.toml`` (separate from P4.5's
``schedule.toml`` — that one is scheduler-cadence, this one is
drawer-UI state). Isolation avoids coupling P8-E to P4.5's internals
during a batched-C2 PR.

Contract:
- Values are UI-facing enums (retention: 7|30|90 days;
  schedule: off|4h|12h|daily|weekly).
- Missing file → returns defaults (retention=30, schedule=12h).
- Malformed file → returns defaults; logs warning.
- Writes are atomic (write-then-rename); no partial file on crash.

Wired to v0.2.2.1 daemon-consumption in a follow-up PR; for v0.2.2
the drawer reads/writes these values but the daemon doesn't yet honor
them. That's a documented feature-flag gap, not a redaction contract
issue (values are UI enum labels, no secrets).
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_VALID_RETENTION = frozenset({7, 30, 90})
_VALID_SCHEDULE = frozenset({"off", "4h", "12h", "daily", "weekly"})

_DEFAULT_RETENTION_DAYS = 30
_DEFAULT_SCHEDULE = "12h"


def _default_settings_path() -> Path:
    """Return default settings path — XDG config dir per P4.5 pattern."""
    return Path.home() / ".config" / "vigil" / "user_settings.toml"


def _load_tomllib() -> Any:
    """Load tomllib (Python 3.11+) or tomli fallback."""
    try:
        import tomllib

        return tomllib
    except ImportError:
        import tomli

        return tomli


def load_user_settings(path: Path | None = None) -> dict[str, Any]:
    """Load user settings; return dict with `retention_days` + `schedule`.

    Missing file or parse error → defaults. Never raises for invalid
    input — always returns a valid dict.
    """
    if path is None:
        path = _default_settings_path()

    if not path.exists():
        return {
            "retention_days": _DEFAULT_RETENTION_DAYS,
            "schedule": _DEFAULT_SCHEDULE,
        }

    try:
        tomllib = _load_tomllib()
        with path.open("rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        logger.warning("user_settings.toml at %s failed to parse: %s; using defaults", path, exc)
        return {
            "retention_days": _DEFAULT_RETENTION_DAYS,
            "schedule": _DEFAULT_SCHEDULE,
        }

    retention = data.get("retention_days", _DEFAULT_RETENTION_DAYS)
    if retention not in _VALID_RETENTION:
        logger.warning(
            "user_settings.toml: retention_days=%r not in %s; using default %d",
            retention,
            sorted(_VALID_RETENTION),
            _DEFAULT_RETENTION_DAYS,
        )
        retention = _DEFAULT_RETENTION_DAYS

    schedule = data.get("schedule", _DEFAULT_SCHEDULE)
    if schedule not in _VALID_SCHEDULE:
        logger.warning(
            "user_settings.toml: schedule=%r not in %s; using default %r",
            schedule,
            sorted(_VALID_SCHEDULE),
            _DEFAULT_SCHEDULE,
        )
        schedule = _DEFAULT_SCHEDULE

    return {"retention_days": int(retention), "schedule": str(schedule)}


def save_user_settings(
    retention_days: int,
    schedule: str,
    path: Path | None = None,
) -> None:
    """Write settings to ``user_settings.toml`` atomically.

    Validation is strict: invalid values raise ``ValueError``. The
    write is atomic (tempfile + rename) so a crash mid-write cannot
    leave a partial TOML on disk.

    Args:
        retention_days: 7, 30, or 90.
        schedule: 'off', '4h', '12h', 'daily', or 'weekly'.
        path: Override the default path (used in tests).

    Raises:
        ValueError: if either value is not in the allowed set.
    """
    if retention_days not in _VALID_RETENTION:
        raise ValueError(f"retention_days must be one of {sorted(_VALID_RETENTION)}; got {retention_days!r}")
    if schedule not in _VALID_SCHEDULE:
        raise ValueError(f"schedule must be one of {sorted(_VALID_SCHEDULE)}; got {schedule!r}")

    if path is None:
        path = _default_settings_path()

    path.parent.mkdir(parents=True, exist_ok=True)

    body = (
        f"# P8-E Attack Surface Settings drawer state.\n"
        f"# Written by the daemon on user toggle; read at daemon start.\n"
        f"retention_days = {retention_days}\n"
        f'schedule = "{schedule}"\n'
    )

    # Atomic write: tempfile in same directory + rename.
    with tempfile.NamedTemporaryFile(
        mode="w",
        dir=str(path.parent),
        prefix=".user_settings.",
        suffix=".toml.tmp",
        delete=False,
        encoding="utf-8",
    ) as tmp:
        tmp.write(body)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)
