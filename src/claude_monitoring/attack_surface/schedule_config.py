"""P4.5 schedule.toml loader — operator-configurable scheduler cadence.

Per spec §8.2 (verbatim):
    "Runs daily by default. Configurable (4h / 12h / daily / weekly / off).
     Default time: 03:00 local. Lower priority than active monitoring."

Operator surface: ``~/.config/vigil/schedule.toml`` (XDG config dir per
v0.2.2 precedent). Two sections:

  ``[discovery]`` — cadence + time_of_day for the scheduled discovery scan
  ``[cve_poll]`` — cadence + time_of_day for the separate CVE poll thread
                   (spec §8.3 "Separate from asset discovery. Runs daily.")

Missing file OR malformed TOML → hardcoded defaults (daily @ 03:00 for
discovery; daily @ 03:30 for cve_poll). A one-time INFO log line surfaces
the fallback so the operator never wonders silently which schedule won.

The ``off`` cadence value disables that loop entirely while keeping the
thread alive — required so ``finalize_crashed_runs_at_startup`` still
runs on daemon start and the dashboard scan-in-progress envelope clears
correctly. With ``off``, ``next_slot()`` returns ``None``; the calling
loop sleeps a long interval and re-checks (operators can flip the toggle
without restarting).
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger("ai-runtime-monitor.attack_surface.schedule_config")


Cadence = Literal["4h", "12h", "daily", "weekly", "off"]

VALID_CADENCES: frozenset[str] = frozenset({"4h", "12h", "daily", "weekly", "off"})


DEFAULT_DISCOVERY_TIME = "03:00"
DEFAULT_CVE_POLL_TIME = "03:30"
"""30-min offset from discovery default — avoids rate-limit contention
on OSV.dev if the daemon starts at exactly the configured discovery slot
and the OSV poll fires simultaneously."""


@dataclass(frozen=True)
class ScheduleSpec:
    """One section of schedule.toml after parsing + validation."""

    cadence: Cadence
    time_of_day: str  # "HH:MM" 24h local

    def next_slot(self, *, after: _dt.datetime | None = None) -> _dt.datetime | None:
        """Compute the next firing time after ``after`` (default = now).

        ``cadence="off"`` → returns ``None`` (caller short-circuits).

        ``daily`` + ``weekly`` cadences honor ``time_of_day`` (next
        occurrence at that wall-clock time). ``4h``/``12h`` cadences
        ignore ``time_of_day`` per §8.2's enum semantics — the operator
        chose an interval, not a wall-clock slot."""
        if self.cadence == "off":
            return None
        now = after if after is not None else _dt.datetime.now()
        if self.cadence == "4h":
            return now + _dt.timedelta(hours=4)
        if self.cadence == "12h":
            return now + _dt.timedelta(hours=12)
        hh, mm = _parse_hhmm(self.time_of_day)
        if self.cadence == "daily":
            candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if candidate <= now:
                candidate += _dt.timedelta(days=1)
            return candidate
        if self.cadence == "weekly":
            candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if candidate <= now:
                candidate += _dt.timedelta(days=7)
            else:
                # Same-day "weekly" still fires today if time is later;
                # otherwise a week from now.
                candidate += _dt.timedelta(days=6)  # weekly default = next 7d slot
            return candidate
        raise ValueError(f"unhandled cadence {self.cadence!r}")  # defensive


def _parse_hhmm(value: str) -> tuple[int, int]:
    """Parse ``"HH:MM"`` → ``(hour, minute)`` with bounds checks. Raises
    ``ValueError`` on malformed input. Used by the loader; downstream
    callers receive a validated ``ScheduleSpec`` and don't need to
    re-validate."""
    parts = value.split(":")
    if len(parts) != 2:
        raise ValueError(f"time_of_day must be HH:MM, got {value!r}")
    hh, mm = int(parts[0]), int(parts[1])
    if not (0 <= hh < 24 and 0 <= mm < 60):
        raise ValueError(f"time_of_day out of range, got {value!r}")
    return hh, mm


@dataclass(frozen=True)
class ScheduleConfig:
    """Top-level schedule.toml after parsing."""

    discovery: ScheduleSpec
    cve_poll: ScheduleSpec

    @classmethod
    def defaults(cls) -> ScheduleConfig:
        return cls(
            discovery=ScheduleSpec(cadence="daily", time_of_day=DEFAULT_DISCOVERY_TIME),
            cve_poll=ScheduleSpec(cadence="daily", time_of_day=DEFAULT_CVE_POLL_TIME),
        )


def _default_config_path() -> Path:
    return Path.home() / ".config" / "vigil" / "schedule.toml"


def _load_tomllib() -> Any:
    """Return a ``tomllib``-compatible module; ``tomli`` backfill on 3.10.

    Mirrors `attack_surface/cves/config.py`'s pattern."""
    if sys.version_info >= (3, 11):
        import tomllib

        return tomllib
    import tomli  # type: ignore[import-not-found]

    return tomli


def load_schedule_config(path: Path | None = None) -> ScheduleConfig:
    """Return the parsed config — defaults on missing/malformed input.

    Always returns a valid ``ScheduleConfig``; failure modes emit a
    single INFO log line and fall back to ``ScheduleConfig.defaults()``.
    Never raises into the scheduler loop — the schedule must always
    have a value.
    """
    if path is None:
        path = _default_config_path()
    if not path.exists():
        logger.info("schedule.toml not found at %s; using defaults (daily @ 03:00)", path)
        return ScheduleConfig.defaults()
    try:
        tomllib = _load_tomllib()
        raw = tomllib.loads(path.read_text())
    except Exception as exc:
        logger.warning("schedule.toml at %s failed to parse: %s; using defaults", path, exc)
        return ScheduleConfig.defaults()

    discovery = _parse_section(raw.get("discovery", {}), default_time=DEFAULT_DISCOVERY_TIME, label="discovery")
    cve_poll = _parse_section(raw.get("cve_poll", {}), default_time=DEFAULT_CVE_POLL_TIME, label="cve_poll")
    return ScheduleConfig(discovery=discovery, cve_poll=cve_poll)


def _parse_section(section: dict[str, Any], *, default_time: str, label: str) -> ScheduleSpec:
    cadence = section.get("cadence", "daily")
    if cadence not in VALID_CADENCES:
        logger.warning(
            "schedule.toml [%s].cadence=%r not in %s; falling back to 'daily'",
            label,
            cadence,
            sorted(VALID_CADENCES),
        )
        cadence = "daily"
    time_of_day = section.get("time_of_day", default_time)
    try:
        _parse_hhmm(time_of_day)
    except ValueError as exc:
        logger.warning(
            "schedule.toml [%s].time_of_day=%r invalid (%s); falling back to %r",
            label,
            time_of_day,
            exc,
            default_time,
        )
        time_of_day = default_time
    return ScheduleSpec(cadence=cadence, time_of_day=time_of_day)


# Convenience env-var override for tests — `VIGIL_SCHEDULE_CONFIG` points
# to a non-default path. Production never sets it.
def resolve_schedule_path() -> Path:
    override = os.environ.get("VIGIL_SCHEDULE_CONFIG")
    if override:
        return Path(override)
    return _default_config_path()
