"""P4.5 schedule_config tests — Phase B (TDD red).

Phase A judge p4.5.a3 APPROVE. D-cfg: schedule.toml under XDG config;
five-cadence enum (4h / 12h / daily / weekly / off) per spec §8.2;
defaults are daily @ 03:00 (discovery) and daily @ 03:30 (cve_poll).
Missing/malformed file → defaults + INFO log, never crash.
"""

from __future__ import annotations

import datetime as _dt

from claude_monitoring.attack_surface.schedule_config import (
    DEFAULT_CVE_POLL_TIME,
    DEFAULT_DISCOVERY_TIME,
    VALID_CADENCES,
    ScheduleConfig,
    ScheduleSpec,
    load_schedule_config,
)


class TestDefaults:
    def test_defaults_match_spec_8_2(self):
        cfg = ScheduleConfig.defaults()
        assert cfg.discovery.cadence == "daily"
        assert cfg.discovery.time_of_day == DEFAULT_DISCOVERY_TIME == "03:00"
        # CVE poll is separate per §8.3, offset 30min to avoid OSV rate-limit contention.
        assert cfg.cve_poll.cadence == "daily"
        assert cfg.cve_poll.time_of_day == DEFAULT_CVE_POLL_TIME == "03:30"

    def test_five_cadence_values_per_8_2(self):
        # Spec §8.2 (verbatim): "Configurable (4h / 12h / daily / weekly / off)."
        assert frozenset({"4h", "12h", "daily", "weekly", "off"}) == VALID_CADENCES


class TestLoaderFallsBackToDefaults:
    def test_missing_file_returns_defaults(self, tmp_path):
        cfg = load_schedule_config(tmp_path / "does-not-exist.toml")
        assert cfg == ScheduleConfig.defaults()

    def test_malformed_toml_returns_defaults(self, tmp_path):
        path = tmp_path / "bad.toml"
        path.write_text("this is not [valid toml at all !!!")
        cfg = load_schedule_config(path)
        assert cfg == ScheduleConfig.defaults()

    def test_invalid_cadence_falls_back_to_daily(self, tmp_path):
        path = tmp_path / "bad-cadence.toml"
        path.write_text('[discovery]\ncadence = "every-tuesday"\ntime_of_day = "05:00"\n')
        cfg = load_schedule_config(path)
        assert cfg.discovery.cadence == "daily"
        assert cfg.discovery.time_of_day == "05:00"  # valid time preserved

    def test_invalid_time_of_day_falls_back_to_default_time(self, tmp_path):
        path = tmp_path / "bad-time.toml"
        path.write_text('[discovery]\ncadence = "daily"\ntime_of_day = "25:99"\n')
        cfg = load_schedule_config(path)
        assert cfg.discovery.time_of_day == DEFAULT_DISCOVERY_TIME


class TestLoaderReadsRealFile:
    def test_full_config_loaded(self, tmp_path):
        path = tmp_path / "schedule.toml"
        path.write_text(
            """\
[discovery]
cadence = "12h"
time_of_day = "06:30"

[cve_poll]
cadence = "weekly"
time_of_day = "02:00"
"""
        )
        cfg = load_schedule_config(path)
        assert cfg.discovery.cadence == "12h"
        assert cfg.discovery.time_of_day == "06:30"
        assert cfg.cve_poll.cadence == "weekly"
        assert cfg.cve_poll.time_of_day == "02:00"

    def test_partial_config_fills_defaults(self, tmp_path):
        path = tmp_path / "partial.toml"
        path.write_text('[discovery]\ncadence = "4h"\n')
        cfg = load_schedule_config(path)
        assert cfg.discovery.cadence == "4h"
        # cve_poll section absent → defaults
        assert cfg.cve_poll.cadence == "daily"
        assert cfg.cve_poll.time_of_day == DEFAULT_CVE_POLL_TIME


class TestNextSlotMath:
    """Compute next firing time. Naive local-time datetimes match the
    production code at `schedule_config.next_slot` (operator schedule is
    wall-clock local per spec §8.2 "Default time: 03:00 local")."""

    # ruff: noqa: DTZ001

    def test_off_returns_none(self):
        spec = ScheduleSpec(cadence="off", time_of_day="03:00")
        assert spec.next_slot(after=_dt.datetime(2026, 6, 13, 12, 0)) is None

    def test_4h_adds_4_hours(self):
        spec = ScheduleSpec(cadence="4h", time_of_day="03:00")
        now = _dt.datetime(2026, 6, 13, 12, 0)
        assert spec.next_slot(after=now) == _dt.datetime(2026, 6, 13, 16, 0)

    def test_12h_adds_12_hours(self):
        spec = ScheduleSpec(cadence="12h", time_of_day="03:00")
        now = _dt.datetime(2026, 6, 13, 12, 0)
        assert spec.next_slot(after=now) == _dt.datetime(2026, 6, 14, 0, 0)

    def test_daily_today_if_time_is_future(self):
        spec = ScheduleSpec(cadence="daily", time_of_day="03:00")
        # It's 01:00 on the same day — 03:00 today is still future.
        now = _dt.datetime(2026, 6, 13, 1, 0)
        assert spec.next_slot(after=now) == _dt.datetime(2026, 6, 13, 3, 0)

    def test_daily_tomorrow_if_time_is_past(self):
        spec = ScheduleSpec(cadence="daily", time_of_day="03:00")
        now = _dt.datetime(2026, 6, 13, 4, 0)
        assert spec.next_slot(after=now) == _dt.datetime(2026, 6, 14, 3, 0)

    def test_weekly_fires_next_week(self):
        spec = ScheduleSpec(cadence="weekly", time_of_day="03:00")
        now = _dt.datetime(2026, 6, 13, 4, 0)  # past today's slot
        result = spec.next_slot(after=now)
        assert result == _dt.datetime(2026, 6, 20, 3, 0)
