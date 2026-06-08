"""P2.6 reputation cache — chmod 600, atomic write, TTL, three-state preservation.

Pins:
- Default 7-day TTL on existence checks; 24-hour TTL on download counts.
- chmod 600 enforced on create + on every write.
- Atomic write via ``*.tmp`` + ``os.replace`` (sentinel-last discipline,
  CONTRACT §10).
- Corrupted JSON / wrong permissions → treat as cache miss, log warning,
  never raise (per-item isolation, ``project_v022_per_item_isolation.md``).
- ``ReputationResult`` round-trips through JSON preserving all three
  states (present True/False/None + reason).
- Rate-limited entries use the shorter TTL ladder (5 / 15 / 60 min
  per the pypistats backoff ratification 2026-06-08 addendum).

Ratifications:
- Item 4 (7d/24h TTL); pypistats backoff schedule in addendum.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.reputation.cache import (
    DEFAULT_DOWNLOADS_TTL_SECONDS,
    DEFAULT_EXISTENCE_TTL_SECONDS,
    RATE_LIMIT_BACKOFF_SCHEDULE_SECONDS,
    ReputationCache,
)
from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)


def _existence_result(present: bool) -> ReputationResult:
    return ReputationResult(
        signal=ReputationSignal.NPM_LOW_DOWNLOADS,
        present=present,
        downloads=200 if present else 50,
    )


def _rate_limited_result() -> ReputationResult:
    return ReputationResult(
        signal=ReputationSignal.PIP_LOW_DOWNLOADS,
        present=None,
        reason=UnavailableReason.RATE_LIMITED,
    )


class TestCacheRoundTrip:
    def test_set_then_get_returns_same_result(self, tmp_path: Path) -> None:
        cache = ReputationCache(tmp_path / "rep.json")
        r = _existence_result(present=True)
        cache.set("npm:left-pad", r)
        got = cache.get("npm:left-pad")
        assert got is not None
        assert got.present is True
        assert got.downloads == 200
        assert got.signal is ReputationSignal.NPM_LOW_DOWNLOADS

    def test_get_missing_key_returns_none(self, tmp_path: Path) -> None:
        cache = ReputationCache(tmp_path / "rep.json")
        assert cache.get("npm:nonexistent") is None

    def test_present_false_state_preserved(self, tmp_path: Path) -> None:
        cache = ReputationCache(tmp_path / "rep.json")
        r = _existence_result(present=False)
        cache.set("npm:typosquat-victim", r)
        got = cache.get("npm:typosquat-victim")
        assert got is not None
        assert got.present is False
        assert got.downloads == 50

    def test_unavailable_state_preserved_with_reason(self, tmp_path: Path) -> None:
        """Hard requirement #2: the reason MUST survive a round trip."""
        cache = ReputationCache(tmp_path / "rep.json")
        cache.set("pip:request", _rate_limited_result())
        got = cache.get("pip:request")
        assert got is not None
        assert got.present is None
        assert got.reason is UnavailableReason.RATE_LIMITED


class TestPermissionsEnforcedChmod600:
    """CLAUDE.md mandatory: chmod 600 on sensitive files via
    ``security.enforce_permissions`` equivalent. The cache file holds
    reputation telemetry the attacker shouldn't read."""

    def test_create_sets_chmod_600(self, tmp_path: Path) -> None:
        cache_path = tmp_path / "rep.json"
        cache = ReputationCache(cache_path)
        cache.set("npm:x", _existence_result(present=True))
        mode = stat.S_IMODE(cache_path.stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"

    def test_update_preserves_chmod_600(self, tmp_path: Path) -> None:
        cache_path = tmp_path / "rep.json"
        cache = ReputationCache(cache_path)
        cache.set("npm:x", _existence_result(present=True))
        # Tamper: chmod 644 then re-save
        os.chmod(cache_path, 0o644)
        cache.set("npm:y", _existence_result(present=False))
        mode = stat.S_IMODE(cache_path.stat().st_mode)
        assert mode == 0o600, f"expected 0o600 after re-save, got {oct(mode)}"


class TestAtomicWrite:
    """Cache writes use ``*.tmp`` + ``os.replace`` so a half-written file
    is never visible to a concurrent reader."""

    def test_tmp_file_is_cleaned_up_after_write(self, tmp_path: Path) -> None:
        cache_path = tmp_path / "rep.json"
        cache = ReputationCache(cache_path)
        cache.set("npm:x", _existence_result(present=True))
        # No lingering *.tmp files
        leftovers = list(tmp_path.glob("*.tmp"))
        assert leftovers == [], f"unexpected *.tmp leftover: {leftovers}"


class TestTTLExpiry:
    def test_existence_ttl_default_is_seven_days(self) -> None:
        assert DEFAULT_EXISTENCE_TTL_SECONDS == 7 * 24 * 3600

    def test_downloads_ttl_default_is_24_hours(self) -> None:
        assert DEFAULT_DOWNLOADS_TTL_SECONDS == 24 * 3600

    def test_rate_limit_backoff_schedule_is_5_15_60_minutes(self) -> None:
        """Addendum ratification 2026-06-08: pypistats backoff 5/15/60 min."""
        assert RATE_LIMIT_BACKOFF_SCHEDULE_SECONDS == (5 * 60, 15 * 60, 60 * 60)

    def test_expired_entry_returns_none(self, tmp_path: Path) -> None:
        """An entry whose TTL elapsed must read as a cache miss."""
        cache = ReputationCache(tmp_path / "rep.json")
        cache.set("npm:x", _existence_result(present=True), ttl_seconds=1)
        time.sleep(1.1)
        assert cache.get("npm:x") is None

    def test_non_expired_entry_returns_result(self, tmp_path: Path) -> None:
        cache = ReputationCache(tmp_path / "rep.json")
        cache.set("npm:x", _existence_result(present=True), ttl_seconds=3600)
        got = cache.get("npm:x")
        assert got is not None
        assert got.present is True


class TestFailOpenOnCorruptedFile:
    """A corrupted cache file or wrong-permissions file must be treated
    as a cache miss + log warning, NEVER raise. Mirrors the per-item
    isolation contract."""

    def test_corrupted_json_treated_as_miss(self, tmp_path: Path, caplog) -> None:
        cache_path = tmp_path / "rep.json"
        cache_path.write_text("{not valid json")
        os.chmod(cache_path, 0o600)
        cache = ReputationCache(cache_path)
        with caplog.at_level("WARNING"):
            assert cache.get("npm:x") is None
        assert any(r.levelname == "WARNING" for r in caplog.records)

    def test_missing_directory_no_writes_succeed_silently(self, tmp_path: Path) -> None:
        # Directory that doesn't exist — set must not crash
        cache = ReputationCache(tmp_path / "missing" / "rep.json")
        # Should create the directory and write
        cache.set("npm:x", _existence_result(present=True))
        assert (tmp_path / "missing" / "rep.json").exists()

    def test_unparseable_entry_skipped_others_kept(self, tmp_path: Path) -> None:
        """Per-item isolation: one bad entry doesn't poison the file."""
        cache_path = tmp_path / "rep.json"
        # Hand-craft a file with one bad entry + one good entry
        payload = {
            "entries": {
                "npm:good": {
                    "signal": "npm_low_downloads",
                    "present": True,
                    "downloads": 200,
                    "reason": None,
                    "expires_at": int(time.time()) + 3600,
                },
                "npm:bad": {"signal": "not_a_real_signal", "present": "not_a_bool"},
            }
        }
        cache_path.write_text(json.dumps(payload))
        os.chmod(cache_path, 0o600)
        cache = ReputationCache(cache_path)
        good = cache.get("npm:good")
        assert good is not None
        assert good.present is True
        assert cache.get("npm:bad") is None  # bad entry skipped


class TestCacheKeyContract:
    """Cache keys are strings; the dispatcher composes them as
    ``f"{registry}:{asset_identifier}"`` per architecture sketch."""

    def test_string_key_accepted(self, tmp_path: Path) -> None:
        cache = ReputationCache(tmp_path / "rep.json")
        cache.set("npm:left-pad", _existence_result(present=True))
        assert cache.get("npm:left-pad") is not None

    def test_non_string_key_rejected_at_set(self, tmp_path: Path) -> None:
        cache = ReputationCache(tmp_path / "rep.json")
        with pytest.raises(TypeError):
            cache.set(12345, _existence_result(present=True))  # type: ignore[arg-type]


class TestBackoffTTLForRateLimited:
    """When a per-registry client caches a rate-limited result, the TTL
    must follow the backoff ladder, NOT the regular 7d/24h. This stops
    the cache from holding "you're rate-limited" for a week."""

    def test_rate_limited_uses_short_ttl(self, tmp_path: Path) -> None:
        """A rate-limited entry passed with the first-rung backoff TTL
        must EXPIRE after that window."""
        cache = ReputationCache(tmp_path / "rep.json")
        cache.set(
            "pip:requests",
            _rate_limited_result(),
            ttl_seconds=1,  # simulating the short backoff
        )
        # immediately readable
        assert cache.get("pip:requests") is not None
        time.sleep(1.1)
        # expired — pypistats will be re-tried on next scan
        assert cache.get("pip:requests") is None
