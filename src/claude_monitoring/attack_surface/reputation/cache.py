"""Reputation cache — chmod 600, atomic write, TTL, three-state preservation.

Ratifications (work-log/2026-06-08-P2.6-ratification.md):

- **Item 4 (TTL):** 7 days for existence checks; 24 hours for download counts.
- **Item 6 (inversion fix):** corrupted file / wrong permissions → cache miss,
  log warning, NEVER raise. Per-item isolation per
  ``project_v022_per_item_isolation.md``.
- **Addendum #1 (pypistats backoff):** 5 / 15 / 60 minutes for rate-limited
  entries — passed via the ``ttl_seconds`` arg by the pypistats client.
- **Hard requirement #2:** ``ReputationResult.reason`` survives a round trip
  through JSON.

Persistence shape (JSON):

.. code-block:: json

    {
      "entries": {
        "npm:left-pad": {
          "signal": "npm_low_downloads",
          "present": true,
          "downloads": 1246297,
          "reason": null,
          "expires_at": 1717920000
        },
        "pip:requests": {
          "signal": "pip_low_downloads",
          "present": null,
          "downloads": null,
          "reason": "rate_limited",
          "expires_at": 1717891200
        }
      }
    }

Atomic write: write the full payload to ``<path>.tmp``, then ``os.replace``.
``chmod 600`` is applied on the temp file BEFORE ``os.replace`` so the
visible file is never world-readable even briefly.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.reputation.cache")


DEFAULT_EXISTENCE_TTL_SECONDS: int = 7 * 24 * 3600
"""7 days for ``in registry?`` lookups (Rajan ratification item 4).

Existence rarely flips — a package that was in npm yesterday is almost
certainly there today. The 7-day TTL absorbs most repeat scans of the
same asset without hitting the network."""


DEFAULT_DOWNLOADS_TTL_SECONDS: int = 24 * 3600
"""24 hours for weekly download counts (Rajan ratification item 4).

Aligns with the existing OSV cache cadence (precedent in §10.3). Weekly
downloads move daily, so a longer TTL would mask a typosquat catching
fire mid-cycle."""


RATE_LIMIT_BACKOFF_SCHEDULE_SECONDS: tuple[int, int, int] = (5 * 60, 15 * 60, 60 * 60)
"""Exponential backoff after HTTP 429 (Rajan addendum 2026-06-08): 5
min → 15 min → 60 min. Per-registry clients pass the current rung as
``ttl_seconds`` when caching a ``RATE_LIMITED`` result so the entry
expires at the end of the backoff window."""


_CACHE_VERSION: int = 1


def _decode_strict(raw: dict) -> ReputationResult:
    """Raises ``KeyError`` / ``ValueError`` on a bad entry; the cache
    wraps this to translate to per-item-isolation behavior."""
    signal = ReputationSignal(raw["signal"])
    present = raw.get("present")
    if present is not None and not isinstance(present, bool):
        raise ValueError(f"present must be bool or None, got {type(present).__name__}")
    downloads = raw.get("downloads")
    if downloads is not None and not isinstance(downloads, int):
        raise ValueError(f"downloads must be int or None, got {type(downloads).__name__}")
    reason_value = raw.get("reason")
    reason = UnavailableReason(reason_value) if reason_value is not None else None
    return ReputationResult(signal=signal, present=present, downloads=downloads, reason=reason)


class ReputationCache:
    """JSON-backed reputation cache. Synchronous, in-process.

    Read path is cache-first by design — every per-registry client
    calls ``get(key)`` before doing any network I/O. A cache hit is the
    primary resilience mechanism against registry downtime and against
    pypistats rate limiting (Rajan ratification addendum).

    Write path is atomic: the full file is rewritten to ``<path>.tmp``,
    chmod 600 is applied, then ``os.replace(<tmp>, <path>)``. Concurrent
    readers never see a partial write.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}
        self._loaded = False

    def get(self, key: str) -> ReputationResult | None:
        """Return the cached ``ReputationResult`` for ``key`` or ``None``.

        ``None`` means cache miss. Cache miss can be: (a) key not present,
        (b) entry expired, (c) entry malformed and skipped per-item.
        Per ratification §6 fail-open: never raises.
        """
        if not isinstance(key, str):
            raise TypeError(f"cache key must be str, got {type(key).__name__}")
        self._load_if_needed()
        raw = self._entries.get(key)
        if raw is None:
            return None
        try:
            expires_at = int(raw.get("expires_at", 0))
        except (TypeError, ValueError):
            return None
        # `<=` (not `<`) because `expires_at` and the current epoch are
        # both int-truncated; `<` leaves an up-to-1-second window where a
        # technically-expired entry still reads as fresh.
        if expires_at <= int(time.time()):
            return None
        return self._decode(raw)

    def set(
        self,
        key: str,
        result: ReputationResult,
        *,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store ``result`` under ``key`` with a TTL.

        ``ttl_seconds`` defaults to:

        - For an unavailable-RATE_LIMITED result: first rung of
          :data:`RATE_LIMIT_BACKOFF_SCHEDULE_SECONDS` (5 min). Subsequent
          rate-limit hits should pass higher rungs explicitly.
        - For results carrying a ``downloads`` count:
          :data:`DEFAULT_DOWNLOADS_TTL_SECONDS` (24h).
        - Otherwise: :data:`DEFAULT_EXISTENCE_TTL_SECONDS` (7d).

        The choice is made HERE so per-registry clients can stay simple.
        """
        if not isinstance(key, str):
            raise TypeError(f"cache key must be str, got {type(key).__name__}")
        if ttl_seconds is None:
            ttl_seconds = self._default_ttl_for(result)
        self._load_if_needed()
        self._entries[key] = self._encode(result, ttl_seconds)
        self._flush()

    def _default_ttl_for(self, result: ReputationResult) -> int:
        if result.reason is UnavailableReason.RATE_LIMITED:
            return RATE_LIMIT_BACKOFF_SCHEDULE_SECONDS[0]
        if result.downloads is not None:
            return DEFAULT_DOWNLOADS_TTL_SECONDS
        return DEFAULT_EXISTENCE_TTL_SECONDS

    def _encode(self, result: ReputationResult, ttl_seconds: int) -> dict:
        return {
            "signal": result.signal.value,
            "present": result.present,
            "downloads": result.downloads,
            "reason": result.reason.value if result.reason is not None else None,
            "expires_at": int(time.time()) + ttl_seconds,
        }

    def _decode(self, raw: dict) -> ReputationResult | None:
        """Per-item isolation: bad entry → return None, log warning."""
        try:
            return _decode_strict(raw)
        except (KeyError, ValueError) as exc:
            logger.warning("cache entry skipped: %s", exc)
            return None

    def _load_if_needed(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path.is_file():
            return
        try:
            raw_text = self._path.read_text()
        except OSError as exc:
            logger.warning("reputation cache read failed (%s); treating as empty", exc)
            return
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            logger.warning("reputation cache parse failed (%s); treating as empty", exc)
            return
        if not isinstance(payload, dict):
            logger.warning("reputation cache top-level not a dict; treating as empty")
            return
        if payload.get("version") not in (None, _CACHE_VERSION):
            logger.warning("reputation cache version mismatch; treating as empty")
            return
        entries = payload.get("entries", {})
        if not isinstance(entries, dict):
            logger.warning("reputation cache entries not a dict; treating as empty")
            return
        self._entries = entries

    def _flush(self) -> None:
        """Atomic write + chmod 600. CONTRACT §10 sentinel-last discipline."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        payload = {"version": _CACHE_VERSION, "entries": self._entries}
        text = json.dumps(payload, separators=(",", ":"))
        # Write + chmod the tmp file BEFORE replace, so the visible file
        # is never world-readable even momentarily.
        tmp.write_text(text)
        try:
            tmp.chmod(0o600)
        except OSError as exc:
            logger.warning("chmod 600 on reputation cache tmp failed: %s", exc)
        tmp.replace(self._path)


__all__ = [
    "DEFAULT_DOWNLOADS_TTL_SECONDS",
    "DEFAULT_EXISTENCE_TTL_SECONDS",
    "RATE_LIMIT_BACKOFF_SCHEDULE_SECONDS",
    "ReputationCache",
]
