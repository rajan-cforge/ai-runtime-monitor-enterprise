"""PyPI + pypistats reputation client.

**Hard requirement #1 (Rajan 2026-06-08):** PyPI's
``info.downloads = {"last_day": -1, "last_month": -1, "last_week": -1}``
sentinel MUST map to ``downloads=None``; the ``-1`` MUST NEVER enter the
``< 100/week`` comparison. The pypi.org primary JSON deprecated usable
download counts; pypistats.org is the only path to real counts.

**Addendum (Rajan 2026-06-08):** pypistats per-scan budget cap = 25;
exponential backoff after 429 (5 / 15 / 60 min — applied at the cache
layer by the dispatcher when caching the rate-limited result).

**Composition:** existence is checked at pypi.org (cheap, no rate limit
observed). If existence is confirmed AND downloads are needed (not
sentinel), THEN we hit pypistats. Budget is consumed by pypistats
calls only; pypi.org calls are free.

**Inversion fix (judge):** any lookup failure (5xx, timeout, parse
error) → ``present=None, reason=LOOKUP_FAILED``. The +15 modifier
never fires on lookup failure.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
from dataclasses import dataclass
from urllib.request import Request, urlopen  # noqa: S310 — allowlisted hostnames

from claude_monitoring.attack_surface.reputation.config import REQUEST_TIMEOUT_SECONDS
from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.reputation.pypi")


PYPI_PKG_URL: str = "https://pypi.org/pypi/{pkg}/json"
PYPISTATS_URL: str = "https://pypistats.org/api/packages/{pkg}/recent?period=week"

LOW_DOWNLOADS_THRESHOLD: int = 100
"""Spec §6.6.3: ``< 100/week`` is the typosquat signal. Strict inequality."""


@dataclass
class PyPIScanBudget:
    """Per-scan call budget for pypistats. Dispatcher constructs ONE budget
    per scan and passes it to the PyPI client. The client decrements
    ``remaining`` on each pypistats call.

    Once ``remaining`` hits 0, the next pypistats lookup returns
    ``UnavailableReason.BUDGET_EXCEEDED`` without making a network call.
    Existence checks at pypi.org are NOT budget-controlled."""

    remaining: int


class PyPIReputationClient:
    """Composite PIP_LOW_DOWNLOADS signal client.

    Logical flow per asset:

    1. GET pypi.org/pypi/<pkg>/json → existence + sentinel-or-real downloads.
    2. If pypi 404 → ``ReputationResult(present=False, downloads=None)``.
       Modifier fires (the typosquat path is "package not even in PyPI").
    3. If pypi 200 + downloads from pypi are usable (NOT sentinel) → done.
    4. If pypi 200 + downloads are sentinel → fall to pypistats:
       a. If budget exhausted → ``present=None, reason=BUDGET_EXCEEDED``.
       b. Else: GET pypistats; consume budget regardless of outcome.
       c. 200 + ``data.last_week`` is int → use as downloads.
       d. 429 → ``reason=RATE_LIMITED``.
       e. 5xx / timeout → ``reason=LOOKUP_FAILED``.
    5. Compute present:
       - ``downloads < 100`` → present=False (fire +15).
       - ``downloads >= 100`` → present=True (no modifier).
    """

    def __init__(self, budget: PyPIScanBudget) -> None:
        self._budget = budget

    def lookup(self, package_name: str) -> ReputationResult:
        """Return the reputation result for ``package_name``.

        Never raises — all errors translate to a three-state result.
        """
        # URL-quote: a package name with `/` (path injection) MUST NOT
        # alter the path. PyPI package names don't contain slashes in
        # practice, but the input is untrusted.
        pkg_quoted = urllib.parse.quote(package_name, safe="")
        logger.info("reputation lookup: pypi %s", package_name)
        try:
            pypi_info = self._fetch_pypi(pkg_quoted)
        except _LookupFailed as exc:
            return self._unavailable(exc.reason)

        if pypi_info is None:
            # 404 → package absent from PyPI → +15 fires
            return ReputationResult(
                signal=ReputationSignal.PIP_LOW_DOWNLOADS,
                present=False,
                downloads=None,
            )

        downloads = pypi_info.get("downloads_last_week")
        if downloads is not None:
            return self._present_from_count(downloads)

        # Sentinel or absent in pypi.org → fall to pypistats
        if self._budget.remaining <= 0:
            return self._unavailable(UnavailableReason.BUDGET_EXCEEDED)
        try:
            pypistats_downloads = self._fetch_pypistats(pkg_quoted)
        except _LookupFailed as exc:
            return self._unavailable(exc.reason)
        if pypistats_downloads is None:
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        return self._present_from_count(pypistats_downloads)

    def _present_from_count(self, downloads: int) -> ReputationResult:
        """Apply the spec §6.6.3 threshold. ``downloads`` is the real
        weekly count, guaranteed non-negative by the fetcher."""
        below_threshold = downloads < LOW_DOWNLOADS_THRESHOLD
        return ReputationResult(
            signal=ReputationSignal.PIP_LOW_DOWNLOADS,
            present=not below_threshold,
            downloads=downloads,
        )

    def _unavailable(self, reason: UnavailableReason) -> ReputationResult:
        return ReputationResult(
            signal=ReputationSignal.PIP_LOW_DOWNLOADS,
            present=None,
            reason=reason,
        )

    def _fetch_pypi(self, pkg_quoted: str) -> dict | None:
        """Returns ``None`` for 404; raises :class:`_LookupFailed` for
        other failure modes; returns a dict with ``downloads_last_week``
        (an int >= 0) or ``None`` (sentinel) on success."""
        url = PYPI_PKG_URL.format(pkg=pkg_quoted)
        try:
            with urlopen(Request(url), timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
                body = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED) from exc

        try:
            payload = json.loads(body)
        except (ValueError, TypeError) as exc:
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED) from exc

        info = payload.get("info") if isinstance(payload, dict) else None
        if not isinstance(info, dict):
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED)

        # Sentinel translation — Hard requirement #1.
        # PyPI returns {"last_week": -1, ...} when usable stats are
        # unavailable. Any negative value means "unusable" → None.
        downloads_dict = info.get("downloads")
        last_week: int | None = None
        if isinstance(downloads_dict, dict):
            candidate = downloads_dict.get("last_week")
            if isinstance(candidate, int) and candidate >= 0:
                last_week = candidate
        return {"downloads_last_week": last_week}

    def _fetch_pypistats(self, pkg_quoted: str) -> int | None:
        """Consumes one budget unit. Returns the non-negative weekly
        count, or ``None`` if pypistats returned a sentinel/missing
        field. Raises :class:`_LookupFailed` for HTTP / parse errors.
        429 maps to ``RATE_LIMITED``."""
        self._budget.remaining -= 1
        url = PYPISTATS_URL.format(pkg=pkg_quoted)
        logger.info("reputation lookup: pypistats %s (budget remaining: %d)", pkg_quoted, self._budget.remaining)
        try:
            with urlopen(Request(url), timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
                body = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise _LookupFailed(UnavailableReason.RATE_LIMITED) from exc
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED) from exc

        try:
            payload = json.loads(body)
        except (ValueError, TypeError) as exc:
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED) from exc

        if not isinstance(payload, dict):
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED)
        data = payload.get("data")
        if not isinstance(data, dict):
            raise _LookupFailed(UnavailableReason.LOOKUP_FAILED)
        last_week = data.get("last_week")
        if not isinstance(last_week, int) or last_week < 0:
            return None
        return last_week


@dataclass
class _LookupFailed(Exception):
    """Internal control-flow marker. The reason field carries the
    three-state translation."""

    reason: UnavailableReason


__all__ = [
    "LOW_DOWNLOADS_THRESHOLD",
    "PyPIReputationClient",
    "PyPIScanBudget",
]
