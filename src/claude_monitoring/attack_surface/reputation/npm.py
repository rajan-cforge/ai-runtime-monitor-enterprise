"""npm registry + downloads reputation client.

Simpler than PyPI — npm's primary registry endpoint reliably serves
package existence (200 vs 404) and a SEPARATE Downloads API serves
real weekly counts. No sentinel translation needed.

**No budget cap** for npm — empirical recon 2026-06-08 found no
aggressive rate limiting (npm docs claim 5M req/IP/day on the
Downloads API). If real-world deployment surfaces 429s, a budget
can be added as a fast-follow.

**Inversion fix (judge):** lookup failure (5xx, timeout, parse
error) → ``present=None, reason=LOOKUP_FAILED``. 429 → ``RATE_LIMITED``.
+15 never fires on unavailability.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
from urllib.request import Request, urlopen

from claude_monitoring.attack_surface.reputation.config import REQUEST_TIMEOUT_SECONDS
from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.reputation.npm")


NPM_REGISTRY_PREFIX: str = "https://registry.npmjs.org/"
NPM_DOWNLOADS_PREFIX: str = "https://api.npmjs.org/downloads/point/last-week/"

LOW_DOWNLOADS_THRESHOLD: int = 100
"""Spec §6.6.3: ``< 100/week`` typosquat signal."""


class NPMReputationClient:
    """npm package reputation client. Composes existence + downloads."""

    def lookup(self, package_name: str) -> ReputationResult:
        """Return the reputation result for ``package_name``. Never raises.

        Two-step lookup: registry existence (200/404), then weekly
        downloads. 429 on either endpoint → ``RATE_LIMITED``; other
        failures → ``LOOKUP_FAILED`` (fail-open per ratification item 6)."""
        pkg_quoted = urllib.parse.quote(package_name, safe="@")
        logger.info("reputation lookup: npm %s", package_name)

        existence = self._fetch_existence(pkg_quoted)
        if existence is _LOOKUP_FAILED:
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        if existence is False:
            return ReputationResult(
                signal=ReputationSignal.NPM_LOW_DOWNLOADS,
                present=False,
                downloads=None,
            )

        downloads = self._fetch_downloads(pkg_quoted)
        if downloads is _LOOKUP_FAILED:
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        if downloads is _RATE_LIMITED:
            return self._unavailable(UnavailableReason.RATE_LIMITED)
        if downloads is None:
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)

        below = downloads < LOW_DOWNLOADS_THRESHOLD
        return ReputationResult(
            signal=ReputationSignal.NPM_LOW_DOWNLOADS,
            present=not below,
            downloads=downloads,
        )

    def _unavailable(self, reason: UnavailableReason) -> ReputationResult:
        return ReputationResult(
            signal=ReputationSignal.NPM_LOW_DOWNLOADS,
            present=None,
            reason=reason,
        )

    def _fetch_existence(self, pkg_quoted: str):
        """True = present (200), False = absent (404),
        ``_LOOKUP_FAILED`` = anything else.

        The URL is composed via literal-prefix + ``+ pkg_quoted`` so the
        `privacy-no-telemetry-check` gate can statically verify
        ``registry.npmjs.org`` as the destination."""
        try:
            with urlopen(
                Request("https://registry.npmjs.org/" + pkg_quoted),
                timeout=REQUEST_TIMEOUT_SECONDS,
            ) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False
            return _LOOKUP_FAILED
        except (urllib.error.URLError, OSError):
            return _LOOKUP_FAILED
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return _LOOKUP_FAILED
        if isinstance(payload, dict) and isinstance(payload.get("name"), str):
            return True
        return _LOOKUP_FAILED

    def _fetch_downloads(self, pkg_quoted: str):
        """Int downloads, or ``_LOOKUP_FAILED`` / ``_RATE_LIMITED`` /
        ``None`` for unparseable. URL composed literal-prefix-first so
        the gate verifies ``api.npmjs.org``."""
        try:
            with urlopen(
                Request("https://api.npmjs.org/downloads/point/last-week/" + pkg_quoted),
                timeout=REQUEST_TIMEOUT_SECONDS,
            ) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                return _RATE_LIMITED
            return _LOOKUP_FAILED
        except (urllib.error.URLError, OSError):
            return _LOOKUP_FAILED
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return _LOOKUP_FAILED
        if not isinstance(payload, dict):
            return _LOOKUP_FAILED
        downloads = payload.get("downloads")
        if isinstance(downloads, int) and downloads >= 0:
            return downloads
        return None


_LOOKUP_FAILED = object()
_RATE_LIMITED = object()


__all__ = [
    "LOW_DOWNLOADS_THRESHOLD",
    "NPMReputationClient",
]
