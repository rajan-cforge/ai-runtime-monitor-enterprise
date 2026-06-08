"""VSCode Marketplace reputation client.

**DORMANT IN P2.6** per Rajan ratification item 3 (work-log
``2026-06-08-P2.6-ratification.md``). Same flag as Chrome
(``reputation.chrome_vscode_enabled``). Flipped when P3.1 lands.

**Detection (empirical recon 2026-06-08):** POST to
``marketplace.visualstudio.com/_apis/public/gallery/extensionquery``
with the extension's ``publisher.name`` as ``filterType: 7`` value.
Empty ``results[0].extensions`` array → absent. Non-empty → present.

**Open-VSX carry-forward (P3.1):** legitimate Cursor/VSCodium extensions
may live on the Open-VSX registry, not MS Marketplace. When the dormant
flag flips, the implementation should ALSO probe Open-VSX as a fallback
and treat presence in either as "in some marketplace."

**Inversion fix (judge):** any failure (5xx, timeout, 429, parse error)
→ ``present=None, reason=...``. The +20 NEVER fires on unavailability.
"""

from __future__ import annotations

import json
import logging
import urllib.error
from urllib.request import Request, urlopen

from claude_monitoring.attack_surface.reputation.config import REQUEST_TIMEOUT_SECONDS
from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.reputation.vscode_marketplace")


EXTENSIONQUERY_URL: str = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"

_FILTER_TYPE_EXTENSION_NAME: int = 7
"""Marketplace API filter type code: 7 = ExtensionName (publisher.name).
Verified against the live API in the 2026-06-08 recon."""

_FLAGS_INCLUDE_STATISTICS: int = 914


class VSCodeMarketplaceReputationClient:
    """VSCode Marketplace ``extensionquery`` POST client.

    DORMANT in P2.6 — the dispatcher gates this client behind
    ``reputation.chrome_vscode_enabled`` (default False). Flipped True
    by the PR that lands managed-install detection (P3.1).
    """

    def lookup(self, extension_identifier: str) -> ReputationResult:
        """Query the marketplace for ``extension_identifier`` (a
        ``publisher.name`` string, e.g. ``ms-python.python``)."""
        logger.info("reputation lookup: vscode_marketplace %s", extension_identifier)
        payload = {
            "filters": [
                {
                    "criteria": [
                        {
                            "filterType": _FILTER_TYPE_EXTENSION_NAME,
                            "value": extension_identifier,
                        }
                    ]
                }
            ],
            "flags": _FLAGS_INCLUDE_STATISTICS,
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        # Request constructed inline so the gate sees the literal URL on
        # urlopen()'s first arg (variable indirection defeats AST-level
        # static analysis).
        try:
            with urlopen(
                Request(
                    "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery",
                    data=body_bytes,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json;api-version=3.0-preview.1",
                    },
                    method="POST",
                ),
                timeout=REQUEST_TIMEOUT_SECONDS,
            ) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            reason = UnavailableReason.RATE_LIMITED if exc.code == 429 else UnavailableReason.LOOKUP_FAILED
            return self._unavailable(reason)
        except (urllib.error.URLError, OSError):
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        if not isinstance(parsed, dict):
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        results = parsed.get("results")
        if not isinstance(results, list) or not results:
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        first = results[0]
        if not isinstance(first, dict):
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        extensions = first.get("extensions")
        if not isinstance(extensions, list):
            return self._unavailable(UnavailableReason.LOOKUP_FAILED)
        absent = len(extensions) == 0
        return ReputationResult(
            signal=ReputationSignal.VSCODE_NOT_IN_MARKETPLACE,
            present=not absent,
        )

    def _unavailable(self, reason: UnavailableReason) -> ReputationResult:
        return ReputationResult(
            signal=ReputationSignal.VSCODE_NOT_IN_MARKETPLACE,
            present=None,
            reason=reason,
        )


__all__ = ["VSCodeMarketplaceReputationClient"]
