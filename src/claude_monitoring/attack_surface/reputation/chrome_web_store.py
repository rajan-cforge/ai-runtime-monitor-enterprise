"""Chrome Web Store reputation client.

**DORMANT IN P2.6** per Rajan ratification item 3 (work-log
``2026-06-08-P2.6-ratification.md``). The Chrome/VSCode "not in store"
rules ship behind ``reputation.chrome_vscode_enabled`` defaulting to
``False``; flipped to ``True`` only by the PR that lands managed-install
detection (P3.2 for Chrome). Until then the dispatcher short-circuits
this client and returns ``UnavailableReason.DORMANT``.

**Detection mechanism (empirical recon 2026-06-08):** HEAD/status check
is BROKEN — both listed and unlisted Chrome Web Store URLs return HTTP
200 after redirect. The workable signal is a body-fetch + string-match
for the literal ``empty-title`` slug Google places in the placeholder
page URL for unlisted extension IDs.

**Hard requirement #3 (Rajan 2026-06-08):** when P3.2 flips the
dormant flag, re-pin the detection against live Chrome Web Store AND
add a **canary test** that fails LOUDLY if Google changes the
placeholder page. Prevents silent rot into always-"present" (never
firing the modifier even on truly unlisted IDs). See
``tests/test_p2_6_reputation_chrome_canary.py`` (added when flag flips).

**Inversion fix (judge):** lookup-failed / 5xx / timeout / managed-
install detection (when wired) → ``present=None, reason=LOOKUP_FAILED``.
The +20 NEVER fires on unavailability.
"""

from __future__ import annotations

import logging
import urllib.error
from urllib.request import Request, urlopen  # noqa: S310 — allowlisted hostname

from claude_monitoring.attack_surface.reputation.config import REQUEST_TIMEOUT_SECONDS
from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.reputation.chrome_web_store")


CHROME_WEB_STORE_URL: str = "https://chrome.google.com/webstore/detail/{ext_id}"

EMPTY_TITLE_MARKER: str = "empty-title"
"""Literal substring Google places in the placeholder URL when an
extension ID is not registered. Re-pin against live store when P3.2
flips the dormant flag — Hard requirement #3."""


class ChromeWebStoreReputationClient:
    """Body-fetch + ``empty-title`` substring detection.

    The dispatcher gates this client behind the dormant flag. If a test
    or P3.2 instantiates and calls ``lookup`` directly, the function
    behaves as designed — it makes the live HTTP call. Tests mock the
    HTTP layer; production gates at the dispatcher.
    """

    def lookup(self, extension_id: str) -> ReputationResult:
        logger.info("reputation lookup: chrome_web_store %s", extension_id)
        url = CHROME_WEB_STORE_URL.format(ext_id=extension_id)
        try:
            with urlopen(Request(url), timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
                body = response.read()
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            return ReputationResult(
                signal=ReputationSignal.CHROME_NOT_IN_STORE,
                present=None,
                reason=UnavailableReason.LOOKUP_FAILED,
            )
        # Decode safely; body is potentially 500+ KB HTML
        try:
            text = body.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, AttributeError):
            return ReputationResult(
                signal=ReputationSignal.CHROME_NOT_IN_STORE,
                present=None,
                reason=UnavailableReason.LOOKUP_FAILED,
            )
        # Empirical detection (recon 2026-06-08): unlisted page contains
        # the literal `empty-title` token. Listed page does not.
        unlisted = EMPTY_TITLE_MARKER in text
        return ReputationResult(
            signal=ReputationSignal.CHROME_NOT_IN_STORE,
            present=not unlisted,
        )


__all__ = [
    "ChromeWebStoreReputationClient",
    "EMPTY_TITLE_MARKER",
]
