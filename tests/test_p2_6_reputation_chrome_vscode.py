"""Chrome Web Store + VSCode Marketplace reputation clients.

Both ship DORMANT in P2.6 (config flag default off). These unit tests
exercise the client logic directly — the dormant gate is at the
dispatcher layer (separately tested) so we can confirm the per-client
logic stays correct when P3.1/P3.2 flips the flag.
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

from claude_monitoring.attack_surface.reputation.chrome_web_store import (
    EMPTY_TITLE_MARKER,
    ChromeWebStoreReputationClient,
)
from claude_monitoring.attack_surface.reputation.types import (
    ReputationSignal,
    UnavailableReason,
)
from claude_monitoring.attack_surface.reputation.vscode_marketplace import (
    VSCodeMarketplaceReputationClient,
)


def _http_response(body: bytes, status: int = 200):
    fake = io.BytesIO(body)
    fake.status = status  # type: ignore[attr-defined]
    return fake


def _http_error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url="http://x", code=status, msg="", hdrs=None, fp=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Chrome Web Store
# ---------------------------------------------------------------------------


class TestChromeListed:
    """Listed extension → body has NO ``empty-title`` marker → present True."""

    def test_listed_body_returns_present(self) -> None:
        client = ChromeWebStoreReputationClient()
        listed_body = b"<html><head><title>uBlock Origin</title></head><body>" + b"x" * 50_000 + b"</body></html>"
        with patch(
            "claude_monitoring.attack_surface.reputation.chrome_web_store.urlopen",
            side_effect=[_http_response(listed_body)],
        ):
            result = client.lookup("cjpalhdlnbpafiamejdnhcphjbkeiagm")
        assert result.signal is ReputationSignal.CHROME_NOT_IN_STORE
        assert result.present is True


class TestChromeUnlisted:
    """Unlisted ID → body CONTAINS ``empty-title`` slug → present False
    (the +20 fires when the dispatcher allows it)."""

    def test_empty_title_marker_in_body_returns_present_false(self) -> None:
        client = ChromeWebStoreReputationClient()
        unlisted_body = (
            b"<html><body>some content with empty-title/aaa in the URL path</body></html>"
        )
        with patch(
            "claude_monitoring.attack_surface.reputation.chrome_web_store.urlopen",
            side_effect=[_http_response(unlisted_body)],
        ):
            result = client.lookup("a" * 32)
        assert result.present is False

    def test_empty_title_marker_constant_unchanged(self) -> None:
        """Hard requirement #3: the marker is the signal Google uses.
        If P3.2 flips the flag, the canary test (added then) checks
        live Google behavior; this test pins the constant."""
        assert EMPTY_TITLE_MARKER == "empty-title"


class TestChromeFailOpen:
    """Inversion fix: no +20 on lookup failure."""

    def test_5xx_returns_lookup_failed(self) -> None:
        client = ChromeWebStoreReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.chrome_web_store.urlopen",
            side_effect=[_http_error(503)],
        ):
            result = client.lookup("x" * 32)
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED

    def test_timeout_returns_lookup_failed(self) -> None:
        client = ChromeWebStoreReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.chrome_web_store.urlopen",
            side_effect=[urllib.error.URLError("timeout")],
        ):
            result = client.lookup("x" * 32)
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED


# ---------------------------------------------------------------------------
# VSCode Marketplace
# ---------------------------------------------------------------------------


class TestVSCodeListed:
    def test_extensions_array_non_empty_returns_present(self) -> None:
        client = VSCodeMarketplaceReputationClient()
        payload = {
            "results": [
                {
                    "extensions": [
                        {
                            "extensionName": "python",
                            "publisher": {"publisherName": "ms-python"},
                            "statistics": [{"statisticName": "install", "value": 221881688.0}],
                        }
                    ]
                }
            ]
        }
        with patch(
            "claude_monitoring.attack_surface.reputation.vscode_marketplace.urlopen",
            side_effect=[_http_response(json.dumps(payload).encode("utf-8"))],
        ):
            result = client.lookup("ms-python.python")
        assert result.present is True
        assert result.signal is ReputationSignal.VSCODE_NOT_IN_MARKETPLACE


class TestVSCodeUnlisted:
    def test_extensions_empty_array_returns_present_false(self) -> None:
        client = VSCodeMarketplaceReputationClient()
        payload = {"results": [{"extensions": []}]}
        with patch(
            "claude_monitoring.attack_surface.reputation.vscode_marketplace.urlopen",
            side_effect=[_http_response(json.dumps(payload).encode("utf-8"))],
        ):
            result = client.lookup("nonexistent-pub.nonexistent-ext")
        assert result.present is False


class TestVSCodeFailOpen:
    def test_429_returns_rate_limited(self) -> None:
        client = VSCodeMarketplaceReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.vscode_marketplace.urlopen",
            side_effect=[_http_error(429)],
        ):
            result = client.lookup("anything")
        assert result.present is None
        assert result.reason is UnavailableReason.RATE_LIMITED

    def test_5xx_returns_lookup_failed(self) -> None:
        client = VSCodeMarketplaceReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.vscode_marketplace.urlopen",
            side_effect=[_http_error(503)],
        ):
            result = client.lookup("anything")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED

    def test_malformed_results_returns_lookup_failed(self) -> None:
        client = VSCodeMarketplaceReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.vscode_marketplace.urlopen",
            side_effect=[_http_response(b"{}")],
        ):
            result = client.lookup("anything")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED
