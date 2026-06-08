"""npm reputation client — existence + downloads, three-state outcomes."""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

from claude_monitoring.attack_surface.reputation.npm import NPMReputationClient
from claude_monitoring.attack_surface.reputation.types import (
    ReputationSignal,
    UnavailableReason,
)


def _http_response(payload, status: int = 200):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    fake = io.BytesIO(body)
    fake.status = status  # type: ignore[attr-defined]
    return fake


def _http_error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url="http://x", code=status, msg="", hdrs=None, fp=None)  # type: ignore[arg-type]


class TestNPMHappyPath:
    def test_listed_with_high_downloads_returns_present(self) -> None:
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[
                _http_response({"name": "left-pad", "versions": {}}),
                _http_response({"downloads": 1_246_297, "package": "left-pad"}),
            ],
        ):
            result = client.lookup("left-pad")
        assert result.present is True
        assert result.downloads == 1_246_297
        assert result.signal is ReputationSignal.NPM_LOW_DOWNLOADS

    def test_listed_with_low_downloads_returns_present_false(self) -> None:
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[
                _http_response({"name": "obscure", "versions": {}}),
                _http_response({"downloads": 42, "package": "obscure"}),
            ],
        ):
            result = client.lookup("obscure")
        # Below threshold → +15 fires
        assert result.present is False
        assert result.downloads == 42

    def test_threshold_strict_inequality(self) -> None:
        """Spec §6.6.3 says < 100, not <= 100."""
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[
                _http_response({"name": "edge", "versions": {}}),
                _http_response({"downloads": 100, "package": "edge"}),
            ],
        ):
            result = client.lookup("edge")
        # NOT below threshold
        assert result.present is True


class TestNPMAbsentMeans404:
    def test_404_returns_present_false_no_downloads(self) -> None:
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[_http_error(404)],
        ):
            result = client.lookup("nonexistent-pkg-12345")
        # Absent → fire +15
        assert result.present is False
        assert result.downloads is None


class TestNPMFailOpen:
    """Inversion fix: lookup failure NEVER fires +15."""

    def test_5xx_returns_unavailable(self) -> None:
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[_http_error(503)],
        ):
            result = client.lookup("anything")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED

    def test_timeout_returns_unavailable(self) -> None:
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[urllib.error.URLError("timeout")],
        ):
            result = client.lookup("anything")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED

    def test_downloads_429_returns_rate_limited(self) -> None:
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[
                _http_response({"name": "x", "versions": {}}),
                _http_error(429),
            ],
        ):
            result = client.lookup("x")
        assert result.present is None
        assert result.reason is UnavailableReason.RATE_LIMITED

    def test_malformed_json_returns_lookup_failed(self) -> None:
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[_http_response(b"not json")],
        ):
            result = client.lookup("x")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED


class TestNPMScopedPackage:
    """Scoped npm packages (@scope/name) have an @ that's valid in URL."""

    def test_scoped_package_name_passed_through(self) -> None:
        client = NPMReputationClient()
        with patch(
            "claude_monitoring.attack_surface.reputation.npm.urlopen",
            side_effect=[_http_error(404)],
        ) as mock_urlopen:
            client.lookup("@vigil/internal")
        request = mock_urlopen.call_args[0][0]
        # @ is safe in our URL quoting; the slash is escaped
        assert "@vigil%2Finternal" in request.full_url
