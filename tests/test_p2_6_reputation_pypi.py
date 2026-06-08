"""P2.6 PyPI reputation — the load-bearing sentinel-ban + 429 + budget tests.

This is the most-scrutinized client file. Hard requirement #1 (Rajan
2026-06-08): PyPI's ``info.downloads = {-1, -1, -1}`` sentinel MUST
map to ``downloads=None`` and MUST NEVER enter the ``< 100/week``
comparison.

Three branches under test:

1. ``pypi.org/pypi/<pkg>/json`` — existence check (200 / 404 / lookup-fail).
2. ``pypistats.org/api/packages/<pkg>/recent?period=week`` — download
   count (200 / 404 / 429 / budget-exhausted / lookup-fail).
3. The composite ``lookup(asset)`` that combines (1) + (2) into a single
   ``ReputationResult`` for ``PIP_LOW_DOWNLOADS``.

All HTTP calls are mocked via ``urllib.request.urlopen`` per the
established ``threat_intel.py`` precedent (no ``responses`` library
added).
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

from claude_monitoring.attack_surface.reputation.pypi import (
    PyPIReputationClient,
    PyPIScanBudget,
)
from claude_monitoring.attack_surface.reputation.types import (
    ReputationSignal,
    UnavailableReason,
)


def _http_response(payload: dict | bytes, status: int = 200) -> io.BytesIO:
    """Mock urlopen return: a file-like object with ``.read()`` + ``.status``."""
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    fake = io.BytesIO(body)
    fake.status = status  # type: ignore[attr-defined]
    return fake


def _http_error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="http://test",
        code=status,
        msg=f"HTTP {status}",
        hdrs=None,
        fp=None,  # type: ignore[arg-type]
    )


def _pypi_payload(*, sentinel_downloads: bool = False, name: str = "requests") -> dict:
    """Realistic-ish ``pypi.org/pypi/<pkg>/json`` body. The recon
    captured the actual sentinel shape:
    ``info.downloads = {"last_day": -1, "last_month": -1, "last_week": -1}``."""
    return {
        "info": {
            "name": name,
            "version": "2.34.2",
            "downloads": {"last_day": -1, "last_month": -1, "last_week": -1} if sentinel_downloads else None,
        },
        "last_serial": 12345,
        "releases": {},
    }


# ---------------------------------------------------------------------------
# Hard requirement #1 — PyPI -1 sentinel MUST NOT trigger +15
# ---------------------------------------------------------------------------


class TestPyPISentinelDoesNotTriggerLowDownloadModifier:
    """**THE load-bearing test** for hard requirement #1.

    The pypi.org JSON returns ``info.downloads = {"last_week": -1, ...}``
    when usable download stats are not available. A naive parser that
    reads ``info.downloads["last_week"]`` would see ``-1`` — less than
    100 — and fire the typosquat modifier on a clean package.

    The client MUST treat ``-1`` (and any negative sentinel) as
    "downloads unavailable" → fall back to pypistats. If pypistats is
    ALSO unavailable, the client returns ``present=None,
    reason=LOOKUP_FAILED`` — NOT a parseable-absent result that would
    fire +15.
    """

    def test_sentinel_minus_one_in_pypi_does_not_set_low_downloads(self) -> None:
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        responses = [
            _http_response(_pypi_payload(sentinel_downloads=True)),
            _http_response({"data": {"last_week": 250_000}, "package": "requests"}),
        ]
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=responses,
        ):
            result = client.lookup("requests")
        assert result.present is True, (
            "package was present in pypi.org (sentinel downloads != absent); "
            "pypistats showed real downloads of 250k → above threshold → present"
        )
        assert result.downloads == 250_000
        assert result.reason is None

    def test_sentinel_in_pypi_and_pypistats_unavailable_produces_None(self) -> None:
        """If both endpoints fail to produce a real number, the result
        is NOT a +15 firing — it's an unavailable result. Silence is
        never all-clear (hard requirement #2)."""
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        responses = [
            _http_response(_pypi_payload(sentinel_downloads=True)),
            _http_error(500),  # pypistats lookup failed
        ]
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=responses,
        ):
            result = client.lookup("requests")
        assert result.present is None
        assert result.downloads is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED


# ---------------------------------------------------------------------------
# Existence check (pypi.org/pypi/<pkg>/json)
# ---------------------------------------------------------------------------


class TestPyPIExistenceCheck:
    def test_404_means_absent(self) -> None:
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        # pypi 404 → package not in registry. pypistats won't be called for absent pkg.
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=[_http_error(404)],
        ):
            result = client.lookup("typosquat-xyz-12345")
        assert result.present is False
        # Modifier MUST fire — this is the only branch that does
        assert result.signal is ReputationSignal.PIP_LOW_DOWNLOADS

    def test_5xx_means_lookup_failed_not_absent(self) -> None:
        """A server error is NOT "package absent" — fail-open per
        ratification §6 inversion fix."""
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=[_http_error(503)],
        ):
            result = client.lookup("requests")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED

    def test_network_timeout_means_lookup_failed(self) -> None:
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=[urllib.error.URLError("connection timeout")],
        ):
            result = client.lookup("requests")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED


# ---------------------------------------------------------------------------
# pypistats — 429 + budget + below-threshold +15 firing
# ---------------------------------------------------------------------------


class TestPyPIStatsBelowThresholdFiresModifier:
    def test_below_100_per_week_returns_present_false(self) -> None:
        """The +15 typosquat signal fires only when we have a REAL
        count that is < 100/week."""
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        responses = [
            _http_response(_pypi_payload(sentinel_downloads=True)),
            _http_response({"data": {"last_week": 42}, "package": "obscure"}),
        ]
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=responses,
        ):
            result = client.lookup("obscure")
        # present=False means "below threshold → fire +15"
        # downloads carries the empirical count
        assert result.present is False
        assert result.downloads == 42

    def test_at_threshold_100_is_NOT_below(self) -> None:
        """< 100, not <= 100. Spec §6.6.3 says < 100/week."""
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        responses = [
            _http_response(_pypi_payload(sentinel_downloads=True)),
            _http_response({"data": {"last_week": 100}, "package": "edge"}),
        ]
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=responses,
        ):
            result = client.lookup("edge")
        assert result.present is True  # not below threshold


class TestPyPIStats429:
    def test_429_returns_rate_limited(self) -> None:
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        responses = [
            _http_response(_pypi_payload(sentinel_downloads=True)),
            _http_error(429),
        ]
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=responses,
        ):
            result = client.lookup("requests")
        assert result.present is None
        assert result.reason is UnavailableReason.RATE_LIMITED


class TestPyPIScanBudget:
    """The 25-call budget is consumed by pypistats calls, NOT by the
    pypi.org existence check (which is cheaper + has no published
    rate limit)."""

    def test_budget_consumed_only_by_pypistats_calls(self) -> None:
        budget = PyPIScanBudget(remaining=2)
        client = PyPIReputationClient(budget)

        # Fresh BytesIO per call (can only be read once).
        def make_responses():
            return [
                _http_response(_pypi_payload(sentinel_downloads=True)),
                _http_response({"data": {"last_week": 5_000}, "package": "x"}),
            ]

        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=make_responses() + make_responses(),
        ):
            client.lookup("a")
            client.lookup("b")
        # Both pypistats calls consumed budget
        assert budget.remaining == 0

    def test_budget_exhausted_returns_BUDGET_EXCEEDED(self) -> None:
        budget = PyPIScanBudget(remaining=0)
        client = PyPIReputationClient(budget)
        # pypi.org still callable; pypistats should NOT be called.
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=[_http_response(_pypi_payload(sentinel_downloads=True))],
        ) as mock_urlopen:
            result = client.lookup("requests")
        assert result.present is None
        assert result.reason is UnavailableReason.BUDGET_EXCEEDED
        # Only 1 HTTP call made — the pypi.org existence check
        assert mock_urlopen.call_count == 1


class TestPyPIPackageNamePassThroughIsURLEncoded:
    """A malicious / weird package name must not produce a request to
    an arbitrary URL via path injection."""

    def test_pkg_name_with_slash_is_URL_quoted(self) -> None:
        client = PyPIReputationClient(PyPIScanBudget(remaining=25))
        with patch(
            "claude_monitoring.attack_surface.reputation.pypi.urlopen",
            side_effect=[_http_error(404)],
        ) as mock_urlopen:
            client.lookup("evil/../escape")
        # mock_urlopen received a Request object as the first positional arg
        request = mock_urlopen.call_args[0][0]
        called_url = request.full_url
        # The slash got encoded → no raw "evil/.." path
        assert "evil%2F" in called_url
        assert "evil/../escape" not in called_url
