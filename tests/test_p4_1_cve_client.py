"""TDD red-phase tests for P4.1 OSVClient.

Pins the contract for `attack_surface/cves/client.py`:
  * querybatch — POST /v1/querybatch with a list of (ecosystem, package, version)
  * vuln_detail — GET /v1/vulns/{id}
  * retry-once on 429/503 with backoff; soft-fail beyond
  * fail-closed on any non-OSV-shape response

All network calls are mocked at urllib.request.urlopen — no real
HTTP, no real network reach (the conftest signal guard would catch
SIGTERM, but we're not signaling; explicit caution).
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch


def _fake_response(payload, status=200):
    """Build an HTTP response object compatible with `urlopen` semantics."""
    fake = MagicMock()
    fake.__enter__.return_value = fake
    fake.__exit__.return_value = None
    fake.read.return_value = json.dumps(payload).encode()
    fake.status = status
    fake.getcode = lambda: status
    return fake


class TestQuerybatch:
    """POST /v1/querybatch returns per-query lists of `{id, modified}`
    objects (empirical 2026-06-10)."""

    def test_querybatch_returns_per_query_vuln_id_lists(self):
        from claude_monitoring.attack_surface.cves.client import OSVClient

        body = {
            "results": [
                {
                    "vulns": [
                        {"id": "GHSA-x", "modified": "2026-02-04T03:44:00Z"},
                        {"id": "PYSEC-1", "modified": "2023-11-08T04:00:00Z"},
                    ]
                },
                {"vulns": []},
            ]
        }
        client = OSVClient()
        with patch(
            "claude_monitoring.attack_surface.cves.client.urlopen",
            return_value=_fake_response(body),
        ):
            results = client.querybatch(
                [
                    {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.18.0"},
                    {"package": {"name": "clean", "ecosystem": "PyPI"}, "version": "1.0.0"},
                ]
            )
        assert results == [
            ["GHSA-x", "PYSEC-1"],
            [],
        ]

    def test_querybatch_empty_queries_returns_empty(self):
        from claude_monitoring.attack_surface.cves.client import OSVClient

        client = OSVClient()
        with patch("claude_monitoring.attack_surface.cves.client.urlopen") as mock_open:
            assert client.querybatch([]) == []
            mock_open.assert_not_called()

    def test_querybatch_no_vulns_key_means_no_vulns(self):
        """OSV.dev sometimes omits the `vulns` key entirely for clean
        packages; treat as `[]`."""
        from claude_monitoring.attack_surface.cves.client import OSVClient

        body = {"results": [{}]}
        client = OSVClient()
        with patch(
            "claude_monitoring.attack_surface.cves.client.urlopen",
            return_value=_fake_response(body),
        ):
            assert client.querybatch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}]) == [[]]

    def test_querybatch_429_retries_once_then_succeeds(self):
        from claude_monitoring.attack_surface.cves.client import OSVClient

        success = _fake_response({"results": [{"vulns": []}]})
        with (
            patch(
                "claude_monitoring.attack_surface.cves.client.urlopen",
                side_effect=[
                    urllib.error.HTTPError("url", 429, "Too Many", {}, None),
                    success,
                ],
            ),
            patch("claude_monitoring.attack_surface.cves.client.time.sleep"),
        ):
            client = OSVClient()
            assert client.querybatch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}]) == [[]]

    def test_querybatch_429_after_retry_raises_rate_limited(self):
        from claude_monitoring.attack_surface.cves.client import (
            OSVClient,
            OSVRateLimited,
        )

        with (
            patch(
                "claude_monitoring.attack_surface.cves.client.urlopen",
                side_effect=urllib.error.HTTPError("url", 429, "Too Many", {}, None),
            ),
            patch("claude_monitoring.attack_surface.cves.client.time.sleep"),
        ):
            client = OSVClient()
            import pytest

            with pytest.raises(OSVRateLimited):
                client.querybatch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}])

    def test_querybatch_503_retries_like_429(self):
        from claude_monitoring.attack_surface.cves.client import OSVClient

        success = _fake_response({"results": [{"vulns": []}]})
        with (
            patch(
                "claude_monitoring.attack_surface.cves.client.urlopen",
                side_effect=[
                    urllib.error.HTTPError("url", 503, "Service Unavailable", {}, None),
                    success,
                ],
            ),
            patch("claude_monitoring.attack_surface.cves.client.time.sleep"),
        ):
            client = OSVClient()
            assert client.querybatch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}]) == [[]]

    def test_querybatch_non_recoverable_error_raises_network_error(self):
        from claude_monitoring.attack_surface.cves.client import (
            OSVClient,
            OSVNetworkError,
        )

        with patch(
            "claude_monitoring.attack_surface.cves.client.urlopen",
            side_effect=urllib.error.URLError("dns gone"),
        ):
            client = OSVClient()
            import pytest

            with pytest.raises(OSVNetworkError):
                client.querybatch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}])

    def test_querybatch_parse_error_raises_parse_error(self):
        from claude_monitoring.attack_surface.cves.client import (
            OSVClient,
            OSVParseError,
        )

        fake = MagicMock()
        fake.__enter__.return_value = fake
        fake.__exit__.return_value = None
        fake.read.return_value = b"{not valid json"
        fake.status = 200
        with patch("claude_monitoring.attack_surface.cves.client.urlopen", return_value=fake):
            client = OSVClient()
            import pytest

            with pytest.raises(OSVParseError):
                client.querybatch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}])

    def test_querybatch_posts_to_api_osv_dev(self):
        from claude_monitoring.attack_surface.cves import config
        from claude_monitoring.attack_surface.cves.client import OSVClient

        captured: list[str] = []

        def fake_urlopen(req, *args, **kwargs):
            captured.append(req.full_url)
            return _fake_response({"results": [{"vulns": []}]})

        with patch(
            "claude_monitoring.attack_surface.cves.client.urlopen",
            side_effect=fake_urlopen,
        ):
            client = OSVClient()
            client.querybatch([{"package": {"name": "x", "ecosystem": "PyPI"}, "version": "1.0"}])
        assert captured == [f"{config.OSV_API_BASE}/v1/querybatch"]


class TestVulnDetail:
    """GET /v1/vulns/{id} returns the full advisory record incl.
    `severity[].score` (CVSS vector string)."""

    def test_vuln_detail_returns_record(self):
        from claude_monitoring.attack_surface.cves.client import OSVClient

        body = {
            "id": "GHSA-x",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        }
        with patch(
            "claude_monitoring.attack_surface.cves.client.urlopen",
            return_value=_fake_response(body),
        ):
            client = OSVClient()
            assert client.vuln_detail("GHSA-x") == body

    def test_vuln_detail_404_raises_not_found(self):
        from claude_monitoring.attack_surface.cves.client import (
            OSVClient,
            OSVNotFound,
        )

        with patch(
            "claude_monitoring.attack_surface.cves.client.urlopen",
            side_effect=urllib.error.HTTPError("url", 404, "Not Found", {}, None),
        ):
            client = OSVClient()
            import pytest

            with pytest.raises(OSVNotFound):
                client.vuln_detail("GHSA-nope")

    def test_vuln_detail_gets_correct_url(self):
        from claude_monitoring.attack_surface.cves import config
        from claude_monitoring.attack_surface.cves.client import OSVClient

        captured: list[str] = []

        def fake_urlopen(req, *args, **kwargs):
            captured.append(req.full_url)
            return _fake_response({"id": "GHSA-x"})

        with patch(
            "claude_monitoring.attack_surface.cves.client.urlopen",
            side_effect=fake_urlopen,
        ):
            client = OSVClient()
            client.vuln_detail("GHSA-x")
        assert captured == [f"{config.OSV_API_BASE}/v1/vulns/GHSA-x"]
