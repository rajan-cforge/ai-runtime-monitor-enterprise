"""P4.1 OSV.dev HTTP client.

Two endpoints (Phase A §2 — corrected per 2026-06-10 empirical curl):

- ``POST /v1/querybatch`` — batch package→vuln-ID lookup. Returns
  per-query `{"vulns": [{"id", "modified"}, ...]}` lists with NO
  severity field. Cheap (1 call per scan typically).

- ``GET /v1/vulns/{id}`` — full advisory record incl. CVSS vector
  in ``severity[].score``. Caller is responsible for caching (7-day
  TTL) and per-scan budget (50/scan).

Retry posture (Phase A §3):
- 429 / 503 → ONE retry with 2s backoff; then raise `OSVRateLimited`.
- Other HTTPError → raise `OSVNetworkError` (network-error reason).
- 404 from vuln_detail → raise `OSVNotFound` (skip the asset's CVE
  enrichment for that ID; rare — would mean OSV removed an ID we
  cached, expected for retracted advisories).
- JSONDecodeError / shape mismatch → raise `OSVParseError`.

No retries are done by this layer beyond the 429/503 case. Per-item
isolation + budget tracking happens in the dispatcher.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
from urllib.request import Request, urlopen

logger = logging.getLogger("ai-runtime-monitor.attack_surface.cves.client")


REQUEST_TIMEOUT_SECONDS: float = 10.0
"""Per-request timeout. Tuned to match P2.6 reputation client."""

RETRY_BACKOFF_SECONDS: float = 2.0
"""Sleep between the first 429/503 and the single retry."""


class OSVError(Exception):
    """Base class for OSV.dev client errors."""


class OSVRateLimited(OSVError):
    """429 / 503 even after the single retry."""


class OSVNotFound(OSVError):
    """404 — vuln ID not present at OSV.dev."""


class OSVNetworkError(OSVError):
    """DNS / TLS / connect / non-recoverable HTTP error."""


class OSVParseError(OSVError):
    """Response body could not be decoded as expected JSON shape."""


class OSVClient:
    """HTTP wrapper for OSV.dev. Stateless — safe to instantiate per scan.

    URLs are constructed via literal-prefix concatenation so the privacy
    gate (``scripts/check_privacy_no_telemetry.py``) can statically verify
    the allowed hostname matches `api.osv.dev`. Tests mock `urlopen`
    entirely; there's no `api_base` override path on purpose.
    """

    def __init__(self, *, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------ querybatch
    def querybatch(self, queries: list[dict]) -> list[list[str]]:
        """POST a batch of package-version queries; return per-query
        vuln-ID lists.

        ``queries`` is a list of OSV.dev request objects:
        ``{"package": {"name": ..., "ecosystem": ...}, "version": ...}``.

        Returns: list of lists; index aligned with input. Each inner
        list is the vuln IDs for that query (empty list = no known vulns).
        """
        if not queries:
            return []
        body = json.dumps({"queries": queries}).encode()
        # urlopen + Request inline so the privacy gate verifies api.osv.dev
        # statically via _leftmost_str_literal recursion into Request's
        # first arg. Same pattern as reputation/pypi.py:_fetch_pypi.
        for attempt in (1, 2):
            try:
                with urlopen(
                    Request(
                        "https://api.osv.dev" + "/v1/querybatch",
                        data=body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    ),
                    timeout=self._timeout,
                ) as response:
                    raw = response.read()
                payload = self._decode_json(raw)
                break
            except urllib.error.HTTPError as exc:
                self._handle_http_error(exc, attempt, retried_already=(attempt == 2))
            except urllib.error.URLError as exc:
                raise OSVNetworkError(f"URLError: {exc}") from exc
        else:  # pragma: no cover — break above is unconditional on success
            raise OSVError("unreachable")
        return OSVClient._extract_vuln_id_lists(payload, queries)

    # ------------------------------------------------------------------ vuln_detail
    def vuln_detail(self, vuln_id: str) -> dict:
        """GET /v1/vulns/{id}; return the full advisory record."""
        for attempt in (1, 2):
            try:
                with urlopen(
                    Request(
                        "https://api.osv.dev" + "/v1/vulns/" + vuln_id,
                        method="GET",
                    ),
                    timeout=self._timeout,
                ) as response:
                    raw = response.read()
                payload = self._decode_json(raw)
                break
            except urllib.error.HTTPError as exc:
                self._handle_http_error(exc, attempt, retried_already=(attempt == 2))
            except urllib.error.URLError as exc:
                raise OSVNetworkError(f"URLError: {exc}") from exc
        else:  # pragma: no cover — break above is unconditional on success
            raise OSVError("unreachable")
        if not isinstance(payload, dict):
            raise OSVParseError(f"vuln_detail body not a dict: {type(payload)}")
        return payload

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _decode_json(raw: bytes) -> dict:
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OSVParseError(f"JSON decode: {exc}") from exc

    @staticmethod
    def _handle_http_error(exc: urllib.error.HTTPError, attempt: int, *, retried_already: bool) -> None:
        """Raise the appropriate `OSVError` subclass, or sleep + return
        (None) to signal the caller's retry loop to continue."""
        if exc.code == 404:
            raise OSVNotFound(str(exc)) from exc
        if exc.code in (429, 503) and not retried_already:
            logger.warning(
                "OSV.dev %s; backing off %.1fs (attempt %d)",
                exc.code,
                RETRY_BACKOFF_SECONDS,
                attempt,
            )
            time.sleep(RETRY_BACKOFF_SECONDS)
            return
        if exc.code in (429, 503):
            raise OSVRateLimited(f"{exc.code} after retry") from exc
        raise OSVNetworkError(f"HTTP {exc.code}: {exc}") from exc

    @staticmethod
    def _extract_vuln_id_lists(payload: dict, queries: list[dict]) -> list[list[str]]:
        try:
            results = payload["results"]
        except (KeyError, TypeError) as exc:
            raise OSVParseError(f"querybatch missing 'results': {exc}") from exc
        if not isinstance(results, list) or len(results) != len(queries):
            raise OSVParseError(f"querybatch results length mismatch: got {results!r}")
        out: list[list[str]] = []
        for entry in results:
            if not isinstance(entry, dict):
                raise OSVParseError(f"querybatch entry not a dict: {entry!r}")
            vulns = entry.get("vulns", [])
            if not isinstance(vulns, list):
                raise OSVParseError(f"querybatch entry.vulns not a list: {vulns!r}")
            ids: list[str] = []
            for v in vulns:
                if isinstance(v, dict) and isinstance(v.get("id"), str):
                    ids.append(v["id"])
            out.append(ids)
        return out
