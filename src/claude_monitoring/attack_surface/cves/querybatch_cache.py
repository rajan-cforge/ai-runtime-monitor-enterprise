"""P4.1 querybatch cache — `(ecosystem, package, version) → vuln-ID list`.

Caches the result of `POST /v1/querybatch` per package version. Both
positive ("vulns found") AND negative ("no vulns") answers get the
SAME 24h TTL (Phase A §4 — corrected; the clean→vulnerable transition
is the catch case so asymmetric TTL would make Vigil blind to it).

Persistence shape (JSON, chmod 600, atomic write — same pattern as
reputation cache):

.. code-block:: json

    {
      "entries": {
        "PyPI:requests:2.18.0": {
          "vuln_ids": ["GHSA-x", "PYSEC-1"],
          "expires_at": 1717920000.0
        },
        "PyPI:clean-pkg:1.0.0": {
          "vuln_ids": [],
          "expires_at": 1717920000.0
        }
      }
    }

Corrupted / missing file → cache miss (logged at WARNING). Per-item
isolation rider — a cache fault never raises into the dispatcher.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from claude_monitoring.attack_surface.cves import config

logger = logging.getLogger("ai-runtime-monitor.attack_surface.cves.querybatch_cache")


class QuerybatchCache:
    """File-backed cache for OSV.dev `/v1/querybatch` results."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}
        self._loaded = False

    @staticmethod
    def _key(ecosystem: str, package: str, version: str) -> str:
        return f"{ecosystem}:{package}:{version}"

    def _load_if_needed(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("querybatch cache parse failed (%s); treating as empty", exc)
            return
        if not isinstance(data, dict):
            logger.warning("querybatch cache root is not a dict; treating as empty")
            return
        entries = data.get("entries", {})
        if isinstance(entries, dict):
            self._entries = entries

    def get(self, ecosystem: str, package: str, version: str) -> list[str] | None:
        """Return cached `vuln_ids` list if present + unexpired, else None.

        Returns `[]` (cleanly cached "no vulns") distinctly from `None`
        ("not in cache"). Distinction is load-bearing — `None` triggers a
        network fetch; `[]` short-circuits to `cves=[]` on the asset."""
        self._load_if_needed()
        entry = self._entries.get(self._key(ecosystem, package, version))
        if entry is None:
            return None
        expires_at = entry.get("expires_at")
        if not isinstance(expires_at, (int, float)) or expires_at <= time.time():
            return None
        vuln_ids = entry.get("vuln_ids")
        if not isinstance(vuln_ids, list):
            return None
        return list(vuln_ids)

    def set(
        self,
        ecosystem: str,
        package: str,
        version: str,
        *,
        vuln_ids: list[str],
        ttl_seconds: int | None = None,
    ) -> None:
        """Cache `vuln_ids` for the given package+version.

        ``ttl_seconds`` defaults to Phase A's 24h for BOTH positive +
        negative (`vuln_ids=[]`)."""
        self._load_if_needed()
        if ttl_seconds is None:
            ttl_seconds = config.QUERYBATCH_POSITIVE_TTL_SECONDS
        self._entries[self._key(ecosystem, package, version)] = {
            "vuln_ids": list(vuln_ids),
            "expires_at": time.time() + ttl_seconds,
        }
        self._flush()

    def _flush(self) -> None:
        payload = {"entries": self._entries}
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(payload))
            # chmod the tmp file BEFORE the atomic rename so the visible
            # file is never world-readable, matching reputation cache.
            tmp.chmod(0o600)
            tmp.replace(self._path)
        except OSError as exc:
            logger.warning("querybatch cache write failed (%s)", exc)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
