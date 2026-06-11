"""P4.1 vulns cache — `vuln-ID → full record` (7-day TTL).

Caches `/v1/vulns/{id}` responses. The records are near-immutable —
severity changes only on advisory revision — so 7 days is the
Phase A-ratified TTL.

Same persistence pattern as :mod:`querybatch_cache`: chmod 600,
atomic write, corrupted-file → cache miss + WARNING log.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from claude_monitoring.attack_surface.cves import config

logger = logging.getLogger("ai-runtime-monitor.attack_surface.cves.vulns_cache")


class VulnsCache:
    """File-backed cache for OSV.dev `/v1/vulns/{id}` records."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._entries: dict[str, dict] = {}
        self._loaded = False

    def _load_if_needed(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("vulns cache parse failed (%s); treating as empty", exc)
            return
        if not isinstance(data, dict):
            logger.warning("vulns cache root is not a dict; treating as empty")
            return
        entries = data.get("entries", {})
        if isinstance(entries, dict):
            self._entries = entries

    def get(self, vuln_id: str) -> dict | None:
        self._load_if_needed()
        entry = self._entries.get(vuln_id)
        if entry is None:
            return None
        expires_at = entry.get("expires_at")
        if not isinstance(expires_at, (int, float)) or expires_at <= time.time():
            return None
        record = entry.get("record")
        if not isinstance(record, dict):
            return None
        return record

    def set(
        self,
        vuln_id: str,
        *,
        record: dict,
        ttl_seconds: int | None = None,
    ) -> None:
        self._load_if_needed()
        if ttl_seconds is None:
            ttl_seconds = config.VULNS_DETAIL_TTL_SECONDS
        self._entries[vuln_id] = {
            "record": record,
            "expires_at": time.time() + ttl_seconds,
        }
        self._flush()

    def _flush(self) -> None:
        payload = {"entries": self._entries}
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(payload))
            tmp.chmod(0o600)
            tmp.replace(self._path)
        except OSError as exc:
            logger.warning("vulns cache write failed (%s)", exc)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
