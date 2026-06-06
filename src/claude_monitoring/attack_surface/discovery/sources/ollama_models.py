"""`OllamaModelsSource` — discovers locally-installed Ollama models.

Per spec §4.2 + P1.4 Phase A §5. C2 source: pure stdout parse of
``ollama list``; no structured input; no secrets. Per-item isolation
contract honored — one bad stdout row does NOT poison the batch.

**Empirical baseline (Rajan's machine 2026-06-05):** 4 models —
llama3.3:70b, llama3.2:latest, nomic-embed-text:latest, llama3:latest.
"""

from __future__ import annotations

import logging
import subprocess
import time

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import safe_subprocess

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.ollama_models")


class OllamaModelsSource(DiscoverySource):
    """Enumerates Ollama models via `ollama list`."""

    DEFAULT_TIMEOUT_SEC = 30
    """Per spec §4.7. Ollama list is fast (~50ms on a healthy install)."""

    def name(self) -> str:
        """Source identifier per spec §4.2."""
        return "ollama-models"

    def requires_auth(self) -> bool:
        """No credentials required; pure local subprocess invocation."""
        return False

    def discover(self) -> list[Asset]:
        """Run ``ollama list`` and emit one Asset per discovered model."""
        try:
            result = safe_subprocess(["ollama", "list"], timeout=self.DEFAULT_TIMEOUT_SEC)
        except FileNotFoundError:
            # Tool not installed — silent normal flow.
            return []
        except subprocess.TimeoutExpired as exc:
            # Re-raise as builtin TimeoutError so `run_with_safety` records
            # the outcome as TIMEOUT (not ERROR — subprocess timeout IS a
            # timeout from the audit's perspective).
            logger.warning("ollama list timed out after %ss", self.DEFAULT_TIMEOUT_SEC)
            raise TimeoutError(f"ollama list timed out after {self.DEFAULT_TIMEOUT_SEC}s") from exc
        if result.returncode != 0:
            logger.warning("ollama list exited %d; stderr: %s", result.returncode, (result.stderr or "")[:200])
            raise RuntimeError(f"ollama list exited {result.returncode}")

        assets: list[Asset] = []
        scan_time = time.time()
        # Skip the header row; iterate body rows with per-item isolation
        lines = result.stdout.splitlines()
        for raw_line in lines[1:] if lines else []:
            line = raw_line.strip()
            if not line:
                continue
            try:
                asset = self._parse_row(line, scan_time)
            except Exception as exc:
                logger.warning("skipping malformed ollama row %r: %s", line[:80], exc)
                continue
            if asset is not None:
                assets.append(asset)
        return assets

    def _parse_row(self, line: str, scan_time: float) -> Asset | None:
        """Parse a single ``ollama list`` row.

        Format: ``NAME  ID  SIZE  MODIFIED`` (whitespace-separated; columns
        may be 1+ spaces or tabs). A row that doesn't split into ≥4
        fields is malformed.
        """
        fields = line.split()
        if len(fields) < 4:
            raise ValueError(f"expected ≥4 fields, got {len(fields)}")
        # The last two columns are SIZE (with unit) and MODIFIED (which is
        # a multi-word string like "5 months ago"). The model name is the
        # first field; the ID is the second.
        model_name = fields[0]
        model_id = fields[1]
        # Tag parsing: name format is "family:tag" → name="family:tag", version="tag"
        version = model_name.split(":", 1)[1] if ":" in model_name else None

        return Asset(
            id=f"ollama-model-{model_id}",
            type="ai_tool",
            parent_asset_id=None,
            name=model_name,
            version=version,
            install_path=None,
            source="ollama-models",
            current_state={"ollama_id": model_id, "raw_row": line[:200]},
            discovered_at=scan_time,
        )
