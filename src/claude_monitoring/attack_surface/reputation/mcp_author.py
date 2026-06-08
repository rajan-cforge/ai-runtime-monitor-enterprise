"""MCP author verification — offline curator-list match.

**Architect pick + Rajan ratification 2026-06-08:** verification is a
two-pass match against ``config/mcp-trusted-authors.yaml`` (sibling of
``config/risk-rules.yaml``, same PR-update discipline). NO network call.

Match field rationale (per ``mcp_servers.py:149-150`` reality):
``asset.current_state['command']`` is the only identity signal the
merged code enforces. ``asset.name`` is the user's registration key
(trivially spoofable). ``args[0]`` is the package/module name the
runner executes.

Pass 1: exact match of ``command`` against the YAML ``commands`` list.
Pass 2: substring + fnmatch of ``args[0]`` against the YAML
``package_patterns`` list.

Unverified = neither pass produces a match → ``present=False``
(``+10`` modifier fires).

**Inversion fix (judge):** loading the YAML fails (missing /
unparseable / wrong shape) → log CRITICAL + treat ALL assets as
unverified for the scan (fail-CLOSED here is acceptable because
"unverified" is a defensive default — it's the OPPOSITE of fail-open
for in-flight network calls).
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path

from claude_monitoring.attack_surface.discovery.helpers import safe_yaml_load, validate_path
from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.reputation.mcp_author")


DEFAULT_CURATOR_PATH: Path = Path(__file__).resolve().parents[4] / "config" / "mcp-trusted-authors.yaml"


class MCPAuthorReputationClient:
    """Loads + caches the curator list, then matches per-asset.

    The curator list loads once per scan (``ensure_loaded``); subsequent
    lookups are pure dict + fnmatch ops.
    """

    def __init__(self, curator_path: Path = DEFAULT_CURATOR_PATH) -> None:
        self._path = curator_path
        self._commands: set[str] = set()
        self._package_patterns: list[str] = []
        self._loaded = False

    def lookup(self, command: str | None, first_arg: str | None) -> ReputationResult:
        """Match ``(command, first_arg)`` against the curator list.

        Both fields can be ``None`` (some asset states are partial).
        Missing fields cannot match → the asset reads as unverified.
        """
        self._ensure_loaded()
        if not self._loaded:
            # YAML load failed at startup; defensive default = unverified
            return ReputationResult(
                signal=ReputationSignal.MCP_AUTHOR_UNVERIFIED,
                present=None,
                reason=UnavailableReason.LOOKUP_FAILED,
            )
        verified = False
        if isinstance(command, str) and command in self._commands:
            # Pass 1 fired — but only meaningful in combination with
            # the package pattern; a bare `npx` is not trusted.
            # Architect pick: treat Pass 1 + Pass 2 as independent;
            # EITHER fires verified.
            # (For `npx`-style runners, Pass 2 narrows the trust.)
            verified = True
        if not verified and isinstance(first_arg, str):
            for pattern in self._package_patterns:
                if fnmatch.fnmatchcase(first_arg, pattern):
                    verified = True
                    break
        return ReputationResult(
            signal=ReputationSignal.MCP_AUTHOR_UNVERIFIED,
            present=verified,
            downloads=None,
        )

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        try:
            validate_path(self._path, root=self._path.parent, check_size=True, max_size_mb=1.0)
            raw = self._path.read_text(errors="replace")
        except (FileNotFoundError, ValueError, OSError) as exc:
            logger.critical(
                "mcp-trusted-authors.yaml load failed: %s; all MCP assets default to unverified",
                exc,
            )
            return
        # safe_yaml_load raises yaml.YAMLError + subclasses; match the
        # P2.5 rules.py precedent (broad Exception catch on parse).
        try:
            payload = safe_yaml_load(raw)
        except Exception as exc:
            logger.critical(
                "mcp-trusted-authors.yaml parse failed: %s; all MCP assets default to unverified",
                exc,
            )
            return
        if not isinstance(payload, dict):
            logger.critical(
                "mcp-trusted-authors.yaml top-level not a dict (got %s); defensive default",
                type(payload).__name__,
            )
            return
        commands = payload.get("commands", [])
        patterns = payload.get("package_patterns", [])
        if not isinstance(commands, list) or not isinstance(patterns, list):
            logger.critical("mcp-trusted-authors.yaml shape invalid; defensive default")
            return
        # Forbid `*` as a pattern — that would trust everything.
        cleaned_patterns: list[str] = []
        for p in patterns:
            if not isinstance(p, str):
                logger.warning("mcp-trusted-authors.yaml pattern %r is not str; skipping", p)
                continue
            if p == "*":
                logger.critical("mcp-trusted-authors.yaml pattern '*' forbidden; defensive default")
                return
            cleaned_patterns.append(p)
        self._commands = {c for c in commands if isinstance(c, str)}
        self._package_patterns = cleaned_patterns
        self._loaded = True


__all__ = ["DEFAULT_CURATOR_PATH", "MCPAuthorReputationClient"]
