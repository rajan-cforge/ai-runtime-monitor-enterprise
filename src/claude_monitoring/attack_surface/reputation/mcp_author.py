"""MCP author verification — offline curator-list match.

**Architect pick + Rajan ratification 2026-06-08:** verification is a
two-pass match against ``config/mcp-trusted-authors.yaml`` (sibling of
``config/risk-rules.yaml``, same PR-update discipline). NO network call.

Match field rationale (per ``mcp_servers.py:149-150`` reality):
``asset.current_state['command']`` is the only identity signal the
merged code enforces. ``asset.name`` is the user's registration key
(trivially spoofable). ``args[0]`` is the package/module name the
runner executes.

**Two-tier match (tightened 2026-06-08 after architect-pass BLOCKER #1):**

- **Pass 1 — privileged_commands:** exact match of ``command`` against
  the curated ``privileged_commands`` list. A privileged command (e.g.,
  the Anthropic-published ``claude-mcp`` runner) carries standalone
  trust and verifies the asset.

- **Pass 2 — generic_runners + package_patterns:** when ``command`` is
  in the ``generic_runners`` list (``npx``, ``uvx``, ``python``, etc.),
  the runner alone is NOT a trust signal. The asset verifies only when
  ``args[0]`` (the package/module the runner executes) substring-or-
  fnmatch matches one of the curated ``package_patterns``.

  WHY this matters: an adversarial MCP server with
  ``command: npx, args: ["evil-package"]`` would slip past a
  command-only check because ``npx`` is on the recognized list. The
  trust signal in that scenario is the PACKAGE the runner executes,
  not the runner itself.

Unverified = neither pass matches → ``present=False`` (``+10`` modifier
fires).

**Inversion fix (judge):** loading the YAML fails (missing /
unparseable / wrong shape) → log CRITICAL ONCE + latch
``_load_failed=True`` so subsequent lookups in the same scan don't
re-attempt the load (architect-pass STRONG #2). Defensive default
returns ``LOOKUP_FAILED`` — the +10 does NOT fire on load failure
(fail-open in the modifier sense; the unverified-by-default posture
applies only when the curator list is present and a lookup misses).
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
    lookups are pure set + fnmatch ops. A load failure latches so the
    CRITICAL log fires once, not once per MCP asset (architect-pass
    STRONG #2).
    """

    def __init__(self, curator_path: Path = DEFAULT_CURATOR_PATH) -> None:
        self._path = curator_path
        self._privileged_commands: set[str] = set()
        self._generic_runners: set[str] = set()
        self._package_patterns: list[str] = []
        self._loaded = False
        self._load_failed = False

    def lookup(self, command: str | None, first_arg: str | None) -> ReputationResult:
        """Match ``(command, first_arg)`` against the curator list.

        Both fields can be ``None`` (some asset states are partial).
        Missing fields cannot match → the asset reads as unverified.
        """
        self._ensure_loaded()
        if self._load_failed:
            return ReputationResult(
                signal=ReputationSignal.MCP_AUTHOR_UNVERIFIED,
                present=None,
                reason=UnavailableReason.LOOKUP_FAILED,
            )
        # Pass 1: privileged command — standalone trust
        if isinstance(command, str) and command in self._privileged_commands:
            return ReputationResult(
                signal=ReputationSignal.MCP_AUTHOR_UNVERIFIED,
                present=True,
                downloads=None,
            )
        # Pass 2: generic runner + curated package pattern (BOTH required)
        verified = False
        if isinstance(command, str) and command in self._generic_runners and isinstance(first_arg, str):
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
        """Load the YAML on first call. Latches success OR failure so
        repeated lookups within a scan never re-read the file."""
        if self._loaded or self._load_failed:
            return
        try:
            validate_path(self._path, root=self._path.parent, check_size=True, max_size_mb=1.0)
            raw = self._path.read_text(errors="replace")
        except (FileNotFoundError, ValueError, OSError) as exc:
            logger.critical(
                "mcp-trusted-authors.yaml load failed: %s; all MCP assets default to unverified",
                exc,
            )
            self._load_failed = True
            return
        try:
            payload = safe_yaml_load(raw)
        except Exception as exc:
            # Broad parse-error catch — safe_yaml_load can raise
            # yaml.YAMLError + subclasses. Matches the P2.5 rules.py
            # precedent for curator-list YAML loading.
            logger.critical(
                "mcp-trusted-authors.yaml parse failed: %s; all MCP assets default to unverified",
                exc,
            )
            self._load_failed = True
            return
        if not isinstance(payload, dict):
            logger.critical(
                "mcp-trusted-authors.yaml top-level not a dict (got %s); defensive default",
                type(payload).__name__,
            )
            self._load_failed = True
            return
        privileged = payload.get("privileged_commands", [])
        runners = payload.get("generic_runners", [])
        patterns = payload.get("package_patterns", [])
        if not (isinstance(privileged, list) and isinstance(runners, list) and isinstance(patterns, list)):
            logger.critical("mcp-trusted-authors.yaml shape invalid; defensive default")
            self._load_failed = True
            return
        # Forbid `*` as a pattern — that would trust everything.
        cleaned_patterns: list[str] = []
        for p in patterns:
            if not isinstance(p, str):
                logger.warning("mcp-trusted-authors.yaml pattern %r is not str; skipping", p)
                continue
            if p == "*":
                logger.critical("mcp-trusted-authors.yaml pattern '*' forbidden; defensive default")
                self._load_failed = True
                return
            cleaned_patterns.append(p)
        self._privileged_commands = {c for c in privileged if isinstance(c, str)}
        self._generic_runners = {c for c in runners if isinstance(c, str)}
        self._package_patterns = cleaned_patterns
        self._loaded = True


__all__ = ["DEFAULT_CURATOR_PATH", "MCPAuthorReputationClient"]
