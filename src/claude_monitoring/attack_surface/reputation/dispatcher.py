"""Reputation dispatcher — per-asset routing + cache + kill-switch + dormant.

Single entry point: :func:`lookup_reputation` takes an asset, picks the
right per-registry client based on ``asset.source``, checks the cache,
and falls through to the per-client lookup on miss.

Cache key: ``f"{signal}:{identifier}"`` (e.g., ``npm_low_downloads:left-pad``).

Per-item isolation per ``project_v022_per_item_isolation.md``: one bad
asset / one network failure NEVER raises out of this function. All
errors translate to a three-state ``ReputationResult``.

**Kill switches** (in priority order):

1. ``VIGIL_NO_REPUTATION=1`` or ``NO_NETWORK=1`` → return ``None`` for
   ALL assets (dispatcher short-circuits before any client). The
   ``RiskScoreResult`` shows no reputation modifier; the UI surfaces
   "Reputation disabled" so silence is never all-clear.
2. Chrome/VSCode + ``reputation.chrome_vscode_enabled=False`` (default)
   → return ``DORMANT`` for those assets. Per-client logic intact;
   the dispatcher gates the call.

A single ``ReputationDispatcher`` instance carries a per-scan
``PyPIScanBudget`` and the cache. Construct once per scan; pass to
the scoring layer.
"""

from __future__ import annotations

import logging
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.reputation.cache import ReputationCache
from claude_monitoring.attack_surface.reputation.chrome_web_store import (
    ChromeWebStoreReputationClient,
)
from claude_monitoring.attack_surface.reputation.config import (
    PYPISTATS_PER_SCAN_BUDGET,
    chrome_vscode_enabled,
    reputation_disabled,
)
from claude_monitoring.attack_surface.reputation.mcp_author import (
    MCPAuthorReputationClient,
)
from claude_monitoring.attack_surface.reputation.npm import NPMReputationClient
from claude_monitoring.attack_surface.reputation.pypi import (
    PyPIReputationClient,
    PyPIScanBudget,
)
from claude_monitoring.attack_surface.reputation.types import (
    ReputationResult,
    ReputationSignal,
    UnavailableReason,
)
from claude_monitoring.attack_surface.reputation.vscode_marketplace import (
    VSCodeMarketplaceReputationClient,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.reputation.dispatcher")


# Per-signal modifier weight (Rajan ratification item 1, 2026-06-08).
# Chrome/VSCode (+20) ship DORMANT until P3.1/P3.2.
MODIFIER_WEIGHTS: dict[ReputationSignal, int] = {
    ReputationSignal.NPM_LOW_DOWNLOADS: 15,
    ReputationSignal.PIP_LOW_DOWNLOADS: 15,
    ReputationSignal.CHROME_NOT_IN_STORE: 20,
    ReputationSignal.VSCODE_NOT_IN_MARKETPLACE: 20,
    ReputationSignal.MCP_AUTHOR_UNVERIFIED: 10,
}


class ReputationDispatcher:
    """One instance per scan. Carries the cache + per-scan budgets."""

    def __init__(
        self,
        cache_path: Path,
        *,
        npm_client: NPMReputationClient | None = None,
        pypi_client: PyPIReputationClient | None = None,
        chrome_client: ChromeWebStoreReputationClient | None = None,
        vscode_client: VSCodeMarketplaceReputationClient | None = None,
        mcp_author_client: MCPAuthorReputationClient | None = None,
    ) -> None:
        self._cache = ReputationCache(cache_path)
        # PyPI client carries its own scan-budget object (shared across
        # all calls within this dispatcher's lifetime).
        self._pypi_budget = PyPIScanBudget(remaining=PYPISTATS_PER_SCAN_BUDGET)
        self._npm = npm_client or NPMReputationClient()
        self._pypi = pypi_client or PyPIReputationClient(self._pypi_budget)
        self._chrome = chrome_client or ChromeWebStoreReputationClient()
        self._vscode = vscode_client or VSCodeMarketplaceReputationClient()
        self._mcp_author = mcp_author_client or MCPAuthorReputationClient()

    def lookup(self, asset: Asset) -> ReputationResult | None:
        """Return the reputation result for ``asset``, or ``None`` if
        the asset type has no reputation signal in P2.6.

        Never raises. Per-item isolation: catches all client exceptions
        and translates them to ``UnavailableReason.LOOKUP_FAILED``.
        """
        if reputation_disabled():
            # Kill switch — return a uniform "disabled" result if the
            # asset has any applicable signal; otherwise None (the
            # asset type just doesn't participate).
            signal = self._signal_for(asset)
            if signal is None:
                return None
            return ReputationResult(
                signal=signal,
                present=None,
                reason=UnavailableReason.LOOKUP_FAILED,
            )

        try:
            return self._lookup_unchecked(asset)
        except Exception as exc:  # noqa: BLE001 — per-item isolation
            logger.warning(
                "reputation dispatcher failed for asset %s (source=%s): %s",
                getattr(asset, "name", "?"),
                getattr(asset, "source", "?"),
                exc,
            )
            signal = self._signal_for(asset)
            if signal is None:
                return None
            return ReputationResult(
                signal=signal,
                present=None,
                reason=UnavailableReason.LOOKUP_FAILED,
            )

    def _lookup_unchecked(self, asset: Asset) -> ReputationResult | None:
        signal = self._signal_for(asset)
        if signal is None:
            return None

        # Cache check (post-signal-resolution so the key is meaningful)
        identifier = self._identifier_for(asset, signal)
        if identifier is None:
            return None
        cache_key = f"{signal.value}:{identifier}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        # Dormant gate (Chrome/VSCode +20 only)
        if signal in (
            ReputationSignal.CHROME_NOT_IN_STORE,
            ReputationSignal.VSCODE_NOT_IN_MARKETPLACE,
        ) and not chrome_vscode_enabled():
            result = ReputationResult(
                signal=signal,
                present=None,
                reason=UnavailableReason.DORMANT,
            )
            # Cache the dormant result so the UI is consistent within
            # a scan but we re-evaluate on the next scan (TTL absorbs
            # the eventual flag flip).
            self._cache.set(cache_key, result)
            return result

        # Fan out per signal
        result = self._call_client(signal, asset, identifier)
        self._cache.set(cache_key, result)
        return result

    def _call_client(
        self,
        signal: ReputationSignal,
        asset: Asset,
        identifier: str,
    ) -> ReputationResult:
        if signal is ReputationSignal.NPM_LOW_DOWNLOADS:
            return self._npm.lookup(identifier)
        if signal is ReputationSignal.PIP_LOW_DOWNLOADS:
            return self._pypi.lookup(identifier)
        if signal is ReputationSignal.CHROME_NOT_IN_STORE:
            return self._chrome.lookup(identifier)
        if signal is ReputationSignal.VSCODE_NOT_IN_MARKETPLACE:
            return self._vscode.lookup(identifier)
        if signal is ReputationSignal.MCP_AUTHOR_UNVERIFIED:
            command, first_arg = self._mcp_command_and_arg(asset)
            return self._mcp_author.lookup(command, first_arg)
        raise RuntimeError(f"no client wired for signal {signal}")

    @staticmethod
    def _signal_for(asset: Asset) -> ReputationSignal | None:
        """Map ``asset.source`` to the applicable signal.

        Sources that have no reputation signal in P2.6 return ``None``
        (those assets simply don't participate in the reputation layer)."""
        source = getattr(asset, "source", None)
        return {
            "node-packages": ReputationSignal.NPM_LOW_DOWNLOADS,
            "python-packages": ReputationSignal.PIP_LOW_DOWNLOADS,
            "chrome-extensions": ReputationSignal.CHROME_NOT_IN_STORE,
            "vscode-extensions": ReputationSignal.VSCODE_NOT_IN_MARKETPLACE,
            "mcp-servers": ReputationSignal.MCP_AUTHOR_UNVERIFIED,
        }.get(source)

    @staticmethod
    def _identifier_for(asset: Asset, signal: ReputationSignal) -> str | None:
        """Per-signal identifier extraction.

        For npm/pip: package name from ``asset.name``.
        For Chrome/VSCode: extension ID or publisher.extName from
        ``asset.name``.
        For MCP-author: use ``asset.name`` as the cache key (the
        ``command`` + ``args[0]`` come from ``current_state``)."""
        name = getattr(asset, "name", None)
        if not isinstance(name, str) or not name.strip():
            return None
        return name

    @staticmethod
    def _mcp_command_and_arg(asset: Asset) -> tuple[str | None, str | None]:
        state = getattr(asset, "current_state", None) or {}
        command = state.get("command") if isinstance(state, dict) else None
        args = state.get("args") if isinstance(state, dict) else None
        first_arg = args[0] if isinstance(args, list) and args else None
        return (
            command if isinstance(command, str) else None,
            first_arg if isinstance(first_arg, str) else None,
        )


def reputation_modifier_for(result: ReputationResult | None) -> int:
    """Translate a result into the int modifier the scoring layer adds.

    - ``result is None`` → 0 (asset type doesn't participate).
    - ``present is True`` → 0 (asset is in registry / verified).
    - ``present is None`` (unavailable) → 0 (fail-open per item 6).
    - ``present is False`` → ``MODIFIER_WEIGHTS[signal]`` (modifier fires).

    The +20 Chrome/VSCode weights still flow through this function;
    the dispatcher's dormant gate ensures those signals come back as
    ``present=None`` while the flag is off, so the modifier doesn't
    fire — the magnitudes stay table-driven for when the flag flips.
    """
    if result is None:
        return 0
    if result.present is not False:
        return 0
    return MODIFIER_WEIGHTS.get(result.signal, 0)


__all__ = [
    "MODIFIER_WEIGHTS",
    "ReputationDispatcher",
    "reputation_modifier_for",
]
