"""Source → expected-destination-host whitelist.

Per spec §7.1.1 amendment (Rajan 2026-06-12): runtime activity is
correlated via `destination_host` filtering, not the never-existed
`process_id` JOIN. Each source whose assets have a known runtime
destination signature gets an entry here; sources whose assets are
NOT runtime processes (packages, MCP configs, etc.) return `None`
to signal "structural n/a" — distinct from "correlatable but no
activity in window" (Q8 rider, Amendment-C discipline).

The list is small (v0.2.2 ships 13 discovery sources; ~half are
correlatable). Hand-curated literal — extend cautiously, every entry
becomes a tested contract.
"""

from __future__ import annotations

# Source → frozenset of destination_host strings (exact match) OR None
# for "structural n/a — this source's assets are not runtime processes
# with a known destination signature."
_EXPECTED_HOSTS: dict[str, frozenset[str] | None] = {
    # Browser extensions calling Anthropic's API. The Claude.ai web UI
    # also routes through claude.ai for browser-mediated traffic; both
    # are legitimate destinations for the Claude Chrome extension.
    "chromium-extensions": frozenset({"api.anthropic.com", "claude.ai"}),
    # VSCode / Cursor extensions — the AI-tool subset hits Anthropic /
    # OpenAI APIs through the editor process. We attribute via host
    # patterns the editor uses, not the extension PID (extensions run
    # in-process under the editor host).
    "vscode-extensions": frozenset({"api.anthropic.com", "api.openai.com"}),
    # Claude Desktop hits api.anthropic.com directly.
    "claude-desktop-integrations": frozenset({"api.anthropic.com"}),
    # Local Ollama daemon listens on 11434 by default (sometimes 11435+
    # for multi-instance). Captures are seen as localhost:11434 when
    # routed through the proxy.
    "ollama-models": frozenset({"localhost:11434", "127.0.0.1:11434"}),
    "ai-tool-versions": frozenset({"api.anthropic.com", "api.openai.com"}),
    # `None` entries = structural n/a. Listed explicitly so adding a
    # new source forces a decision (test_unknown_source_returns_none
    # pin protects the contract too).
    "python-packages": None,
    "python-project-deps": None,
    "node-packages": None,
    "mcp-servers": None,
    "claude-code-skills": None,
    "openclaw-skills": None,
    "homebrew-ai-tools": None,
    "ai-apps-info-plist": None,
}


def expected_hosts_for_source(source: str) -> frozenset[str] | None:
    """Look up the expected destination-host whitelist for a source.

    Args:
        source: The `Asset.source` value (one of the registered
            discovery source names).

    Returns:
        A `frozenset[str]` of expected hosts when the source is
        correlatable, or `None` for structural n/a (this source's
        assets are not runtime processes). An unknown source also
        returns `None` so a future contributor adding a new source
        without an `_EXPECTED_HOSTS` entry triggers
        `asset_has_no_runtime_correlation` rather than silently
        producing empty aggregations.
    """
    return _EXPECTED_HOSTS.get(source)
