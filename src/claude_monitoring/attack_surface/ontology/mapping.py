"""Per-source ontology mapping — spec §5.5 simple maps.

Phase A: ``~/Documents/vigil-notes/v022/phase-2/phase-a-investigation.md``.

Each merged discovery source has a corresponding mapper that
converts an :class:`Asset` into a ``frozenset[OntologyCategory]``.
The :func:`map_asset` dispatcher routes by ``asset.source``.

**Q5 structural-completeness contract (2026-06-06).** Every
registered :class:`DiscoverySource` MUST appear in :data:`_REGISTRY`,
but the mapper MAY return ``frozenset()`` for identity-only sources
(ollama-models, ai-tool-versions, ai-apps-info-plist). The
``scripts/check_ontology_mapping_completeness.py`` CI gate is
structural ("a mapper exists"), not functional ("the mapper
produces tags"). Q1 ratification confirms a zero-tag asset lands
at INFO band, which is the correct conservative result for these
identity-only sources today; richer tags emerge in Phase 3+ as
permission/CVE/activity signals attach.

**Q4 split (2026-06-06).** The MCP **scored** multi-signal mapper
(directive §7.3.2) is DEFERRED to P2.1. This module ships only the
simple keyword map on command/args + secrets-presence-from-env
signals.

**Derived-tag prohibition.** Per-source mappers MUST NOT emit
``OntologyCategory.DATA_EXFILTRATION_CAPABLE`` directly — that tag
is computed in :mod:`derived` (P2.2) from the base tag set. The
P2.0 mapper-contract tests pin this property across every mapper.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory

logger = logging.getLogger("ai-runtime-monitor.ontology.mapping")

# ---------------------------------------------------------------------------
# Identity-only sources — empty result is the structurally-correct answer
# ---------------------------------------------------------------------------


def map_ollama_model(asset: Asset) -> frozenset[OntologyCategory]:
    """Ollama models are identity-only — local LLM weights.

    Returns empty. Risk emerges from CVE feeds (Phase 4) and runtime
    activity correlation (Phase 4 P4.3), not from native permissions.
    """
    del asset
    return frozenset()


def map_ai_tool_version(asset: Asset) -> frozenset[OntologyCategory]:
    """CLI tools (``claude``, ``cursor``, etc.) are identity-only.

    The actual permissions are declared by extensions / MCP servers /
    integrations attached to the tool, not the tool binary itself.
    """
    del asset
    return frozenset()


def map_ai_app_info_plist(asset: Asset) -> frozenset[OntologyCategory]:
    """macOS ``.app`` bundles via Info.plist — identity-only at this tier.

    ``LSEnvironment`` + ``CFBundleURLTypes`` + UTI handler analysis is
    Phase 3 expansion.
    """
    del asset
    return frozenset()


# ---------------------------------------------------------------------------
# Skill sources — code_execution by design
# ---------------------------------------------------------------------------


_SKILL_TAGS: frozenset[OntologyCategory] = frozenset({OntologyCategory.CODE_EXECUTION})


def map_claude_code_skill(asset: Asset) -> frozenset[OntologyCategory]:
    """Claude Code skills execute markdown-defined prompts in Claude's
    process context. The asset class IS ``code_execution`` by design."""
    del asset
    return _SKILL_TAGS


def map_openclaw_skill(asset: Asset) -> frozenset[OntologyCategory]:
    """OpenClaw skills are the same protocol shape as Claude Code skills."""
    del asset
    return _SKILL_TAGS


def map_vscode_extension(asset: Asset) -> frozenset[OntologyCategory]:
    """VSCode/Cursor extension rules (P3.8).

    Field → tag mapping:

    - ``main`` non-null → ``CODE_EXECUTION`` (Node.js entry point runs
      in the extension host process).
    - ``main`` null AND ``browser`` non-null → web-only extension; no
      host process executes user code; ``CODE_EXECUTION`` NOT emitted.
    - ``contributes_debug``/``contributes_terminal``/``contributes_tasks``
      → ``SHELL_EXECUTE``.
    - ``extension_kind`` contains ``"workspace"`` →
      ``{FILE_SYSTEM_READ, FILE_SYSTEM_WRITE}``.

    Wildcard ``activation_events`` (``"*"``) is a scope-broadener
    modifier, NOT a base ontology category. Per AP-1 ratification it is
    NOT mapped to any tag and is NOT half-wired in ``risk-rules.yaml``;
    if a wildcard-activation rule is wanted later, the predicate +
    dispatch + LIVE_PREDICATES move land in the SAME PR.
    """
    state = asset.current_state
    tags: set[OntologyCategory] = set()

    main = state.get("main")
    if main:
        tags.add(OntologyCategory.CODE_EXECUTION)

    if state.get("contributes_debug") or state.get("contributes_terminal") or state.get("contributes_tasks"):
        tags.add(OntologyCategory.SHELL_EXECUTE)

    extension_kind = state.get("extension_kind") or []
    if isinstance(extension_kind, list) and "workspace" in extension_kind:
        tags.add(OntologyCategory.FILE_SYSTEM_READ)
        tags.add(OntologyCategory.FILE_SYSTEM_WRITE)

    return frozenset(tags)


_CHROME_PERMISSION_MAP: dict[str, frozenset[OntologyCategory]] = {
    # `tabs` grants chrome.tabs.* metadata (URL/title/favicon of open tabs);
    # framed here as file_system_read because it reads user navigation state.
    # It does NOT grant page DOM access — that requires a host permission.
    "tabs": frozenset({OntologyCategory.FILE_SYSTEM_READ}),
    "cookies": frozenset({OntologyCategory.SECRETS_ACCESS}),
    "history": frozenset({OntologyCategory.FILE_SYSTEM_READ}),
    "downloads": frozenset({OntologyCategory.FILE_SYSTEM_WRITE}),
    # `storage` is the extension's own sandboxed key-value store — not cross-
    # origin, not filesystem. Intentionally empty; do NOT "fix" to emit FS tags.
    "storage": frozenset(),
    "webRequest": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "webRequestBlocking": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "nativeMessaging": frozenset({OntologyCategory.SHELL_EXECUTE, OntologyCategory.INTER_TOOL_COMMUNICATION}),
    "debugger": frozenset({OntologyCategory.SHELL_EXECUTE}),
    "identity": frozenset({OntologyCategory.SECRETS_ACCESS}),
    "management": frozenset({OntologyCategory.SYSTEM_MODIFICATION}),
    "browsingData": frozenset({OntologyCategory.SECRETS_ACCESS}),
    "topSites": frozenset({OntologyCategory.FILE_SYSTEM_READ}),
    "bookmarks": frozenset({OntologyCategory.FILE_SYSTEM_READ}),
    "contentSettings": frozenset({OntologyCategory.SYSTEM_MODIFICATION}),
}
"""Chrome API permission → capability map. Inline per AP-3 ratification
(authorized deferral of directive §7.3.3 YAML externalization).

**R6 ratification (2026-06-09):** ``nativeMessaging`` co-emits
``{SHELL_EXECUTE, INTER_TOOL_COMMUNICATION}`` (not just ``SHELL_EXECUTE``).
Reason: native messaging is the IPC channel Chrome extensions use to
talk to non-browser host programs over JSON-RPC; that channel both
shells out (SHELL_EXECUTE) and is an inter-tool protocol
(INTER_TOOL_COMMUNICATION). The ``categories.py`` docstring for
``INTER_TOOL_COMMUNICATION`` was updated in the same PR to reflect
non-MCP IPC coverage."""


_WILDCARD_HOST_PATTERNS: frozenset[str] = frozenset({"<all_urls>", "https://*/*", "http://*/*", "*://*/*"})
"""Literal host patterns that unambiguously grant any-origin access."""


def _classify_host_pattern(entry: str) -> frozenset[OntologyCategory]:
    """Classify a single host-permission pattern.

    Returns the tag set the pattern contributes. Empty set means "did
    not classify" (caller continues looking at other entries).

    Rules:

    - ``<all_urls>``, ``https://*/*``, ``http://*/*``, ``*://*/*`` →
      ``NETWORK_UNRESTRICTED`` (any origin).
    - ``file://*`` and any ``file://`` pattern → ``FILE_SYSTEM_READ``.
      These grant local-filesystem access via the extension; they are
      NOT a network capability and the network classifier must not
      claim them.
    - Privileged browser-internal schemes (``chrome://``, ``edge://``,
      ``brave://``, ``about:``) → empty. These are not user-routable
      origins; they grant access to internal browser pages, which the
      P3.8 base ontology does not model. Phase 4 may add a category.
    - Patterns where the host portion is a bare wildcard (``host == "*"``
      or ``host == "*.*"``) → ``NETWORK_UNRESTRICTED``. Catches the
      ``https://*.*/*`` case the literal set misses.
    - Patterns matching a multi-subdomain wildcard on a specific
      registrable domain (e.g., ``https://*.google.com/*``) →
      ``NETWORK_SCOPED``. Broad but bounded.
    - Any other URL-shaped pattern → ``NETWORK_SCOPED``.
    """
    if entry in _WILDCARD_HOST_PATTERNS:
        return frozenset({OntologyCategory.NETWORK_UNRESTRICTED})

    if entry.startswith("file:"):
        return frozenset({OntologyCategory.FILE_SYSTEM_READ})

    if entry.startswith(("chrome://", "edge://", "brave://", "about:")):
        return frozenset()

    # Extract scheme + host from match patterns like
    # `scheme://host/path` (the Chrome host-permission shape).
    if "://" in entry:
        rest = entry.split("://", 1)[1]
        host = rest.split("/", 1)[0]
        # Bare host wildcards: "*" or "*.*" cover any origin.
        if host in {"*", "*.*"}:
            return frozenset({OntologyCategory.NETWORK_UNRESTRICTED})
        return frozenset({OntologyCategory.NETWORK_SCOPED})

    # Plain "/*" path patterns without a scheme — defensive: treat as
    # scoped (the source-side validator should have rejected these).
    if entry.endswith("/*"):
        return frozenset({OntologyCategory.NETWORK_SCOPED})

    return frozenset()


def _classify_host_permissions(hosts: list) -> frozenset[OntologyCategory]:
    """Walk a list of host-permission patterns and union the classifications.
    Empty input → empty result. Defensive against non-string entries.

    Precedence: ``NETWORK_UNRESTRICTED`` SUPPRESSES ``NETWORK_SCOPED`` (a
    list with one wildcard + one specific origin is effectively
    unrestricted; emitting both tags would double-count permission
    breadth). ``FILE_SYSTEM_READ`` from a ``file://`` pattern is
    independent and additive.
    """
    if not isinstance(hosts, list) or not hosts:
        return frozenset()
    tags: set[OntologyCategory] = set()
    for entry in hosts:
        if not isinstance(entry, str):
            continue
        tags |= _classify_host_pattern(entry)
    if OntologyCategory.NETWORK_UNRESTRICTED in tags:
        tags.discard(OntologyCategory.NETWORK_SCOPED)
    return frozenset(tags)


def map_chromium_extension(asset: Asset) -> frozenset[OntologyCategory]:
    """Chromium-family extension rules (P3.8). Five rule chains:

    1. ``permissions`` lookup against :data:`_CHROME_PERMISSION_MAP`.
       Unmapped permission strings log at INFO and emit no tag (AP-5
       ratification + authorized deferral of directive §5.6 — UI
       renders these as "not yet classified", never "safe", via the
       memory rider ``project_unrecognized_is_not_low_risk.md``).
    2. Host permissions (``host_permissions`` ∪ ``mv2_host_permissions``):
       wildcard → ``NETWORK_UNRESTRICTED``; scoped origin → ``NETWORK_SCOPED``.
    3. Background presence (``has_background_service_worker`` OR
       ``has_background_scripts``) → ``CODE_EXECUTION``.
    4. Content-script ``<all_urls>`` match → ``FILE_SYSTEM_READ`` (the
       extension reads page DOMs across all sites).
    5. Optional-permissions are NOT mapped at this tier (they are
       inactive until the user grants them; surfacing as base tags
       would over-tag).
    """
    state = asset.current_state
    tags: set[OntologyCategory] = set()

    permissions = state.get("permissions") or []
    if isinstance(permissions, list):
        for perm in permissions:
            if not isinstance(perm, str):
                continue
            mapped = _CHROME_PERMISSION_MAP.get(perm)
            if mapped is not None:
                tags |= mapped
            else:
                logger.info(
                    "unmapped_chrome_permission permission=%s extension_id=%s browser=%s",
                    perm,
                    state.get("extension_id", "?"),
                    state.get("browser", "?"),
                )

    hosts_union: list = []
    for key in ("host_permissions", "mv2_host_permissions"):
        h = state.get(key)
        if isinstance(h, list):
            hosts_union.extend(h)
    tags |= _classify_host_permissions(hosts_union)

    if state.get("has_background_service_worker") or state.get("has_background_scripts"):
        tags.add(OntologyCategory.CODE_EXECUTION)

    content_matches = state.get("content_scripts_matches") or []
    if isinstance(content_matches, list) and "<all_urls>" in content_matches:
        tags.add(OntologyCategory.FILE_SYSTEM_READ)

    return frozenset(tags)


_PYTHON_PACKAGE_CAPABILITY_HINTS: dict[str, frozenset[OntologyCategory]] = {
    "boto3": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "botocore": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "paramiko": frozenset({OntologyCategory.SHELL_EXECUTE, OntologyCategory.NETWORK_UNRESTRICTED}),
    "fabric": frozenset({OntologyCategory.SHELL_EXECUTE, OntologyCategory.NETWORK_UNRESTRICTED}),
    "requests": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "httpx": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "aiohttp": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "urllib3": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "cryptography": frozenset({OntologyCategory.SECRETS_ACCESS}),
    "keyring": frozenset({OntologyCategory.SECRETS_ACCESS}),
    "openai": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "anthropic": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
}
"""Narrow hand-curated package-name → capability map. Keys are PEP 503
normalized lowercase. Most packages return ``frozenset()`` by design —
Python packages do not declare permissions in metadata, so the hint
table covers only well-known-class libraries whose name reliably
predicts capability.

**Authorized deferral of directive §7.3.3** (2026-06-09): the directive
calls for ``config/package-capability-hints.yaml`` to externalize this
table. Per AP-3 ratification, P3.8 inlines the map following the
``_MCP_SCORED_KEYWORDS`` precedent above; YAML externalization is a
follow-up when the list grows beyond curatable-in-source size.
Logged in ``v022/directive-gap-log.md``.
"""


def map_python_package(asset: Asset) -> frozenset[OntologyCategory]:
    """Installed Python package rules (P3.8).

    Look up ``package_name_normalized`` (PEP 503 lowercase, normalized
    source-side) in :data:`_PYTHON_PACKAGE_CAPABILITY_HINTS`. Unrecognized
    packages legitimately return ``frozenset()`` (INFO band) — risk for
    them emerges from CVE severity + repository activity in Phase 4,
    not from name-based capability inference.
    """
    name = str(asset.current_state.get("package_name_normalized") or "").lower()
    return _PYTHON_PACKAGE_CAPABILITY_HINTS.get(name, frozenset())


def map_python_dependency(asset: Asset) -> frozenset[OntologyCategory]:
    """Declared Python dependency rules (P3.8).

    Identical lookup to :func:`map_python_package` (shared
    :data:`_PYTHON_PACKAGE_CAPABILITY_HINTS` table). The
    declared-vs-installed cross-source join is a pipeline / P4.x
    concern, not a per-asset mapper concern — this function tags the
    single asset based on its package name.
    """
    name = str(asset.current_state.get("package_name_normalized") or "").lower()
    return _PYTHON_PACKAGE_CAPABILITY_HINTS.get(name, frozenset())


_NODE_PACKAGE_CAPABILITY_HINTS: dict[str, frozenset[OntologyCategory]] = {
    "axios": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "node-fetch": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "got": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "superagent": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "shelljs": frozenset({OntologyCategory.SHELL_EXECUTE, OntologyCategory.FILE_SYSTEM_WRITE}),
    "execa": frozenset({OntologyCategory.SHELL_EXECUTE}),
    "cross-spawn": frozenset({OntologyCategory.SHELL_EXECUTE}),
    "openai": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "@anthropic-ai/sdk": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "@aws-sdk/client-s3": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
}
"""Narrow hand-curated npm package-name → capability map. Keys are
lowercased (npm names are case-insensitive in normalized form). Same
authorized-deferral disposition as the Python table — inline now,
externalize later when curatable-in-source size is exceeded."""


def map_node_package(asset: Asset) -> frozenset[OntologyCategory]:
    """Node package rules (P3.8).

    Two rule chains:

    1. **Self-asset only** (``dep_kind == "self"``):
       ``lifecycle_scripts`` non-empty OR ``bin_entries`` non-empty
       → ``CODE_EXECUTION``. Lifecycle scripts run automatically on
       ``npm install``; bin entries add executable commands to PATH.

       **R3 ratification (2026-06-09):** ``bin_entries`` is restricted
       to the user's own project package (``dep_kind == "self"``), NOT
       every ``prettier`` in node_modules — the source already enforces
       this asymmetry by only collecting ``bin_entries`` on the self-asset.
       The mapper double-guards via the ``dep_kind == "self"`` check.

    2. **All assets** (self or dependency): look up
       ``package_name_normalized`` in
       :data:`_NODE_PACKAGE_CAPABILITY_HINTS`.

    The two chains union.
    """
    state = asset.current_state
    tags: set[OntologyCategory] = set()

    if state.get("dep_kind") == "self":
        lifecycle = state.get("lifecycle_scripts") or []
        bins = state.get("bin_entries") or []
        if (isinstance(lifecycle, list) and lifecycle) or (isinstance(bins, list) and bins):
            tags.add(OntologyCategory.CODE_EXECUTION)

    name = str(state.get("package_name_normalized") or "").lower()
    tags |= _NODE_PACKAGE_CAPABILITY_HINTS.get(name, frozenset())

    return frozenset(tags)


_HOMEBREW_LLM_HTTP_KEYWORDS: frozenset[str] = frozenset({"ollama", "llama", "llama-cpp", "vllm", "gguf", "gpt4all"})
"""AP-4 taxonomy: LLM HTTP servers. Locally-installed LLM runners that
expose a network listener (Ollama's REST API on 11434, llama.cpp's
``--host`` server) AND execute model inference. Tag with both
``CODE_EXECUTION`` and ``NETWORK_UNRESTRICTED`` per spec §6.6
declared-capability (R4 ratification 2026-06-09: capability is declared
by presence, not runtime observation)."""


_HOMEBREW_GPU_KEYWORDS: frozenset[str] = frozenset({"cuda", "cudnn", "rocm", "openvino"})
"""AP-4 taxonomy: GPU runtimes. Execute compute kernels but do not
themselves serve network — tag with ``CODE_EXECUTION`` only."""


_HOMEBREW_ML_FRAMEWORK_KEYWORDS: frozenset[str] = frozenset(
    {"pytorch", "tensorflow", "jax", "mlx", "onnx", "onnxruntime"}
)
"""AP-4 taxonomy: ML frameworks. Compute pipelines; no network listener.
Tag with ``CODE_EXECUTION`` only."""


_HOMEBREW_API_CLIENT_KEYWORDS: frozenset[str] = frozenset({"openai", "anthropic"})
"""AP-4 taxonomy: API client CLIs. Network-only — the installed CLI
makes outbound calls; no local code execution beyond the CLI binary's
own (which doesn't qualify as ``CODE_EXECUTION`` on its own)."""


def map_homebrew_ai_tool(asset: Asset) -> frozenset[OntologyCategory]:
    """Homebrew AI tool rules (P3.8). Tagging is keyword-driven on
    ``match_reason.keyword`` — the source already classified the formula
    by AI-keyword family; this mapper translates that classification to
    ontology tags via the AP-4 taxonomy split:

    - LLM HTTP servers (``ollama``, ``llama``, …) → ``CODE_EXECUTION``
      + ``NETWORK_UNRESTRICTED``
    - GPU runtimes (``cuda``, ``rocm``, …) → ``CODE_EXECUTION`` only
    - ML frameworks (``pytorch``, ``tensorflow``, …) → ``CODE_EXECUTION``
      only
    - API client CLIs (``openai``, ``anthropic``) → ``NETWORK_UNRESTRICTED``
    - Other (unrecognized keyword, ambiguous) → ``frozenset()`` (INFO).

    R4 ratification: brew Ollama tags the capability *potential* per
    spec §6.6 declared-capability — the static install IS the
    capability declaration; the running daemon's behavior is a Phase 4
    runtime-correlation concern.
    """
    state = asset.current_state
    match_reason = state.get("match_reason") or {}
    keyword = ""
    if isinstance(match_reason, dict):
        keyword = str(match_reason.get("keyword") or "").lower()
    if not keyword:
        return frozenset()
    if keyword in _HOMEBREW_LLM_HTTP_KEYWORDS:
        return frozenset({OntologyCategory.CODE_EXECUTION, OntologyCategory.NETWORK_UNRESTRICTED})
    if keyword in _HOMEBREW_GPU_KEYWORDS or keyword in _HOMEBREW_ML_FRAMEWORK_KEYWORDS:
        return frozenset({OntologyCategory.CODE_EXECUTION})
    if keyword in _HOMEBREW_API_CLIENT_KEYWORDS:
        return frozenset({OntologyCategory.NETWORK_UNRESTRICTED})
    return frozenset()


_CLAUDE_DESKTOP_TOGGLE_TAGS: dict[str, frozenset[OntologyCategory]] = {
    "coworkwebsearchenabled": frozenset({OntologyCategory.NETWORK_UNRESTRICTED}),
    "coworkscheduledtasksenabled": frozenset({OntologyCategory.CODE_EXECUTION}),
    "ccdscheduledtasksenabled": frozenset({OntologyCategory.CODE_EXECUTION}),
}
"""Toggle-name → capability map. R5 ratification (2026-06-09):
``coworkScheduledTasksEnabled`` and ``ccdScheduledTasksEnabled`` enable
scheduled execution of Claude-Desktop-side code, which is squarely
``CODE_EXECUTION`` per spec §5.2. Web-search enables outbound HTTP to
arbitrary search providers → ``NETWORK_UNRESTRICTED``.

Names are lowercased to match the source-side normalization in
:mod:`claude_monitoring.attack_surface.discovery.sources.claude_desktop_integrations`."""


def map_claude_desktop_integration(asset: Asset) -> frozenset[OntologyCategory]:
    """Claude Desktop integration rules (P3.8). Three integration kinds:

    - ``toggle`` — Look up ``integration_name_normalized`` in
      :data:`_CLAUDE_DESKTOP_TOGGLE_TAGS`. Unknown toggles emit
      ``frozenset()`` (INFO band).
    - ``filesystem_access`` — Emit
      ``{FILE_SYSTEM_READ, FILE_SYSTEM_WRITE}``. The integration grants
      Claude Desktop both directions on the configured path.
    - ``unknown_top_level`` — Emit ``frozenset()`` (forward-compat
      capture). UI renders these as "Not yet classified", never "safe"
      (memory rider ``project_unrecognized_is_not_low_risk.md``; the
      §6.8 unknown-capable-floor does NOT extend to this source).

    Defensive against missing fields: unrecognized ``integration_kind``
    or missing ``current_state`` defaults to ``frozenset()`` (fail-closed).
    """
    state = asset.current_state
    kind = state.get("integration_kind")
    if kind == "toggle":
        name = state.get("integration_name_normalized") or ""
        return _CLAUDE_DESKTOP_TOGGLE_TAGS.get(str(name).lower(), frozenset())
    if kind == "filesystem_access":
        return frozenset({OntologyCategory.FILE_SYSTEM_READ, OntologyCategory.FILE_SYSTEM_WRITE})
    return frozenset()


# ---------------------------------------------------------------------------
# MCP — simple keyword map + P2.1 scored config-only multi-signal layer
# ---------------------------------------------------------------------------
#
# Ratification trail (Rajan 2026-06-07): P2.1 implements the directive
# §7.3.2 algorithm SHAPE — weighted signals + cumulative threshold — over
# the LOCAL CONFIG fields the P1.4 source captured (command, args, env),
# NOT the wire-published `tools[]` array the directive's original example
# consumed. The fragility §7.3.2 was meant to solve (naming-convention
# drift across MCP server packages) is only fully solved when wire
# introspection lands. That work is deferred to v0.3 issue #89, which
# carries the egress-and-execution design decision (spawning discovered
# possibly-hostile servers as subprocesses) on its own.
#
# Honest framing: this is a marginal upgrade over the simple map. The
# accumulator + threshold scaffold pays off downstream — P2.3's risk
# scoring + P2.4's rules engine compose over scored tags. The actual
# robustness §7.3.2 promised arrives with introspection in v0.3.


_SECRETS_KEY_SUFFIXES: tuple[str, ...] = ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD")
"""Suffix half of the helpers :data:`TOKEN_VAR_NAMES` vocabulary. The
AUTH_ arm of that regex is checked separately as a substring (not
prefix) match — see :data:`_AUTH_SUBSTRING`. Single source of truth
for secret-key-name detection lives in helpers; this set is a small
duplicate to avoid the mapping module importing the helpers redaction
infrastructure."""


_AUTH_SUBSTRING: str = "AUTH_"
"""Substring marker matching the helpers regex ``r".*AUTH_.*"`` arm.
Anywhere in the key name, NOT just at position 0 — ``X_AUTH_HEADER``
matches the helpers regex and must match here too."""


_MCP_COMMAND_KEYWORDS: dict[OntologyCategory, tuple[str, ...]] = {
    OntologyCategory.FILE_SYSTEM_READ: ("server-filesystem", "fs-mcp", "filesystem-server"),
    OntologyCategory.FILE_SYSTEM_WRITE: ("server-filesystem", "fs-mcp", "filesystem-server"),
    OntologyCategory.SHELL_EXECUTE: ("server-shell", "shell-mcp", "bash-mcp", "server-bash"),
    OntologyCategory.NETWORK_UNRESTRICTED: (
        "server-fetch",
        "http-mcp",
        "server-github",
        "server-puppeteer",
        "server-brave-search",
    ),
}
"""Conservative substring map on lowercased ``command + args``. Hand-curated
from the official Anthropic MCP server catalog. The scored multi-signal
version in P2.1 reads server-published tool definitions (richer signal,
but requires the MCP protocol handshake; outside P1 scope).

Mis-tuning here under-tags assets (silently lower risk score), so the
list is intentionally narrow — false negatives are preferable to
false positives that erode operator trust in the score."""


def map_mcp_server_simple(asset: Asset) -> frozenset[OntologyCategory]:
    """Spec §5.5 simple MCP map. Three signal sources:

    1. **Universal:** every MCP server gets ``inter_tool_communication``
       (the MCP protocol is itself this category by definition).
    2. **env:** any key matching the ``_TOKEN/_KEY/_SECRET/_PASSWORD/
       AUTH_*`` suffix pattern → ``secrets_access`` (the value is
       post-redaction; we tag on key-name presence only).
    3. **command + args substring:** known well-known MCP server
       packages tag ``file_system_*``, ``shell_execute``, or
       ``network_unrestricted`` per :data:`_MCP_COMMAND_KEYWORDS`.

    Defensive against malformed ``current_state``: missing fields
    default to empty (the universal ``inter_tool_communication`` tag
    still applies, which is the honest minimum for an MCP asset).
    """
    tags: set[OntologyCategory] = {OntologyCategory.INTER_TOOL_COMMUNICATION}

    # env → secrets_access (post-redaction key-name presence)
    env = asset.current_state.get("env") or {}
    if isinstance(env, dict):
        for key in env:
            upper_key = str(key).upper()
            if _AUTH_SUBSTRING in upper_key or any(upper_key.endswith(s) for s in _SECRETS_KEY_SUFFIXES):
                tags.add(OntologyCategory.SECRETS_ACCESS)
                break

    # command + args → known-package substring map
    command = asset.current_state.get("command") or ""
    args = asset.current_state.get("args") or []
    if isinstance(args, list):
        args_str = " ".join(str(a) for a in args)
    else:
        args_str = ""
    cmd_blob = f"{command} {args_str}".lower()
    for category, keywords in _MCP_COMMAND_KEYWORDS.items():
        if any(kw in cmd_blob for kw in keywords):
            tags.add(category)

    return frozenset(tags)


# ---------------------------------------------------------------------------
# P2.1 scored config-only multi-signal map
# ---------------------------------------------------------------------------


MCP_SCORED_THRESHOLD: float = 0.5
"""Inclusion threshold for the scored map (directive §7.3.2 magic number).

Surfaced as a module constant for two reasons:

1. Tunable in one place if empirical data later justifies adjustment.
2. Visible to operators reading the score breakdown — the threshold
   is part of the contract, not buried in a function literal.
"""


_HIGH_CONFIDENCE_WEIGHT: float = 0.7
"""Score contributed by an exact official-package keyword match. Matches
the directive §7.3.2 `name` signal weight — the strongest signal in the
original wire-input formulation."""


_LOW_CONFIDENCE_WEIGHT: float = 0.4
"""Score contributed by a loose substring keyword (vendor fork, internal
naming variant). Two loose hits in the same category accumulate to 0.8
> :data:`MCP_SCORED_THRESHOLD`, the property that distinguishes the
scored map from the binary simple map."""


_NAME_CHARS: frozenset[str] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")
"""Characters that constitute a package-name token. A keyword match is
only counted when both sides of the match are NOT in this set (i.e., the
match sits at a word boundary). Prevents substring-anywhere traps like
``server-shell-utilities`` falsely matching the ``server-shell`` keyword
(architect-pass H2, 2026-06-07)."""


def _keyword_at_boundary(blob: str, keyword: str) -> bool:
    """True iff ``keyword`` appears in ``blob`` at a word boundary on both
    sides (preceded and followed by either string-start/end OR a character
    outside :data:`_NAME_CHARS`).

    Real false-positive cases this catches (from architect-pass empirical
    probes):

    - ``server-shell-utilities`` — ``server-shell`` keyword would not match
      because the trailing ``-`` is a name char.
    - ``proxy-server-fetch-tests`` — ``server-fetch`` keyword would not
      match because the preceding ``-`` is a name char.
    - ``server-github-clone-mirror`` — same shape.

    True-positive cases still match:

    - ``/usr/local/bin/server-filesystem`` (preceded by ``/``, trailed by
      string-end).
    - ``npx @modelcontextprotocol/server-filesystem /tmp`` (preceded by
      ``/``, trailed by `` ``).
    """
    idx = 0
    klen = len(keyword)
    while True:
        pos = blob.find(keyword, idx)
        if pos == -1:
            return False
        left_ok = pos == 0 or blob[pos - 1] not in _NAME_CHARS
        end_pos = pos + klen
        right_ok = end_pos == len(blob) or blob[end_pos] not in _NAME_CHARS
        if left_ok and right_ok:
            return True
        idx = pos + 1


_MCP_SCORED_KEYWORDS: dict[OntologyCategory, dict[str, float]] = {
    OntologyCategory.FILE_SYSTEM_READ: {
        # High confidence — exact official package names
        "@modelcontextprotocol/server-filesystem": _HIGH_CONFIDENCE_WEIGHT,
        "server-filesystem": _HIGH_CONFIDENCE_WEIGHT,
        # Low confidence — loose substring patterns
        "mcp-fs": _LOW_CONFIDENCE_WEIGHT,
        "filesystem": _LOW_CONFIDENCE_WEIGHT,
    },
    OntologyCategory.FILE_SYSTEM_WRITE: {
        "@modelcontextprotocol/server-filesystem": _HIGH_CONFIDENCE_WEIGHT,
        "server-filesystem": _HIGH_CONFIDENCE_WEIGHT,
        "mcp-fs": _LOW_CONFIDENCE_WEIGHT,
        "filesystem": _LOW_CONFIDENCE_WEIGHT,
    },
    OntologyCategory.SHELL_EXECUTE: {
        "server-shell": _HIGH_CONFIDENCE_WEIGHT,
        "server-bash": _HIGH_CONFIDENCE_WEIGHT,
        "shell-mcp": _LOW_CONFIDENCE_WEIGHT,
        "bash-mcp": _LOW_CONFIDENCE_WEIGHT,
    },
    OntologyCategory.NETWORK_UNRESTRICTED: {
        "@modelcontextprotocol/server-fetch": _HIGH_CONFIDENCE_WEIGHT,
        "@modelcontextprotocol/server-github": _HIGH_CONFIDENCE_WEIGHT,
        "@modelcontextprotocol/server-puppeteer": _HIGH_CONFIDENCE_WEIGHT,
        "@modelcontextprotocol/server-brave-search": _HIGH_CONFIDENCE_WEIGHT,
        "server-fetch": _HIGH_CONFIDENCE_WEIGHT,
        "server-github": _HIGH_CONFIDENCE_WEIGHT,
        "server-puppeteer": _HIGH_CONFIDENCE_WEIGHT,
        "server-brave-search": _HIGH_CONFIDENCE_WEIGHT,
        "http-mcp": _LOW_CONFIDENCE_WEIGHT,
    },
}
"""Weighted keyword map. Each (category, keyword) pair contributes its
weight to the category's score when the keyword appears in lowercased
``command + args``. Per-category scores accumulate; tags clearing
:data:`MCP_SCORED_THRESHOLD` are emitted.

Mis-tuning here under-tags assets (silently lower risk score), so the
keyword list stays conservative — false negatives are preferable to
false positives that erode operator trust in the score. The high
weight (0.7) is reserved for exact official Anthropic catalog package
names; the low weight (0.4) for community fork patterns.
"""


def map_mcp_server_scored(asset: Asset) -> frozenset[OntologyCategory]:
    """Scored multi-signal MCP map — config-only (P2.1, Rajan 2026-06-07).

    Implements the directive §7.3.2 algorithm SHAPE (weighted signals,
    cumulative threshold) over the local config fields the P1.4 source
    captured (command, args, env). Does NOT read wire-published
    ``tools[]`` definitions — that requires spawning discovered servers
    as subprocesses, an egress-and-execution decision deferred to v0.3
    issue #89.

    Signal sources (config-only adaptation):

    1. **Baseline** (universal): every MCP server gets
       ``inter_tool_communication``. Identical to :func:`map_mcp_server_simple`.
    2. **Secrets**: env key matching the token-suffix vocabulary or
       containing ``AUTH_`` → ``secrets_access``. Identical to simple.
    3. **Scored command/args**: keywords accumulate weighted scores per
       category; categories clearing :data:`MCP_SCORED_THRESHOLD` are
       emitted. Strict upgrade over the simple binary substring path —
       a server with multiple loose indicators correctly clears the
       bar; a single weak signal correctly does not.

    Returns the union of all triggered tags.
    """
    tags: set[OntologyCategory] = {OntologyCategory.INTER_TOOL_COMMUNICATION}

    # env → secrets_access (identical to simple map; same vocabulary)
    env = asset.current_state.get("env") or {}
    if isinstance(env, dict):
        for key in env:
            upper_key = str(key).upper()
            if _AUTH_SUBSTRING in upper_key or any(upper_key.endswith(s) for s in _SECRETS_KEY_SUFFIXES):
                tags.add(OntologyCategory.SECRETS_ACCESS)
                break

    # Build the searchable blob
    command = asset.current_state.get("command") or ""
    args = asset.current_state.get("args") or []
    args_str = " ".join(str(a) for a in args) if isinstance(args, list) else ""
    cmd_blob = f"{command} {args_str}".lower()

    # Accumulate weighted scores per category. Keyword matches use a
    # word-boundary check (`_keyword_at_boundary`) to prevent substring
    # traps like `server-shell-utilities` matching `server-shell`.
    for category, weighted in _MCP_SCORED_KEYWORDS.items():
        score = sum(weight for kw, weight in weighted.items() if _keyword_at_boundary(cmd_blob, kw))
        # Strict greater per directive §7.3.2 "only include tags with
        # cumulative score >0.5". Exactly 0.5 does NOT emit.
        if score > MCP_SCORED_THRESHOLD:
            tags.add(category)

    return frozenset(tags)


# ---------------------------------------------------------------------------
# Registry + dispatcher
# ---------------------------------------------------------------------------


_REGISTRY: dict[str, Callable[[Asset], frozenset[OntologyCategory]]] = {
    "ollama-models": map_ollama_model,
    "ai-tool-versions": map_ai_tool_version,
    "ai-apps-info-plist": map_ai_app_info_plist,
    "claude-code-skills": map_claude_code_skill,
    "openclaw-skills": map_openclaw_skill,
    "mcp-servers": map_mcp_server_scored,
    "vscode-extensions": map_vscode_extension,
    "chromium-extensions": map_chromium_extension,
    "python-packages": map_python_package,
    "python-project-deps": map_python_dependency,
    "node-packages": map_node_package,
    "homebrew-ai-tools": map_homebrew_ai_tool,
    "claude-desktop-integrations": map_claude_desktop_integration,
}
"""Per-source mapping registry. Adding a new source REQUIRES adding
an entry here — the structural completeness CI gate enforces this.

The ``mcp-servers`` entry routes to the P2.1 scored mapper. The simple
keyword map (:func:`map_mcp_server_simple`) is retained as the floor
the scored layer composes over and is still publicly exported for
direct callers + tests; the dispatcher uses the scored version."""


REGISTERED_SOURCES: frozenset[str] = frozenset(_REGISTRY)
"""Public view of registered source names. Tests + the CI gate
script consume this."""


def get_mapper(source_name: str) -> Callable[[Asset], frozenset[OntologyCategory]] | None:
    """Return the mapping function for ``source_name``, or ``None`` when
    the source is not registered."""
    return _REGISTRY.get(source_name)


def map_asset(asset: Asset) -> frozenset[OntologyCategory]:
    """Dispatch by ``asset.source``. Returns ``frozenset()`` for sources
    without a registered mapper (fail-closed default; the CI gate is
    the durable defense against forgotten registrations).
    """
    mapper = _REGISTRY.get(asset.source)
    if mapper is None:
        return frozenset()
    return mapper(asset)


__all__ = [
    "MCP_SCORED_THRESHOLD",
    "REGISTERED_SOURCES",
    "get_mapper",
    "map_ai_app_info_plist",
    "map_ai_tool_version",
    "map_asset",
    "map_chromium_extension",
    "map_claude_code_skill",
    "map_claude_desktop_integration",
    "map_homebrew_ai_tool",
    "map_mcp_server_scored",
    "map_mcp_server_simple",
    "map_node_package",
    "map_ollama_model",
    "map_openclaw_skill",
    "map_python_dependency",
    "map_python_package",
    "map_vscode_extension",
]
