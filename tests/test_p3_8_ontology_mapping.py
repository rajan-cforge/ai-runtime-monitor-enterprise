"""P3.8 — Phase 3 ontology mapping bodies + Phase B contract verification.

This module pins the real rule bodies P3.8 wires across the eight
Phase-3 mapper placeholders. The identity-only sources (`ollama-models`,
`ai-tool-versions`, `ai-apps-info-plist`), the skill sources
(`claude-code-skills`, `openclaw-skills`), and the already-complete
`mcp-servers` scored mapper are NOT modified by P3.8.

**Phase C contract:** `~/Documents/vigil-notes/v022/phase-3/p3.8-phase-b-summary.md`.

Tests are organized by source:

- ``TestVSCodeExtensionMapping`` — `main`/`browser`/`contributes_*`/`extension_kind` matrix.
- ``TestChromiumExtensionMapping`` — chrome permission map + host permissions + bg + content scripts. R6: `nativeMessaging` → `{SHELL_EXECUTE, INTER_TOOL_COMMUNICATION}`.
- ``TestPythonPackageMapping`` — package-name hint table (shared with project deps).
- ``TestPythonDependencyMapping`` — identical lookup; per-asset, no cross-source join.
- ``TestNodePackageMapping`` — lifecycle + bin (self-asset only) + name hint table.
- ``TestHomebrewMapping`` — keyword taxonomy split (LLM HTTP / GPU / ML / orchestration with net / ambiguous).
- ``TestClaudeDesktopMapping`` — three integration kinds (toggle / filesystem_access / unknown_top_level).

Cross-cutting:

- ``TestDerivedTagProhibition`` — positive-case parametric rows that
  produce non-empty tag sets; pins that NO mapper ever emits
  ``DATA_EXFILTRATION_CAPABLE`` directly (AP-2 architect-pass
  condition; empty-fixture rows pass trivially).
- ``TestDataExfiltrationCapableDerivation`` — end-to-end integration:
  per-source mapper → ``derived.py`` correctly composes
  ``DATA_EXFILTRATION_CAPABLE`` from the canonical exfil pattern
  (`cookies + <all_urls>` on a Chrome extension).
"""

from __future__ import annotations

import time

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import (
    BASE_CATEGORIES,
    OntologyCategory,
)
from claude_monitoring.attack_surface.ontology.derived import apply_derived
from claude_monitoring.attack_surface.ontology.mapping import (
    map_asset,
    map_chromium_extension,
    map_claude_desktop_integration,
    map_homebrew_ai_tool,
    map_mcp_server_simple,
    map_node_package,
    map_python_dependency,
    map_python_package,
    map_vscode_extension,
)


def _asset(*, source: str, asset_type: str, current_state: dict) -> Asset:
    return Asset(
        id=f"{source}-fixture",
        type=asset_type,
        parent_asset_id=None,
        name="fixture",
        version=None,
        install_path=None,
        source=source,
        current_state=current_state,
        discovered_at=time.time(),
    )


# ---------------------------------------------------------------------------
# VSCode / Cursor extensions
# ---------------------------------------------------------------------------


class TestVSCodeExtensionMapping:
    """`main` non-null → CODE_EXECUTION. `contributes_debug/terminal/tasks`
    → SHELL_EXECUTE. `extension_kind` contains 'workspace' → FILE_SYSTEM_*.
    Web-only (`browser` set, `main` None) → no CODE_EXECUTION."""

    def test_main_entry_emits_code_execution(self) -> None:
        asset = _asset(
            source="vscode-extensions",
            asset_type="extension",
            current_state={"main": "out/extension.js"},
        )
        assert OntologyCategory.CODE_EXECUTION in map_vscode_extension(asset)

    def test_debugger_contributes_emits_shell_execute(self) -> None:
        asset = _asset(
            source="vscode-extensions",
            asset_type="extension",
            current_state={"contributes_debug": True},
        )
        assert OntologyCategory.SHELL_EXECUTE in map_vscode_extension(asset)

    def test_terminal_contributes_emits_shell_execute(self) -> None:
        asset = _asset(
            source="vscode-extensions",
            asset_type="extension",
            current_state={"contributes_terminal": True},
        )
        assert OntologyCategory.SHELL_EXECUTE in map_vscode_extension(asset)

    def test_tasks_contributes_emits_shell_execute(self) -> None:
        asset = _asset(
            source="vscode-extensions",
            asset_type="extension",
            current_state={"contributes_tasks": True},
        )
        assert OntologyCategory.SHELL_EXECUTE in map_vscode_extension(asset)

    def test_workspace_kind_emits_filesystem_read_and_write(self) -> None:
        asset = _asset(
            source="vscode-extensions",
            asset_type="extension",
            current_state={"extension_kind": ["workspace"]},
        )
        result = map_vscode_extension(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in result
        assert OntologyCategory.FILE_SYSTEM_WRITE in result

    def test_web_only_does_not_emit_code_execution(self) -> None:
        """`browser` set, `main` None → web-only extension; no host
        process executes user code."""
        asset = _asset(
            source="vscode-extensions",
            asset_type="extension",
            current_state={"main": None, "browser": "dist/web.js"},
        )
        assert OntologyCategory.CODE_EXECUTION not in map_vscode_extension(asset)

    def test_empty_state_is_empty_tag_set(self) -> None:
        asset = _asset(source="vscode-extensions", asset_type="extension", current_state={})
        assert map_vscode_extension(asset) == frozenset()

    def test_missing_extension_kind_treated_as_ui_only(self) -> None:
        """No `extension_kind` field → no workspace filesystem tags."""
        asset = _asset(
            source="vscode-extensions",
            asset_type="extension",
            current_state={"main": "out/extension.js"},
        )
        result = map_vscode_extension(asset)
        assert OntologyCategory.FILE_SYSTEM_READ not in result
        assert OntologyCategory.FILE_SYSTEM_WRITE not in result


# ---------------------------------------------------------------------------
# Chromium extensions
# ---------------------------------------------------------------------------


class TestChromiumExtensionMapping:
    """`permissions` → CHROME_PERMISSION_MAP. Host permissions
    `<all_urls>`/`https://*/*`/`http://*/*` → NETWORK_UNRESTRICTED.
    Scoped origins → NETWORK_SCOPED. Background → CODE_EXECUTION.
    Content scripts `<all_urls>` → FILE_SYSTEM_READ.

    **R6 ratification (2026-06-09):** `nativeMessaging` →
    `{SHELL_EXECUTE, INTER_TOOL_COMMUNICATION}` (not just SHELL_EXECUTE)."""

    def test_native_messaging_emits_shell_execute_and_inter_tool(self) -> None:
        """R6 pinpoint: nativeMessaging always co-emits both tags."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"permissions": ["nativeMessaging"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.SHELL_EXECUTE in result
        assert OntologyCategory.INTER_TOOL_COMMUNICATION in result

    def test_debugger_permission_emits_shell_execute(self) -> None:
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"permissions": ["debugger"]},
        )
        assert OntologyCategory.SHELL_EXECUTE in map_chromium_extension(asset)

    def test_webrequest_permission_emits_network_unrestricted(self) -> None:
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"permissions": ["webRequest"]},
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_chromium_extension(asset)

    def test_cookies_permission_emits_secrets_access(self) -> None:
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"permissions": ["cookies"]},
        )
        assert OntologyCategory.SECRETS_ACCESS in map_chromium_extension(asset)

    def test_all_urls_host_permission_emits_network_unrestricted(self) -> None:
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["<all_urls>"]},
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_chromium_extension(asset)

    def test_mv2_host_permission_all_urls_emits_network_unrestricted(self) -> None:
        """Carry-forward from P3.2: MV2 host perms surface via
        `mv2_host_permissions` after split."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"mv2_host_permissions": ["<all_urls>"]},
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_chromium_extension(asset)

    def test_https_wildcard_emits_network_unrestricted(self) -> None:
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["https://*/*"]},
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_chromium_extension(asset)

    def test_scoped_origin_emits_network_scoped(self) -> None:
        """A specific origin like `https://api.github.com/*` is scoped,
        not unrestricted. Removes `NETWORK_SCOPED` from 'dormant' status."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["https://api.github.com/*"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.NETWORK_SCOPED in result
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_file_url_pattern_emits_filesystem_read(self) -> None:
        """``file://*`` host permissions grant local filesystem access via
        the extension — NOT a network capability. Caught by the host
        classifier's special-cased ``file:`` scheme handler."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["file:///*"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in result
        assert OntologyCategory.NETWORK_SCOPED not in result
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_chrome_internal_scheme_emits_nothing(self) -> None:
        """``chrome://`` and similar privileged-internal schemes don't map
        to a P3.8 ontology category (they aren't routable web origins).
        Must NOT be misclassified as ``NETWORK_SCOPED``."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["chrome://*/*"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.NETWORK_SCOPED not in result
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_any_domain_wildcard_emits_network_unrestricted(self) -> None:
        """``https://*.*/*`` (any-domain any-TLD) is effectively unrestricted.
        The literal pattern isn't in ``_WILDCARD_HOST_PATTERNS`` but the
        host-portion classifier catches ``host == "*.*"``."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["https://*.*/*"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.NETWORK_UNRESTRICTED in result

    def test_subdomain_wildcard_on_specific_domain_is_scoped(self) -> None:
        """``https://*.google.com/*`` is broad but bounded to one
        registrable domain → ``NETWORK_SCOPED``, not unrestricted."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["https://*.google.com/*"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.NETWORK_SCOPED in result
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_unrestricted_suppresses_scoped(self) -> None:
        """A list containing both a wildcard and a specific origin should
        emit only ``NETWORK_UNRESTRICTED`` — the scoped entry is
        functionally subsumed and emitting both would double-count
        permission breadth."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["<all_urls>", "https://api.github.com/*"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.NETWORK_UNRESTRICTED in result
        assert OntologyCategory.NETWORK_SCOPED not in result

    def test_no_scheme_path_pattern_is_scoped(self) -> None:
        """Defensive: a pattern without a scheme that ends in ``/*``
        (e.g., a malformed host permission) classifies as scoped."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["foo/*"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.NETWORK_SCOPED in result

    def test_non_string_host_permission_entry_skipped(self) -> None:
        """A non-string entry in ``host_permissions`` (corrupt input) is
        skipped, not raised."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": [123, "<all_urls>"]},
        )
        # Should not raise; the wildcard still classifies.
        result = map_chromium_extension(asset)
        assert OntologyCategory.NETWORK_UNRESTRICTED in result

    def test_non_string_permission_entry_skipped(self) -> None:
        """A non-string entry in ``permissions`` (corrupt input) is
        skipped, not raised."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"permissions": [None, "cookies"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.SECRETS_ACCESS in result

    def test_bare_string_host_entry_emits_nothing(self) -> None:
        """A bare-garbage host-permission string (no scheme, no /*) falls
        through every classifier branch and emits nothing — defensive
        final fallback."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"host_permissions": ["bare-garbage-string"]},
        )
        result = map_chromium_extension(asset)
        assert OntologyCategory.NETWORK_SCOPED not in result
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_background_service_worker_emits_code_execution(self) -> None:
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"has_background_service_worker": True},
        )
        assert OntologyCategory.CODE_EXECUTION in map_chromium_extension(asset)

    def test_background_scripts_emits_code_execution(self) -> None:
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"has_background_scripts": True},
        )
        assert OntologyCategory.CODE_EXECUTION in map_chromium_extension(asset)

    def test_management_permission_emits_system_modification(self) -> None:
        """Removes `SYSTEM_MODIFICATION` from 'dormant' status."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"permissions": ["management"]},
        )
        assert OntologyCategory.SYSTEM_MODIFICATION in map_chromium_extension(asset)

    def test_content_script_all_urls_emits_filesystem_read(self) -> None:
        """Reading the page DOM across all sites is a form of file_system_read."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"content_scripts_matches": ["<all_urls>"]},
        )
        assert OntologyCategory.FILE_SYSTEM_READ in map_chromium_extension(asset)

    def test_unmapped_permission_does_not_crash(self) -> None:
        """AP-5: unknown permissions log at INFO; no tag emitted, no crash."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={"permissions": ["someFutureUnmappedPermission"]},
        )
        # Should not raise, and should return empty (or whatever other
        # tags apply from other fields — here, none).
        result = map_chromium_extension(asset)
        assert isinstance(result, frozenset)

    def test_unmapped_permission_logged_once_per_invocation(self, caplog) -> None:
        """AP-5 dedup contract: a manifest listing the same unmapped
        permission twice logs ONCE, not twice. Within-invocation dedup;
        the orchestrator's once-per-asset-per-scan call pattern carries
        the rest (no module-level state, per CLAUDE.md)."""
        import logging as _logging

        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={
                "permissions": ["someFutureUnmappedPermission", "someFutureUnmappedPermission"],
                "extension_id": "abcd1234",
                "browser": "chrome",
            },
        )
        with caplog.at_level(_logging.INFO, logger="ai-runtime-monitor.ontology.mapping"):
            map_chromium_extension(asset)
        unmapped_lines = [r for r in caplog.records if "unmapped_chrome_permission" in r.getMessage()]
        assert len(unmapped_lines) == 1

    def test_empty_state_is_empty_tag_set(self) -> None:
        asset = _asset(source="chromium-extensions", asset_type="extension", current_state={})
        assert map_chromium_extension(asset) == frozenset()


# ---------------------------------------------------------------------------
# Python packages (installed) + project dependencies
# ---------------------------------------------------------------------------


class TestPythonPackageMapping:
    """Per-source mapper looks up the package name (normalized) in the
    hint table. Most packages return frozenset() — the table is narrow
    by design."""

    def test_requests_emits_network_unrestricted(self) -> None:
        asset = _asset(
            source="python-packages",
            asset_type="python_package",
            current_state={"package_name_normalized": "requests"},
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_python_package(asset)

    def test_boto3_emits_network_unrestricted(self) -> None:
        asset = _asset(
            source="python-packages",
            asset_type="python_package",
            current_state={"package_name_normalized": "boto3"},
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_python_package(asset)

    def test_paramiko_emits_shell_execute_and_network(self) -> None:
        asset = _asset(
            source="python-packages",
            asset_type="python_package",
            current_state={"package_name_normalized": "paramiko"},
        )
        result = map_python_package(asset)
        assert OntologyCategory.SHELL_EXECUTE in result
        assert OntologyCategory.NETWORK_UNRESTRICTED in result

    def test_cryptography_emits_secrets_access(self) -> None:
        asset = _asset(
            source="python-packages",
            asset_type="python_package",
            current_state={"package_name_normalized": "cryptography"},
        )
        assert OntologyCategory.SECRETS_ACCESS in map_python_package(asset)

    def test_unknown_package_emits_empty(self) -> None:
        asset = _asset(
            source="python-packages",
            asset_type="python_package",
            current_state={"package_name_normalized": "some-random-internal-package"},
        )
        assert map_python_package(asset) == frozenset()

    def test_pep503_normalization_already_applied(self) -> None:
        """Source-side normalization guarantees lowercase. Mapper does NOT
        re-normalize; mismatched-case key would be a source-side bug."""
        asset = _asset(
            source="python-packages",
            asset_type="python_package",
            current_state={"package_name_normalized": "requests"},
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_python_package(asset)


class TestPythonDependencyMapping:
    """Per the contract: identical lookup table to python_package. The
    declared-vs-installed JOIN is a P4.x concern, not a per-asset mapper concern."""

    def test_requests_dep_emits_network_unrestricted(self) -> None:
        asset = _asset(
            source="python-project-deps",
            asset_type="python_dependency",
            current_state={"package_name_normalized": "requests"},
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_python_dependency(asset)

    def test_unknown_dep_emits_empty(self) -> None:
        asset = _asset(
            source="python-project-deps",
            asset_type="python_dependency",
            current_state={"package_name_normalized": "internal-foo"},
        )
        assert map_python_dependency(asset) == frozenset()


# ---------------------------------------------------------------------------
# Node packages
# ---------------------------------------------------------------------------


class TestNodePackageMapping:
    """Lifecycle scripts + bin entries (self-asset only) → CODE_EXECUTION.
    Dependency assets use the npm name hint table.

    **R3 ratification:** `bin_entries` only emits on self-assets (the
    user's own project package), not every `prettier` in node_modules."""

    def test_self_with_lifecycle_scripts_emits_code_execution(self) -> None:
        asset = _asset(
            source="node-packages",
            asset_type="node_package",
            current_state={
                "dep_kind": "self",
                "lifecycle_scripts": ["postinstall"],
                "bin_entries": [],
            },
        )
        assert OntologyCategory.CODE_EXECUTION in map_node_package(asset)

    def test_self_with_bin_entries_emits_code_execution(self) -> None:
        asset = _asset(
            source="node-packages",
            asset_type="node_package",
            current_state={
                "dep_kind": "self",
                "lifecycle_scripts": [],
                "bin_entries": ["my-cli"],
            },
        )
        assert OntologyCategory.CODE_EXECUTION in map_node_package(asset)

    def test_dependency_with_bin_entries_does_not_emit_code_execution(self) -> None:
        """R3: `bin_entries` on a dep_kind=dependencies row would be a
        source-side bug (only self-assets carry it). Even if present,
        the mapper restricts the rule to dep_kind='self'."""
        asset = _asset(
            source="node-packages",
            asset_type="node_package",
            current_state={
                "package_name_normalized": "prettier",
                "dep_kind": "dependencies",
                "bin_entries": ["prettier"],
            },
        )
        result = map_node_package(asset)
        assert OntologyCategory.CODE_EXECUTION not in result

    def test_axios_dep_emits_network_unrestricted(self) -> None:
        asset = _asset(
            source="node-packages",
            asset_type="node_package",
            current_state={
                "package_name_normalized": "axios",
                "dep_kind": "dependencies",
            },
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_node_package(asset)

    def test_shelljs_dep_emits_shell_and_fs_write(self) -> None:
        asset = _asset(
            source="node-packages",
            asset_type="node_package",
            current_state={
                "package_name_normalized": "shelljs",
                "dep_kind": "dependencies",
            },
        )
        result = map_node_package(asset)
        assert OntologyCategory.SHELL_EXECUTE in result
        assert OntologyCategory.FILE_SYSTEM_WRITE in result

    def test_unknown_node_package_emits_empty(self) -> None:
        asset = _asset(
            source="node-packages",
            asset_type="node_package",
            current_state={
                "package_name_normalized": "some-internal-pkg",
                "dep_kind": "dependencies",
            },
        )
        assert map_node_package(asset) == frozenset()


# ---------------------------------------------------------------------------
# Homebrew AI tools — AP-4 keyword taxonomy split
# ---------------------------------------------------------------------------


class TestHomebrewMapping:
    """**AP-4 architect-pass taxonomy split (collapses with R4):**

    - LLM HTTP servers (ollama, llama.cpp, vllm) → CODE_EXECUTION + NETWORK_UNRESTRICTED
    - GPU/ML compute (cuda, cudnn, rocm, pytorch, tensorflow, mlx, jax) → CODE_EXECUTION only
    - Orchestration with network (langchain-cli, etc.) → CODE_EXECUTION + NETWORK_UNRESTRICTED
    - Ambiguous (whisper, spacy) → CODE_EXECUTION only with TODO

    **R4 ratification (2026-06-09):** Brew Ollama → tag the
    capability potential per spec §6.6 declared-capability."""

    def test_ollama_emits_code_execution_and_network(self) -> None:
        """R4 + AP-4: LLM HTTP server class."""
        asset = _asset(
            source="homebrew-ai-tools",
            asset_type="homebrew_ai_tool",
            current_state={"match_reason": {"keyword": "ollama", "field": "name"}},
        )
        result = map_homebrew_ai_tool(asset)
        assert OntologyCategory.CODE_EXECUTION in result
        assert OntologyCategory.NETWORK_UNRESTRICTED in result

    def test_llama_emits_code_execution_and_network(self) -> None:
        asset = _asset(
            source="homebrew-ai-tools",
            asset_type="homebrew_ai_tool",
            current_state={"match_reason": {"keyword": "llama", "field": "name"}},
        )
        result = map_homebrew_ai_tool(asset)
        assert OntologyCategory.CODE_EXECUTION in result
        assert OntologyCategory.NETWORK_UNRESTRICTED in result

    def test_cuda_emits_code_execution_only(self) -> None:
        """AP-4: GPU runtime → CODE_EXECUTION only (no network in the runtime itself)."""
        asset = _asset(
            source="homebrew-ai-tools",
            asset_type="homebrew_ai_tool",
            current_state={"match_reason": {"keyword": "cuda", "field": "name"}},
        )
        result = map_homebrew_ai_tool(asset)
        assert OntologyCategory.CODE_EXECUTION in result
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_pytorch_emits_code_execution_only(self) -> None:
        """AP-4: ML framework → CODE_EXECUTION only."""
        asset = _asset(
            source="homebrew-ai-tools",
            asset_type="homebrew_ai_tool",
            current_state={"match_reason": {"keyword": "pytorch", "field": "name"}},
        )
        result = map_homebrew_ai_tool(asset)
        assert OntologyCategory.CODE_EXECUTION in result
        assert OntologyCategory.NETWORK_UNRESTRICTED not in result

    def test_openai_api_client_emits_network_only(self) -> None:
        """AP-4: API client CLIs (openai/anthropic) → NETWORK_UNRESTRICTED only;
        no CODE_EXECUTION (the CLI binary doesn't host arbitrary user code)."""
        asset = _asset(
            source="homebrew-ai-tools",
            asset_type="homebrew_ai_tool",
            current_state={"match_reason": {"keyword": "openai", "field": "name"}},
        )
        result = map_homebrew_ai_tool(asset)
        assert OntologyCategory.NETWORK_UNRESTRICTED in result
        assert OntologyCategory.CODE_EXECUTION not in result

    def test_unknown_keyword_emits_empty(self) -> None:
        asset = _asset(
            source="homebrew-ai-tools",
            asset_type="homebrew_ai_tool",
            current_state={"match_reason": {"keyword": "random-tool", "field": "name"}},
        )
        assert map_homebrew_ai_tool(asset) == frozenset()

    def test_missing_match_reason_emits_empty(self) -> None:
        asset = _asset(source="homebrew-ai-tools", asset_type="homebrew_ai_tool", current_state={})
        assert map_homebrew_ai_tool(asset) == frozenset()


# ---------------------------------------------------------------------------
# Claude Desktop integrations
# ---------------------------------------------------------------------------


class TestClaudeDesktopMapping:
    """Three integration kinds, three rule chains. R5 ratified
    `coworkScheduledTasksEnabled` → CODE_EXECUTION (spec §5.2)."""

    def test_cowork_web_search_toggle_emits_network_unrestricted(self) -> None:
        asset = _asset(
            source="claude-desktop-integrations",
            asset_type="claude_desktop_integration",
            current_state={
                "integration_kind": "toggle",
                "integration_name_normalized": "coworkwebsearchenabled",
            },
        )
        assert OntologyCategory.NETWORK_UNRESTRICTED in map_claude_desktop_integration(asset)

    def test_cowork_scheduled_tasks_emits_code_execution(self) -> None:
        """R5 ratification."""
        asset = _asset(
            source="claude-desktop-integrations",
            asset_type="claude_desktop_integration",
            current_state={
                "integration_kind": "toggle",
                "integration_name_normalized": "coworkscheduledtasksenabled",
            },
        )
        assert OntologyCategory.CODE_EXECUTION in map_claude_desktop_integration(asset)

    def test_ccd_scheduled_tasks_emits_code_execution(self) -> None:
        asset = _asset(
            source="claude-desktop-integrations",
            asset_type="claude_desktop_integration",
            current_state={
                "integration_kind": "toggle",
                "integration_name_normalized": "ccdscheduledtasksenabled",
            },
        )
        assert OntologyCategory.CODE_EXECUTION in map_claude_desktop_integration(asset)

    def test_filesystem_access_emits_read_and_write(self) -> None:
        asset = _asset(
            source="claude-desktop-integrations",
            asset_type="claude_desktop_integration",
            current_state={
                "integration_kind": "filesystem_access",
                "filesystem_path": "/Users/foo/Documents",
            },
        )
        result = map_claude_desktop_integration(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in result
        assert OntologyCategory.FILE_SYSTEM_WRITE in result

    def test_unknown_top_level_emits_empty(self) -> None:
        """Forward-compat capture. INFO band per spec §6.5 Q1. UI renders
        as 'Not yet classified' (operator-surprise minimization)."""
        asset = _asset(
            source="claude-desktop-integrations",
            asset_type="claude_desktop_integration",
            current_state={
                "integration_kind": "unknown_top_level",
                "integration_name_normalized": "somenewfeature",
            },
        )
        assert map_claude_desktop_integration(asset) == frozenset()

    def test_unknown_toggle_name_emits_empty(self) -> None:
        """Toggle of an unrecognized name → conservative empty (no tag)."""
        asset = _asset(
            source="claude-desktop-integrations",
            asset_type="claude_desktop_integration",
            current_state={
                "integration_kind": "toggle",
                "integration_name_normalized": "someunknownTogglename",
            },
        )
        assert map_claude_desktop_integration(asset) == frozenset()


# ---------------------------------------------------------------------------
# Cross-cutting — Derived-tag prohibition (AP-2 architect-pass condition)
# ---------------------------------------------------------------------------


# 12 fixtures chosen to exercise non-trivial mapper code paths across the
# 8 Phase-3 sources. Each row produces at least one base tag — i.e., the
# mapper actually runs its body, not the empty-state shortcut.
_POSITIVE_FIXTURES: list[tuple[str, str, dict]] = [
    # vscode-extensions — main + workspace + debug
    ("vscode-extensions", "extension", {"main": "out/x.js", "extension_kind": ["workspace"]}),
    ("vscode-extensions", "extension", {"contributes_debug": True}),
    # chromium-extensions — every major rule chain
    ("chromium-extensions", "extension", {"permissions": ["nativeMessaging"]}),
    ("chromium-extensions", "extension", {"permissions": ["cookies"]}),
    ("chromium-extensions", "extension", {"host_permissions": ["<all_urls>"]}),
    ("chromium-extensions", "extension", {"has_background_service_worker": True}),
    # python-packages + python-project-deps
    ("python-packages", "python_package", {"package_name_normalized": "requests"}),
    ("python-project-deps", "python_dependency", {"package_name_normalized": "boto3"}),
    # node-packages — self + dep paths
    ("node-packages", "node_package", {"dep_kind": "self", "lifecycle_scripts": ["postinstall"]}),
    ("node-packages", "node_package", {"package_name_normalized": "axios", "dep_kind": "dependencies"}),
    # homebrew-ai-tools — AP-4 taxonomy
    ("homebrew-ai-tools", "homebrew_ai_tool", {"match_reason": {"keyword": "ollama", "field": "name"}}),
    # claude-desktop-integrations
    ("claude-desktop-integrations", "claude_desktop_integration", {"integration_kind": "filesystem_access"}),
]


class TestDerivedTagProhibition:
    """**AP-2 architect-pass condition:** the existing parametric test in
    `test_p2_0_ontology_mapping.py` uses `current_state={}` and trivially
    passes for any mapper. These positive-case rows exercise non-empty
    rule paths so the prohibition is actually tested.

    **Invariant:** per-source mappers MUST NOT emit
    ``DATA_EXFILTRATION_CAPABLE`` directly. ``derived.py`` owns the
    derivation (P2.2)."""

    @pytest.mark.parametrize(("source", "asset_type", "current_state"), _POSITIVE_FIXTURES)
    def test_mapper_never_emits_data_exfiltration_capable(
        self, source: str, asset_type: str, current_state: dict
    ) -> None:
        asset = _asset(source=source, asset_type=asset_type, current_state=current_state)
        result = map_asset(asset)
        # The fixture should produce SOME tag (otherwise we're not testing
        # a real code path); guard against the trivial-empty regression.
        assert result != frozenset(), (
            f"fixture {source}/{current_state!r} produced no tags — empty fixtures "
            "pass derived-tag prohibition trivially. Update fixture or mapper."
        )
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE not in result

    @pytest.mark.parametrize(("source", "asset_type", "current_state"), _POSITIVE_FIXTURES)
    def test_mapper_emits_only_base_categories(self, source: str, asset_type: str, current_state: dict) -> None:
        """Stronger invariant: every emitted tag is in BASE_CATEGORIES."""
        asset = _asset(source=source, asset_type=asset_type, current_state=current_state)
        result = map_asset(asset)
        assert result <= BASE_CATEGORIES


# ---------------------------------------------------------------------------
# End-to-end — DATA_EXFILTRATION_CAPABLE derivation
# ---------------------------------------------------------------------------


class TestDataExfiltrationCapableDerivation:
    """Per architect-pass §11 (deliverable #5): a Chrome extension with
    `cookies + <all_urls>` must yield `DATA_EXFILTRATION_CAPABLE` after
    the per-source mapper + derived.py pipeline."""

    def test_cookies_plus_all_urls_derives_exfil(self) -> None:
        """Canonical exfil pattern: secrets_access (cookies) + network_unrestricted (<all_urls>)."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={
                "permissions": ["cookies"],
                "host_permissions": ["<all_urls>"],
            },
        )
        base = map_chromium_extension(asset)
        assert OntologyCategory.SECRETS_ACCESS in base
        assert OntologyCategory.NETWORK_UNRESTRICTED in base
        # Per-source mapper does NOT emit the derived tag (prohibition).
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE not in base
        # derived.py composes the derived tag from the base set.
        full = apply_derived(base)
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE in full

    def test_mcp_simple_non_list_args_does_not_crash(self) -> None:
        """Pre-existing `map_mcp_server_simple` defensive branch: non-list
        ``args`` (corrupt input) → empty args_str fallback, no crash.
        Coverage-ratchet companion: brings the pre-PR-3.8 uncovered line
        up to >= the post-PR coverage threshold."""
        asset = _asset(
            source="mcp-servers",
            asset_type="mcp_server",
            current_state={"command": "node", "args": "not-a-list"},
        )
        result = map_mcp_server_simple(asset)
        # No crash; baseline INTER_TOOL_COMMUNICATION still emitted.
        assert OntologyCategory.INTER_TOOL_COMMUNICATION in result

    def test_filesystem_read_plus_network_derives_exfil(self) -> None:
        """The other branch of the OR: file_system_read + network_unrestricted."""
        asset = _asset(
            source="chromium-extensions",
            asset_type="extension",
            current_state={
                "permissions": ["history"],  # → FILE_SYSTEM_READ
                "host_permissions": ["<all_urls>"],
            },
        )
        base = map_chromium_extension(asset)
        assert OntologyCategory.FILE_SYSTEM_READ in base
        assert OntologyCategory.NETWORK_UNRESTRICTED in base
        full = apply_derived(base)
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE in full
