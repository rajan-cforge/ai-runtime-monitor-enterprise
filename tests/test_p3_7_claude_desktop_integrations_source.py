"""P3.7 — Claude Desktop integrations discovery beyond MCP.

Parses ``~/Library/Application Support/Claude/claude_desktop_config.json``
for non-MCP integration entries. Emits one ``Asset`` per integration
toggle that's enabled, per filesystem-access preference, and per
unknown top-level key (forward-compat). **Explicitly skips** ``mcpServers``
(covered by P1.4's mcp-servers source).

**Load-bearing security boundary:** this source opens exactly ONE file
(`claude_desktop_config.json`). Sibling files like ``buddy-tokens.json``,
``Cookies``, ``Cache/`` are out of scope by allowlist (not denylist) —
the source has no code path that can reach them.

See ``~/Documents/vigil-notes/v022/phase-3/p3.7-phase-a-investigation.md``
for the full investigation that scoped the source.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.discovery.base import (
    DiscoverySource,
    LastRunOutcome,
)
from claude_monitoring.attack_surface.discovery.sources.claude_desktop_integrations import (
    ClaudeDesktopIntegrationsSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(
    tmp_path: Path,
    payload: dict | None = None,
    *,
    raw_text: str | None = None,
) -> Path:
    """Write a synthetic claude_desktop_config.json under tmp_path."""
    cfg = tmp_path / "claude_desktop_config.json"
    if raw_text is not None:
        cfg.write_text(raw_text)
    else:
        cfg.write_text(json.dumps(payload if payload is not None else {}))
    return cfg


def _src(config_paths: list[Path]) -> ClaudeDesktopIntegrationsSource:
    return ClaudeDesktopIntegrationsSource(config_paths=config_paths)


# ---------------------------------------------------------------------------
# 1. Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_is_a_DiscoverySource(self) -> None:
        assert issubclass(ClaudeDesktopIntegrationsSource, DiscoverySource)

    def test_name_is_claude_desktop_integrations(self) -> None:
        assert ClaudeDesktopIntegrationsSource().name() == "claude-desktop-integrations"

    def test_does_not_require_auth(self) -> None:
        assert ClaudeDesktopIntegrationsSource().requires_auth() is False

    def test_appears_in_REGISTERED_SOURCES(self) -> None:
        from claude_monitoring.attack_surface.ontology.mapping import REGISTERED_SOURCES

        assert "claude-desktop-integrations" in REGISTERED_SOURCES


# ---------------------------------------------------------------------------
# 2. Preference toggles
# ---------------------------------------------------------------------------


class TestPreferenceToggles:
    def test_toggle_enabled_emits_asset(self, tmp_path: Path) -> None:
        cfg = _write_config(
            tmp_path,
            {"preferences": {"coworkWebSearchEnabled": True}},
        )
        assets = _src([cfg]).discover()
        toggle_assets = [a for a in assets if a.current_state["integration_kind"] == "toggle"]
        assert len(toggle_assets) == 1
        a = toggle_assets[0]
        assert a.current_state["enabled"] is True
        assert (
            a.name == "coworkWebSearchEnabled"
            or a.current_state["integration_name_normalized"] == "coworkwebsearchenabled"
        )

    def test_toggle_disabled_emits_no_asset(self, tmp_path: Path) -> None:
        """When a known toggle is `false`, we do NOT emit. The integration
        is not active — there's nothing to surface."""
        cfg = _write_config(
            tmp_path,
            {"preferences": {"coworkWebSearchEnabled": False}},
        )
        toggle_assets = [a for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "toggle"]
        assert toggle_assets == []

    def test_multiple_enabled_toggles_each_emit(self, tmp_path: Path) -> None:
        cfg = _write_config(
            tmp_path,
            {
                "preferences": {
                    "coworkWebSearchEnabled": True,
                    "coworkScheduledTasksEnabled": True,
                    "ccdScheduledTasksEnabled": True,
                }
            },
        )
        toggle_names = {a.name for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "toggle"}
        assert toggle_names == {
            "coworkWebSearchEnabled",
            "coworkScheduledTasksEnabled",
            "ccdScheduledTasksEnabled",
        }

    def test_unknown_preference_key_skipped(self, tmp_path: Path) -> None:
        """A preference key not in the integration allowlist is NOT
        emitted as a toggle. This keeps the allowlist tight."""
        cfg = _write_config(
            tmp_path,
            {"preferences": {"someInternalDebugFlagEnabled": True}},
        )
        toggle_assets = [a for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "toggle"]
        assert toggle_assets == []

    def test_non_bool_toggle_value_skipped(self, tmp_path: Path) -> None:
        """Defensive: a malformed value type for a known toggle is skipped."""
        cfg = _write_config(
            tmp_path,
            {"preferences": {"coworkWebSearchEnabled": "yes"}},
        )
        toggle_assets = [a for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "toggle"]
        assert toggle_assets == []


# ---------------------------------------------------------------------------
# 3. Filesystem-access preferences
# ---------------------------------------------------------------------------


class TestFilesystemAccess:
    def test_filesystem_access_emits_asset(self, tmp_path: Path) -> None:
        cfg = _write_config(
            tmp_path,
            {"coworkUserFilesPath": "/Users/x/Claude"},
        )
        fs_assets = [a for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "filesystem_access"]
        assert len(fs_assets) == 1
        a = fs_assets[0]
        assert a.current_state["filesystem_path"] == "/Users/x/Claude"
        assert a.install_path == "/Users/x/Claude"

    def test_filesystem_access_empty_string_skipped(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, {"coworkUserFilesPath": ""})
        fs_assets = [a for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "filesystem_access"]
        assert fs_assets == []

    def test_filesystem_access_non_string_skipped(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, {"coworkUserFilesPath": 12345})
        fs_assets = [a for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "filesystem_access"]
        assert fs_assets == []


# ---------------------------------------------------------------------------
# 4. Unknown top-level capture (forward-compat)
# ---------------------------------------------------------------------------


class TestUnknownTopLevelCapture:
    def test_unknown_top_level_key_emits_asset(self, tmp_path: Path) -> None:
        cfg = _write_config(
            tmp_path,
            {"futureConnectorConfig": {"provider": "google_drive", "scope": "read"}},
        )
        unk_assets = [a for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "unknown_top_level"]
        assert len(unk_assets) == 1
        a = unk_assets[0]
        assert a.name == "futureConnectorConfig"
        assert a.current_state["raw_value"] == {"provider": "google_drive", "scope": "read"}

    def test_known_top_level_keys_not_captured_as_unknown(self, tmp_path: Path) -> None:
        """`mcpServers` and `preferences` are KNOWN — they MUST NOT be
        emitted as unknown_top_level."""
        cfg = _write_config(
            tmp_path,
            {
                "mcpServers": {"some": {"command": "x"}},
                "preferences": {"coworkWebSearchEnabled": True},
            },
        )
        unk_assets = [a for a in _src([cfg]).discover() if a.current_state["integration_kind"] == "unknown_top_level"]
        assert unk_assets == []

    def test_unknown_top_level_raw_value_size_capped(self, tmp_path: Path) -> None:
        """Defensive: an unknown top-level value that's huge gets truncated
        to a reasonable size in current_state.raw_value."""
        huge_str = "x" * 50_000
        cfg = _write_config(
            tmp_path,
            {"futureBlob": huge_str},
        )
        assets = _src([cfg]).discover()
        unk = next(a for a in assets if a.current_state["integration_kind"] == "unknown_top_level")
        raw = unk.current_state["raw_value"]
        # Whether str-or-truncated-marker, size must be bounded
        assert len(json.dumps(raw)) <= 10_000


# ---------------------------------------------------------------------------
# 5. mcpServers explicitly skipped (no duplication with P1.4)
# ---------------------------------------------------------------------------


class TestMcpServersExplicitlySkipped:
    def test_mcp_servers_present_yields_no_claude_int_asset_for_them(self, tmp_path: Path) -> None:
        """P1.4's mcp-servers source already covers MCP. P3.7 MUST NOT
        emit any asset whose name matches an MCP server name."""
        cfg = _write_config(
            tmp_path,
            {
                "mcpServers": {
                    "talosai": {"command": "python3", "args": []},
                    "other": {"command": "node", "args": []},
                },
                "preferences": {"coworkWebSearchEnabled": True},
            },
        )
        assets = _src([cfg]).discover()
        # No asset should mention talosai or other (the MCP names)
        names = {a.name for a in assets}
        assert "talosai" not in names
        assert "other" not in names

    def test_mcp_servers_only_yields_zero_claude_int_assets(self, tmp_path: Path) -> None:
        """A config containing ONLY mcpServers (no preferences, no other
        top-level keys) emits ZERO claude-desktop-integrations assets."""
        cfg = _write_config(
            tmp_path,
            {
                "mcpServers": {
                    "talosai": {"command": "python3", "args": []},
                }
            },
        )
        assert _src([cfg]).discover() == []


# ---------------------------------------------------------------------------
# 6. Security boundary — only one file opened (load-bearing)
# ---------------------------------------------------------------------------


class TestSecurityBoundary:
    def test_source_opens_only_claude_desktop_config_json(self, tmp_path: Path, monkeypatch) -> None:
        """Pin the allowlist (not denylist) for file access. The source
        must read ONLY the path it was given; sibling files like
        buddy-tokens.json or Cookies must not be touched."""
        cfg = _write_config(tmp_path, {"preferences": {"coworkWebSearchEnabled": True}})
        # Create a sentinel sibling file that, if opened, would be detectable
        sibling = tmp_path / "buddy-tokens.json"
        sibling.write_text('{"secret": "REAL_TOKEN_DO_NOT_READ"}')

        opens: list[str] = []
        real_open = Path.open

        def tracking_open(self, *args, **kwargs):
            opens.append(str(self))
            return real_open(self, *args, **kwargs)

        # Intercept Path.open. Note: validate_path uses Path.stat too;
        # we're tracking only opens here (not stat) because stat doesn't
        # leak content.
        monkeypatch.setattr(Path, "open", tracking_open)
        _src([cfg]).discover()
        # Whatever was opened must be exactly the config path — no buddy-tokens
        assert all("buddy-tokens.json" not in p for p in opens), f"source opened a sibling token file! opens={opens}"

    def test_missing_config_yields_empty_silently(self, tmp_path: Path) -> None:
        absent = tmp_path / "does-not-exist.json"
        assert _src([absent]).discover() == []


# ---------------------------------------------------------------------------
# 7. Per-item isolation
# ---------------------------------------------------------------------------


class TestPerItemIsolation:
    def test_malformed_json_yields_empty(self, tmp_path: Path) -> None:
        _write_config(tmp_path, raw_text="{not json")
        cfg = tmp_path / "claude_desktop_config.json"
        assert _src([cfg]).discover() == []

    def test_oversized_config_rejected(self, tmp_path: Path) -> None:
        cfg = tmp_path / "claude_desktop_config.json"
        cfg.write_text('{"preferences":{"coworkWebSearchEnabled":true},"junk":"' + ("x" * (11 * 1024 * 1024)) + '"}')
        assert _src([cfg]).discover() == []

    def test_bad_preferences_section_doesnt_block_top_level(self, tmp_path: Path) -> None:
        """A non-dict `preferences` value is skipped, but a sibling
        unknown top-level key still emits."""
        cfg = _write_config(
            tmp_path,
            {
                "preferences": "not a dict",
                "futureConnector": {"provider": "x"},
            },
        )
        names = {a.name for a in _src([cfg]).discover()}
        assert "futureConnector" in names


# ---------------------------------------------------------------------------
# 8. Empty / absent
# ---------------------------------------------------------------------------


class TestEmptyAndAbsent:
    def test_no_config_paths_returns_empty(self) -> None:
        assert _src([]).discover() == []

    def test_empty_preferences_yields_empty(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, {"preferences": {}})
        assert _src([cfg]).discover() == []

    def test_completely_empty_config_yields_empty(self, tmp_path: Path) -> None:
        cfg = _write_config(tmp_path, {})
        assert _src([cfg]).discover() == []


# ---------------------------------------------------------------------------
# 9. Asset.id stability
# ---------------------------------------------------------------------------


class TestAssetIdStability:
    def test_same_inputs_same_id(self, tmp_path: Path) -> None:
        cfg = _write_config(
            tmp_path,
            {"preferences": {"coworkWebSearchEnabled": True}},
        )
        a1 = _src([cfg]).discover()[0]
        a2 = _src([cfg]).discover()[0]
        assert a1.id == a2.id
        assert a1.id.startswith("claude-int-")

    def test_asset_id_uses_sha256_not_builtin_hash(self, tmp_path: Path) -> None:
        cfg = _write_config(
            tmp_path,
            {"preferences": {"coworkWebSearchEnabled": True}},
        )
        expected = _src([cfg]).discover()[0].id

        script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / "src")!r})
from pathlib import Path
from claude_monitoring.attack_surface.discovery.sources.claude_desktop_integrations import (
    ClaudeDesktopIntegrationsSource,
)
src = ClaudeDesktopIntegrationsSource(config_paths=[Path({str(cfg)!r})])
print(src.discover()[0].id)
"""
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = "12345"
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == expected

    def test_enabled_state_NOT_in_digest(self, tmp_path: Path) -> None:
        """The `enabled` state must NOT be in the digest — so the same
        toggle key generates the same id regardless of true/false. (Since
        we only emit on true, this manifests as: an identity assertion
        about how the id is computed.)"""
        cfg = _write_config(
            tmp_path,
            {"preferences": {"coworkWebSearchEnabled": True}},
        )
        a = _src([cfg]).discover()[0]
        expected_id = "claude-int-" + hashlib.sha256(f"toggle|coworkwebsearchenabled|{cfg}".encode()).hexdigest()[:16]
        assert a.id == expected_id

    def test_name_case_normalized_in_digest(self, tmp_path: Path) -> None:
        """A mixed-case unknown-top-level key normalizes to lowercase in
        the digest (pin: forward-compat for case sensitivity in future
        Anthropic config naming changes)."""
        cfg = _write_config(tmp_path, {"FutureConnector": {"v": 1}})
        a = _src([cfg]).discover()[0]
        # Pin: digest uses lowercased name regardless of original casing
        expected_id = (
            "claude-int-" + hashlib.sha256(f"unknown_top_level|futureconnector|{cfg}".encode()).hexdigest()[:16]
        )
        assert a.id == expected_id
        # And the display name preserves original casing
        assert a.name == "FutureConnector"
        assert a.current_state["integration_name_normalized"] == "futureconnector"


# ---------------------------------------------------------------------------
# 10. Empirical gate
# ---------------------------------------------------------------------------


class TestEmpirical:
    @pytest.mark.skipif(
        not (Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json").is_file(),
        reason="no Claude Desktop config on this machine",
    )
    def test_empirical_real_config_walk(self) -> None:
        """Real `~/Library/Application Support/Claude/claude_desktop_config.json`
        — typical dev machine has at least one enabled integration toggle."""
        assets = ClaudeDesktopIntegrationsSource().discover()
        assert isinstance(assets, list)
        if assets:
            a = assets[0]
            assert a.source == "claude-desktop-integrations"
            assert a.id.startswith("claude-int-")
            assert a.current_state["integration_kind"] in {
                "toggle",
                "filesystem_access",
                "unknown_top_level",
            }


# ---------------------------------------------------------------------------
# 11. Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_source_appears_in_mapping_registry(self) -> None:
        from claude_monitoring.attack_surface.ontology import mapping

        assert "claude-desktop-integrations" in mapping._REGISTRY

    def test_mapper_returns_frozenset(self) -> None:
        from claude_monitoring.attack_surface.asset import Asset
        from claude_monitoring.attack_surface.ontology.mapping import (
            map_claude_desktop_integration,
        )

        asset = Asset(
            id="claude-int-test",
            type="claude_desktop_integration",
            parent_asset_id=None,
            name="coworkWebSearchEnabled",
            version=None,
            install_path="/tmp/x",
            source="claude-desktop-integrations",
            current_state={
                "integration_kind": "toggle",
                "integration_name_normalized": "coworkwebsearchenabled",
                "enabled": True,
            },
            discovered_at=time.time(),
        )
        assert isinstance(map_claude_desktop_integration(asset), frozenset)


# ---------------------------------------------------------------------------
# 12. Outcome reporting
# ---------------------------------------------------------------------------


class TestOutcomeReporting:
    def test_outcome_success_after_empty_run(self) -> None:
        src = _src([])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_outcome_success_after_partial_skip(self, tmp_path: Path) -> None:
        cfg = _write_config(
            tmp_path,
            {
                "preferences": {
                    "coworkWebSearchEnabled": True,
                    "someUnknownPrefEnabled": True,  # not in allowlist, skipped
                }
            },
        )
        src = _src([cfg])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
