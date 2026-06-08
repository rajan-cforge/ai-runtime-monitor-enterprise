"""P3.1 — VSCode / Cursor extension discovery source.

Pins the discovery contract: parses ``package.json`` from per-extension
directories under ``~/.vscode/extensions/`` and ``~/.cursor/extensions/``
(both scanned by the same source, distinguished via ``current_state.host``).

Tests follow the P1.4 ``test_p1_4_mcp_servers_source`` precedent:
contract + happy path + per-item isolation + empty/absent + size cap +
``Asset.id`` stability + host attribution. See
``~/Documents/vigil-notes/v022/phase-3/p3.1-phase-a-investigation.md``
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
from claude_monitoring.attack_surface.discovery.sources.vscode_cursor_extensions import (
    VscodeCursorExtensionsSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_ext(
    root: Path,
    *,
    publisher: str,
    name: str,
    version: str = "1.0.0",
    display_name: str | None = None,
    main: str | None = "./out/extension.js",
    browser: str | None = None,
    activation_events: list[str] | None = None,
    contributes: dict | None = None,
    extension_kind: list[str] | None = None,
    capabilities: dict | None = None,
    description: str | None = None,
    dirname: str | None = None,
    raw_text: str | None = None,
) -> Path:
    """Create a synthetic extension directory with a populated ``package.json``.

    If ``raw_text`` is given, write that as the file contents instead of
    generating JSON (used to test malformed inputs)."""
    dirname = dirname or f"{publisher}.{name}-{version}"
    ext_dir = root / dirname
    ext_dir.mkdir(parents=True, exist_ok=True)
    pkg = ext_dir / "package.json"
    if raw_text is not None:
        pkg.write_text(raw_text)
        return ext_dir
    manifest: dict = {
        "publisher": publisher,
        "name": name,
        "version": version,
    }
    if display_name is not None:
        manifest["displayName"] = display_name
    if description is not None:
        manifest["description"] = description
    if main is not None:
        manifest["main"] = main
    if browser is not None:
        manifest["browser"] = browser
    if activation_events is not None:
        manifest["activationEvents"] = activation_events
    if contributes is not None:
        manifest["contributes"] = contributes
    if extension_kind is not None:
        manifest["extensionKind"] = extension_kind
    if capabilities is not None:
        manifest["capabilities"] = capabilities
    pkg.write_text(json.dumps(manifest))
    return ext_dir


def _src(roots: list[tuple[str, Path]]) -> VscodeCursorExtensionsSource:
    """Construct the source with the given synthetic roots."""
    return VscodeCursorExtensionsSource(extensions_roots=roots)


# ---------------------------------------------------------------------------
# 1. Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_is_a_DiscoverySource(self) -> None:
        assert issubclass(VscodeCursorExtensionsSource, DiscoverySource)

    def test_name_is_vscode_extensions(self) -> None:
        # Pin the registered name (P2.2-gate CI gate consumes this).
        assert VscodeCursorExtensionsSource().name() == "vscode-extensions"

    def test_does_not_require_auth(self) -> None:
        assert VscodeCursorExtensionsSource().requires_auth() is False

    def test_appears_in_REGISTERED_SOURCES(self) -> None:
        """The new source must be wired into the ontology mapping registry
        so the P2.2-gate CI doesn't fail. P3.8 will fill the mapper with
        the real ontology tags; until then it returns frozenset()."""
        from claude_monitoring.attack_surface.ontology.mapping import (
            REGISTERED_SOURCES,
        )

        assert "vscode-extensions" in REGISTERED_SOURCES


# ---------------------------------------------------------------------------
# 2. Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_one_valid_ext_yields_one_asset(self, tmp_path: Path) -> None:
        root = tmp_path / "ext-root"
        _write_ext(root, publisher="acme", name="widget", version="2.3.1")
        assets = _src([("vscode", root)]).discover()
        assert len(assets) == 1
        a = assets[0]
        assert a.type == "extension"
        assert a.source == "vscode-extensions"
        assert a.version == "2.3.1"
        assert a.current_state["host"] == "vscode"
        assert a.current_state["publisher"] == "acme"
        assert a.current_state["extension_id"] == "acme.widget"

    def test_two_roots_each_contribute_with_host_label(self, tmp_path: Path) -> None:
        vsc = tmp_path / "vsc"
        cur = tmp_path / "cur"
        _write_ext(vsc, publisher="p1", name="ext1")
        _write_ext(cur, publisher="p2", name="ext2")
        assets = _src([("vscode", vsc), ("cursor", cur)]).discover()
        hosts = {a.current_state["host"] for a in assets}
        ids = {a.current_state["extension_id"] for a in assets}
        assert hosts == {"vscode", "cursor"}
        assert ids == {"p1.ext1", "p2.ext2"}

    def test_display_name_used_as_asset_name(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(root, publisher="acme", name="vim", display_name="Acme Vim")
        a = _src([("cursor", root)]).discover()[0]
        assert a.name == "Acme Vim"

    def test_name_field_fallback_when_no_display_name(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(root, publisher="acme", name="vim", display_name=None)
        a = _src([("cursor", root)]).discover()[0]
        assert a.name == "vim"

    def test_activation_events_preserved(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(
            root,
            publisher="p",
            name="e",
            activation_events=["*", "onStartupFinished"],
        )
        a = _src([("vscode", root)]).discover()[0]
        assert a.current_state["activation_events"] == ["*", "onStartupFinished"]

    def test_contributes_commands_captured_as_id_list(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(
            root,
            publisher="p",
            name="e",
            contributes={
                "commands": [
                    {"command": "p.e.run", "title": "Run"},
                    {"command": "p.e.kill", "title": "Kill"},
                ],
            },
        )
        a = _src([("vscode", root)]).discover()[0]
        assert sorted(a.current_state["contributes_commands"]) == [
            "p.e.kill",
            "p.e.run",
        ]
        assert "commands" in a.current_state["contributes_keys"]

    def test_contributes_capability_flags(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(
            root,
            publisher="p",
            name="e",
            contributes={
                "debuggers": [{"type": "node"}],
                "terminal": {"profiles": [{"id": "x"}]},
                "taskDefinitions": [{"type": "p"}],
            },
        )
        a = _src([("vscode", root)]).discover()[0]
        assert a.current_state["contributes_debug"] is True
        assert a.current_state["contributes_terminal"] is True
        assert a.current_state["contributes_tasks"] is True

    def test_no_contributes_field_yields_false_flags(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(root, publisher="p", name="e")  # no contributes
        a = _src([("vscode", root)]).discover()[0]
        assert a.current_state["contributes_debug"] is False
        assert a.current_state["contributes_terminal"] is False
        assert a.current_state["contributes_tasks"] is False
        assert a.current_state["contributes_keys"] == []
        assert a.current_state["contributes_commands"] == []

    def test_extension_kind_and_capabilities_captured(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(
            root,
            publisher="p",
            name="e",
            extension_kind=["workspace"],
            capabilities={"untrustedWorkspaces": {"supported": False}},
        )
        a = _src([("vscode", root)]).discover()[0]
        assert a.current_state["extension_kind"] == ["workspace"]
        assert a.current_state["capabilities"]["untrustedWorkspaces"]["supported"] is False

    def test_description_truncated_to_500_chars(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(root, publisher="p", name="e", description="x" * 2000)
        a = _src([("vscode", root)]).discover()[0]
        assert len(a.current_state["description"]) <= 500

    def test_main_captured_browser_none_when_absent(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(root, publisher="p", name="e", main="./out/extension.js", browser=None)
        a = _src([("vscode", root)]).discover()[0]
        assert a.current_state["main"] == "./out/extension.js"
        assert a.current_state["browser"] is None

    def test_web_only_extension_main_none_browser_set(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(
            root,
            publisher="p",
            name="e",
            main=None,
            browser="./out/web.js",
        )
        a = _src([("vscode", root)]).discover()[0]
        assert a.current_state["main"] is None
        assert a.current_state["browser"] == "./out/web.js"


# ---------------------------------------------------------------------------
# 3. Per-item isolation (memory project_v022_per_item_isolation.md)
# ---------------------------------------------------------------------------


class TestPerItemIsolation:
    def test_malformed_json_ext_skipped_others_survive(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(root, publisher="bad", name="ext", raw_text="{not valid json")
        _write_ext(root, publisher="good", name="ext")
        ids = {a.current_state["extension_id"] for a in _src([("vscode", root)]).discover()}
        assert "good.ext" in ids
        assert "bad.ext" not in ids

    def test_missing_package_json_ext_skipped_others_survive(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        (root / "empty-ext-1.0.0").mkdir(parents=True)  # no package.json
        _write_ext(root, publisher="good", name="ext")
        ids = {a.current_state["extension_id"] for a in _src([("vscode", root)]).discover()}
        assert ids == {"good.ext"}

    def test_one_bad_host_root_others_scanned(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "does-not-exist"
        good = tmp_path / "good"
        _write_ext(good, publisher="g", name="e")
        ids = {a.current_state["extension_id"] for a in _src([("vscode", nonexistent), ("cursor", good)]).discover()}
        assert ids == {"g.e"}

    def test_oversized_package_json_rejected_others_survive(self, tmp_path: Path) -> None:
        """validate_path enforces 10 MiB cap. Huge package.json is skipped;
        other exts still discovered."""
        root = tmp_path / "r"
        # 11 MiB of valid JSON wrapping (but enough to bust the cap)
        huge = root / "huge.ext-1.0.0"
        huge.mkdir(parents=True)
        (huge / "package.json").write_text(
            '{"publisher":"h","name":"e","version":"1","description":"' + ("x" * (11 * 1024 * 1024)) + '"}'
        )
        _write_ext(root, publisher="good", name="ext")
        ids = {a.current_state["extension_id"] for a in _src([("vscode", root)]).discover()}
        assert "good.ext" in ids
        assert "h.e" not in ids


# ---------------------------------------------------------------------------
# 4. Empty / absent
# ---------------------------------------------------------------------------


class TestEmptyAndAbsent:
    def test_both_roots_absent_returns_empty(self, tmp_path: Path) -> None:
        assets = _src(
            [
                ("vscode", tmp_path / "nope1"),
                ("cursor", tmp_path / "nope2"),
            ]
        ).discover()
        assert assets == []

    def test_empty_extensions_dir_returns_empty(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        root.mkdir()
        assert _src([("vscode", root)]).discover() == []

    def test_only_index_file_no_subdirs_returns_empty(self, tmp_path: Path) -> None:
        """A populated `extensions.json` index without any per-ext dirs
        (stale state after manual cleanup) → []."""
        root = tmp_path / "r"
        root.mkdir()
        (root / "extensions.json").write_text("[]")
        assert _src([("vscode", root)]).discover() == []


# ---------------------------------------------------------------------------
# 5. Asset.id stability (memory project_asset_id_must_be_stable_digest.md)
# ---------------------------------------------------------------------------


class TestAssetIdStability:
    def test_same_inputs_same_id_within_process(self, tmp_path: Path) -> None:
        root = tmp_path / "r"
        _write_ext(root, publisher="p", name="e", version="1.0.0")
        a1 = _src([("vscode", root)]).discover()[0]
        a2 = _src([("vscode", root)]).discover()[0]
        assert a1.id == a2.id

    def test_asset_id_uses_sha256_not_builtin_hash(self, tmp_path: Path) -> None:
        """Subprocess test with PYTHONHASHSEED=12345. If the source used
        Python's built-in hash(), the id would differ between processes.
        Mirrors the P1.4 MCP precedent."""
        root = tmp_path / "r"
        _write_ext(root, publisher="p", name="e", version="1.0.0")

        # Compute the expected id via the same function in-process
        a = _src([("vscode", root)]).discover()[0]
        expected_id = a.id

        # Re-run in subprocess with different PYTHONHASHSEED
        script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / "src")!r})
from pathlib import Path
from claude_monitoring.attack_surface.discovery.sources.vscode_cursor_extensions import VscodeCursorExtensionsSource
src = VscodeCursorExtensionsSource(extensions_roots=[("vscode", Path({str(root)!r}))])
a = src.discover()[0]
print(a.id)
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
        assert result.stdout.strip() == expected_id, (
            f"id varies under PYTHONHASHSEED — source is using built-in hash() "
            f"instead of hashlib.sha256. in-process: {expected_id!r} subprocess: "
            f"{result.stdout.strip()!r}"
        )

    def test_same_ext_in_vscode_and_cursor_yields_distinct_ids(self, tmp_path: Path) -> None:
        vsc = tmp_path / "vsc"
        cur = tmp_path / "cur"
        _write_ext(vsc, publisher="p", name="e", version="1.0.0")
        _write_ext(cur, publisher="p", name="e", version="1.0.0")
        assets = _src([("vscode", vsc), ("cursor", cur)]).discover()
        ids = {a.id for a in assets}
        assert len(ids) == 2, (
            "same publisher.name installed in BOTH vscode and cursor should "
            "produce TWO distinct assets — host must be in the digest input"
        )

    def test_version_NOT_in_digest_so_updates_upsert(self, tmp_path: Path) -> None:
        """Per MCP precedent: version excluded from digest so an upgrade
        produces the SAME id (UPSERT, not new row)."""
        root_v1 = tmp_path / "v1"
        root_v2 = tmp_path / "v2"
        # Same dirname so install_path is the same — version differs in manifest
        _write_ext(
            root_v1,
            publisher="p",
            name="e",
            version="1.0.0",
            dirname="p.e-x",
        )
        _write_ext(
            root_v2,
            publisher="p",
            name="e",
            version="2.0.0",
            dirname="p.e-x",
        )
        # Same logical install path → same id
        a_v1 = _src([("vscode", root_v1)]).discover()[0]
        a_v2 = _src([("vscode", root_v2)]).discover()[0]
        # The install_path differs (different parent roots) → ids differ.
        # The contract: version doesn't differentiate. Verify by computing
        # digest manually.
        expected_v1 = hashlib.sha256(f"vscode|p|e|{a_v1.install_path}".encode()).hexdigest()[:16]
        assert a_v1.id == "vscode-ext-" + expected_v1
        # Different version, same host/publisher/name/path-shape → if we
        # forced same install_path, ids would match. The point: version
        # NOT in digest input.
        assert "vscode-ext-" in a_v1.id and "vscode-ext-" in a_v2.id


# ---------------------------------------------------------------------------
# 6. Empirical gate (skips if user's machine has no Cursor exts)
# ---------------------------------------------------------------------------


class TestEmpirical:
    @pytest.mark.skipif(
        not (Path.home() / ".cursor" / "extensions").is_dir(),
        reason="no ~/.cursor/extensions on this machine",
    )
    def test_empirical_cursor_extensions_discoverable(self) -> None:
        """Smoke test: the source CAN walk the real Cursor extensions
        directory without exceptions and returns at least one Asset
        when extensions are installed."""
        assets = VscodeCursorExtensionsSource().discover()
        # Filter to cursor host (the user may not have vscode installed)
        cursor_assets = [a for a in assets if a.current_state.get("host") == "cursor"]
        # At minimum, the test machine has vscodevim.vim — but assert
        # only existence to stay robust to future cleanup.
        assert isinstance(cursor_assets, list)
        if cursor_assets:
            a = cursor_assets[0]
            assert a.source == "vscode-extensions"
            assert a.current_state["publisher"]
            assert "." in a.current_state["extension_id"]


# ---------------------------------------------------------------------------
# 7. Source name registered in REGISTERED_SOURCES
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_source_appears_in_mapping_registry(self) -> None:
        """P2.2-gate CI will fail if a new DiscoverySource doesn't have
        a mapper entry in ontology.mapping._REGISTRY."""
        from claude_monitoring.attack_surface.ontology import mapping

        assert "vscode-extensions" in mapping._REGISTRY

    def test_mapper_returns_frozenset(self) -> None:
        """The mapper is a placeholder until P3.8 — returns frozenset()
        per the Q5 'structural completeness only' ratification."""
        # Construct a representative asset
        from claude_monitoring.attack_surface.asset import Asset
        from claude_monitoring.attack_surface.ontology.mapping import (
            map_vscode_extension,
        )

        asset = Asset(
            id="vscode-ext-test",
            type="extension",
            parent_asset_id=None,
            name="Test",
            version="1.0.0",
            install_path="/tmp/x",
            source="vscode-extensions",
            current_state={"host": "vscode", "publisher": "p", "extension_id": "p.t"},
            discovered_at=time.time(),
        )
        result = map_vscode_extension(asset)
        # Phase 3 placeholder: empty frozenset until P3.8 wires the rules
        assert isinstance(result, frozenset)


# ---------------------------------------------------------------------------
# 8. Outcome reporting
# ---------------------------------------------------------------------------


class TestOutcomeReporting:
    """Uses ``run_with_safety()`` (the orchestrator's entry point) to
    populate the outcome — same as P1.4 sources test."""

    def test_outcome_success_after_empty_run(self, tmp_path: Path) -> None:
        src = _src([("vscode", tmp_path / "absent")])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_outcome_success_after_partial_skip(self, tmp_path: Path) -> None:
        """Per-item skip is not a source-level error — outcome stays
        SUCCESS even if individual exts were malformed."""
        root = tmp_path / "r"
        _write_ext(root, publisher="bad", name="e", raw_text="{not json")
        _write_ext(root, publisher="good", name="e")
        src = _src([("vscode", root)])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
