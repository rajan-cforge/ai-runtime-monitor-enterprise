"""P3.2 — Chromium-family extension discovery source.

Pins the discovery contract: parses ``manifest.json`` from per-extension
version directories under ``~/Library/Application Support/<browser>/<profile>/Extensions/<ext-id>/<version>_<N>/``
across Chrome / Edge / Brave / Arc (all four are Chromium forks sharing
the identical layout). The source is named ``"chromium-extensions"`` and
distinguishes hosts via ``current_state.browser`` and
``current_state.profile``.

Tests follow the P3.1 ``test_p3_1_vscode_cursor_extensions_source``
precedent with one extra layer of structure (per-browser → per-profile
→ per-extension → per-version) and one extra split (MV2 vs MV3 host
permissions). See
``~/Documents/vigil-notes/v022/phase-3/p3.2-phase-a-investigation.md``
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
from claude_monitoring.attack_surface.discovery.sources.chromium_extensions import (
    ChromiumExtensionsSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_ext(
    browser_root: Path,
    *,
    profile: str = "Default",
    extension_id: str = "abcdefghijklmnopabcdefghijklmnop",
    manifest_version: int = 3,
    name: str = "Test Extension",
    version: str = "1.0.0",
    description: str | None = None,
    permissions: list[str] | None = None,
    host_permissions: list[str] | None = None,
    optional_permissions: list[str] | None = None,
    content_scripts: list[dict] | None = None,
    background: dict | None = None,
    app_background: dict | None = None,
    externally_connectable: dict | None = None,
    oauth2: dict | None = None,
    version_dir: str | None = None,
    extra_version_dirs: list[str] | None = None,
    raw_text: str | None = None,
) -> Path:
    """Create a synthetic chromium extension under a browser root.

    Layout: ``<browser_root>/<profile>/Extensions/<extension_id>/<version_dir>/manifest.json``

    If ``raw_text`` is given, write that to manifest.json instead of
    generating JSON (used to test malformed inputs). The ``version_dir``
    defaults to ``"{version}_0"`` (Chrome's ordinal-suffix convention).

    Returns the ext-id dir (the parent of the version dir)."""
    version_dir = version_dir or f"{version}_0"
    ext_id_dir = browser_root / profile / "Extensions" / extension_id
    v_dir = ext_id_dir / version_dir
    v_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = v_dir / "manifest.json"
    if raw_text is not None:
        manifest_path.write_text(raw_text)
    else:
        manifest: dict = {
            "manifest_version": manifest_version,
            "name": name,
            "version": version,
        }
        if description is not None:
            manifest["description"] = description
        if permissions is not None:
            manifest["permissions"] = permissions
        if host_permissions is not None:
            manifest["host_permissions"] = host_permissions
        if optional_permissions is not None:
            manifest["optional_permissions"] = optional_permissions
        if content_scripts is not None:
            manifest["content_scripts"] = content_scripts
        if background is not None:
            manifest["background"] = background
        if app_background is not None:
            manifest["app"] = {"background": app_background}
        if externally_connectable is not None:
            manifest["externally_connectable"] = externally_connectable
        if oauth2 is not None:
            manifest["oauth2"] = oauth2
        manifest_path.write_text(json.dumps(manifest))
    # Create any sibling version dirs requested (without manifests)
    for extra in extra_version_dirs or []:
        (ext_id_dir / extra).mkdir(parents=True, exist_ok=True)
    return ext_id_dir


def _src(roots: list[tuple[str, Path]]) -> ChromiumExtensionsSource:
    """Construct the source with the given synthetic browser roots."""
    return ChromiumExtensionsSource(browser_roots=roots)


# 32-char a-p lowercase extension ids (Chrome convention)
EID_A = "abcdefghijklmnopabcdefghijklmnop"
EID_B = "ponmlkjihgfedcbaponmlkjihgfedcba"
EID_C = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


# ---------------------------------------------------------------------------
# 1. Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_is_a_DiscoverySource(self) -> None:
        assert issubclass(ChromiumExtensionsSource, DiscoverySource)

    def test_name_is_chromium_extensions(self) -> None:
        # Pin the registered name (P2.2-gate CI gate consumes this).
        assert ChromiumExtensionsSource().name() == "chromium-extensions"

    def test_does_not_require_auth(self) -> None:
        assert ChromiumExtensionsSource().requires_auth() is False

    def test_appears_in_REGISTERED_SOURCES(self) -> None:
        """The new source must be wired into the ontology mapping registry
        so the P2.2-gate CI doesn't fail. P3.8 will fill the mapper with
        the real ontology tags; until then it returns frozenset()."""
        from claude_monitoring.attack_surface.ontology.mapping import (
            REGISTERED_SOURCES,
        )

        assert "chromium-extensions" in REGISTERED_SOURCES


# ---------------------------------------------------------------------------
# 2. Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_one_valid_ext_yields_one_asset(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A, name="Acme", version="2.3.1")
        assets = _src([("chrome", chrome)]).discover()
        assert len(assets) == 1
        a = assets[0]
        assert a.type == "extension"
        assert a.source == "chromium-extensions"
        assert a.version == "2.3.1"
        assert a.current_state["browser"] == "chrome"
        assert a.current_state["profile"] == "Default"
        assert a.current_state["extension_id"] == EID_A

    def test_multiple_profiles_each_contribute(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, profile="Default", extension_id=EID_A)
        _write_ext(chrome, profile="Profile 1", extension_id=EID_B)
        assets = _src([("chrome", chrome)]).discover()
        profiles = {a.current_state["profile"] for a in assets}
        ext_ids = {a.current_state["extension_id"] for a in assets}
        assert profiles == {"Default", "Profile 1"}
        assert ext_ids == {EID_A, EID_B}

    def test_multiple_browsers_each_contribute(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        brave = tmp_path / "Brave"
        _write_ext(chrome, extension_id=EID_A)
        _write_ext(brave, extension_id=EID_B)
        assets = _src([("chrome", chrome), ("brave", brave)]).discover()
        browsers = {a.current_state["browser"] for a in assets}
        assert browsers == {"chrome", "brave"}

    def test_mv3_permissions_and_host_permissions_captured(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(
            chrome,
            extension_id=EID_A,
            manifest_version=3,
            permissions=["tabs", "cookies", "nativeMessaging"],
            host_permissions=["<all_urls>", "https://example.com/*"],
        )
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.current_state["manifest_version"] == 3
        assert sorted(a.current_state["permissions"]) == ["cookies", "nativeMessaging", "tabs"]
        assert sorted(a.current_state["host_permissions"]) == ["<all_urls>", "https://example.com/*"]
        assert a.current_state["mv2_host_permissions"] == []

    def test_mv2_url_patterns_split_into_mv2_host_permissions(self, tmp_path: Path) -> None:
        """MV2 puts URL patterns inline with API permissions.
        The source MUST split them: API strings → permissions;
        entries containing '://' or '*' → mv2_host_permissions."""
        chrome = tmp_path / "Chrome"
        _write_ext(
            chrome,
            extension_id=EID_A,
            manifest_version=2,
            permissions=[
                "identity",
                "tabs",
                "https://www.googleapis.com/*",
                "https://accounts.google.com/*",
                "<all_urls>",
            ],
        )
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.current_state["manifest_version"] == 2
        assert sorted(a.current_state["permissions"]) == ["identity", "tabs"]
        assert sorted(a.current_state["mv2_host_permissions"]) == [
            "<all_urls>",
            "https://accounts.google.com/*",
            "https://www.googleapis.com/*",
        ]

    def test_content_scripts_matches_flattened_and_deduped(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(
            chrome,
            extension_id=EID_A,
            content_scripts=[
                {"matches": ["https://a.com/*", "https://b.com/*"]},
                {"matches": ["https://a.com/*", "<all_urls>"]},
            ],
        )
        a = _src([("chrome", chrome)]).discover()[0]
        assert sorted(a.current_state["content_scripts_matches"]) == [
            "<all_urls>",
            "https://a.com/*",
            "https://b.com/*",
        ]

    def test_mv3_background_service_worker_flag(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(
            chrome,
            extension_id=EID_A,
            manifest_version=3,
            background={"service_worker": "sw.js"},
        )
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.current_state["has_background_service_worker"] is True
        assert a.current_state["has_background_scripts"] is False

    def test_mv2_background_scripts_flag(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(
            chrome,
            extension_id=EID_A,
            manifest_version=2,
            background={"scripts": ["bg.js"], "persistent": False},
        )
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.current_state["has_background_service_worker"] is False
        assert a.current_state["has_background_scripts"] is True

    def test_no_background_yields_both_false(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A)
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.current_state["has_background_service_worker"] is False
        assert a.current_state["has_background_scripts"] is False

    def test_description_truncated_to_500_chars(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A, description="x" * 2000)
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.current_state["description"] is not None
        assert len(a.current_state["description"]) <= 500

    def test_multiple_version_dirs_take_latest(self, tmp_path: Path) -> None:
        """Chrome keeps prior versions during update. Source must take the
        latest version dir that has a manifest.json."""
        chrome = tmp_path / "Chrome"
        ext_id_dir = chrome / "Default" / "Extensions" / EID_A
        # Two version dirs both with manifests; latest should win.
        for ver_dir, ver in [("1.0.70_0", "1.0.70"), ("1.0.75_0", "1.0.75")]:
            v = ext_id_dir / ver_dir
            v.mkdir(parents=True)
            (v / "manifest.json").write_text(json.dumps({"manifest_version": 3, "name": "Multi", "version": ver}))
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.version == "1.0.75"

    def test_i18n_msg_name_preserved_as_is(self, tmp_path: Path) -> None:
        """Some Chrome extensions use __MSG_*__ i18n placeholders for name.
        Store as-is; the extension_id is the stable identity anyway."""
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A, name="__MSG_APP_NAME__")
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.name == "__MSG_APP_NAME__"

    def test_install_path_is_ext_id_dir_not_version_subdir(self, tmp_path: Path) -> None:
        """install_path must be stable across version updates.
        It points at the ext-id directory, not the version subdir."""
        chrome = tmp_path / "Chrome"
        ext_id_dir = _write_ext(chrome, extension_id=EID_A, version_dir="1.0.0_0")
        a = _src([("chrome", chrome)]).discover()[0]
        assert a.install_path == str(ext_id_dir)
        assert not a.install_path.endswith("1.0.0_0")


# ---------------------------------------------------------------------------
# 3. Per-item isolation (THREE layers — memory project_v022_per_item_isolation.md)
# ---------------------------------------------------------------------------


class TestPerItemIsolation:
    def test_malformed_json_ext_skipped_others_survive(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A, raw_text="{not valid json")
        _write_ext(chrome, extension_id=EID_B)
        ids = {a.current_state["extension_id"] for a in _src([("chrome", chrome)]).discover()}
        assert EID_B in ids
        assert EID_A not in ids

    def test_ext_id_dir_with_no_version_subdir_skipped(self, tmp_path: Path) -> None:
        """An empty ext-id directory (no version subdir, no manifest)
        is skipped without affecting siblings."""
        chrome = tmp_path / "Chrome"
        (chrome / "Default" / "Extensions" / EID_A).mkdir(parents=True)
        _write_ext(chrome, extension_id=EID_B)
        ids = {a.current_state["extension_id"] for a in _src([("chrome", chrome)]).discover()}
        assert ids == {EID_B}

    def test_one_bad_browser_root_others_scanned(self, tmp_path: Path) -> None:
        """Per-browser-root isolation — first layer."""
        nonexistent = tmp_path / "Edge-not-installed"
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A)
        ids = {a.current_state["extension_id"] for a in _src([("edge", nonexistent), ("chrome", chrome)]).discover()}
        assert ids == {EID_A}

    def test_one_bad_profile_others_scanned(self, tmp_path: Path) -> None:
        """Per-profile isolation — second layer.
        A profile dir without Extensions/ does not block the sibling profile."""
        chrome = tmp_path / "Chrome"
        (chrome / "Profile 99").mkdir(parents=True)  # no Extensions subdir
        _write_ext(chrome, profile="Default", extension_id=EID_A)
        ids = {a.current_state["extension_id"] for a in _src([("chrome", chrome)]).discover()}
        assert ids == {EID_A}

    def test_oversized_manifest_rejected_others_survive(self, tmp_path: Path) -> None:
        """validate_path enforces 10 MiB cap. Huge manifest.json is skipped;
        sibling exts still emit."""
        chrome = tmp_path / "Chrome"
        huge_dir = chrome / "Default" / "Extensions" / EID_A / "1.0.0_0"
        huge_dir.mkdir(parents=True)
        (huge_dir / "manifest.json").write_text(
            '{"manifest_version":3,"name":"H","version":"1","description":"' + ("x" * (11 * 1024 * 1024)) + '"}'
        )
        _write_ext(chrome, extension_id=EID_B)
        ids = {a.current_state["extension_id"] for a in _src([("chrome", chrome)]).discover()}
        assert EID_B in ids
        assert EID_A not in ids


# ---------------------------------------------------------------------------
# 4. Empty / absent
# ---------------------------------------------------------------------------


class TestEmptyAndAbsent:
    def test_all_browser_roots_absent_returns_empty(self, tmp_path: Path) -> None:
        assets = _src(
            [
                ("chrome", tmp_path / "nope1"),
                ("edge", tmp_path / "nope2"),
                ("brave", tmp_path / "nope3"),
                ("arc", tmp_path / "nope4"),
            ]
        ).discover()
        assert assets == []

    def test_empty_extensions_dir_returns_empty(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        (chrome / "Default" / "Extensions").mkdir(parents=True)
        assert _src([("chrome", chrome)]).discover() == []

    def test_browser_root_with_no_profile_dirs_returns_empty(self, tmp_path: Path) -> None:
        """Empirically Edge/Brave on this machine: browser root has only
        NativeMessagingHosts/ (no Default/ profile). Source must return []."""
        chrome = tmp_path / "Chrome"
        (chrome / "NativeMessagingHosts").mkdir(parents=True)
        assert _src([("chrome", chrome)]).discover() == []


# ---------------------------------------------------------------------------
# 5. Asset.id stability (memory project_asset_id_must_be_stable_digest.md)
# ---------------------------------------------------------------------------


class TestAssetIdStability:
    def test_same_inputs_same_id_within_process(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A, version="1.0.0")
        a1 = _src([("chrome", chrome)]).discover()[0]
        a2 = _src([("chrome", chrome)]).discover()[0]
        assert a1.id == a2.id
        assert a1.id.startswith("chrome-ext-")

    def test_asset_id_uses_sha256_not_builtin_hash(self, tmp_path: Path) -> None:
        """Subprocess test with PYTHONHASHSEED=12345. If the source used
        Python's built-in hash(), the id would differ between processes.
        Mirrors the P3.1 precedent."""
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A, version="1.0.0")

        a = _src([("chrome", chrome)]).discover()[0]
        expected_id = a.id

        script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / "src")!r})
from pathlib import Path
from claude_monitoring.attack_surface.discovery.sources.chromium_extensions import ChromiumExtensionsSource
src = ChromiumExtensionsSource(browser_roots=[("chrome", Path({str(chrome)!r}))])
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

    def test_same_ext_in_two_profiles_yields_distinct_ids(self, tmp_path: Path) -> None:
        """Same extension installed in Default + Profile 1 → two distinct
        assets (separate installations on disk)."""
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, profile="Default", extension_id=EID_A)
        _write_ext(chrome, profile="Profile 1", extension_id=EID_A)
        ids = {a.id for a in _src([("chrome", chrome)]).discover()}
        assert len(ids) == 2, (
            "same extension_id installed in BOTH profiles should produce TWO "
            "distinct assets — profile must be in the digest input"
        )

    def test_same_ext_in_two_browsers_yields_distinct_ids(self, tmp_path: Path) -> None:
        chrome = tmp_path / "Chrome"
        brave = tmp_path / "Brave"
        _write_ext(chrome, extension_id=EID_A)
        _write_ext(brave, extension_id=EID_A)
        ids = {a.id for a in _src([("chrome", chrome), ("brave", brave)]).discover()}
        assert len(ids) == 2

    def test_version_NOT_in_digest_so_updates_upsert(self, tmp_path: Path) -> None:
        """Per MCP + P3.1 precedent: version excluded from digest so an
        upgrade produces the SAME id. Two version dirs under the same
        ext-id → install_path stays at the ext-id dir, so id is stable."""
        chrome = tmp_path / "Chrome"
        ext_id_dir = chrome / "Default" / "Extensions" / EID_A
        for ver_dir, ver in [("1.0.0_0", "1.0.0"), ("2.0.0_0", "2.0.0")]:
            v = ext_id_dir / ver_dir
            v.mkdir(parents=True)
            (v / "manifest.json").write_text(json.dumps({"manifest_version": 3, "name": "T", "version": ver}))
        a = _src([("chrome", chrome)]).discover()[0]
        # Compute expected id manually — version not part of digest
        expected = hashlib.sha256(f"chrome|Default|{EID_A}|{ext_id_dir}".encode()).hexdigest()[:16]
        assert a.id == "chrome-ext-" + expected
        # latest version was selected
        assert a.version == "2.0.0"


# ---------------------------------------------------------------------------
# 6. Empirical gate (skips if user's machine has no Chrome ext)
# ---------------------------------------------------------------------------


class TestEmpirical:
    @pytest.mark.skipif(
        not (Path.home() / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Extensions").is_dir(),
        reason="no Chrome extensions on this machine",
    )
    def test_empirical_chrome_extensions_discoverable(self) -> None:
        """Smoke test: the source CAN walk the real Chrome extensions
        directory without exceptions and returns at least one Asset
        when extensions are installed."""
        assets = ChromiumExtensionsSource().discover()
        chrome_assets = [a for a in assets if a.current_state.get("browser") == "chrome"]
        assert isinstance(chrome_assets, list)
        if chrome_assets:
            a = chrome_assets[0]
            assert a.source == "chromium-extensions"
            assert len(a.current_state["extension_id"]) == 32
            assert a.id.startswith("chrome-ext-")


# ---------------------------------------------------------------------------
# 7. Registration in REGISTERED_SOURCES (P2.2-gate)
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_source_appears_in_mapping_registry(self) -> None:
        """P2.2-gate CI will fail if a new DiscoverySource doesn't have
        a mapper entry in ontology.mapping._REGISTRY."""
        from claude_monitoring.attack_surface.ontology import mapping

        assert "chromium-extensions" in mapping._REGISTRY

    def test_mapper_returns_frozenset(self) -> None:
        """The mapper is a placeholder until P3.8 — returns frozenset()
        per the Q5 'structural completeness only' ratification."""
        from claude_monitoring.attack_surface.asset import Asset
        from claude_monitoring.attack_surface.ontology.mapping import (
            map_chromium_extension,
        )

        asset = Asset(
            id="chrome-ext-test",
            type="extension",
            parent_asset_id=None,
            name="Test",
            version="1.0.0",
            install_path="/tmp/x",
            source="chromium-extensions",
            current_state={
                "browser": "chrome",
                "profile": "Default",
                "extension_id": EID_A,
            },
            discovered_at=time.time(),
        )
        result = map_chromium_extension(asset)
        assert isinstance(result, frozenset)


# ---------------------------------------------------------------------------
# 8. Outcome reporting
# ---------------------------------------------------------------------------


class TestOutcomeReporting:
    """Uses ``run_with_safety()`` (the orchestrator's entry point) to
    populate the outcome — same as P3.1 / P1.4 sources test."""

    def test_outcome_success_after_empty_run(self, tmp_path: Path) -> None:
        src = _src([("chrome", tmp_path / "absent")])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_outcome_success_after_partial_skip(self, tmp_path: Path) -> None:
        """Per-item skip is not a source-level error — outcome stays
        SUCCESS even if individual exts were malformed."""
        chrome = tmp_path / "Chrome"
        _write_ext(chrome, extension_id=EID_A, raw_text="{not json")
        _write_ext(chrome, extension_id=EID_B)
        src = _src([("chrome", chrome)])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
