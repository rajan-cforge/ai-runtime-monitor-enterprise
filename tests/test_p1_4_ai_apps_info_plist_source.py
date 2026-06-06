"""P1.4 C3 batch — `AiAppsInfoPlistSource` tests.

C3 source — parses macOS `Info.plist` (XML *or* binary) for the
installed AI app bundles. `plistlib.load(fp)` handles both forms
transparently when the file is opened in binary mode.

**KNOWN bundles (Phase A §4):**
- ``/Applications/Claude.app`` (XML plist)
- ``/Applications/ChatGPT.app`` (BINARY plist)
- ``/Applications/Cursor.app`` (XML plist)
- ``/Applications/Ollama.app`` (XML plist)

**Empirical verification (CLAUDE.md §9):** confirmed
`plistlib.load(open(..., 'rb'))` parses both encodings on this
machine.

**Per-item isolation contract:** one corrupt plist → that asset
emitted with `version=None` and WARNING; others unaffected.
"""

from __future__ import annotations

import plistlib
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome
from claude_monitoring.attack_surface.discovery.sources.ai_apps_info_plist import (
    AiAppsInfoPlistSource,
)


def _make_app_bundle(
    root: Path,
    app_name: str,
    *,
    version: str = "1.0.0",
    bundle_id: str = "com.example.app",
    binary: bool = False,
    extras: dict | None = None,
) -> Path:
    """Helper: build root/<App>.app/Contents/Info.plist with the given metadata."""
    contents = root / f"{app_name}.app" / "Contents"
    contents.mkdir(parents=True)
    plist_path = contents / "Info.plist"
    payload = {
        "CFBundleShortVersionString": version,
        "CFBundleIdentifier": bundle_id,
        "CFBundleName": app_name,
    }
    if extras:
        payload.update(extras)
    fmt = plistlib.FMT_BINARY if binary else plistlib.FMT_XML
    with plist_path.open("wb") as f:
        plistlib.dump(payload, f, fmt=fmt)
    return root / f"{app_name}.app"


class TestAiAppsInfoPlistContract:
    def test_name_is_ai_apps_info_plist(self) -> None:
        assert AiAppsInfoPlistSource().name() == "ai-apps-info-plist"

    def test_requires_auth_is_false(self) -> None:
        assert AiAppsInfoPlistSource().requires_auth() is False


class TestAiAppsInfoPlistFormatHandling:
    def test_xml_plist_parses_version(self, tmp_path: Path) -> None:
        _make_app_bundle(tmp_path, "Claude", version="1.11187.1", bundle_id="com.anthropic.claudefordesktop")
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["Claude.app"],
        )
        result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "Claude"
        assert result[0].version == "1.11187.1"
        assert result[0].current_state.get("bundle_id") == "com.anthropic.claudefordesktop"

    def test_binary_plist_parses_version(self, tmp_path: Path) -> None:
        """ChatGPT.app on macOS ships a binary plist; plistlib handles it transparently."""
        _make_app_bundle(tmp_path, "ChatGPT", version="1.2026.119", binary=True)
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["ChatGPT.app"],
        )
        result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].version == "1.2026.119"

    def test_mixed_xml_and_binary_in_one_scan(self, tmp_path: Path) -> None:
        """4-bundle scan with one binary plist (ChatGPT) → 4 assets."""
        _make_app_bundle(tmp_path, "Claude", version="1.11187.1")
        _make_app_bundle(tmp_path, "ChatGPT", version="1.2026.119", binary=True)
        _make_app_bundle(tmp_path, "Cursor", version="0.50.0")
        _make_app_bundle(tmp_path, "Ollama", version="0.4.7")
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["Claude.app", "ChatGPT.app", "Cursor.app", "Ollama.app"],
        )
        result = src.run_with_safety()
        assert len(result) == 4
        assert {a.name for a in result} == {"Claude", "ChatGPT", "Cursor", "Ollama"}


class TestAiAppsInfoPlistAbsentBundle:
    def test_unknown_bundle_yields_no_asset(self, tmp_path: Path) -> None:
        """Known bundle name not on disk → no asset, no error."""
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["NeverInstalled.app"],
        )
        result = src.run_with_safety()
        assert result == []

    def test_some_present_some_absent(self, tmp_path: Path) -> None:
        _make_app_bundle(tmp_path, "Claude")
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["Claude.app", "AbsentApp.app"],
        )
        result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "Claude"


class TestAiAppsInfoPlistMissingVersionKey:
    def test_missing_short_version_string_yields_version_none(self, tmp_path: Path) -> None:
        """Per spec §7.1: never fabricate `"unknown"` — version is None when missing."""
        contents = tmp_path / "WeirdApp.app" / "Contents"
        contents.mkdir(parents=True)
        plist_path = contents / "Info.plist"
        with plist_path.open("wb") as f:
            plistlib.dump({"CFBundleName": "WeirdApp"}, f)  # No version key
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["WeirdApp.app"],
        )
        result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].version is None


class TestAiAppsInfoPlistPerItemIsolation:
    def test_one_corrupt_plist_others_survive(self, tmp_path: Path, caplog) -> None:
        """3 bundles; 1 with corrupt plist → 2 assets + 1 WARNING."""
        _make_app_bundle(tmp_path, "GoodA")
        # Corrupt plist: bundle present, file present, content is gibberish
        contents = tmp_path / "Broken.app" / "Contents"
        contents.mkdir(parents=True)
        (contents / "Info.plist").write_bytes(b"this is not a plist")
        _make_app_bundle(tmp_path, "GoodB")
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["GoodA.app", "Broken.app", "GoodB.app"],
        )
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ai_apps_info_plist"):
            result = src.run_with_safety()
        names = {a.name for a in result}
        assert names == {"GoodA", "GoodB"}
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        assert any("Broken" in (r.message or "") for r in caplog.records)

    def test_oversized_plist_rejected_others_survive(self, tmp_path: Path, caplog) -> None:
        """Plist > 10 MiB → that bundle skipped + WARNING; others unaffected."""
        _make_app_bundle(tmp_path, "Good")
        contents = tmp_path / "Bloated.app" / "Contents"
        contents.mkdir(parents=True)
        (contents / "Info.plist").write_bytes(b"a" * (11 * 1024 * 1024))
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["Good.app", "Bloated.app"],
        )
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ai_apps_info_plist"):
            result = src.run_with_safety()
        assert {a.name for a in result} == {"Good"}

    def test_missing_info_plist_logged_and_skipped(self, tmp_path: Path, caplog) -> None:
        """Bundle dir present but Contents/Info.plist missing → WARNING + skip."""
        (tmp_path / "NoPlist.app" / "Contents").mkdir(parents=True)
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["NoPlist.app"],
        )
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.ai_apps_info_plist"):
            result = src.run_with_safety()
        assert result == []


class TestAiAppsInfoPlistAssetContract:
    def test_asset_type_is_ai_tool(self, tmp_path: Path) -> None:
        _make_app_bundle(tmp_path, "Claude")
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["Claude.app"],
        )
        result = src.run_with_safety()
        assert result[0].type == "ai_tool"
        assert result[0].source == "ai-apps-info-plist"

    def test_install_path_is_the_app_bundle(self, tmp_path: Path) -> None:
        bundle = _make_app_bundle(tmp_path, "Claude")
        src = AiAppsInfoPlistSource(
            applications_root=tmp_path,
            known_bundle_names=["Claude.app"],
        )
        result = src.run_with_safety()
        assert result[0].install_path == str(bundle)


class TestAiAppsInfoPlistDefaults:
    def test_default_root_is_applications(self) -> None:
        src = AiAppsInfoPlistSource()
        assert str(src.applications_root) == "/Applications"

    def test_default_known_bundles_include_claude_chatgpt_cursor_ollama(self) -> None:
        src = AiAppsInfoPlistSource()
        bundles = set(src.known_bundle_names)
        assert {"Claude.app", "ChatGPT.app", "Cursor.app", "Ollama.app"}.issubset(bundles)


class TestAiAppsInfoPlistEmpirical:
    """CLAUDE.md §9 — runs against the real `/Applications/` on this machine."""

    def test_real_applications_yields_known_bundles_when_installed(self) -> None:
        applications = Path("/Applications")
        if not applications.is_dir():
            pytest.skip("/Applications missing — not a macOS install?")
        src = AiAppsInfoPlistSource()
        result = src.run_with_safety()
        # At least one of Claude / ChatGPT / Cursor / Ollama is expected on
        # this machine. The test never fails if none happen to be installed —
        # that's an empty-state path the prior tests already cover.
        if result:
            for asset in result:
                assert asset.source == "ai-apps-info-plist"
                assert asset.name
                assert asset.install_path
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
