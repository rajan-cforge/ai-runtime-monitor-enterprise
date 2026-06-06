"""`AiAppsInfoPlistSource` — discovers AI app bundle metadata via Info.plist.

Phase A: ``~/Documents/vigil-notes/v022/phase-1/p1.4/phase-a-investigation.md`` §4.

C3 source — reads macOS application bundle ``Info.plist`` files
(XML *or* binary; ``plistlib.load`` handles both transparently
when given a binary-mode file). Parses are wrapped in per-bundle
try/except so one corrupt plist cannot poison the batch.

**KNOWN bundles (Phase A §4, ratified default list):**

- ``/Applications/Claude.app`` (XML)
- ``/Applications/ChatGPT.app`` (BINARY)
- ``/Applications/Cursor.app`` (XML)
- ``/Applications/Ollama.app`` (XML)

**Empirical verification gate (CLAUDE.md §9):** confirmed
``plistlib.load(open(<bundle>/Contents/Info.plist, 'rb'))`` parses
both encodings on this machine.

**Relationship to ``AiToolVersionsSource``:** that source already
shipped covers CLI tools (``claude --version``, ``cursor --version``).
This source covers the ``.app`` bundle install — the two are
complementary and produce distinct ``Asset.id`` values (different
install_paths).
"""

from __future__ import annotations

import logging
import plistlib
import time
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import validate_path

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.ai_apps_info_plist")


_DEFAULT_APPLICATIONS_ROOT: Path = Path("/Applications")
_DEFAULT_KNOWN_BUNDLES: list[str] = [
    "Claude.app",
    "ChatGPT.app",
    "Cursor.app",
    "Ollama.app",
]


class AiAppsInfoPlistSource(DiscoverySource):
    """Enumerates installed AI app bundles by reading Info.plist."""

    DEFAULT_TIMEOUT_SEC = 30
    MAX_FILE_SIZE_MB = 10

    def __init__(
        self,
        applications_root: Path | None = None,
        known_bundle_names: list[str] | None = None,
    ) -> None:
        self.applications_root: Path = (
            Path(applications_root) if applications_root is not None else _DEFAULT_APPLICATIONS_ROOT
        )
        self.known_bundle_names: list[str] = (
            list(known_bundle_names) if known_bundle_names is not None else list(_DEFAULT_KNOWN_BUNDLES)
        )

    def name(self) -> str:
        """Source identifier per spec §4.2."""
        return "ai-apps-info-plist"

    def requires_auth(self) -> bool:
        """No credentials required; pure local plist read."""
        return False

    def discover(self) -> list[Asset]:
        """Iterate the known bundle list; emit one asset per .app present under per-item isolation."""
        if not self.applications_root.is_dir():
            return []
        assets: list[Asset] = []
        scan_time = time.time()
        for bundle_name in self.known_bundle_names:
            bundle_path = self.applications_root / bundle_name
            if not bundle_path.is_dir():
                # App not installed — silent normal flow.
                continue
            try:
                asset = self._build_asset(bundle_path, scan_time)
            except Exception as exc:
                logger.warning("skipping %s: %s", bundle_path.name, exc)
                continue
            if asset is not None:
                assets.append(asset)
        return assets

    def _build_asset(self, bundle_path: Path, scan_time: float) -> Asset | None:
        validate_path(bundle_path, root=self.applications_root, max_depth=2)
        plist_path = bundle_path / "Contents" / "Info.plist"
        if not plist_path.is_file():
            raise ValueError(f"Info.plist missing in {bundle_path.name}")
        # Size cap BEFORE plistlib.load — defense against a malicious app
        # shipping a huge plist designed to OOM the parser.
        validate_path(
            plist_path,
            root=self.applications_root,
            max_depth=4,
            check_size=True,
            max_size_mb=self.MAX_FILE_SIZE_MB,
        )
        with plist_path.open("rb") as f:
            try:
                payload = plistlib.load(f)
            except (plistlib.InvalidFileException, ValueError, OSError) as exc:
                raise ValueError(f"failed to parse Info.plist for {bundle_path.name}: {exc}") from exc
        if not isinstance(payload, dict):
            raise TypeError(f"Info.plist root is not a dict in {bundle_path.name}")
        # Strip the .app suffix for the human-readable name.
        app_name = bundle_path.name[:-4] if bundle_path.name.endswith(".app") else bundle_path.name
        version = payload.get("CFBundleShortVersionString")
        version_str = version if isinstance(version, str) and version.strip() else None
        bundle_id = payload.get("CFBundleIdentifier")
        bundle_id_str = bundle_id if isinstance(bundle_id, str) else None
        current_state: dict = {
            "bundle_id": bundle_id_str,
            "bundle_name": payload.get("CFBundleName") if isinstance(payload.get("CFBundleName"), str) else None,
        }
        return Asset(
            id=f"ai-app-info-plist-{bundle_path.name}",
            type="ai_tool",
            parent_asset_id=None,
            name=app_name,
            version=version_str,
            install_path=str(bundle_path),
            source=self.name(),
            current_state=current_state,
            discovered_at=scan_time,
        )
