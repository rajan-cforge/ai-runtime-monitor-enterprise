# Claude Code Sprint Prompt — Track B: Editor Extension Scanner

## Mission

Add a new subsystem to `ai-runtime-monitor` that inventories editor extensions across all installed editors, scores them for risk, correlates with threat intelligence, and alerts on critical findings. This is the headline feature for the post-a16z product launch.

## Branch

```
git checkout -b feature/extension-scanner
```

## Files to Create

```
claude_monitoring/extension_scanner/__init__.py
claude_monitoring/extension_scanner/models.py
claude_monitoring/extension_scanner/inventory.py
claude_monitoring/extension_scanner/risk_scorer.py
claude_monitoring/extension_scanner/threat_intel.py
claude_monitoring/extension_scanner/scanner_service.py
claude_monitoring/extension_scanner/known_iocs.json
claude_monitoring/api/extension_routes.py

tests/extension_scanner/__init__.py
tests/extension_scanner/test_inventory.py
tests/extension_scanner/test_risk_scorer.py
tests/extension_scanner/test_threat_intel.py
tests/extension_scanner/test_scanner_service.py
tests/extension_scanner/fixtures/vscode_glassworm_manifest.json
tests/extension_scanner/fixtures/cursor_typosquat_manifest.json
tests/extension_scanner/fixtures/vscode_legit_prettier.json
tests/extension_scanner/fixtures/jetbrains_plugin.xml
tests/extension_scanner/fixtures/xcode_appex_info.plist
```

## Data Model (`models.py`)

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

class Editor(str, Enum):
    VSCODE = "vscode"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    JETBRAINS = "jetbrains"
    XCODE = "xcode"
    SUBLIME = "sublime"
    NEOVIM = "neovim"
    ZED = "zed"
    CLAUDE_CODE = "claude_code"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Extension:
    editor: Editor
    extension_id: str            # e.g. "esbenp.prettier-vscode"
    name: str
    display_name: str
    publisher: str
    publisher_verified: bool
    version: str
    install_path: Path
    install_date: datetime
    publish_date: datetime | None
    permissions: list[str] = field(default_factory=list)
    activation_events: list[str] = field(default_factory=list)
    has_native_binaries: bool = False
    binary_signatures: dict[str, str] = field(default_factory=dict)
    has_postinstall: bool = False
    telemetry_endpoints: list[str] = field(default_factory=list)
    marketplace_url: str | None = None
    raw_manifest: dict[str, Any] = field(default_factory=dict)

@dataclass
class RiskFinding:
    extension_id: str
    editor: Editor
    severity: Severity
    rule_id: str                 # e.g. "R001_KNOWN_IOC"
    description: str
    evidence: dict[str, Any]
    detected_at: datetime
    threat_intel_source: str | None = None   # "GHSA-xxxx", "OpenVSX-2025-002"
```

## Inventory (`inventory.py`)

Implement one function per editor. All return `list[Extension]`. Skip silently if the editor's directory does not exist.

```python
def scan_vscode() -> list[Extension]:
    """Walk ~/.vscode/extensions/*/package.json"""

def scan_cursor() -> list[Extension]:
    """Walk ~/.cursor/extensions/*/package.json"""

def scan_windsurf() -> list[Extension]:
    """Walk ~/.windsurf/extensions/*/package.json"""

def scan_jetbrains() -> list[Extension]:
    """Walk ~/Library/Application Support/JetBrains/*/plugins/, parse plugin.xml"""

def scan_xcode() -> list[Extension]:
    """Find .appex bundles in ~/Library/Developer/Xcode/ and /Applications/*.app/Contents/PlugIns/"""

def scan_sublime() -> list[Extension]:
    """Walk ~/Library/Application Support/Sublime Text/Packages/"""

def scan_neovim() -> list[Extension]:
    """Walk ~/.config/nvim/pack/, lazy.nvim, packer paths"""

def scan_zed() -> list[Extension]:
    """Walk ~/Library/Application Support/Zed/extensions/"""

def scan_claude_code() -> list[Extension]:
    """Walk ~/.claude/ for MCP servers and hooks (treat each as an 'extension')"""

def scan_all_editors() -> list[Extension]:
    """Run every scanner, aggregate, dedupe by (editor, extension_id)"""
```

Signal extraction rules:

- `permissions`: pull from `contributes.*` keys in VS Code package.json
- `activation_events`: from `activationEvents` array
- `has_native_binaries`: walk extension directory for `.node`, `.dylib`, `.so`, `.dll`
- `binary_signatures`: on macOS, run `codesign -dv --verbose=4 <path>` and capture identity
- `has_postinstall`: check `scripts.postinstall` in package.json
- `telemetry_endpoints`: regex-scan extension JS files for `https?://` URLs that are not the publisher's verified domain
- `install_date`: file mtime of the extension directory
- `publish_date`: fetch from marketplace API on demand and cache for 7 days

## Risk Scoring (`risk_scorer.py`)

```python
def score_extension(
    ext: Extension,
    threat_intel: ThreatIntelClient,
    all_extensions: list[Extension],
    ai_session_correlator: SessionCorrelator | None = None,
) -> list[RiskFinding]:
    """Apply all rules. Return zero or more findings."""
```

Rules to implement (each is a separate function `apply_R001(...)`, etc.):

```
R001 KNOWN_IOC          critical  Matches known_iocs.json or threat intel feed
R002 ADVISORY_MATCH     critical/high  Matches GHSA or OpenVSX advisory (severity from feed)
R003 UNVERIFIED_RISKY   high      Unverified publisher + child_process permission + publish_date < 30 days
R004 UNSIGNED_BROAD     high      Unsigned native binary + activationEvents includes "*"
R005 POSTINSTALL_NET    medium    Postinstall script + network permissions
R006 SUSPICIOUS_TELEMETRY medium  Telemetry endpoint to non-publisher domain
R007 AI_INSTALLED_RECENT high     Install date within 1 hour of AI agent process activity
R008 TYPOSQUAT          high      Levenshtein distance < 3 from a popular extension name
                                  but different publisher
R009 HIJACKED_PUBLISHER critical  Publisher had ownership change in last 14 days
                                  (from marketplace audit log if available)
```

For R008, embed a small popular-extensions list (top 100 VS Code marketplace) in `known_iocs.json`. Use `python-Levenshtein` for distance.

## Threat Intel (`threat_intel.py`)

```python
class ThreatIntelClient:
    def __init__(self, cache_dir: Path):
        ...

    async def refresh_all(self) -> None:
        """Pull all feeds. Run every 6 hours."""

    async def fetch_ghsa(self) -> list[dict]:
        """GitHub Security Advisories via GraphQL.
        Filter ecosystem=NPM for VS Code-family, PIP for JetBrains via Python."""

    async def fetch_openvsx_advisories(self) -> list[dict]:
        """Scrape https://open-vsx.org/security or use their API if available."""

    async def fetch_snyk_vuln_db(self) -> list[dict]:
        """Public Snyk vulnerability DB endpoint."""

    def is_known_bad(self, extension_id: str, version: str) -> tuple[bool, str | None]:
        """Returns (is_bad, advisory_source_id)."""

    def get_severity(self, advisory_id: str) -> Severity:
        ...
```

Cache feeds in `~/.ai-runtime-monitor/threat_intel_cache/` as JSON files with `fetched_at` timestamps. Respect rate limits.

Seed `known_iocs.json` with the GlassWorm cluster from November 2025 and any other public IOCs you can find. Format:

```json
{
  "iocs": [
    {
      "extension_id": "evil-publisher.evil-extension",
      "versions": ["*"],
      "source": "GlassWorm-OpenVSX-Campaign-2025",
      "url": "https://...",
      "added_at": "2025-11-15T00:00:00Z"
    }
  ],
  "popular_extensions": [
    {"id": "esbenp.prettier-vscode", "publisher": "esbenp"},
    {"id": "eamodio.gitlens", "publisher": "eamodio"}
  ]
}
```

## Scanner Service (`scanner_service.py`)

```python
class ExtensionScannerService:
    def __init__(self, db, alert_dispatcher, threat_intel, scan_interval_sec=3600):
        ...

    async def start(self) -> None:
        """Initial scan, then periodic + filesystem watcher."""

    async def scan_once(self) -> list[RiskFinding]:
        """Inventory + score + diff + emit alerts for new findings."""

    def _diff_against_previous(self, current: list[Extension]) -> tuple[list[Extension], list[Extension]]:
        """Return (newly_installed, removed)."""

    async def _emit_alert(self, finding: RiskFinding) -> None:
        """Hand off to existing alert_dispatcher. Critical findings also
        fire native macOS notification via subprocess osascript."""
```

Register the service in the existing daemon startup at `claude_monitoring/monitor.py`. Add CLI flag `--no-extension-scanner` for opt-out.

## API Routes (`extension_routes.py`)

Wire into the existing FastAPI app on the dashboard:

```python
GET  /api/extensions                # list all with latest findings
GET  /api/extensions/{ext_id}       # details + manifest + all findings
POST /api/extensions/scan           # trigger immediate rescan
POST /api/extensions/{ext_id}/dismiss-finding/{rule_id}  # mark false positive
GET  /api/extensions/threat-feeds   # last-fetched timestamps per feed
```

## Tests

Each test file should have at minimum:

```python
# test_inventory.py
def test_scan_vscode_parses_real_manifest(tmp_path): ...
def test_scan_vscode_handles_missing_directory(): ...
def test_scan_jetbrains_parses_plugin_xml(tmp_path): ...
def test_scan_xcode_finds_appex_bundles(tmp_path): ...
def test_native_binary_detection(tmp_path): ...
def test_codesign_check_unsigned(tmp_path): ...

# test_risk_scorer.py
def test_R001_known_ioc_critical(glassworm_fixture): ...
def test_R002_advisory_match_high(): ...
def test_R003_unverified_risky(): ...
def test_R004_unsigned_broad(): ...
def test_R007_correlation_with_ai_session(mock_session_correlator): ...
def test_R008_typosquat_detection(): ...
def test_legit_extension_no_findings(prettier_fixture): ...

# test_threat_intel.py
def test_ghsa_fetch_parses_response(httpx_mock): ...
def test_cache_respects_ttl(tmp_path): ...
def test_rate_limit_backoff(httpx_mock): ...

# test_scanner_service.py
def test_initial_scan_emits_findings(mock_db, mock_dispatcher): ...
def test_diff_detects_new_install(mock_db): ...
def test_critical_finding_fires_notification(): ...
def test_dismiss_persists_across_scans(): ...
```

All async tests use `pytest-asyncio`. Coverage target: ≥85% on the new module.

## Fixtures

`vscode_glassworm_manifest.json`: real (or realistic) package.json from the GlassWorm campaign. Look at the November 2025 reporting for actual artifact details.

`cursor_typosquat_manifest.json`: a `pretti3r.prettier-vscode` style typosquat manifest.

`vscode_legit_prettier.json`: copy the real Prettier extension's package.json from disk.

`jetbrains_plugin.xml`: real plugin.xml structure with `<idea-plugin>`, `<vendor>`, `<depends>`.

`xcode_appex_info.plist`: minimal Info.plist for a source editor extension.

## Verification Checklist

After implementation, run this checklist and report results inline:

```bash
# 1. Type check
mypy claude_monitoring/extension_scanner/ --strict

# 2. Tests
pytest tests/extension_scanner/ -v --cov=claude_monitoring.extension_scanner --cov-report=term-missing

# 3. Full regression
pytest -v 2>&1 | tail -50

# 4. Live scan on dev machine
python -m claude_monitoring.extension_scanner.scanner_service --once --verbose

# 5. API smoke test
curl -s http://localhost:9081/api/extensions | jq '.[] | {id: .extension_id, severity: .findings[0].severity}'

# 6. Manual: install a known-bad fixture extension into a sandbox VS Code, confirm critical alert fires within 60 seconds
```

## Commit Message

```
feat(extension-scanner): inventory + risk scoring + threat intel for editor extensions

- Scans VS Code, Cursor, Windsurf, JetBrains, Xcode, Sublime, Neovim, Zed, Claude Code
- 9 risk rules including known-IOC match, typosquat detection, AI-correlated installs
- Threat intel from GHSA, OpenVSX, Snyk with 6-hour refresh
- New API routes under /api/extensions
- 85%+ test coverage with real-world malicious fixtures
- Native macOS notifications on critical findings
```

## Stop and Ask If

- The existing alert dispatcher signature differs from what is assumed here
- The existing DB schema does not have a table for extension findings (you may need to add a migration)
- Any threat feed requires authentication that is not already wired
