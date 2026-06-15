"""P5.3 — Demo-mode data for CISO evaluation pitches.

Directive line 208 (verbatim): "Demo mode data per spec §2.5.1.
Hardcoded representative environment with 6-8 tools, 20-30 assets across
all 5 risk bands. Including 1× 'ACTIVITY EXCEEDS DECLARED SCOPE', 1×
known-malicious package, 1× high-sensitivity GitHub OAuth."

Directive §8.6.1 (verbatim): "Demo data is loaded from a hardcoded
source (Python dict at `attack_surface/demo_data.py`), NEVER persisted
to the `assets` table. ... Architecture: demo data and real data NEVER
share storage. Isolation is structural, not just logical."

Phase A judge p5.3.a1 APPROVE 2026-06-15 with one binding carry-forward:

  The "ACTIVITY EXCEEDS DECLARED SCOPE" finding has NO merged curated
  rule on origin/main (it would have shipped with the unmerged P4.3
  runtime-correlation work). So this module presents the finding as
  curated display content via the `applied_rules[].label` field in
  risk_factors — NOT a reference to a live rule ID. Demo mode's whole
  purpose (directive line 1492) is showing what Vigil *would* flag; it
  does not require a live rule to exist.

risk_factors JSON shape matches the v1 schema produced by
`orchestrator._factors_payload` and consumed by
`dashboard_api.render_asset_row` (origin/main):

    {
      "schema_version": 1,
      "contributions": {"max_cve_severity": ..., ...},
      "weights": {...},
      "applied_rules": [
        {"label": str, "explanation": str, "modifier": int,
         "framework_refs": [str, ...]},
      ],
      "applied_reputation": [...],
      "cves": [...] | null,
      "cve_status": "ok" | "not_applicable" | "unavailable",
      "cve_unavailable_reason": str | null,
    }

Composition (24 assets / 6 tools, comfortably inside the directive's
6-8 / 20-30 bounds):

  * 2 CRITICAL:
    - typosquatted PyPI package `requets` (known-malicious detection)
    - GitHub OAuth integration with `admin:org` scope
  * 4 HIGH:
    - Cursor extension with declared-scope violation ("ACTIVITY
      EXCEEDS DECLARED SCOPE" curated label)
    - Claude Desktop with three unaudited MCP servers
    - Chrome extension with `<all_urls>` host permissions
    - Ollama model with internet-out enabled
  * 8 MEDIUM: realistic packages / extensions / MCP servers
  * 8 LOW + 2 INFO: boring developer-machine flotsam

All paths use the `<USER>` placeholder (matches the home-dir
normalization the merged `privacy_audit._normalize_home_paths`
performs) so even the underlying source data carries no real username.
The `_for_export()` wrapper still routes through
`redact_value_for_display` for defense-in-depth.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from claude_monitoring.privacy_audit import (
    SAFE_COLUMNS_BY_TABLE,
    redact_value_for_display,
)

# Per-band weighting used by the orchestrator's scoring engine —
# matched in the demo `contributions` blocks so a CISO who clicks into
# the breakdown popover sees a coherent factor decomposition.
_DEFAULT_WEIGHTS = {
    "max_cve_severity": 0.35,
    "permission_breadth": 0.30,
    "integration_sensitivity": 0.20,
    "activity_recency": 0.15,
}


def _demo_id(seed: str) -> str:
    """Deterministic SHA-256 digest for a demo asset id. Stable across
    runs (CISO evaluation must see the same examples each time)."""
    return hashlib.sha256(f"demo-{seed}".encode()).hexdigest()


def _ts_iso(value: str = "2026-06-01T03:00:00Z") -> str:
    """Frozen timestamp for the demo set — every asset shares it so the
    demo doesn't drift relative to the operator's clock."""
    return value


def _risk_factors(
    *,
    contributions: dict[str, float],
    applied_rules: list[dict[str, Any]] | None = None,
    applied_reputation: list[dict[str, Any]] | None = None,
    cves: list[dict[str, Any]] | None = None,
    cve_status: str = "not_applicable",
    cve_unavailable_reason: str | None = None,
) -> str:
    """Build the v1 risk_factors JSON dict and serialize it. Mirrors the
    `_factors_payload` shape orchestrator.py emits on real scans."""
    payload = {
        "schema_version": 1,
        "contributions": contributions,
        "weights": dict(_DEFAULT_WEIGHTS),
        "applied_rules": list(applied_rules or []),
        "applied_reputation": list(applied_reputation or []),
        "cves": cves,
        "cve_status": cve_status,
        "cve_unavailable_reason": cve_unavailable_reason,
    }
    return json.dumps(payload)


def _asset(
    *,
    seed: str,
    type_: str,
    name: str,
    source: str,
    risk_score: int,
    risk_band: str,
    version: str | None = None,
    install_path: str | None = None,
    parent_seed: str | None = None,
    current_state: dict[str, Any] | None = None,
    ontology_tags: list[str] | None = None,
    risk_factors: str | None = None,
    is_vigil_component: int = 0,
) -> dict[str, Any]:
    """Build one demo-asset row matching the assets-table column set."""
    return {
        "id": _demo_id(seed),
        "type": type_,
        "parent_asset_id": _demo_id(parent_seed) if parent_seed else None,
        "name": name,
        "version": version,
        "install_path": install_path,
        "source": source,
        "first_seen": _ts_iso(),
        "last_seen": _ts_iso(),
        "last_scanned": _ts_iso(),
        "current_state": json.dumps(current_state or {}),
        "ontology_tags": json.dumps(ontology_tags or []),
        "risk_score": risk_score,
        "risk_band": risk_band,
        "risk_factors": risk_factors,
        "is_vigil_component": is_vigil_component,
    }


# ---------------------------------------------------------------------------
# CRITICAL — 2 assets
# ---------------------------------------------------------------------------


_CRITICAL_TYPOSQUAT_PKG = _asset(
    seed="requets-pypi",
    type_="dependency",
    name="requets",
    version="2.32.4",
    source="python-packages",
    install_path="/Users/<USER>/.venv/lib/python3.12/site-packages/requets",
    risk_score=92,
    risk_band="critical",
    current_state={
        "ecosystem": "PyPI",
        "publisher": "newaccount-2024-12",
        "downloads_30d": 412,
    },
    ontology_tags=["software_supply_chain", "code_execution"],
    risk_factors=_risk_factors(
        contributions={
            "max_cve_severity": 0.0,
            "permission_breadth": 18.0,
            "integration_sensitivity": 18.0,
            "activity_recency": 0.0,
        },
        applied_rules=[
            {
                "label": "KNOWN-MALICIOUS TYPOSQUAT",
                "explanation": "Package name 'requets' is a one-edit typosquat of the legitimate 'requests' library; "
                "publisher account is <90 days old with no other releases.",
                "modifier": 56,
                "framework_refs": ["MITRE T1195.002", "CIS 16.1"],
            }
        ],
        applied_reputation=[
            {
                "signal": "publisher_age_under_90_days",
                "modifier": 8,
                "reason": "newaccount-2024-12 first published 2024-12-09",
            }
        ],
        cves=[],
        cve_status="ok",
    ),
)

_CRITICAL_GITHUB_ADMIN_ORG_OAUTH = _asset(
    seed="github-admin-org",
    type_="integration",
    name="GitHub for Claude Code",
    source="claude-desktop-integrations",
    install_path="/Users/<USER>/Library/Application Support/Claude/integrations/github.json",
    risk_score=84,
    risk_band="critical",
    current_state={
        "integration": "github",
        "oauth_scopes": ["admin:org", "repo", "workflow"],
        "client_app": "Claude Code",
        "granted_at": "2025-09-04T16:12:03Z",
        "last_used": "2026-05-28T11:04:51Z",
    },
    ontology_tags=["data_exfiltration_capable", "credential_access", "remote_execution"],
    risk_factors=_risk_factors(
        contributions={
            "max_cve_severity": 0.0,
            "permission_breadth": 30.0,
            "integration_sensitivity": 20.0,
            "activity_recency": 12.0,
        },
        applied_rules=[
            {
                "label": "HIGH-SENSITIVITY OAUTH SCOPE",
                "explanation": "Integration holds GitHub `admin:org` — full org-level admin including member management. "
                "Recommend downgrading to least-privilege scopes.",
                "modifier": 22,
                "framework_refs": ["NIST AC-6", "CIS 6.8"],
            }
        ],
        cve_status="not_applicable",
    ),
)


# ---------------------------------------------------------------------------
# HIGH — 4 assets
# ---------------------------------------------------------------------------


_HIGH_CURSOR_SCOPE_VIOLATION = _asset(
    seed="cursor-extension-scope-violation",
    type_="extension",
    name="Tabnine for Cursor",
    version="0.18.4",
    source="vscode-extensions",
    install_path="/Users/<USER>/.cursor/extensions/tabnine.tabnine-vscode-0.18.4",
    risk_score=72,
    risk_band="high",
    current_state={
        "host": "Cursor",
        "declared_permissions": ["activeEditor"],
        "observed_destinations_last_24h": ["api.tabnine.com", "github.com", "raw.githubusercontent.com"],
    },
    ontology_tags=["code_execution", "data_exfiltration_capable"],
    risk_factors=_risk_factors(
        contributions={
            "max_cve_severity": 0.0,
            "permission_breadth": 6.0,
            "integration_sensitivity": 14.0,
            "activity_recency": 12.0,
        },
        applied_rules=[
            {
                "label": "ACTIVITY EXCEEDS DECLARED SCOPE",
                "explanation": "Extension declares `activeEditor` permission only; runtime traffic observed to "
                "github.com and raw.githubusercontent.com (not declared). Indicates broader access than the "
                "operator approved.",
                "modifier": 30,
                "framework_refs": ["NIST SC-7", "MITRE T1071.001"],
            }
        ],
        cve_status="not_applicable",
    ),
)

_HIGH_CLAUDE_DESKTOP_UNAUDITED_MCPS = _asset(
    seed="claude-desktop-unaudited-mcps",
    type_="ai_tool",
    name="Claude Desktop",
    version="0.9.4",
    source="ai-tool-versions",
    install_path="/Users/<USER>/Library/Application Support/Claude",
    risk_score=66,
    risk_band="high",
    current_state={
        "mcp_server_count": 7,
        "audited_mcp_count": 4,
        "unaudited_mcps": ["repo-explorer", "cron-runner", "slack-poster"],
    },
    ontology_tags=["inter_tool_communication", "code_execution"],
    risk_factors=_risk_factors(
        contributions={
            "max_cve_severity": 0.0,
            "permission_breadth": 24.0,
            "integration_sensitivity": 10.0,
            "activity_recency": 12.0,
        },
        applied_rules=[
            {
                "label": "UNAUDITED MCP SERVERS",
                "explanation": "Claude Desktop is configured with 7 MCP servers; 3 are not on the operator's audited list. "
                "Each unaudited server can execute arbitrary shell + network operations on Claude's behalf.",
                "modifier": 18,
                "framework_refs": ["CIS 4.1", "NIST CM-7"],
            }
        ],
        cve_status="not_applicable",
    ),
)

_HIGH_CHROME_ALL_URLS_EXT = _asset(
    seed="chrome-extension-all-urls",
    type_="extension",
    name="WebRead Capture",
    version="3.2.1",
    source="chromium-extensions",
    install_path="/Users/<USER>/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghij",
    risk_score=68,
    risk_band="high",
    current_state={
        "host_permissions": ["<all_urls>"],
        "content_scripts": [{"matches": ["<all_urls>"]}],
        "store_listing": "https://chrome.google.com/webstore/detail/abcdefghij",
    },
    ontology_tags=["data_exfiltration_capable", "system_access"],
    risk_factors=_risk_factors(
        contributions={
            "max_cve_severity": 0.0,
            "permission_breadth": 30.0,
            "integration_sensitivity": 8.0,
            "activity_recency": 6.0,
        },
        applied_rules=[
            {
                "label": "WILDCARD HOST PERMISSIONS",
                "explanation": "Extension declares `<all_urls>` host permission and matching content scripts — "
                "reads every page the user visits.",
                "modifier": 24,
                "framework_refs": ["NIST AC-3"],
            }
        ],
        cve_status="not_applicable",
    ),
)

_HIGH_OLLAMA_INTERNET_OUT = _asset(
    seed="ollama-model-internet-out",
    type_="ai_tool",
    name="Ollama (llama3.1:70b)",
    version="0.4.7",
    source="ollama-models",
    install_path="/Users/<USER>/.ollama/models/manifests/registry.ollama.ai/library/llama3.1/70b",
    risk_score=62,
    risk_band="high",
    current_state={
        "model_family": "llama3.1",
        "size_b": 70,
        "outbound_network_enabled": True,
        "listen_addr": "0.0.0.0:11434",
    },
    ontology_tags=["data_exfiltration_capable", "system_access"],
    risk_factors=_risk_factors(
        contributions={
            "max_cve_severity": 0.0,
            "permission_breadth": 24.0,
            "integration_sensitivity": 8.0,
            "activity_recency": 6.0,
        },
        applied_rules=[
            {
                "label": "MODEL SERVES ON ALL INTERFACES",
                "explanation": "Ollama server bound to 0.0.0.0 — reachable from the local network, not just localhost.",
                "modifier": 16,
                "framework_refs": ["NIST SC-7"],
            }
        ],
        cve_status="not_applicable",
    ),
)


# ---------------------------------------------------------------------------
# MEDIUM — 8 assets
# ---------------------------------------------------------------------------


def _medium_asset(seed: str, type_: str, name: str, source: str, score: int, ctx: dict[str, Any]) -> dict[str, Any]:
    return _asset(
        seed=seed,
        type_=type_,
        name=name,
        source=source,
        risk_score=score,
        risk_band="medium",
        version=ctx.get("version"),
        install_path=ctx.get("install_path"),
        current_state=ctx.get("current_state", {}),
        ontology_tags=ctx.get("ontology_tags", []),
        risk_factors=_risk_factors(
            contributions={
                "max_cve_severity": 0.0,
                "permission_breadth": 12.0,
                "integration_sensitivity": ctx.get("integration_sensitivity_contrib", 6.0),
                "activity_recency": 6.0,
            },
            applied_rules=ctx.get("applied_rules", []),
            cve_status=ctx.get("cve_status", "not_applicable"),
        ),
    )


_MEDIUM_ASSETS = [
    _medium_asset(
        "claude-code-skill-jira",
        "ai_tool",
        "Claude Code — Jira skill",
        "claude-code-skills",
        52,
        {
            "version": "1.3.0",
            "install_path": "/Users/<USER>/.claude-code/skills/jira",
            "current_state": {"skill": "jira", "scopes": ["read:jira-work"]},
            "ontology_tags": ["data_exfiltration_capable"],
        },
    ),
    _medium_asset(
        "vscode-copilot",
        "extension",
        "GitHub Copilot",
        "vscode-extensions",
        48,
        {
            "version": "1.232.0",
            "install_path": "/Users/<USER>/.vscode/extensions/github.copilot-1.232.0",
            "current_state": {"host": "VS Code", "telemetry": "off"},
            "ontology_tags": ["code_execution"],
        },
    ),
    _medium_asset(
        "mcp-filesystem",
        "mcp_server",
        "filesystem-mcp",
        "mcp-servers",
        45,
        {
            "version": "0.6.0",
            "install_path": "/Users/<USER>/.claude-code/mcp/filesystem-mcp",
            "current_state": {"allowed_root": "/Users/<USER>/Projects"},
            "ontology_tags": ["system_access"],
        },
    ),
    _medium_asset(
        "chatgpt-desktop",
        "ai_tool",
        "ChatGPT Desktop",
        "ai-tool-versions",
        50,
        {
            "version": "1.2024.355",
            "install_path": "/Applications/ChatGPT.app",
            "current_state": {"login_state": "signed-in"},
            "ontology_tags": ["data_exfiltration_capable"],
        },
    ),
    _medium_asset(
        "py-package-pytest",
        "dependency",
        "pytest",
        "python-packages",
        42,
        {
            "version": "8.3.4",
            "install_path": "/Users/<USER>/.venv/lib/python3.12/site-packages/pytest",
            "current_state": {"ecosystem": "PyPI", "publisher": "pytest-dev"},
            "ontology_tags": [],
        },
    ),
    _medium_asset(
        "ollama-llama32-3b",
        "ai_tool",
        "Ollama (llama3.2:3b)",
        "ollama-models",
        44,
        {
            "version": "0.4.7",
            "install_path": "/Users/<USER>/.ollama/models/manifests/registry.ollama.ai/library/llama3.2/3b",
            "current_state": {"model_family": "llama3.2", "size_b": 3, "outbound_network_enabled": False},
            "ontology_tags": [],
        },
    ),
    _medium_asset(
        "claude-code-skill-postgres",
        "ai_tool",
        "Claude Code — Postgres skill",
        "claude-code-skills",
        47,
        {
            "version": "0.8.1",
            "install_path": "/Users/<USER>/.claude-code/skills/postgres",
            "current_state": {"skill": "postgres", "scopes": ["read", "exec"]},
            "ontology_tags": ["data_exfiltration_capable"],
        },
    ),
    _medium_asset(
        "vscode-prettier",
        "extension",
        "Prettier",
        "vscode-extensions",
        40,
        {
            "version": "11.0.0",
            "install_path": "/Users/<USER>/.vscode/extensions/esbenp.prettier-vscode-11.0.0",
            "current_state": {"host": "VS Code"},
            "ontology_tags": [],
        },
    ),
]


# ---------------------------------------------------------------------------
# LOW — 8 assets, INFO — 2 assets
# ---------------------------------------------------------------------------


def _low_asset(seed: str, type_: str, name: str, source: str, score: int, ctx: dict[str, Any]) -> dict[str, Any]:
    return _asset(
        seed=seed,
        type_=type_,
        name=name,
        source=source,
        risk_score=score,
        risk_band="low",
        version=ctx.get("version"),
        install_path=ctx.get("install_path"),
        current_state=ctx.get("current_state", {}),
        ontology_tags=ctx.get("ontology_tags", []),
        risk_factors=_risk_factors(
            contributions={
                "max_cve_severity": 0.0,
                "permission_breadth": 6.0,
                "integration_sensitivity": 4.0,
                "activity_recency": 0.0,
            },
            applied_rules=[],
            cve_status="not_applicable",
        ),
    )


_LOW_ASSETS = [
    _low_asset(
        "py-package-numpy",
        "dependency",
        "numpy",
        "python-packages",
        28,
        {"version": "2.2.0", "install_path": "/Users/<USER>/.venv/lib/python3.12/site-packages/numpy"},
    ),
    _low_asset(
        "py-package-pandas",
        "dependency",
        "pandas",
        "python-packages",
        30,
        {"version": "2.2.3", "install_path": "/Users/<USER>/.venv/lib/python3.12/site-packages/pandas"},
    ),
    _low_asset(
        "node-package-lodash",
        "dependency",
        "lodash",
        "node-packages",
        24,
        {"version": "4.17.21", "install_path": "/Users/<USER>/proj/node_modules/lodash"},
    ),
    _low_asset(
        "node-package-axios",
        "dependency",
        "axios",
        "node-packages",
        26,
        {"version": "1.7.9", "install_path": "/Users/<USER>/proj/node_modules/axios"},
    ),
    _low_asset(
        "vscode-language-python",
        "extension",
        "Python (Microsoft)",
        "vscode-extensions",
        22,
        {"version": "2024.22.2", "install_path": "/Users/<USER>/.vscode/extensions/ms-python.python-2024.22.2"},
    ),
    _low_asset(
        "vscode-language-typescript",
        "extension",
        "TypeScript Vue Plugin",
        "vscode-extensions",
        20,
        {"version": "2.2.4", "install_path": "/Users/<USER>/.vscode/extensions/vue.volar-2.2.4"},
    ),
    _low_asset(
        "mcp-time",
        "mcp_server",
        "time-mcp",
        "mcp-servers",
        24,
        {
            "version": "0.1.0",
            "install_path": "/Users/<USER>/.claude-code/mcp/time-mcp",
            "current_state": {"scopes": ["clock-only"]},
        },
    ),
    _low_asset(
        "ollama-llama32-1b",
        "ai_tool",
        "Ollama (llama3.2:1b)",
        "ollama-models",
        28,
        {
            "version": "0.4.7",
            "install_path": "/Users/<USER>/.ollama/models/manifests/registry.ollama.ai/library/llama3.2/1b",
            "current_state": {"model_family": "llama3.2", "size_b": 1, "outbound_network_enabled": False},
        },
    ),
]


def _info_asset(seed: str, name: str, source: str, ctx: dict[str, Any]) -> dict[str, Any]:
    return _asset(
        seed=seed,
        type_=ctx.get("type_", "dependency"),
        name=name,
        source=source,
        risk_score=ctx.get("score", 10),
        risk_band="info",
        version=ctx.get("version"),
        install_path=ctx.get("install_path"),
        current_state=ctx.get("current_state", {}),
        ontology_tags=[],
        risk_factors=_risk_factors(
            contributions={
                "max_cve_severity": 0.0,
                "permission_breadth": 0.0,
                "integration_sensitivity": 0.0,
                "activity_recency": 0.0,
            },
            cve_status="not_applicable",
        ),
    )


_INFO_ASSETS = [
    _info_asset(
        "py-package-setuptools",
        "setuptools",
        "python-packages",
        {
            "version": "75.6.0",
            "install_path": "/Users/<USER>/.venv/lib/python3.12/site-packages/setuptools",
        },
    ),
    _info_asset(
        "homebrew-formula-git",
        "git",
        "homebrew-formulae",
        {
            "version": "2.47.1",
            "install_path": "/opt/homebrew/Cellar/git/2.47.1",
            "type_": "ai_tool",  # treated as dev-tooling installed locally
        },
    ),
]


# ---------------------------------------------------------------------------
# Top-level constants + accessors
# ---------------------------------------------------------------------------


DEMO_ASSETS: tuple[dict[str, Any], ...] = (
    _CRITICAL_TYPOSQUAT_PKG,
    _CRITICAL_GITHUB_ADMIN_ORG_OAUTH,
    _HIGH_CURSOR_SCOPE_VIOLATION,
    _HIGH_CLAUDE_DESKTOP_UNAUDITED_MCPS,
    _HIGH_CHROME_ALL_URLS_EXT,
    _HIGH_OLLAMA_INTERNET_OUT,
    *_MEDIUM_ASSETS,
    *_LOW_ASSETS,
    *_INFO_ASSETS,
)
"""24-asset hardcoded demo environment. HARDCODED, not random, per
directive line 1492: CISOs always see the same examples Rajan describes
in pitches."""


# Expected column set every demo asset must carry (the contract that
# lets the merged P5.2 exports render the demo set unchanged).
_REQUIRED_COLUMNS: frozenset[str] = frozenset(SAFE_COLUMNS_BY_TABLE["assets"].keys())


def get_demo_assets() -> tuple[dict[str, Any], ...]:
    """Return the hardcoded demo environment. The same constant every
    time — directive §8.6 demands deterministic CISO-pitch examples."""
    return DEMO_ASSETS


def get_demo_assets_for_export() -> list[dict[str, str]]:
    """Return rows shaped for the merged P5.2 exports.

    Every cell flows through ``privacy_audit.redact_value_for_display``
    even though the demo data is curated — defense in depth, per the
    Phase A D-redaction-defense decision. If a future edit accidentally
    introduces a real username or a token-shaped string, the display
    pipeline catches it at this boundary instead of leaking through.
    """
    rendered: list[dict[str, str]] = []
    for row in DEMO_ASSETS:
        display: dict[str, str] = {}
        for col_name in SAFE_COLUMNS_BY_TABLE["assets"]:
            display[col_name] = redact_value_for_display("assets", col_name, row.get(col_name))
        rendered.append(display)
    return rendered
