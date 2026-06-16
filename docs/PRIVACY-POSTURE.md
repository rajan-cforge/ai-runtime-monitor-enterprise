# Vigil — Privacy Posture

This document is the canonical privacy guarantee for Vigil v0.2.2.
Every claim below is grounded in a specific source-code path on the
merged tree so a reader can verify any sentence by reading the code.

The structure follows directive line 1537–1541 verbatim:

1. **What Vigil reads** (always vs. with permission vs. never)
2. **What Vigil transmits** (the egress allowlist + per-callsite map)
3. **What Vigil stores** (the SQLite schema + the no-credential
   invariant)
4. **User verification modes** (`--network-audit`, `--read-audit`,
   `--db-audit`)
5. **Source-code transparency** (privacy-critical files and their
   role)

## The no-telemetry guarantee (spec §10.1, unchanged from v0.2.1)

> Vigil v0.2.2 does NOT transmit any user data to any remote server
> controlled by Vigil/GoCloudForge.

There are no analytics endpoints, no crash-reporting beacons, no
"phone home" calls. The only outbound HTTP the
`src/claude_monitoring/attack_surface/` package may make is to the
short list of public registries enumerated in §2 below — and a CI
gate fails any attempt to add a destination off-list.

## 1. What Vigil reads

### Always read (no per-integration permission required)

Each of the 13 registered discovery sources reads only manifests,
configuration files, or CLI tool output. None of them reads document
content, email bodies, password files, browser-saved credentials, or
private keys.

| Source | Reads what |
|---|---|
| `discovery/sources/ai_apps_info_plist.py` | macOS app-bundle `Info.plist` metadata for AI tools |
| `discovery/sources/ai_tool_versions.py` | stdout of `<tool> --version` |
| `discovery/sources/chromium_extensions.py` | extension manifest JSON only |
| `discovery/sources/claude_code_skills.py` | `~/.claude/projects/*/metadata.json` |
| `discovery/sources/claude_desktop_integrations.py` | Claude Desktop config file metadata |
| `discovery/sources/homebrew_ai_tools.py` | `brew list --json` output |
| `discovery/sources/mcp_servers.py` | Claude Desktop `mcp_servers.json` (env vars in this file are redacted before persist — see below) |
| `discovery/sources/node_packages.py` | `npm list -g --json` + `package.json` manifests |
| `discovery/sources/ollama_models.py` | `ollama list` + `~/.ollama/models` |
| `discovery/sources/openclaw_skills.py` | OpenClaw skill config files |
| `discovery/sources/python_packages.py` | `<python> -m pip list --format=json` |
| `discovery/sources/python_project_deps.py` | `requirements.txt`, `pyproject.toml`, `Pipfile.lock` |
| `discovery/sources/vscode_cursor_extensions.py` | VS Code / Cursor extension manifest JSON |

**Source registry**: `src/claude_monitoring/attack_surface/discovery/sources/`.

### Read with explicit user permission (per-integration prompt)

**Not shipped in v0.2.2.** Spec §10.2 lists per-integration consent
reads for `gh` CLI auth tokens, `~/.aws/credentials`, Anthropic /
OpenAI API keys, Google / Slack / Notion OAuth tokens. **The merged
v0.2.2 tree contains zero code paths that read any of these.** This
introspection surface is scoped for v0.3.

If you want to verify this yourself:

```bash
git grep -nE 'ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|SLACK_TOKEN|NOTION_TOKEN|aws/credentials|gh auth token|\.netrc|id_rsa' src/
```

Returns exactly one hit — a docstring in `discovery/sources/mcp_servers.py`
*describing* what redaction protects against, not a credential read.

### Never read

- Browser saved passwords (out of scope)
- Email content (out of scope)
- General document contents (out of scope)
- Anything not related to AI tool configuration

### Defense-in-depth: env-var redaction at the discovery layer

Of the 13 discovery sources, exactly one (`mcp_servers.py`) reads an
`env` dict from its config (`mcp_servers.py:153`). That source calls
`redact_secrets_in_env` and `redact_secrets_in_args` unconditionally
before persistence (`mcp_servers.py:159-169`). The redaction primitive
itself (`discovery/helpers.py:471-567`) matches a curated set of
token-shaped patterns (GitHub `ghp_/gho_/ghu_/ghs_`, Anthropic
`sk-ant-`, OpenAI `sk-`, Slack `xox[bps]-`, AWS `AKIA…`) plus a
denylist of known credential variable names. It applies to every key
in the env dict, not just the ones whose name looks suspicious — so a
token persisted under an innocuously named env var still gets caught.

## 2. What Vigil transmits

### The egress allowlist

`src/claude_monitoring/attack_surface/` may contact exactly the
following hosts, and no others. A CI gate
(`scripts/check_privacy_no_telemetry.py`) scans the module tree and
fails any outbound HTTP whose hostname is not on this list, so the
list and the code stay in lockstep.

| Host | Purpose | Status in v0.2.2 |
|---|---|---|
| `api.osv.dev` | OSV.dev CVE lookups (P4.1 scan-time + P4.5 daemon-poll cache refresh) | **active** |
| `localhost`, `127.0.0.1`, `::1` | internal dashboard loopback only | active |
| `registry.npmjs.org` | npm package existence + publisher metadata (P2.6) | active |
| `api.npmjs.org` | npm weekly download counts (P2.6) | active |
| `pypi.org` | PyPI package existence (P2.6) | active |
| `pypistats.org` | PyPI weekly download counts (P2.6) | active |
| `chrome.google.com` | Chrome Web Store presence check (P2.6) | **dormant** — gated by `reputation.chrome_vscode_enabled = False` |
| `marketplace.visualstudio.com` | VS Code Marketplace `extensionquery` (P2.6) | **dormant** — same gate |

For each call, the **only payload transmitted** is the asset
identifier (package name, extension ID, or `publisher.extName`) — no
machine ID, no user ID, no install path, no credentials, no file
content.

The two dormant entries (`chrome.google.com`,
`marketplace.visualstudio.com`) are allowlisted because the
dispatcher code paths exist; their runtime call sites are gated
behind the `chrome_vscode_enabled()` predicate at
`attack_surface/reputation/config.py:79`, which defaults False.
They activate when P3.1 / P3.2 wire the corresponding managed-install
detection. Until then, no actual HTTP requests fire.

### Per-call-site map (audit trail)

| Call site | Host |
|---|---|
| `attack_surface/cves/client.py:94, 96` | `api.osv.dev/v1/querybatch` |
| `attack_surface/cves/client.py:119, 121` | `api.osv.dev/v1/vulns/<id>` |
| `attack_surface/reputation/npm.py:94-95` | `registry.npmjs.org/<pkg>` |
| `attack_surface/reputation/npm.py:118-119` | `api.npmjs.org/downloads/point/last-week/<pkg>` |
| `attack_surface/reputation/pypi.py:146-147` | `pypi.org/pypi/<pkg>/json` |
| `attack_surface/reputation/pypi.py:186-187` | `pypistats.org/api/packages/<pkg>/recent` |
| `attack_surface/reputation/chrome_web_store.py:69-70` | `chrome.google.com/webstore/detail/<id>` (dormant) |
| `attack_surface/reputation/vscode_marketplace.py:77-79` | `marketplace.visualstudio.com/_apis/public/gallery/extensionquery` (dormant) |

The CI gate's allowlist matches this call-site list exactly. There is
no provider-API egress in v0.2.2 (per §1 — no credentials are read,
so no per-user provider calls are issued).

### Scope of the no-telemetry gate

The CI gate scans `src/claude_monitoring/attack_surface/` only. The
v0.2.1 runtime-capture stack (`watch.py`, `validators.py`,
`threat_intel.py`) has its own outbound posture covered by its own
review process; the privacy guarantee in this section applies to the
attack-surface (discovery + reputation + CVE) layer.

### Operator kill-switches

Two environment variables short-circuit egress at the call sites:

- `NO_NETWORK=1` — universal egress kill-switch. Obeyed by all three
  egress paths:
  - Reputation dispatcher
    (`attack_surface/reputation/dispatcher.py:104-115`)
  - Scan-time CVE dispatcher
    (`attack_surface/cves/dispatcher.py:180-181`)
  - Daemon CVE-poll thread
    (`cve_poll_scheduler.py:102-113` — gated on the same
    `cve_feed_disabled()` predicate)
- `VIGIL_NO_REPUTATION=1` — reputation-only kill-switch
  (`reputation/config.py:54-56`).
- `VIGIL_NO_CVE_FEED=1` — CVE-only kill-switch
  (`cves/config.py:40-47`); also stops the daemon poll.

Setting `NO_NETWORK=1` on a daemon-running machine guarantees zero
attack-surface egress: an `lsof` / tcpdump snapshot after the env var
is exported will show no outbound to any of the active hosts above.

## 3. What Vigil stores

All discovered data is persisted to SQLite in `monitor.db`. The
attack-surface schema lives in
`src/claude_monitoring/persistence/migrations.py:163-273` and
consists of six tables. **No column in any table stores raw tokens,
OAuth bearers, API keys, passwords, or other credential material.**

| Table | Columns | What it contains |
|---|---|---|
| `assets` | `id, type, parent_asset_id, name, version, install_path, source, first_seen, last_seen, last_scanned, current_state, ontology_tags, risk_score, risk_band, risk_factors, is_vigil_component` | One row per discovered asset (package, extension, MCP server, etc.). All metadata. `current_state` is a JSON blob whose token-shaped content was redacted at the discovery layer (see §1). |
| `asset_cves` | `asset_id, cve_id, severity, published, description, cve_references, discovered_at` | Per-asset CVE attribution. Public vulnerability metadata only. |
| `asset_history` | `asset_id, scan_timestamp, state_snapshot, changes_from_previous, discovery_run_id` | Per-scan snapshots of `current_state` for change tracking. Inherits §1 redaction. |
| `cve_cache` | `package_ecosystem, package_name, cve_id, severity, affected_versions, published, description, cve_references, fetched_at` | Cached OSV.dev responses. Public CVE data; nothing personal. |
| `discovery_runs` | `id, started_at, completed_at, trigger, assets_discovered, new_assets, removed_assets, new_cves, errors` | Per-scan audit log. Counters + error messages only. |
| `permission_grants` | `integration, granted_at, granted_scope` | Per-integration consent metadata (scope strings, not tokens). Empty in v0.2.2 because the per-integration provider reads are scoped for v0.3. |

API keys, OAuth tokens, and other credentials are **never** stored in
`monitor.db`. They stay in their original locations (keychain, config
files, environment) and Vigil's discovery layer redacts any
token-shaped value that would otherwise enter the `current_state`
JSON.

## 4. User verification modes

Vigil ships three verification CLIs that let an operator confirm
the privacy posture empirically on a live machine. All three
dispatch from `src/claude_monitoring/monitor.py:2546-2557` and exit
without starting the daemon.

### `vigil --network-audit`

Entry point: `privacy_audit.network_audit_mode()` at
`privacy_audit.py:407`. Installs `sys.addaudithook("socket.connect")`
and snapshots `lsof` over the Vigil process tree. Runs a brief
discovery pass and logs every outbound destination. A truthful run
sees only:

- `api.osv.dev` (if CVE feed is active)
- `registry.npmjs.org`, `api.npmjs.org` (if any npm packages are
  found)
- `pypi.org`, `pypistats.org` (if any PyPI packages are found)
- loopback (dashboard health checks)

Any other destination is a bug; please open an issue.

### `vigil --read-audit`

Entry point: `privacy_audit.read_audit_mode()` at
`privacy_audit.py:447`. Installs `sys.addaudithook("open")` filtered
to the Vigil-spawned process tree and logs every file path opened
during a discovery scan. A truthful run sees only the manifests and
configs enumerated in §1.

### `vigil --db-audit`

Entry point: `privacy_audit.db_audit_mode()` at
`privacy_audit.py:867`. Walks every table in `monitor.db`, prints
schema + per-column classification (`raw / masked / opaque_id`), and
samples a redacted row per table through
`privacy_audit.redact_value_for_display`. The redaction primitive
(shipped in P5.1b as a security-C4 human-reviewed PR) is the same one
the exports pipeline (`exports.py`) uses, so what you see in the
audit is what gets emitted in any JSON / CSV / Markdown export.

## 5. Source-code transparency

The following files are the privacy-critical surfaces. Any change to
them goes through the architect-pass review tier:

- **Egress allowlist:**
  `scripts/check_privacy_no_telemetry.py:58-90` — `ALLOWED_HOSTNAMES`.
  Adding a host requires a PR justifying the new destination AND
  updating §2 above.
- **CVE feed kill-switch:**
  `src/claude_monitoring/attack_surface/cves/config.py:40-47` —
  `cve_feed_disabled()`. Returns True for `NO_NETWORK` OR
  `VIGIL_NO_CVE_FEED`.
- **Reputation kill-switch:**
  `src/claude_monitoring/attack_surface/reputation/config.py:54-56` —
  `reputation_disabled()`. Returns True for `NO_NETWORK` OR
  `VIGIL_NO_REPUTATION`.
- **Daemon CVE-poll gate:**
  `src/claude_monitoring/cve_poll_scheduler.py:102-113` — fail-closed
  early return on `cve_feed_disabled()`.
- **Env-var redaction primitive:**
  `src/claude_monitoring/attack_surface/discovery/helpers.py:471-567`
  — `redact_secrets_in_env` + `redact_secrets_in_args`. Unconditional
  on every key/value in the input dict.
- **Display-time redaction primitive:**
  `src/claude_monitoring/privacy_audit.py` — `redact_value_for_display`
  + `SAFE_COLUMNS_BY_TABLE` + `CAPTURE_TABLES_NO_SAMPLES`. Shipped in
  P5.1b as a security-C4 (human-reviewed) PR.
- **CI tripwires:**
  - `scripts/check_privacy_no_telemetry.py` (egress allowlist gate)
  - `scripts/check_db_audit_classification.py` (every DB column is
    classified)
  - `pip-audit (CVE scan)` (dependency vulnerability scan)

### Independent verification ladder (spec §10.7)

1. **Run the audit modes.** `vigil --network-audit`,
   `--read-audit`, `--db-audit` produce the empirical evidence
   yourself. No screenshot, no narration — your terminal output is
   the artifact.
2. **Read the source.** The privacy-critical files above are the
   load-bearing ones. The CI tripwires guarantee they cannot drift
   silently.
3. **Audit the schema.** `vigil --db-audit` shows every column +
   classification; `scripts/check_db_audit_classification.py`
   enforces that every column gets a classification before merge.
4. **Test the kill-switch.** Set `NO_NETWORK=1`, run a discovery
   scan, and confirm via tcpdump or `lsof` that no outbound traffic
   leaves the box.
5. **Third-party audit** — deferred to v2.0 per spec §10.7. The
   per-version published audit will sit at the same canonical
   location as this document.

---

## Document scope and follow-ups

This document satisfies directive line 210 + spec §10.6 item 4
("New doc: `docs/PRIVACY-POSTURE.md` — single canonical privacy
guarantee with v0.2.2 specifics"). The other §10.6 deliverables —
README "What Vigil reads locally" section, `THREAT-MODEL.md` B4
callout extension, `security.md` §13 future-direction update — are
scoped for the v0.2.2 release-prep doc sweep, alongside the other
privacy-sensitive cluster work (P5.1, P4.1).
