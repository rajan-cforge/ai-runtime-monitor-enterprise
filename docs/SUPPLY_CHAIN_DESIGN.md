# Supply Chain Tab — Design & Flow

Quick reference for how the Supply Chain monitoring tab works end-to-end:
data pipeline, scanning, risk assessment, threat correlation, and
dashboard rendering.

---

## Architecture overview

```
 Agent Bash commands              Periodic scan ("Scan now")
        |                                   |
        v                                   v
 parse_install_command()         run_full_scan() — 6 phases
        |                       ┌───────────────────────────────┐
        v                       │ Phase 0: pip list + brew list │
 agent_dependencies             │ Phase 1: pip-audit            │
   (real-time)                  │ Phase 2: OSV.dev per-package  │
                                │ Phase 3: ThreatFox CSV feed   │
                                │ Phase 4: URLhaus CSV feed     │
                                │ Phase 5: Registry metadata    │
                                └──────────┬────────────────────┘
                                           |
                  ┌────────────────────────┬┴──────────────────┐
                  v                        v                   v
        environment_packages    package_vulnerabilities   threat_iocs
                  |                        |                   |
                  └────────────┬───────────┘                   |
                               v                               v
                   /api/supply-chain/*               IOC correlation
                               |                    (network monitor)
                               v
                       Dashboard UI
```

---

## Data sources & tables

### `agent_dependencies` — real-time package detection

Populated whenever an AI agent runs a package install via Bash
(e.g. `pip install requests`, `npm i express`, `cargo add serde`).

**Flow:** JSONL event → `monitor.py::_check_supply_chain()` →
`supply_chain.parse_install_command()` → `supply_chain.store_dependency()`.

Each row stores: package name, version, manager, pinned flag, risk
score, risk flags (JSON), the original command, session ID, and a
dedup hash. Typosquats and high-risk packages trigger alerts on insert.

**Supported managers:** pip, npm, yarn, pnpm, cargo, go, gem, brew,
apt, apt-get, npx (remote exec detection).

### `environment_packages` — full machine inventory

Populated by the "environment" phase of `run_full_scan()`.

- **pip:** `python -m pip list --format=json` (uses `sys.executable`
  to avoid PATH issues under launchd)
- **brew:** `/opt/homebrew/bin/brew list --versions` (absolute path,
  falls back to `/usr/local/bin/brew` for Intel Macs)

UPSERT on `(package_name, manager)`, so subsequent scans update
versions without duplicating rows.

### `package_vulnerabilities` — CVEs and advisories

Populated by two scan phases:

1. **pip-audit** (Phase 1): runs `pip-audit --format=json --desc`
   against the active Python environment. Fast, local-only.
2. **OSV.dev** (Phase 2): queries `api.osv.dev/v1/query` per package
   from `agent_dependencies`. Extracts CVSS scores, severity levels,
   fix versions, and advisory URLs. Detects malicious packages via the
   `MAL-` prefix convention. 6-hour cache per package.

### `threat_iocs` — IP and domain indicators of compromise

Populated by two threat feed phases:

3. **ThreatFox** (Phase 3): GET `threatfox.abuse.ch/export/csv/recent/`.
   Extracts `ip:port` and `domain` IOC types with malware family +
   confidence level. ~900 IOCs per pull.
4. **URLhaus** (Phase 4): GET `urlhaus.abuse.ch/downloads/csv_recent/`.
   Extracts hostnames from malicious URLs. Capped at 500 rows/pull.

Both feeds are public CSV exports (no API key required). IOCs are
correlated against outbound network connections at runtime via
`threat_intel.check_connection_against_iocs()`.

### `intel_source_status` — feed health tracking

One row per source (environment, pip-audit, osv, threatfox, urlhaus,
registry). Tracks `last_attempt`, `last_success`, `last_error`,
`record_count`. Every fetcher calls `record_intel_status()` on
success or failure, feeding the 4-state health dots on the dashboard.

### `package_registry_cache` — PyPI / npm metadata

Fetched on-demand when a user expands a package row. Stores description,
author, license, repository URL, first publish date, maintainer list,
and publisher change history. Used by the risk scorer for signals like
"published <24h ago" or "maintainer changed recently."

---

## Scan pipeline — `run_full_scan()`

Triggered by POST `/api/supply-chain/scan`. Runs in a daemon thread.
The UI polls `/api/supply-chain/scan-progress` every 1s for phase-by-phase
status. Six phases execute sequentially:

| Phase | Source | What it does | Typical duration |
|-------|--------|--------------|------------------|
| 0 | environment | `pip list` + `brew list` → `environment_packages` | 2-5s |
| 1 | pip-audit | `pip-audit --format=json` → `package_vulnerabilities` | 5-15s |
| 2 | osv | Query osv.dev per agent-installed package (0.5s rate limit) | 30-90s |
| 3 | threatfox | Fetch CSV, parse IPs + domains → `threat_iocs` | 3-8s |
| 4 | urlhaus | Fetch CSV, parse URLs → hostnames → `threat_iocs` | 3-8s |
| 5 | registry | Count cached metadata rows (synthetic) | <1s |

Each phase emits a `progress_cb(phase, status, records, error)` callback
that updates the global `_scan_state` dict under a threading lock. The
progress endpoint returns a snapshot of this dict.

Concurrent scans are rejected with HTTP 409.

---

## Risk assessment — `assess_risk()`

Every agent-installed package gets a risk score (0-10) computed from:

| Signal | Points | Example |
|--------|--------|---------|
| Known typosquat | +5 | `reqeusts` instead of `requests` |
| Active critical CVE | +5 per CVE | CVE with CVSS >= 9.0 |
| Active high CVE | +3 per CVE | CVE with CVSS >= 7.0 |
| npx remote exec | +3 | `npx create-evil-app` |
| High-capability package | +3 | `python-binance`, `mitmproxy`, `ssh2-python` |
| Financial keywords | +2 | package name contains `trade`, `wallet`, etc. |
| Unpinned version | +1 | `pip install requests` (no `==`) |
| Active medium CVE | +1 per CVE | CVE with CVSS >= 4.0 |

**Risk levels:** critical (>=7), high (>=4), medium (>=2), low (<2).

### Registry risk scoring — `assess_registry_risk()`

Additional signals from PyPI/npm metadata:

| Signal | Points |
|--------|--------|
| Published <24h ago | +4 |
| Published 1-7 days ago | +2 |
| No description + no repository | +2 |
| Has postinstall scripts (npm) | +2 |
| Maintainer changed <7 days ago | +5 |
| Maintainer changed <30 days ago | +3 |
| Single maintainer | +1 |
| No source repository | +1 |
| Yanked versions | +2 |

---

## IOC correlation

When the network monitor detects an outbound connection, it calls
`check_connection_against_iocs(remote_host, db)`:

1. Exact IP match against `threat_iocs WHERE ioc_type='ip'`
2. Exact domain match against `threat_iocs WHERE ioc_type='domain'`
3. Subdomain walk: `sub.evil.com` → check `evil.com` → check `com`

If a match is found, `correlate_install_to_connection()` checks whether
a package was installed within 60 seconds before the connection — linking
"agent installed package X" → "process immediately connected to known-bad
IP/domain Y."

---

## Dashboard UI

### Intel health bar

Five colored dots at the top of the Supply Chain tab. Each represents
one intel source with a 4-state indicator:

- **Green:** last successful fetch within 24 hours
- **Yellow:** last successful fetch was >24 hours ago (stale)
- **Red:** last fetch attempt failed (error stored)
- **Gray:** source has never been fetched

Hover shows a tooltip with record count, last attempt/success timestamps,
and error message if red. "Refresh all" button triggers
POST `/api/supply-chain/intel-refresh` (ThreatFox + URLhaus only).

### Scan progress panel

Appears when "Scan now" is clicked. Shows 6 rows with status icons:

```
 ✅ Environment inventory    (183 records)
 ✅ pip-audit                (0 records)
 ⏳ OSV.dev                  in progress...
 ⏸ ThreatFox                pending
 ⏸ URLhaus                  pending
 ⏸ Registry metadata        pending
```

On completion: "Scan complete: N vulns across M packages, X new since
last scan."

### Package table

Three views controlled by filters:

- **All / Full Environment:** queries `/api/supply-chain/environment`,
  returns every pip + brew package with cross-referenced vuln counts.
- **Agent-installed:** queries `/api/supply-chain?view=grouped`, returns
  only packages installed by AI agents via Bash, grouped by
  (name, manager), with risk scores and install history.
- **Tool Executions / System Tools:** same endpoint with
  `category=tool_exec` or `category=build_tool` filter.

### Row expansion (detail panel)

Clicking a row calls `scExpandRow()` which renders three sections:

1. **Vulnerabilities:** CVE table with ID, severity, CVSS score,
   affected/fixed version comparison, advisory link. Queries
   `package_vulnerabilities` for the package.
2. **Registry metadata:** author, license, repository, first published
   date, maintainer count, publisher change alerts. Fetched on-demand
   from `/api/supply-chain/registry`.
3. **Install history:** every Bash command that installed this package,
   with timestamps, session links, and pinned/unpinned flags. Queries
   `/api/supply-chain/detail`.

### SBOM export

"Export SBOM" button generates a CycloneDX 1.5 JSON document from
`agent_dependencies` + `package_vulnerabilities`. Includes component
name, version, manager (as purl), and linked vulnerability IDs.

### Watchlist

Auto-populated from agent-installed packages (high priority, 6h check)
and packages with active CVEs (high priority, 6h check). Drives the
monitoring badge: "Watching: N critical (hourly) / M high (6h) / K
normal (daily)."

---

## API endpoints summary

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/supply-chain` | Agent-installed packages (grouped, filtered) |
| GET | `/api/supply-chain/detail` | Install history for one package |
| GET | `/api/supply-chain/environment` | Full pip+brew inventory with vuln cross-ref |
| GET | `/api/supply-chain/scan-status` | Last scan timestamp + vuln totals |
| GET | `/api/supply-chain/scan-progress` | Live scan phase-by-phase status |
| GET | `/api/supply-chain/intel-status` | 5-source health (green/yellow/red/gray) |
| GET | `/api/supply-chain/registry` | PyPI/npm metadata for one package |
| GET | `/api/supply-chain/sbom` | CycloneDX 1.5 JSON export |
| GET | `/api/supply-chain/watchlist` | Auto-generated watchlist with priority counts |
| POST | `/api/supply-chain/scan` | Trigger full 6-phase scan (async, returns immediately) |
| POST | `/api/supply-chain/intel-refresh` | Refresh ThreatFox + URLhaus feeds only (async) |
