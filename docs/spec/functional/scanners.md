# Functional Spec — Supply Chain and Scanners Cluster

**Modules:** `supply_chain.py`, `threat_intel.py`, `vuln_scanner.py`, `report.py`, `utils.py`
**Status:** v0.2 launch candidate

This is a combined spec for the cluster of modules that implement supply-chain intelligence, threat-intel ingestion, vulnerability scanning, report generation, and shared utilities. They are documented together because they form a cohesive subsystem and depend on each other.

## 1. Cluster purpose

The cluster delivers three of the six product capabilities described in the PRD:

- **Supply chain intelligence** (slide 5, box 2 of the pitch deck)
- **Sensitive data detection** (slide 5, box 3 — `utils.scan_sensitive` is the entry point)
- **Real-time alerts** (slide 5, box 6 — populated by all three)

Each module owns one concern. `monitor.py` orchestrates them; `dashboard.html` displays their output.

## 2. Module-by-module

### 2.1 utils.py

The shared utility layer. Three functions are hot-path:

```python
def scan_sensitive(text: str, names_only: bool = False, validate: bool = True) -> list:
    """Scan text for sensitive data patterns.
    
    Called on every captured message body, prompt, and tool call.
    Filters out low-confidence matches via the validators pipeline.
    """

def extract_file_paths(text: str) -> list[str]:
    """Extract file paths mentioned in text. Used by JSONL scanner."""

def is_ai_process(name: str, cmdline: str, exe_path: str = "") -> bool:
    """Two-tier matching: exact name + substring pattern.
    
    Called on every psutil process iteration. Must be fast.
    """
```

Plus two helpers:

```python
def extract_urls(text: str) -> list[str]: ...  # for IOC matching
def now_iso() -> str: ...  # timestamps
```

### 2.2 supply_chain.py

Package inventory across 19 package managers. Functions:

- `get_full_environment()` — collect installed packages from pip, npm, cargo, go, gem, brew, apt, and others (best effort per manager)
- `store_environment_packages(db, packages)` — persist to `environment_packages` table
- Per-manager inventory functions (`get_pip_packages`, `get_npm_packages`, etc.)

Output: structured records with `manager`, `name`, `version`, `metadata`, `last_seen`.

### 2.3 threat_intel.py

External threat intelligence feed ingestion. Functions:

- `fetch_threatfox_iocs(db)` — query abuse.ch ThreatFox for malware C2 IOCs
- `fetch_urlhaus_iocs(db)` — query abuse.ch URLhaus for malicious URLs
- `store_iocs(db, iocs)` — persist IOC records (IPs, domains, URLs, hashes)
- `record_intel_status(db, source, success, error, record_count)` — health tracking per source

The feeds are pull-based. The daemon refreshes them on a daily schedule (configurable). Stale data triggers a warning in the dashboard.

### 2.4 vuln_scanner.py

CVE detection for installed packages. The most complex module in the cluster because it combines multiple data sources:

```python
def run_full_scan(db, progress_cb=None) -> dict:
    """Run all vulnerability scanners and store results."""
```

Five-phase execution:

1. **Environment inventory** — `supply_chain.get_full_environment()` populates `environment_packages`
2. **pip-audit** — local Python-specific scan via subprocess
3. **OSV.dev** — per-package query against the OSV API (rate-limited, 6h cache)
4. **ThreatFox** — IOC refresh
5. **URLhaus** — URL feed refresh

Each phase emits progress events via the optional `progress_cb` callback. Each phase records its outcome in `intel_source_status` so the dashboard can show green/yellow/red per source.

The CVE-to-severity mapping uses three sources in priority order:

1. `database_specific.severity` field from OSV (most reliable for GHSA advisories)
2. CVSS vector string parsing (fallback)
3. Whether a fix exists (last resort)

A special case: vuln IDs starting with `MAL-` are flagged as `severity: "malicious"` regardless of CVSS — these are actively-malicious packages, not just vulnerable ones.

### 2.5 report.py

Shareable report generation in three formats:

```python
def generate_summary_report(db_path, period_days: int = 7, fmt: str = "html") -> str:
    """Generate a summary report for the given period.
    
    fmt: "html" (default, standalone HTML with Chart.js), "markdown", or "csv".
    """
```

The HTML format produces a self-contained file with inline CSS and Chart.js loaded from CDN. The Markdown format produces GitHub-flavored tables. The CSV format gives raw daily breakdowns.

Reports are triggered by `ai-monitor --report --format=html --period=7` or via a `/api/export?type=report` endpoint (planned).

## 3. Combined data flow

```
External APIs              vuln_scanner.py          db.py             dashboard.html
─────────────              ───────────────         ──────             ──────────────
OSV.dev API   ──────┐
ThreatFox     ──────┼──→  run_full_scan ──┐
URLhaus       ──────┘                     │
pip-audit (local)                         │
                                          │
                                          ▼
                                    Per-phase
                                    storage ───→  package_vulnerabilities,
                                                  iocs,
                                                  intel_source_status
                                                                            ↑
                                                                            │
                                                                  GET /api/supply_chain
                                                                  (planned endpoint)
                                                                  Renders Supply Chain tab
```

## 4. Shared failure modes

Across the cluster:

| Mode | Module | Symptom | Recovery |
|------|--------|---------|----------|
| Network down | vuln_scanner, threat_intel | OSV/ThreatFox/URLhaus return errors; `record_intel_status` flags red | Retries on next cycle |
| Rate limited | vuln_scanner | OSV returns 429; cached results used | Respect 6h cache; backoff |
| pip not installed | vuln_scanner, supply_chain | pip-audit phase skipped | Linux/macOS guard installed pip |
| External tool fails (brew, npm) | supply_chain | That manager skipped; others continue | Per-manager isolation |
| Validator import fails | utils | Falls back to unvalidated matches | Already handled in code |

## 5. Hot-path notes

- `utils.scan_sensitive` runs on every captured message body and tool call. Pattern compilation is module-level. Validator dispatch is dict lookup (O(1)).
- `utils.is_ai_process` runs on every psutil process iter (~30s interval × 100+ processes). Exact-match tier hits the fast path; pattern-match tier handles edge cases.
- `vuln_scanner.run_full_scan` runs on a daily schedule (cold path); not optimization-sensitive.
- `report.generate_summary_report` runs on user request (cold path); HTML generation is acceptable to spend 100ms on.

## 6. Extension points

- **New package manager:** add to `supply_chain.py` (one new function per manager); add to `ECOSYSTEM_MAP` in `vuln_scanner.py`
- **New threat intel feed:** add a `fetch_<source>_iocs()` function to `threat_intel.py`; register in `vuln_scanner.run_full_scan`
- **New sensitive pattern:** add to `constants.SENSITIVE_PATTERNS`; optionally add validator
- **New report format:** add a `_render_<fmt>` function to `report.py`; dispatch in `generate_summary_report`

## 7. Testing

- **Unit tests:** `tests/test_utils.py` covers `scan_sensitive` with positive/negative cases per pattern
- **Mocked external APIs:** `tests/test_vuln_scanner.py` uses responses library to fake OSV.dev
- **Integration tests:** real pip-audit invocation in `tests/integration/test_vuln_scan.py`
- **Report snapshot tests:** golden-file comparison for HTML/Markdown output

## 8. Dependencies

- Standard library: `csv`, `io`, `json`, `re`, `urllib.request`, `subprocess`, `time`, `datetime`, `sqlite3`, `pathlib`
- Project modules: `config`, `constants`, `validators`, `utils`, `db`, `security` (only for `mask_value` in reports)
- Third-party: none beyond stdlib for the core scanners

This is by design — the supply chain cluster has minimal external dependencies so it can run in restricted environments.

## 9. Future direction

- **GitHub Advisory Database direct integration (v0.3):** more granular than OSV.dev
- **NVD direct integration (v0.3):** CVE data with CVSS v3.1 vectors
- **Custom IOC feeds (v1.0 Enterprise):** customers can plug in their own threat intel sources
- **Snyk integration (v1.0):** for customers who already pay Snyk, ingest their findings here
- **Real-time CVE alerting (v0.3):** new CVE for an installed package triggers an immediate alert, not just on next scan
- **Package reputation scoring (v0.4):** maintainer trust, publication patterns, popularity, age — to flag suspicious packages before they have a CVE
