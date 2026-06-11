"""P4.1 — OSV.dev CVE feed.

Per-asset CVE lookups for package-type assets (PyPI / npm). Wires the
dominant scoring factor (`max_cve_severity`, weight 0.35 in
`compute_risk_score`) which has been accepting `cves: list[dict] | None`
since P2.3.

Phase A doc:
~/Documents/vigil-notes/v022/phase-4-prep/p4.1-osv-cve-feed-phase-a.md

Submodules:
  * `types`               — `CVEResult` dataclass + `UnavailableReason` enum
  * `config`              — env-var kill switches + TTL + budget constants
  * `querybatch_cache`    — package → vuln-ID-list cache (24h TTL)
  * `vulns_cache`         — vuln-ID → full record cache (7d TTL)
  * `client`              — OSV.dev HTTP wrapper (querybatch + detail)
  * `dispatcher`          — per-scan orchestration with per-item isolation
"""

from __future__ import annotations
