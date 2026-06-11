"""P4.1 CVE dispatcher — per-scan orchestration with per-item isolation.

Walks the asset list, batches package-type assets into a single
``POST /v1/querybatch`` call (when not already cached), then fetches
the unique vuln IDs via ``GET /v1/vulns/{id}`` (subject to a 50-call
budget per scan; cached aggressively at 7d TTL).

Per Phase A §5, §7, §8 — tri-state result per asset:

  ``None`` + ``reason``  — KILL_SWITCH / NO_NETWORK / RATE_LIMITED /
                            BUDGET_EXHAUSTED / NETWORK_ERROR / PARSE_ERROR
  ``[]``                 — looked up, no known vulns
  ``[{"cvss": float}, …]`` — `compute_risk_score` consumes this shape

Per-item isolation: one asset's failure NEVER raises out of the
dispatcher. Each per-item exception is caught + logged + recorded as
``cves=None`` with the right reason, and the next asset proceeds
normally. Matches `project_v022_per_item_isolation` rider.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from claude_monitoring.attack_surface.cves import config
from claude_monitoring.attack_surface.cves.client import (
    OSVClient,
    OSVError,
    OSVNetworkError,
    OSVNotFound,
    OSVParseError,
    OSVRateLimited,
)
from claude_monitoring.attack_surface.cves.querybatch_cache import QuerybatchCache
from claude_monitoring.attack_surface.cves.types import CVEResult, UnavailableReason
from claude_monitoring.attack_surface.cves.vulns_cache import VulnsCache

logger = logging.getLogger("ai-runtime-monitor.attack_surface.cves.dispatcher")


# ---------------------------------------------------------------------------
# Source → OSV ecosystem map (Phase A §9 — only the 3 package-type sources;
# everything else returns cves=None with reason=None, score-unchanged)
# ---------------------------------------------------------------------------

_SOURCE_TO_ECOSYSTEM: dict[str, str] = {
    "python-packages": "PyPI",
    "python-project-deps": "PyPI",
    "node-packages": "npm",
}


def _ecosystem_for_source(source: str) -> str | None:
    return _SOURCE_TO_ECOSYSTEM.get(source)


_EXACT_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)*(?:[\-+a-zA-Z0-9.]+)?$")
"""OSV's `/v1/querybatch` needs an exact version. python_project_deps + node_packages
emit `Asset.version = version_spec` which may be a range (`>=2.0`, `^1.0`, `~1`,
etc.) — those are not OSV-queryable and must be skipped, not guessed. This regex
accepts a leading digit + dot-separated digits + an optional suffix
(`1.0.0`, `2.25.0`, `1.0.0a1`, `1.0.0-rc.1`, `2.0+meta`). Rejects anything
beginning with `<>=~^*!` or containing space, comma, pipe."""


def _package_version(asset: Any) -> tuple[str, str] | None:
    """Extract (package, version) from an asset, or None if unqueryable.

    Reads the MERGED source contracts (verified 2026-06-11 against
    `python_packages.py:252-258`, `python_project_deps.py:440-448`,
    `node_packages.py:411-419`):

      * `current_state["package_name"]` — the canonical name on all three
        sources. `package_name_normalized` exists alongside but is for
        identity, not OSV (OSV uses the canonical name).
      * `asset.version` — the version on `python-packages` is a real
        installed version (always exact); on `python-project-deps` and
        `node-packages` it is the `version_spec`, which may be a range
        like `>=2.0` / `^1.0` / `*`. Ranges are NOT OSV-queryable; the
        regex `_EXACT_VERSION_RE` requires a literal version.

    Per Phase A §9 + verdict scan-scoring-callsite.a1 Finding 1: NEVER
    guess at a range — return ``None`` so the asset surfaces as
    ``cve_status="not_applicable"`` (range was not queryable), distinct
    from "we asked and OSV said clean".
    """
    state = getattr(asset, "current_state", None) or {}
    pkg = state.get("package_name")
    ver = getattr(asset, "version", None)
    if not isinstance(pkg, str) or not pkg:
        return None
    if not isinstance(ver, str) or not _EXACT_VERSION_RE.match(ver):
        return None
    return pkg, ver


# ---------------------------------------------------------------------------
# CVE record → scoring-formula shape
# ---------------------------------------------------------------------------

_CVSS_VECTOR_PREFIXES = ("CVSS:3.", "CVSS:2.")
"""OSV severity records use a CVSS vector string in `severity[].score`.
We extract the numeric base score using the `cvss` library when present;
falls back to a defensive 0.0 if not parseable. Score-vs-vector
distinction is captured in the docstring."""


def _cvss_score_from_vector(vector: str) -> float | None:
    """Parse a CVSS vector → numeric base score. Returns None on parse
    failure or missing `cvss` dependency."""
    try:
        from cvss import CVSS2, CVSS3  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover — dependency is a tightening pass
        return None
    try:
        if vector.startswith("CVSS:3."):
            return float(CVSS3(vector).base_score)
        if vector.startswith("CVSS:2."):
            return float(CVSS2(vector).base_score)
    except Exception:
        return None
    return None


def _vuln_record_to_score_dict(record: dict) -> dict | None:
    """Convert an OSV vuln record → the `{"cvss": float, "id": ...}` shape
    that `compute_risk_score`'s `cves` argument expects.

    Returns None when the record has no usable severity (the dispatcher
    treats this as "vuln exists but unparseable" — we still surface the
    ID in `cves` with a fallback score of 0.0 so downstream UI can list it.
    """
    severities = record.get("severity") or []
    if not isinstance(severities, list):
        return None
    for entry in severities:
        if not isinstance(entry, dict):
            continue
        vector = entry.get("score")
        if not isinstance(vector, str):
            continue
        score = _cvss_score_from_vector(vector)
        if score is not None:
            return {"cvss": score, "id": record.get("id")}
    # Vuln exists but no parseable severity — surface as a 0.0 entry so
    # the operator can see the ID in the dashboard, but it doesn't move
    # the max-CVSS scoring needle.
    return {"cvss": 0.0, "id": record.get("id")}


class CVEDispatcher:
    """Per-scan CVE lookup orchestrator.

    Construct fresh per scan (or per orchestrator instance) — holds a
    budget counter and the two cache files. The OSV ``client`` is
    injected so tests can swap a `MagicMock`.
    """

    def __init__(
        self,
        *,
        client: OSVClient | None = None,
        querybatch_cache: QuerybatchCache | None = None,
        vulns_cache: VulnsCache | None = None,
    ) -> None:
        self._client = client or OSVClient()
        self._qb_cache = querybatch_cache or QuerybatchCache(config.get_querybatch_cache_path())
        self._vc = vulns_cache or VulnsCache(config.get_vulns_cache_path())
        self._budget_remaining = config.VULN_DETAIL_CALLS_PER_SCAN_BUDGET

    def scan(self, assets: list[Any]) -> dict[str, CVEResult]:
        """Return `{asset.id: CVEResult}` for every asset in input order.

        Assets without an OSV ecosystem (skip-list sources, missing
        package/version) get `cves=None, reason=None` — distinct from
        the kill-switch path which sets ``reason=KILL_SWITCH``.
        """
        if config.cve_feed_disabled():
            return {asset.id: CVEResult(cves=None, reason=UnavailableReason.KILL_SWITCH) for asset in assets}

        # Phase 1: classify and gather querybatch inputs.
        queryable: list[tuple[Any, str, str, str]] = []  # (asset, ecosystem, pkg, ver)
        results: dict[str, CVEResult] = {}
        for asset in assets:
            ecosystem = _ecosystem_for_source(asset.source)
            if ecosystem is None:
                results[asset.id] = CVEResult(cves=None, reason=None)
                continue
            pv = _package_version(asset)
            if pv is None:
                results[asset.id] = CVEResult(cves=None, reason=None)
                continue
            queryable.append((asset, ecosystem, pv[0], pv[1]))

        if not queryable:
            return results

        # Phase 2: cache lookup → batch-fetch the rest.
        asset_to_vuln_ids: dict[str, list[str]] = {}
        uncached_queries: list[dict] = []
        uncached_index: list[tuple[Any, str, str, str]] = []
        for asset, eco, pkg, ver in queryable:
            cached = self._qb_cache.get(eco, pkg, ver)
            if cached is not None:
                asset_to_vuln_ids[asset.id] = cached
            else:
                uncached_queries.append({"package": {"name": pkg, "ecosystem": eco}, "version": ver})
                uncached_index.append((asset, eco, pkg, ver))

        if uncached_queries:
            try:
                vuln_id_lists = self._client.querybatch(uncached_queries)
            except OSVRateLimited:
                for asset, _, _, _ in uncached_index:
                    results[asset.id] = CVEResult(cves=None, reason=UnavailableReason.RATE_LIMITED)
                vuln_id_lists = []
            except OSVNetworkError:
                for asset, _, _, _ in uncached_index:
                    results[asset.id] = CVEResult(cves=None, reason=UnavailableReason.NETWORK_ERROR)
                vuln_id_lists = []
            except OSVParseError:
                for asset, _, _, _ in uncached_index:
                    results[asset.id] = CVEResult(cves=None, reason=UnavailableReason.PARSE_ERROR)
                vuln_id_lists = []
            for (asset, eco, pkg, ver), ids in zip(uncached_index, vuln_id_lists, strict=False):
                asset_to_vuln_ids[asset.id] = ids
                self._qb_cache.set(eco, pkg, ver, vuln_ids=ids)

        # Phase 3: detail-fetch + per-item isolation + budget.
        for asset, _, _, _ in queryable:
            if asset.id in results:
                continue  # already failed at querybatch
            vuln_ids = asset_to_vuln_ids.get(asset.id, [])
            if not vuln_ids:
                results[asset.id] = CVEResult(cves=[])
                continue
            try:
                cves_for_asset = self._fetch_details(vuln_ids)
            except _BudgetExhausted:
                results[asset.id] = CVEResult(cves=None, reason=UnavailableReason.BUDGET_EXHAUSTED)
                continue
            results[asset.id] = CVEResult(cves=cves_for_asset)

        return results

    # ---------------------------------------------------------------- internals
    def _fetch_details(self, vuln_ids: list[str]) -> list[dict]:
        """Look up each vuln ID. Returns the score-dicts for the ones that
        succeeded; raises `_BudgetExhausted` if we cannot fetch the first
        uncached ID for this asset (best-effort: fully-cached assets are
        always served)."""
        cves_for_asset: list[dict] = []
        for vid in vuln_ids:
            cached_record = self._vc.get(vid)
            if cached_record is not None:
                score = _vuln_record_to_score_dict(cached_record)
                if score is not None:
                    cves_for_asset.append(score)
                continue
            if self._budget_remaining <= 0:
                # Per-asset: if we haven't found ANY useful vulns yet AND
                # there are no cached lookups left, treat as budget-exhausted
                # for this asset so the UI can show the right reason.
                if not cves_for_asset:
                    raise _BudgetExhausted()
                # Otherwise: we have partial data; surface what we have.
                break
            try:
                record = self._client.vuln_detail(vid)
            except OSVNotFound:
                logger.warning("vuln_detail 404 for %s — record removed/retracted", vid)
                self._budget_remaining -= 1
                continue
            except (OSVError, OSVNetworkError, OSVRateLimited, OSVParseError) as exc:
                logger.warning("vuln_detail failed for %s: %s", vid, exc)
                self._budget_remaining -= 1
                continue
            self._budget_remaining -= 1
            self._vc.set(vid, record=record)
            score = _vuln_record_to_score_dict(record)
            if score is not None:
                cves_for_asset.append(score)
        return cves_for_asset


class _BudgetExhausted(Exception):
    """Internal signal: hit the per-scan vuln-detail call cap before fetching
    any usable data for this asset. Caught by `scan()` to set the right
    `UnavailableReason`."""
