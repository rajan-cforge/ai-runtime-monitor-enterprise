# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Vulnerability scanner — pip-audit + OSV.dev integration."""

import json
import subprocess
import time
import urllib.request
from datetime import datetime, timezone

ECOSYSTEM_MAP = {
    "pip": "PyPI",
    "npm": "npm",
    "cargo": "crates.io",
    "go": "Go",
    "gem": "RubyGems",
    "brew": None,
    "apt": None,
}


def resolve_installed_version(package_name, manager):
    """Get actual installed version of a package."""
    try:
        if manager == "pip":
            result = subprocess.run(
                ["pip", "show", package_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
        elif manager == "npm":
            result = subprocess.run(
                ["npm", "list", package_name, "--json", "--depth=0"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            data = json.loads(result.stdout)
            deps = data.get("dependencies", {})
            if package_name in deps:
                return deps[package_name].get("version", "")
    except Exception:
        pass
    return ""


def run_pip_audit():
    """Run pip-audit and return vulnerability data."""
    try:
        result = subprocess.run(
            ["pip-audit", "--format=json", "--desc"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode in (0, 1):  # 1 = vulns found
            data = json.loads(result.stdout)
            vulns = []
            for dep in data.get("dependencies", []):
                for v in dep.get("vulns", []):
                    vulns.append(
                        {
                            "package_name": dep["name"],
                            "package_version": dep["version"],
                            "ecosystem": "PyPI",
                            "vuln_id": v.get("id", ""),
                            "aliases": json.dumps(v.get("aliases", [])),
                            "severity": _fix_severity(v.get("fix_versions", [])),
                            "cvss_score": None,
                            "fix_version": v["fix_versions"][0] if v.get("fix_versions") else None,
                            "description": (v.get("description") or "")[:200],
                            "source": "pip-audit",
                        }
                    )
            return vulns
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return []


def _fix_severity(fix_versions):
    """Estimate severity from whether a fix exists."""
    return "high" if fix_versions else "medium"


def query_osv(package_name, ecosystem, version=None):
    """Query OSV.dev for vulnerabilities."""
    if not ecosystem:
        return []
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version and version != "latest":
        payload["version"] = version
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        results = []
        for vuln in data.get("vulns", []):
            cvss = _extract_cvss(vuln)
            _, db_sev = _extract_db_severity(vuln)
            # MAL- prefix = malicious code, not just a vulnerability
            is_malicious = vuln.get("id", "").startswith("MAL-")
            severity = "malicious" if is_malicious else (db_sev if db_sev != "unknown" else _cvss_to_severity(cvss))
            fix_version = _extract_fix(vuln)
            results.append(
                {
                    "package_name": package_name,
                    "package_version": version or "unknown",
                    "ecosystem": ecosystem,
                    "vuln_id": vuln.get("id", ""),
                    "aliases": json.dumps(vuln.get("aliases", [])),
                    "severity": severity,
                    "cvss_score": cvss,
                    "fix_version": fix_version,
                    "description": (vuln.get("summary") or "")[:200],
                    "source": "osv",
                    "published": vuln.get("published", ""),
                    "modified": vuln.get("modified", ""),
                }
            )
        return results
    except Exception:
        return []


_SEVERITY_SCORE_MAP = {
    "CRITICAL": (9.5, "critical"),
    "HIGH": (7.5, "high"),
    "MODERATE": (5.0, "medium"),
    "MEDIUM": (5.0, "medium"),
    "LOW": (2.5, "low"),
}


def _extract_db_severity(vuln):
    """Extract severity from OSV database_specific field (most reliable source)."""
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if db_sev:
        mapped = _SEVERITY_SCORE_MAP.get(db_sev.upper())
        if mapped:
            return mapped
    return None, "unknown"


def _extract_cvss(vuln):
    """Extract CVSS score from OSV vulnerability — try multiple sources."""
    # Source 1: database_specific.severity (always present for GHSA)
    db_score, db_sev = _extract_db_severity(vuln)
    if db_score is not None:
        return db_score
    # Source 2: CVSS vector string in severity array
    for s in vuln.get("severity", []):
        if s.get("type") == "CVSS_V3":
            score_str = s.get("score", "")
            # CVSS vector: "CVSS:3.1/AV:N/AC:L/..."
            # Try numeric first (some provide just the score)
            try:
                return float(score_str)
            except (ValueError, TypeError):
                pass
            # Map from vector prefix to estimated score based on AV/AC/C/I/A
            if "/C:H" in score_str or "/I:H" in score_str:
                return 7.5
            if "/C:N" in score_str and "/I:N" in score_str and "/A:H" in score_str:
                return 7.0
            return 5.0  # conservative estimate for any CVSS presence
    return None


def _extract_fix(vuln):
    """Extract fix version from OSV vulnerability."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for evt in rng.get("events", []):
                if "fixed" in evt:
                    return evt["fixed"]
    return None


def _cvss_to_severity(cvss):
    """Map CVSS score to severity label."""
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def store_vuln(db, vuln):
    """Store a vulnerability record with dedup."""
    try:
        db.execute(
            """INSERT OR IGNORE INTO package_vulnerabilities
               (scan_timestamp, package_name, package_version, ecosystem,
                vuln_id, aliases, severity, cvss_score, fix_version,
                description, source, published, modified)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                vuln["package_name"],
                vuln.get("package_version"),
                vuln.get("ecosystem"),
                vuln["vuln_id"],
                vuln.get("aliases", "[]"),
                vuln.get("severity", "unknown"),
                vuln.get("cvss_score"),
                vuln.get("fix_version"),
                vuln.get("description", ""),
                vuln.get("source", ""),
                vuln.get("published", ""),
                vuln.get("modified", ""),
            ),
        )
    except Exception:
        pass


def run_full_scan(db, progress_cb=None):
    """Run all vulnerability scanners and store results.

    Feature B: ``progress_cb(phase, status, records, error)`` is an optional
    callback invoked before/after each phase so the dashboard can stream
    progress. ``phase`` is one of:
      - "environment" (full installed-package inventory via pip/brew list)
      - "pip-audit"  (local Python vuln scan)
      - "osv"        (OSV.dev query per package)
      - "threatfox"  (abuse.ch IOC refresh)
      - "urlhaus"    (abuse.ch URL feed refresh)
      - "registry"   (PyPI/npm metadata refresh — future)
    ``status`` is "running" | "done" | "error".

    Also records per-source health into intel_source_status so the
    status endpoint can show green/yellow/red for pip-audit and OSV.
    """
    from claude_monitoring.supply_chain import (
        get_full_environment,
        store_environment_packages,
    )
    from claude_monitoring.threat_intel import (
        fetch_threatfox_iocs,
        fetch_urlhaus_iocs,
        record_intel_status,
        store_iocs,
    )

    def _cb(*args, **kwargs):
        if progress_cb is not None:
            try:
                progress_cb(*args, **kwargs)
            except Exception:
                pass

    results = {"scanned": 0, "vulns_found": 0, "new_since_last_scan": 0}
    scan_start = datetime.now(timezone.utc).isoformat()

    # ── Phase 0: full environment inventory (pip list + brew list) ──
    # Populates environment_packages so the Supply Chain tab's
    # "Full Environment" view has something to render. Before this
    # phase existed, the table stayed empty forever because
    # get_full_environment() was defined but never called.
    _cb("environment", "running")
    try:
        env_pkgs = get_full_environment()
        store_environment_packages(db, env_pkgs)
        record_intel_status(db, "environment", success=True, record_count=len(env_pkgs))
        _cb("environment", "done", records=len(env_pkgs))
    except Exception as exc:
        record_intel_status(db, "environment", success=False, error=str(exc)[:200])
        _cb("environment", "error", error=str(exc)[:200])

    # ── Phase 1: pip-audit (local, fast) ──
    _cb("pip-audit", "running")
    try:
        pip_vulns = run_pip_audit()
        for v in pip_vulns:
            store_vuln(db, v)
        results["vulns_found"] += len(pip_vulns)
        results["scanned"] += 1
        record_intel_status(db, "pip-audit", success=True, record_count=len(pip_vulns))
        _cb("pip-audit", "done", records=len(pip_vulns))
    except Exception as exc:
        record_intel_status(db, "pip-audit", success=False, error=str(exc)[:200])
        _cb("pip-audit", "error", error=str(exc)[:200])

    # ── Phase 2: OSV.dev per package ──
    _cb("osv", "running")
    osv_count = 0
    try:
        packages = db.execute(
            """SELECT DISTINCT package_name, package_manager, package_version
               FROM agent_dependencies WHERE category='package'"""
        ).fetchall()

        for pkg in packages:
            name = pkg["package_name"] if hasattr(pkg, "keys") else pkg[0]
            manager = pkg["package_manager"] if hasattr(pkg, "keys") else pkg[1]
            version = pkg["package_version"] if hasattr(pkg, "keys") else pkg[2]
            ecosystem = ECOSYSTEM_MAP.get(manager)
            if not ecosystem:
                continue

            # Cache: skip if scanned in last 6 hours
            cached = db.execute(
                """SELECT scan_timestamp FROM package_vulnerabilities
                   WHERE package_name=? AND source='osv'
                   ORDER BY scan_timestamp DESC LIMIT 1""",
                (name,),
            ).fetchone()
            if cached:
                try:
                    cache_ts = cached["scan_timestamp"] if hasattr(cached, "keys") else cached[0]
                    age = time.time() - datetime.fromisoformat(cache_ts.replace("Z", "+00:00")).timestamp()
                    if age < 21600:
                        continue
                except Exception:
                    pass

            osv_vulns = query_osv(name, ecosystem, version if version != "latest" else None)
            for v in osv_vulns:
                store_vuln(db, v)
            osv_count += len(osv_vulns)
            results["vulns_found"] += len(osv_vulns)
            results["scanned"] += 1
            time.sleep(0.5)  # Rate limit
        record_intel_status(db, "osv", success=True, record_count=osv_count)
        _cb("osv", "done", records=osv_count)
    except Exception as exc:
        record_intel_status(db, "osv", success=False, error=str(exc)[:200])
        _cb("osv", "error", error=str(exc)[:200])

    # ── Phase 3: ThreatFox IOC refresh ──
    _cb("threatfox", "running")
    try:
        iocs = fetch_threatfox_iocs(db=db)
        tf_count = 0
        if iocs and (iocs.get("ips") or iocs.get("domains")):
            tf_count = store_iocs(db, iocs)
        _cb("threatfox", "done", records=tf_count or 0)
    except Exception as exc:
        _cb("threatfox", "error", error=str(exc)[:200])

    # ── Phase 4: URLhaus refresh ──
    _cb("urlhaus", "running")
    try:
        uh_count = fetch_urlhaus_iocs(db)
        _cb("urlhaus", "done", records=uh_count or 0)
    except Exception as exc:
        _cb("urlhaus", "error", error=str(exc)[:200])

    # ── Phase 5: Registry metadata refresh (synthetic — just record the state) ──
    _cb("registry", "running")
    try:
        reg_count = db.execute("SELECT COUNT(*) FROM package_registry_cache").fetchone()[0]
        record_intel_status(db, "registry", success=True, record_count=reg_count)
        _cb("registry", "done", records=reg_count)
    except Exception as exc:
        _cb("registry", "error", error=str(exc)[:200])

    # Compute delta: vulns newly added since this scan started
    try:
        row = db.execute(
            "SELECT COUNT(*) FROM package_vulnerabilities WHERE scan_timestamp >= ?",
            (scan_start,),
        ).fetchone()
        results["new_since_last_scan"] = int(row[0] if row else 0)
    except Exception:
        pass

    # Store scan history
    try:
        db.execute(
            """INSERT INTO scan_history (timestamp, packages_scanned, vulns_found, sources)
               VALUES (?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                results["scanned"],
                results["vulns_found"],
                "pip-audit,osv,threatfox,urlhaus,registry",
            ),
        )
    except Exception:
        pass
    db.commit()
    return results
