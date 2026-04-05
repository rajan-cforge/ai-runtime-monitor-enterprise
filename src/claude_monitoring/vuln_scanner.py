"""Vulnerability scanner — pip-audit + OSV.dev integration."""

import json
import subprocess
import time
import urllib.request
from datetime import datetime, timezone

ECOSYSTEM_MAP = {
    "pip": "PyPI", "npm": "npm", "cargo": "crates.io",
    "go": "Go", "gem": "RubyGems", "brew": None, "apt": None,
}


def resolve_installed_version(package_name, manager):
    """Get actual installed version of a package."""
    try:
        if manager == "pip":
            result = subprocess.run(
                ["pip", "show", package_name],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if line.startswith("Version:"):
                    return line.split(":", 1)[1].strip()
        elif manager == "npm":
            result = subprocess.run(
                ["npm", "list", package_name, "--json", "--depth=0"],
                capture_output=True, text=True, timeout=5,
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
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode in (0, 1):  # 1 = vulns found
            data = json.loads(result.stdout)
            vulns = []
            for dep in data.get("dependencies", []):
                for v in dep.get("vulns", []):
                    vulns.append({
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
                    })
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
            fix_version = _extract_fix(vuln)
            results.append({
                "package_name": package_name,
                "package_version": version or "unknown",
                "ecosystem": ecosystem,
                "vuln_id": vuln.get("id", ""),
                "aliases": json.dumps(vuln.get("aliases", [])),
                "severity": _cvss_to_severity(cvss),
                "cvss_score": cvss,
                "fix_version": fix_version,
                "description": (vuln.get("summary") or "")[:200],
                "source": "osv",
                "published": vuln.get("published", ""),
                "modified": vuln.get("modified", ""),
            })
        return results
    except Exception:
        return []


def _extract_cvss(vuln):
    """Extract CVSS score from OSV vulnerability."""
    for s in vuln.get("severity", []):
        if s.get("type") == "CVSS_V3":
            try:
                return float(s["score"].split("/")[0])
            except (ValueError, IndexError, KeyError):
                pass
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
                vuln["package_name"], vuln.get("package_version"),
                vuln.get("ecosystem"), vuln["vuln_id"],
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


def run_full_scan(db):
    """Run all vulnerability scanners and store results."""
    results = {"scanned": 0, "vulns_found": 0}

    # pip-audit (local, fast)
    pip_vulns = run_pip_audit()
    for v in pip_vulns:
        store_vuln(db, v)
    results["vulns_found"] += len(pip_vulns)
    results["scanned"] += 1

    # OSV for each unique package
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

        # Check cache (skip if scanned in last 6 hours)
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
        results["vulns_found"] += len(osv_vulns)
        results["scanned"] += 1
        time.sleep(0.5)  # Rate limit

    # Store scan history
    try:
        db.execute(
            """INSERT INTO scan_history (timestamp, packages_scanned, vulns_found, sources)
               VALUES (?, ?, ?, ?)""",
            (datetime.now(timezone.utc).isoformat(), results["scanned"],
             results["vulns_found"], "pip-audit,osv"),
        )
    except Exception:
        pass
    db.commit()
    return results
