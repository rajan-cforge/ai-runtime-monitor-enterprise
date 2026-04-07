# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Threat intelligence — registry metadata, IOC feeds, malicious package detection."""

import json
import urllib.request
from datetime import datetime, timezone

# ── Registry metadata enrichment ─────────────────────────


def fetch_pypi_metadata(package_name):
    """Fetch package metadata from PyPI."""
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        resp = urllib.request.urlopen(url, timeout=10)
        data = json.loads(resp.read())
        info = data.get("info", {})
        releases = data.get("releases", {})
        # Find earliest release date
        first_release = None
        for ver_files in releases.values():
            for f in ver_files:
                upload = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload and (not first_release or upload < first_release):
                    first_release = upload
        # License: prefer classifier over raw text (which can be full license body)
        raw_license = info.get("license") or ""
        license_name = raw_license if len(raw_license) < 50 else ""
        if not license_name:
            for c in info.get("classifiers", []):
                if "License" in c and "::" in c:
                    license_name = c.split("::")[-1].strip()
                    break
        repo_url = info.get("project_urls", {}).get("Source") or info.get("project_urls", {}).get("Repository") or info.get("project_urls", {}).get("Homepage") or ""
        return {
            "name": package_name,
            "description": (info.get("summary") or "")[:200],
            "author": info.get("author") or info.get("author_email") or "",
            "license": license_name,
            "home_page": info.get("home_page") or "",
            "repository": repo_url,
            "first_published": first_release,
            "has_description": bool(info.get("summary")),
            "has_repository": bool(repo_url),
            "latest_version": info.get("version") or "",
        }
    except Exception:
        return None


def fetch_npm_metadata(package_name):
    """Fetch package metadata from npm registry with maintainer tracking."""
    try:
        url = f"https://registry.npmjs.org/{package_name}"
        resp = urllib.request.urlopen(url, timeout=10)
        data = json.loads(resp.read())
        time_data = data.get("time", {})
        created = time_data.get("created", "")
        latest = data.get("dist-tags", {}).get("latest", "")
        latest_data = data.get("versions", {}).get(latest, {})
        scripts = latest_data.get("scripts", {})
        has_install_scripts = any(k in scripts for k in ("preinstall", "postinstall", "install"))
        maintainers = data.get("maintainers", [])
        publisher = latest_data.get("_npmUser", {})
        publisher_name = publisher.get("name", "") if isinstance(publisher, dict) else str(publisher)

        # Detect publisher change between versions
        versions_list = sorted(time_data.keys() - {"created", "modified"})
        previous_version = versions_list[-2] if len(versions_list) >= 2 else None
        previous_publisher = ""
        maintainer_changed = False
        maintainer_change_age_days = None
        if previous_version:
            prev_data = data.get("versions", {}).get(previous_version, {})
            prev_user = prev_data.get("_npmUser", {})
            previous_publisher = prev_user.get("name", "") if isinstance(prev_user, dict) else str(prev_user)
            if publisher_name and previous_publisher and publisher_name.lower() != previous_publisher.lower():
                maintainer_changed = True
                try:
                    latest_ts = datetime.fromisoformat(time_data.get(latest, "").replace("Z", "+00:00"))
                    maintainer_change_age_days = (datetime.now(timezone.utc) - latest_ts).days
                except Exception:
                    maintainer_change_age_days = None

        return {
            "name": package_name,
            "description": (data.get("description") or "")[:200],
            "author": data.get("author", {}).get("name", "") if isinstance(data.get("author"), dict) else str(data.get("author", "")),
            "license": data.get("license") or "",
            "repository": data.get("repository", {}).get("url", "") if isinstance(data.get("repository"), dict) else "",
            "first_published": created,
            "has_description": bool(data.get("description")),
            "has_repository": bool(data.get("repository")),
            "has_install_scripts": has_install_scripts,
            "maintainers": maintainers,
            "maintainer_count": len(maintainers),
            "publisher": publisher_name,
            "previous_publisher": previous_publisher,
            "maintainer_changed": maintainer_changed,
            "maintainer_change_age_days": maintainer_change_age_days,
            "latest_version": latest,
            "version_count": len(data.get("versions", {})),
        }
    except Exception:
        return None


def fetch_registry_metadata(package_name, manager):
    """Fetch metadata from the appropriate registry."""
    if manager == "pip":
        return fetch_pypi_metadata(package_name)
    if manager in ("npm", "yarn", "pnpm"):
        return fetch_npm_metadata(package_name)
    return None


def assess_registry_risk(package_name, manager, meta):
    """Score registry risk signals. Returns (score, reasons)."""
    if not meta:
        return 0, []
    score = 0
    reasons = []

    # Package age
    if meta.get("first_published"):
        try:
            pub = datetime.fromisoformat(meta["first_published"].replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - pub).days
            if age_days < 1:
                score += 4
                reasons.append("Published <24h ago (+4)")
            elif age_days < 7:
                score += 2
                reasons.append(f"Published {age_days}d ago (+2)")
        except Exception:
            pass

    # Missing metadata
    if not meta.get("has_description") and not meta.get("has_repository"):
        score += 2
        reasons.append("No description, no repository (+2)")

    # Install scripts (npm only)
    if meta.get("has_install_scripts"):
        score += 2
        reasons.append("Has postinstall scripts (+2)")

    # Maintainer change detection
    if meta.get("maintainer_changed"):
        change_age = meta.get("maintainer_change_age_days")
        if change_age is not None and change_age <= 7:
            score += 5
            reasons.append(f"Maintainer changed {change_age}d ago — new publisher differs from previous (+5)")
        elif change_age is not None and change_age <= 30:
            score += 3
            reasons.append(f"Maintainer changed {change_age}d ago (+3)")
        elif change_age is not None and change_age <= 90:
            score += 1
            reasons.append(f"Maintainer changed {change_age}d ago (+1)")

    # Single maintainer — bus factor / takeover risk
    if meta.get("maintainer_count") == 1:
        score += 1
        reasons.append("Single maintainer — higher takeover risk (+1)")

    # No source repository
    if not meta.get("has_repository") and not meta.get("has_source_repo"):
        if not any("repository" in r.lower() for r in reasons):  # avoid double-counting
            score += 1
            reasons.append("No source repository linked (+1)")

    # Yanked versions (packages that were pulled)
    if meta.get("yanked_versions"):
        count = len(meta["yanked_versions"])
        score += 2
        reasons.append(f"{count} version(s) yanked (removed) — possible malicious version retracted (+2)")

    return score, reasons


# ── Maintainer change detection across scans ─────────────


def detect_maintainer_changes(name, manager, current_meta, db):
    """Compare current maintainers against last known state."""
    previous = db.execute(
        """SELECT maintainer_data, publisher, version, scan_timestamp
           FROM package_maintainer_history
           WHERE package_name = ? AND manager = ?
           ORDER BY scan_timestamp DESC LIMIT 1""",
        (name, manager),
    ).fetchone()

    curr_maintainers = current_meta.get("maintainers", [])
    curr_publisher = current_meta.get("publisher", "")
    curr_version = current_meta.get("latest_version", "")

    if previous:
        try:
            prev_maintainers = json.loads(previous["maintainer_data"] if hasattr(previous, "keys") else previous[0])
        except (json.JSONDecodeError, TypeError):
            prev_maintainers = []
        prev_publisher = (previous["publisher"] if hasattr(previous, "keys") else previous[1]) or ""

        changes = []
        prev_names = {(m.get("name", "") if isinstance(m, dict) else str(m)).lower() for m in prev_maintainers}
        curr_names = {(m.get("name", "") if isinstance(m, dict) else str(m)).lower() for m in curr_maintainers}
        added = curr_names - prev_names
        removed = prev_names - curr_names

        if added:
            changes.append(f"New maintainer(s) added: {', '.join(added)}")
        if removed:
            changes.append(f"Maintainer(s) removed: {', '.join(removed)}")
        if prev_publisher and curr_publisher and prev_publisher.lower() != curr_publisher.lower():
            changes.append(f"Publisher changed: {prev_publisher} → {curr_publisher}")

        if changes:
            # Store updated state
            try:
                db.execute(
                    """INSERT OR REPLACE INTO package_maintainer_history
                       (package_name, manager, scan_timestamp, maintainer_data, publisher, version)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (name, manager, datetime.now(timezone.utc).isoformat(),
                     json.dumps(curr_maintainers), curr_publisher, curr_version),
                )
                db.commit()
            except Exception:
                pass
            return {
                "changed": True,
                "changes": changes,
                "previous_scan": (previous["scan_timestamp"] if hasattr(previous, "keys") else previous[3]),
                "previous_version": (previous["version"] if hasattr(previous, "keys") else previous[2]),
            }

    # Store current state for next comparison
    try:
        db.execute(
            """INSERT OR REPLACE INTO package_maintainer_history
               (package_name, manager, scan_timestamp, maintainer_data, publisher, version)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, manager, datetime.now(timezone.utc).isoformat(),
             json.dumps(curr_maintainers), curr_publisher, curr_version),
        )
        db.commit()
    except Exception:
        pass

    return {"changed": False}


# ── Malicious package detection via OSV MAL- prefix ──────

KNOWN_MALICIOUS_PACKAGES = {
    "strapi-plugin-cron", "strapi-plugin-config", "strapi-plugin-server",
    "strapi-plugin-database", "strapi-plugin-core", "strapi-plugin-hooks",
}


def is_malicious_advisory(vuln_id):
    """Check if an OSV advisory indicates malicious code (not just a vulnerability)."""
    return vuln_id.startswith("MAL-")


# ── ThreatFox IOC feed ───────────────────────────────────


def fetch_threatfox_iocs():
    """Fetch recent IOCs from ThreatFox (free, no API key)."""
    try:
        payload = json.dumps({"query": "get_iocs", "days": 7}).encode()
        req = urllib.request.Request(
            "https://threatfox-api.abuse.ch/api/v1/",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        ips = {}
        domains = {}
        for ioc in (data.get("data") or []):
            ioc_val = ioc.get("ioc", "")
            ioc_type = ioc.get("ioc_type", "")
            info = {
                "threat_type": ioc.get("threat_type", ""),
                "malware": ioc.get("malware_printable", ""),
                "confidence": ioc.get("confidence_level", 0),
            }
            if ioc_type == "ip:port":
                ip = ioc_val.split(":")[0]
                ips[ip] = info
            elif ioc_type == "domain":
                domains[ioc_val] = info
        return {"ips": ips, "domains": domains}
    except Exception:
        return {"ips": {}, "domains": {}}


def store_iocs(db, ioc_data):
    """Store IOCs in the database."""
    ts = datetime.now(timezone.utc).isoformat()
    for ip, info in ioc_data.get("ips", {}).items():
        try:
            db.execute(
                """INSERT OR IGNORE INTO threat_iocs
                   (ioc_type, ioc_value, threat_type, malware_family, confidence, source, fetch_timestamp)
                   VALUES ('ip', ?, ?, ?, ?, 'threatfox', ?)""",
                (ip, info.get("threat_type", ""), info.get("malware", ""), info.get("confidence", 0), ts),
            )
        except Exception:
            pass
    for domain, info in ioc_data.get("domains", {}).items():
        try:
            db.execute(
                """INSERT OR IGNORE INTO threat_iocs
                   (ioc_type, ioc_value, threat_type, malware_family, confidence, source, fetch_timestamp)
                   VALUES ('domain', ?, ?, ?, ?, 'threatfox', ?)""",
                (domain, info.get("threat_type", ""), info.get("malware", ""), info.get("confidence", 0), ts),
            )
        except Exception:
            pass
    db.commit()


def check_connection_against_iocs(remote_host, db):
    """Check if a remote host matches any known IOCs."""
    if not remote_host:
        return None
    # Exact IP match
    row = db.execute(
        "SELECT * FROM threat_iocs WHERE ioc_type='ip' AND ioc_value=?", (remote_host,)
    ).fetchone()
    if row:
        return dict(row)
    # Exact domain match
    row = db.execute(
        "SELECT * FROM threat_iocs WHERE ioc_type='domain' AND ioc_value=?", (remote_host,)
    ).fetchone()
    if row:
        return dict(row)
    # Subdomain match
    parts = remote_host.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        row = db.execute(
            "SELECT * FROM threat_iocs WHERE ioc_type='domain' AND ioc_value=?", (parent,)
        ).fetchone()
        if row:
            return dict(row)
    return None


# ── URLhaus feed ─────────────────────────────────────────


def fetch_urlhaus_iocs(db):
    """Fetch active malicious URLs/domains from URLhaus."""
    try:
        payload = b"urlhaus_status=online"
        req = urllib.request.Request(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        ts = datetime.now(timezone.utc).isoformat()
        count = 0
        for entry in (data.get("urls") or [])[:500]:
            url_str = entry.get("url", "")
            try:
                from urllib.parse import urlparse

                parsed = urlparse(url_str)
                if parsed.hostname:
                    db.execute(
                        """INSERT OR IGNORE INTO threat_iocs
                           (ioc_type, ioc_value, threat_type, malware_family,
                            confidence, source, first_seen, fetch_timestamp)
                           VALUES ('domain', ?, ?, ?, 75, 'urlhaus', ?, ?)""",
                        (
                            parsed.hostname,
                            entry.get("threat", "malware"),
                            (entry.get("tags") or ["unknown"])[0],
                            entry.get("date_added", ""),
                            ts,
                        ),
                    )
                    count += 1
            except Exception:
                continue
        db.commit()
        return count
    except Exception:
        return 0


# ── Install-to-connection correlation ────────────────────


def correlate_install_to_connection(session_id, connection_ts, remote_host, ioc_info, db):
    """Check if a package was installed right before this IOC-matched connection."""
    if not session_id:
        return None
    try:
        # Normalize timestamp for comparison (strip T/Z for SQLite datetime math)
        norm_ts = connection_ts.replace("T", " ").replace("Z", "")
        recent = db.execute(
            """SELECT package_name, package_manager, timestamp, command
               FROM agent_dependencies
               WHERE session_id = ?
               AND replace(replace(timestamp, 'T', ' '), 'Z', '')
                   BETWEEN datetime(?, '-60 seconds') AND ?
               ORDER BY timestamp DESC LIMIT 1""",
            (session_id, norm_ts, norm_ts),
        ).fetchone()
        if recent:
            return {
                "correlated": True,
                "package": recent["package_name"] if hasattr(recent, "keys") else recent[0],
                "manager": recent["package_manager"] if hasattr(recent, "keys") else recent[1],
                "install_time": recent["timestamp"] if hasattr(recent, "keys") else recent[2],
                "command": recent["command"] if hasattr(recent, "keys") else recent[3],
                "connection_host": remote_host,
                "connection_time": connection_ts,
            }
    except Exception:
        pass
    return None
