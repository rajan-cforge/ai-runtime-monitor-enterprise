# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Tests for package watchlist and SBOM export."""

import sqlite3

import pytest

from claude_monitoring.db import init_db


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    return conn


class TestWatchlist:
    def test_table_exists(self, db):
        row = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='package_watchlist'"
        ).fetchone()
        assert row is not None

    def test_populate_from_agent_deps(self, db):
        from claude_monitoring.supply_chain import populate_watchlist

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, action, package_manager, package_name, category, dedup_hash)
               VALUES ('t', 'install', 'pip', 'requests', 'package', 'wl1')"""
        )
        db.commit()
        counts = populate_watchlist(db)
        assert counts.get("high", 0) >= 1
        row = db.execute(
            "SELECT * FROM package_watchlist WHERE package_name='requests'"
        ).fetchone()
        assert row is not None
        assert row["priority"] == "high"

    def test_populate_from_vulns(self, db):
        from claude_monitoring.supply_chain import populate_watchlist

        db.execute(
            """INSERT INTO package_vulnerabilities
               (scan_timestamp, package_name, vuln_id, source)
               VALUES ('t', 'cryptography', 'CVE-test', 'osv')"""
        )
        db.commit()
        populate_watchlist(db)
        row = db.execute(
            "SELECT * FROM package_watchlist WHERE package_name='cryptography'"
        ).fetchone()
        assert row is not None

    def test_dedup(self, db):
        from claude_monitoring.supply_chain import populate_watchlist

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, action, package_manager, package_name, category, dedup_hash)
               VALUES ('t', 'install', 'pip', 'flask', 'package', 'wl2')"""
        )
        db.commit()
        populate_watchlist(db)
        populate_watchlist(db)  # Second call
        count = db.execute(
            "SELECT COUNT(*) FROM package_watchlist WHERE package_name='flask'"
        ).fetchone()[0]
        assert count == 1


class TestSBOMExport:
    def test_generates_valid_json(self, db):
        from claude_monitoring.supply_chain import generate_sbom

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, session_id, agent_type, action, package_manager,
                package_name, package_version, category, risk_score, project, dedup_hash)
               VALUES ('t', 's1', 'claude_code', 'install', 'pip',
                'requests', '2.31.0', 'package', 1, 'myproject', 'sbom1')"""
        )
        db.commit()
        sbom = generate_sbom(db)
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert len(sbom["components"]) == 1

    def test_includes_agent_provenance(self, db):
        from claude_monitoring.supply_chain import generate_sbom

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, agent_type, action, package_manager,
                package_name, package_version, category, project, dedup_hash)
               VALUES ('t', 'claude_code', 'install', 'pip',
                'fastapi', '0.100.0', 'package', 'cp', 'sbom2')"""
        )
        db.commit()
        sbom = generate_sbom(db)
        comp = sbom["components"][0]
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["ai-monitor:agent_installed"] == "true"
        assert props["ai-monitor:agent_type"] == "claude_code"

    def test_includes_vulns(self, db):
        from claude_monitoring.supply_chain import generate_sbom
        from claude_monitoring.vuln_scanner import store_vuln

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, action, package_manager, package_name, category, dedup_hash)
               VALUES ('t', 'install', 'pip', 'crypto', 'package', 'sbom3')"""
        )
        store_vuln(db, {
            "package_name": "crypto", "vuln_id": "CVE-test-sbom",
            "severity": "high", "source": "osv",
        })
        db.commit()
        sbom = generate_sbom(db)
        comp = sbom["components"][0]
        assert "vulnerabilities" in comp
        assert comp["vulnerabilities"][0]["id"] == "CVE-test-sbom"

    def test_purl_format(self, db):
        from claude_monitoring.supply_chain import generate_sbom

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, action, package_manager, package_name,
                package_version, category, dedup_hash)
               VALUES ('t', 'install', 'pip', 'flask', '3.0.0', 'package', 'sbom4')"""
        )
        db.commit()
        sbom = generate_sbom(db)
        assert sbom["components"][0]["purl"] == "pkg:pip/flask@3.0.0"
