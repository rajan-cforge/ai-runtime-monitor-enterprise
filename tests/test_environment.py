"""Tests for full environment package inventory."""

import json
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring.db import init_db


@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    conn = init_db(db_path)
    conn.row_factory = sqlite3.Row
    return conn


class TestEnvironmentGather:
    @patch("claude_monitoring.supply_chain.subprocess")
    def test_pip_list(self, mock_sub):
        from claude_monitoring.supply_chain import get_pip_packages

        mock_sub.run.return_value = MagicMock(
            stdout=json.dumps([
                {"name": "requests", "version": "2.31.0"},
                {"name": "flask", "version": "3.0.0"},
            ]),
            returncode=0,
        )
        pkgs = get_pip_packages()
        assert len(pkgs) == 2
        assert pkgs[0]["name"] == "requests"
        assert pkgs[0]["version"] == "2.31.0"
        assert pkgs[0]["manager"] == "pip"

    @patch("claude_monitoring.supply_chain.subprocess")
    def test_pip_list_failure(self, mock_sub):
        from claude_monitoring.supply_chain import get_pip_packages

        mock_sub.run.side_effect = FileNotFoundError()
        assert get_pip_packages() == []


class TestEnvironmentStore:
    def test_table_exists(self, db):
        row = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='environment_packages'"
        ).fetchone()
        assert row is not None

    def test_store_and_query(self, db):
        from claude_monitoring.supply_chain import store_environment_packages

        pkgs = [
            {"name": "requests", "version": "2.31.0", "manager": "pip"},
            {"name": "flask", "version": "3.0.0", "manager": "pip"},
        ]
        store_environment_packages(db, pkgs)
        rows = db.execute("SELECT * FROM environment_packages").fetchall()
        assert len(rows) == 2

    def test_dedup_on_rescan(self, db):
        from claude_monitoring.supply_chain import store_environment_packages

        pkgs = [{"name": "requests", "version": "2.31.0", "manager": "pip"}]
        store_environment_packages(db, pkgs)
        store_environment_packages(db, pkgs)  # Second scan
        count = db.execute("SELECT COUNT(*) FROM environment_packages").fetchone()[0]
        assert count == 1


class TestEnvironmentCrossRef:
    def test_vuln_join(self, db):
        """Packages in environment should show CVE counts from package_vulnerabilities."""
        from claude_monitoring.supply_chain import store_environment_packages
        from claude_monitoring.vuln_scanner import store_vuln

        store_environment_packages(db, [
            {"name": "cryptography", "version": "41.0.0", "manager": "pip"},
        ])
        store_vuln(db, {
            "package_name": "cryptography", "package_version": "41.0.0",
            "ecosystem": "PyPI", "vuln_id": "CVE-test-1",
            "severity": "high", "cvss_score": 7.5, "source": "osv",
        })
        db.commit()

        row = db.execute("""
            SELECT ep.package_name, COUNT(pv.id) as vuln_count
            FROM environment_packages ep
            LEFT JOIN package_vulnerabilities pv ON ep.package_name = pv.package_name
            GROUP BY ep.package_name
        """).fetchone()
        assert row["vuln_count"] == 1

    def test_agent_attribution(self, db):
        """Packages installed by agents should be attributed."""
        from claude_monitoring.supply_chain import store_environment_packages

        store_environment_packages(db, [
            {"name": "fastapi", "version": "0.100.0", "manager": "pip"},
        ])
        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, action, package_manager, package_name, category, dedup_hash)
               VALUES ('t', 'install', 'pip', 'fastapi', 'package', 'h1')"""
        )
        db.commit()

        row = db.execute("""
            SELECT ep.package_name,
                   (SELECT COUNT(*) FROM agent_dependencies ad
                    WHERE ad.package_name = ep.package_name) as agent_installs
            FROM environment_packages ep WHERE ep.package_name = 'fastapi'
        """).fetchone()
        assert row["agent_installs"] == 1
