"""Tests for vulnerability scanner — pip-audit + OSV.dev integration."""

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


class TestVersionResolution:
    @patch("claude_monitoring.vuln_scanner.subprocess")
    def test_pip_version(self, mock_sub):
        from claude_monitoring.vuln_scanner import resolve_installed_version

        mock_sub.run.return_value = MagicMock(
            stdout="Name: cryptography\nVersion: 42.0.4\nSummary: ...\n"
        )
        v = resolve_installed_version("cryptography", "pip")
        assert v == "42.0.4"

    def test_unknown_manager(self):
        from claude_monitoring.vuln_scanner import resolve_installed_version

        v = resolve_installed_version("foo", "unknown_manager")
        assert v == ""


class TestPipAuditParsing:
    @patch("claude_monitoring.vuln_scanner.subprocess")
    def test_parses_vulns(self, mock_sub):
        from claude_monitoring.vuln_scanner import run_pip_audit

        mock_sub.run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps({
                "dependencies": [
                    {
                        "name": "cryptography",
                        "version": "41.0.0",
                        "vulns": [
                            {
                                "id": "PYSEC-2024-001",
                                "aliases": ["CVE-2024-26130"],
                                "fix_versions": ["42.0.4"],
                                "description": "NULL pointer dereference",
                            }
                        ],
                    }
                ]
            }),
        )
        vulns = run_pip_audit()
        assert len(vulns) == 1
        assert vulns[0]["package_name"] == "cryptography"
        assert vulns[0]["vuln_id"] == "PYSEC-2024-001"
        assert vulns[0]["fix_version"] == "42.0.4"

    @patch("claude_monitoring.vuln_scanner.subprocess")
    def test_no_vulns(self, mock_sub):
        from claude_monitoring.vuln_scanner import run_pip_audit

        mock_sub.run.return_value = MagicMock(
            returncode=0, stdout=json.dumps({"dependencies": []})
        )
        assert run_pip_audit() == []


class TestOSVQuery:
    @patch("claude_monitoring.vuln_scanner.urllib.request.urlopen")
    def test_with_vulns(self, mock_urlopen):
        from claude_monitoring.vuln_scanner import query_osv

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "vulns": [
                {
                    "id": "GHSA-xxxx",
                    "summary": "XSS vulnerability",
                    "aliases": ["CVE-2024-99999"],
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                    "database_specific": {"severity": "HIGH"},
                    "affected": [{"ranges": [{"events": [{"fixed": "2.0.1"}]}]}],
                }
            ]
        }).encode()
        mock_urlopen.return_value.__enter__ = lambda s: mock_resp
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        vulns = query_osv("lodash", "npm", "4.17.20")
        assert len(vulns) == 1
        assert vulns[0]["cvss_score"] == 7.5
        assert vulns[0]["severity"] == "high"
        assert vulns[0]["fix_version"] == "2.0.1"

    @patch("claude_monitoring.vuln_scanner.urllib.request.urlopen")
    def test_no_vulns(self, mock_urlopen):
        from claude_monitoring.vuln_scanner import query_osv

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"vulns": []}).encode()
        mock_urlopen.return_value = mock_resp
        assert query_osv("safe-pkg", "PyPI") == []

    @patch("claude_monitoring.vuln_scanner.urllib.request.urlopen")
    def test_timeout_graceful(self, mock_urlopen):
        from claude_monitoring.vuln_scanner import query_osv

        mock_urlopen.side_effect = TimeoutError("timeout")
        assert query_osv("foo", "PyPI") == []

    def test_no_ecosystem(self):
        from claude_monitoring.vuln_scanner import query_osv

        assert query_osv("jq", None) == []


class TestStoreAndScan:
    def test_store_vuln(self, db):
        from claude_monitoring.vuln_scanner import store_vuln

        store_vuln(db, {
            "package_name": "foo", "package_version": "1.0",
            "ecosystem": "PyPI", "vuln_id": "CVE-2024-1",
            "severity": "high", "cvss_score": 7.5,
            "fix_version": "1.1", "description": "test",
            "source": "osv",
        })
        db.commit()
        row = db.execute("SELECT * FROM package_vulnerabilities WHERE vuln_id='CVE-2024-1'").fetchone()
        assert row is not None
        assert row["severity"] == "high"

    def test_dedup_vuln(self, db):
        from claude_monitoring.vuln_scanner import store_vuln

        for _ in range(2):
            store_vuln(db, {
                "package_name": "foo", "package_version": "1.0",
                "ecosystem": "PyPI", "vuln_id": "CVE-DUPE",
                "source": "osv",
            })
        db.commit()
        count = db.execute(
            "SELECT COUNT(*) FROM package_vulnerabilities WHERE vuln_id='CVE-DUPE'"
        ).fetchone()[0]
        assert count == 1

    def test_tables_exist(self, db):
        tables = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        assert "package_vulnerabilities" in tables
        assert "scan_history" in tables


class TestCVSSSeverity:
    def test_critical(self):
        from claude_monitoring.vuln_scanner import _cvss_to_severity

        assert _cvss_to_severity(9.8) == "critical"

    def test_high(self):
        from claude_monitoring.vuln_scanner import _cvss_to_severity

        assert _cvss_to_severity(7.5) == "high"

    def test_medium(self):
        from claude_monitoring.vuln_scanner import _cvss_to_severity

        assert _cvss_to_severity(5.0) == "medium"

    def test_low(self):
        from claude_monitoring.vuln_scanner import _cvss_to_severity

        assert _cvss_to_severity(2.0) == "low"

    def test_none(self):
        from claude_monitoring.vuln_scanner import _cvss_to_severity

        assert _cvss_to_severity(None) == "unknown"
