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

        mock_sub.run.return_value = MagicMock(stdout="Name: cryptography\nVersion: 42.0.4\nSummary: ...\n")
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
            stdout=json.dumps(
                {
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
                }
            ),
        )
        vulns = run_pip_audit()
        assert len(vulns) == 1
        assert vulns[0]["package_name"] == "cryptography"
        assert vulns[0]["vuln_id"] == "PYSEC-2024-001"
        assert vulns[0]["fix_version"] == "42.0.4"

    @patch("claude_monitoring.vuln_scanner.subprocess")
    def test_no_vulns(self, mock_sub):
        from claude_monitoring.vuln_scanner import run_pip_audit

        mock_sub.run.return_value = MagicMock(returncode=0, stdout=json.dumps({"dependencies": []}))
        assert run_pip_audit() == []


class TestOSVQuery:
    @patch("claude_monitoring.vuln_scanner.urllib.request.urlopen")
    def test_with_vulns(self, mock_urlopen):
        from claude_monitoring.vuln_scanner import query_osv

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
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
            }
        ).encode()
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

        store_vuln(
            db,
            {
                "package_name": "foo",
                "package_version": "1.0",
                "ecosystem": "PyPI",
                "vuln_id": "CVE-2024-1",
                "severity": "high",
                "cvss_score": 7.5,
                "fix_version": "1.1",
                "description": "test",
                "source": "osv",
            },
        )
        db.commit()
        row = db.execute("SELECT * FROM package_vulnerabilities WHERE vuln_id='CVE-2024-1'").fetchone()
        assert row is not None
        assert row["severity"] == "high"

    def test_dedup_vuln(self, db):
        from claude_monitoring.vuln_scanner import store_vuln

        for _ in range(2):
            store_vuln(
                db,
                {
                    "package_name": "foo",
                    "package_version": "1.0",
                    "ecosystem": "PyPI",
                    "vuln_id": "CVE-DUPE",
                    "source": "osv",
                },
            )
        db.commit()
        count = db.execute("SELECT COUNT(*) FROM package_vulnerabilities WHERE vuln_id='CVE-DUPE'").fetchone()[0]
        assert count == 1

    def test_tables_exist(self, db):
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        assert "package_vulnerabilities" in tables
        assert "scan_history" in tables


class TestNpmVersionResolution:
    @patch("claude_monitoring.vuln_scanner.subprocess")
    def test_npm_version(self, mock_sub):
        from claude_monitoring.vuln_scanner import resolve_installed_version

        mock_sub.run.return_value = MagicMock(stdout=json.dumps({"dependencies": {"express": {"version": "4.18.2"}}}))
        v = resolve_installed_version("express", "npm")
        assert v == "4.18.2"

    @patch("claude_monitoring.vuln_scanner.subprocess")
    def test_npm_package_not_installed(self, mock_sub):
        from claude_monitoring.vuln_scanner import resolve_installed_version

        mock_sub.run.return_value = MagicMock(stdout=json.dumps({"dependencies": {}}))
        v = resolve_installed_version("not-installed", "npm")
        assert v == ""


class TestPipAuditEdgeCases:
    @patch("claude_monitoring.vuln_scanner.subprocess")
    def test_file_not_found(self, mock_sub):
        from claude_monitoring.vuln_scanner import run_pip_audit

        mock_sub.run.side_effect = FileNotFoundError("pip-audit not installed")
        assert run_pip_audit() == []

    @patch("claude_monitoring.vuln_scanner.subprocess")
    def test_unexpected_error(self, mock_sub):
        from claude_monitoring.vuln_scanner import run_pip_audit

        mock_sub.run.side_effect = RuntimeError("boom")
        assert run_pip_audit() == []


class TestExtractDbSeverity:
    def test_critical_severity(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        score, label = _extract_db_severity({"database_specific": {"severity": "CRITICAL"}})
        assert score == 9.5
        assert label == "critical"

    def test_moderate_maps_to_medium(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        score, label = _extract_db_severity({"database_specific": {"severity": "MODERATE"}})
        assert score == 5.0
        assert label == "medium"

    def test_unknown_severity(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        score, label = _extract_db_severity({"database_specific": {}})
        assert score is None
        assert label == "unknown"

    def test_missing_db_specific(self):
        from claude_monitoring.vuln_scanner import _extract_db_severity

        score, label = _extract_db_severity({})
        assert label == "unknown"


class TestExtractCvssVector:
    def test_numeric_score_string(self):
        from claude_monitoring.vuln_scanner import _extract_cvss

        vuln = {"severity": [{"type": "CVSS_V3", "score": "8.1"}]}
        assert _extract_cvss(vuln) == 8.1

    def test_vector_with_high_confidentiality(self):
        from claude_monitoring.vuln_scanner import _extract_cvss

        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}
        assert _extract_cvss(vuln) == 7.5

    def test_vector_with_high_availability_only(self):
        from claude_monitoring.vuln_scanner import _extract_cvss

        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}
        assert _extract_cvss(vuln) == 7.0

    def test_vector_generic(self):
        from claude_monitoring.vuln_scanner import _extract_cvss

        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"}]}
        assert _extract_cvss(vuln) == 5.0

    def test_no_severity_returns_none(self):
        from claude_monitoring.vuln_scanner import _extract_cvss

        assert _extract_cvss({}) is None


class TestExtractFix:
    def test_extracts_fixed_version(self):
        from claude_monitoring.vuln_scanner import _extract_fix

        vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}]}
        assert _extract_fix(vuln) == "1.2.3"

    def test_no_fix_returns_none(self):
        from claude_monitoring.vuln_scanner import _extract_fix

        vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
        assert _extract_fix(vuln) is None

    def test_empty_affected(self):
        from claude_monitoring.vuln_scanner import _extract_fix

        assert _extract_fix({}) is None


class TestMaliciousDetection:
    @patch("claude_monitoring.vuln_scanner.urllib.request.urlopen")
    def test_mal_prefix_marked_malicious(self, mock_urlopen):
        from claude_monitoring.vuln_scanner import query_osv

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {"vulns": [{"id": "MAL-2024-001", "summary": "Malicious package"}]}
        ).encode()
        mock_urlopen.return_value = mock_resp
        vulns = query_osv("evil-pkg", "npm")
        assert len(vulns) == 1
        assert vulns[0]["severity"] == "malicious"


class TestRunFullScan:
    @patch("claude_monitoring.vuln_scanner.run_pip_audit")
    @patch("claude_monitoring.vuln_scanner.query_osv")
    @patch("claude_monitoring.vuln_scanner.time.sleep")
    def test_scans_all_packages(self, mock_sleep, mock_osv, mock_pip, db):
        from claude_monitoring.vuln_scanner import run_full_scan

        mock_pip.return_value = [{"package_name": "foo", "vuln_id": "CVE-1", "source": "pip-audit"}]
        mock_osv.return_value = [{"package_name": "bar", "vuln_id": "GHSA-1", "source": "osv"}]
        # Insert a package so the OSV loop has something to scan
        db.execute(
            "INSERT INTO agent_dependencies (timestamp, session_id, action, package_name, package_manager, package_version, category) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("2026-04-01T00:00:00Z", "test", "install", "bar", "pip", "1.0", "package"),
        )
        db.commit()

        results = run_full_scan(db)
        assert results["vulns_found"] >= 2
        assert results["scanned"] >= 2
        # Verify scan_history was written
        row = db.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT 1").fetchone()
        assert row is not None

    @patch("claude_monitoring.vuln_scanner.run_pip_audit")
    def test_no_packages_still_succeeds(self, mock_pip, db):
        from claude_monitoring.vuln_scanner import run_full_scan

        mock_pip.return_value = []
        results = run_full_scan(db)
        assert results["scanned"] >= 1  # pip-audit counts as 1 scan
        assert results["vulns_found"] == 0

    @patch("claude_monitoring.supply_chain.get_full_environment")
    @patch("claude_monitoring.vuln_scanner.run_pip_audit")
    def test_environment_phase_populates_table(self, mock_pip, mock_env, db):
        """run_full_scan must call get_full_environment() + store the
        results in environment_packages. Previously those functions
        existed but had zero callers, so Full Environment view stayed
        empty forever."""
        from claude_monitoring.vuln_scanner import run_full_scan

        mock_pip.return_value = []
        mock_env.return_value = [
            {"name": "requests", "version": "2.31.0", "manager": "pip"},
            {"name": "flask", "version": "3.0.0", "manager": "pip"},
            {"name": "htop", "version": "3.2.2", "manager": "brew"},
        ]

        run_full_scan(db)

        rows = db.execute(
            "SELECT package_name, manager, package_version FROM environment_packages ORDER BY package_name"
        ).fetchall()
        names = [r[0] for r in rows]
        assert "requests" in names
        assert "flask" in names
        assert "htop" in names
        # Intel status row records the success
        status_row = db.execute(
            "SELECT record_count, last_error FROM intel_source_status WHERE name='environment'"
        ).fetchone()
        assert status_row is not None
        assert status_row[0] == 3
        assert status_row[1] is None

    @patch("claude_monitoring.supply_chain.get_full_environment")
    @patch("claude_monitoring.vuln_scanner.run_pip_audit")
    def test_environment_phase_invokes_progress_callback(self, mock_pip, mock_env, db):
        """The scan progress UI panel expects an 'environment' phase
        in the callback stream, same as pip-audit / osv / etc."""
        from claude_monitoring.vuln_scanner import run_full_scan

        mock_pip.return_value = []
        mock_env.return_value = [{"name": "requests", "version": "2.31.0", "manager": "pip"}]

        phases_seen: list[tuple[str, str]] = []

        def cb(phase, status, **kwargs):
            phases_seen.append((phase, status))

        run_full_scan(db, progress_cb=cb)

        assert ("environment", "running") in phases_seen
        assert ("environment", "done") in phases_seen
        # Environment phase runs BEFORE pip-audit (Phase 0)
        env_running_idx = phases_seen.index(("environment", "running"))
        pip_running_idx = phases_seen.index(("pip-audit", "running"))
        assert env_running_idx < pip_running_idx


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
