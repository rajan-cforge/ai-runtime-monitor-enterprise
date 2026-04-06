"""Tests for threat intelligence — registry metadata, IOC feeds, malicious detection."""

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


class TestRegistryMetadata:
    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_pypi_metadata(self, mock_urlopen):
        from claude_monitoring.threat_intel import fetch_pypi_metadata

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "info": {
                "summary": "HTTP library", "author": "Kenneth Reitz",
                "license": "Apache 2.0", "home_page": "https://requests.readthedocs.io",
                "project_urls": {"Source": "https://github.com/psf/requests"},
            },
            "releases": {"2.31.0": [{"upload_time_iso_8601": "2023-05-22T00:00:00Z"}]},
        }).encode()
        mock_urlopen.return_value = mock_resp
        meta = fetch_pypi_metadata("requests")
        assert meta is not None
        assert meta["has_description"] is True
        assert meta["has_repository"] is True
        assert meta["author"] == "Kenneth Reitz"

    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_npm_metadata_with_scripts(self, mock_urlopen):
        from claude_monitoring.threat_intel import fetch_npm_metadata

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "description": "", "author": {"name": "attacker"},
            "license": "", "repository": {},
            "time": {"created": "2026-04-05T00:00:00Z"},
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"scripts": {"postinstall": "node exploit.js"}}},
        }).encode()
        mock_urlopen.return_value = mock_resp
        meta = fetch_npm_metadata("evil-pkg")
        assert meta is not None
        assert meta["has_install_scripts"] is True
        assert meta["has_description"] is False

    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_timeout_returns_none(self, mock_urlopen):
        from claude_monitoring.threat_intel import fetch_pypi_metadata

        mock_urlopen.side_effect = TimeoutError()
        assert fetch_pypi_metadata("foo") is None


class TestRegistryRisk:
    def test_new_package_high_risk(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "first_published": "2026-04-05T00:00:00+00:00",
            "has_description": False, "has_repository": False,
            "has_install_scripts": True,
        }
        score, reasons = assess_registry_risk("evil", "npm", meta)
        assert score >= 6  # < 7 days (+2) + no desc/repo (+2) + install scripts (+2)

    def test_very_new_package(self):
        from datetime import datetime, timedelta, timezone

        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "first_published": (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat(),
            "has_description": True, "has_repository": True,
        }
        score, reasons = assess_registry_risk("x", "npm", meta)
        assert score >= 4  # < 24h ago

    def test_established_package_clean(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "first_published": "2020-01-01T00:00:00+00:00",
            "has_description": True, "has_repository": True,
        }
        score, reasons = assess_registry_risk("requests", "pip", meta)
        assert score == 0

    def test_no_metadata_returns_zero(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        score, reasons = assess_registry_risk("x", "pip", None)
        assert score == 0


class TestMaliciousDetection:
    def test_mal_prefix_detected(self):
        from claude_monitoring.threat_intel import is_malicious_advisory

        assert is_malicious_advisory("MAL-2026-2457") is True
        assert is_malicious_advisory("GHSA-xxxx") is False
        assert is_malicious_advisory("CVE-2024-1234") is False

    def test_known_malicious(self):
        from claude_monitoring.threat_intel import KNOWN_MALICIOUS_PACKAGES

        assert "strapi-plugin-cron" in KNOWN_MALICIOUS_PACKAGES


class TestThreatFoxFeed:
    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_fetch_iocs(self, mock_urlopen):
        from claude_monitoring.threat_intel import fetch_threatfox_iocs

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "query_status": "ok",
            "data": [
                {"ioc": "185.173.38.99:443", "ioc_type": "ip:port",
                 "threat_type": "payload_delivery", "malware_printable": "npm-malware",
                 "confidence_level": 75},
                {"ioc": "evil.com", "ioc_type": "domain",
                 "threat_type": "c2", "malware_printable": "cobalt_strike",
                 "confidence_level": 90},
            ],
        }).encode()
        mock_urlopen.return_value = mock_resp
        result = fetch_threatfox_iocs()
        assert "185.173.38.99" in result["ips"]
        assert "evil.com" in result["domains"]

    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_timeout_empty(self, mock_urlopen):
        from claude_monitoring.threat_intel import fetch_threatfox_iocs

        mock_urlopen.side_effect = TimeoutError()
        result = fetch_threatfox_iocs()
        assert result == {"ips": {}, "domains": {}}


class TestIOCMatching:
    def test_ip_match(self, db):
        from claude_monitoring.threat_intel import check_connection_against_iocs, store_iocs

        store_iocs(db, {"ips": {"185.173.38.99": {"threat_type": "c2", "malware": "npm-malware", "confidence": 75}}, "domains": {}})
        result = check_connection_against_iocs("185.173.38.99", db)
        assert result is not None
        assert result["ioc_value"] == "185.173.38.99"

    def test_domain_match(self, db):
        from claude_monitoring.threat_intel import check_connection_against_iocs, store_iocs

        store_iocs(db, {"ips": {}, "domains": {"evil.com": {"threat_type": "c2", "malware": "cobalt", "confidence": 90}}})
        result = check_connection_against_iocs("evil.com", db)
        assert result is not None

    def test_subdomain_match(self, db):
        from claude_monitoring.threat_intel import check_connection_against_iocs, store_iocs

        store_iocs(db, {"ips": {}, "domains": {"evil.com": {"threat_type": "c2", "malware": "cobalt", "confidence": 90}}})
        result = check_connection_against_iocs("sub.evil.com", db)
        assert result is not None

    def test_clean_host_no_match(self, db):
        from claude_monitoring.threat_intel import check_connection_against_iocs, store_iocs

        store_iocs(db, {"ips": {"1.2.3.4": {"threat_type": "c2", "malware": "x", "confidence": 50}}, "domains": {}})
        result = check_connection_against_iocs("api.anthropic.com", db)
        assert result is None

    def test_ioc_dedup(self, db):
        from claude_monitoring.threat_intel import store_iocs

        iocs = {"ips": {"1.2.3.4": {"threat_type": "c2", "malware": "x", "confidence": 50}}, "domains": {}}
        store_iocs(db, iocs)
        store_iocs(db, iocs)  # Second store
        count = db.execute("SELECT COUNT(*) FROM threat_iocs WHERE ioc_value='1.2.3.4'").fetchone()[0]
        assert count == 1


class TestURLhaus:
    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_fetch_urlhaus(self, mock_urlopen, db):
        from claude_monitoring.threat_intel import fetch_urlhaus_iocs

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "urls": [
                {"url": "http://evil.example.com/malware.exe", "threat": "malware_download",
                 "tags": ["emotet"], "date_added": "2026-04-05"},
            ],
        }).encode()
        mock_urlopen.return_value = mock_resp
        count = fetch_urlhaus_iocs(db)
        assert count == 1
        row = db.execute("SELECT * FROM threat_iocs WHERE source='urlhaus'").fetchone()
        assert row is not None
        assert row["ioc_value"] == "evil.example.com"

    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_urlhaus_timeout(self, mock_urlopen, db):
        from claude_monitoring.threat_intel import fetch_urlhaus_iocs

        mock_urlopen.side_effect = TimeoutError()
        assert fetch_urlhaus_iocs(db) == 0


class TestCorrelation:
    def test_correlation_found(self, db):
        from claude_monitoring.threat_intel import correlate_install_to_connection

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, session_id, action, package_manager, package_name, command, dedup_hash)
               VALUES ('2026-04-05T10:00:00Z', 'sess1', 'install', 'npm', 'evil-pkg', 'npm i evil-pkg', 'corr1')"""
        )
        db.commit()
        result = correlate_install_to_connection(
            "sess1", "2026-04-05T10:00:05Z", "185.1.2.3",
            {"malware_family": "npm-malware"}, db,
        )
        assert result is not None
        assert result["correlated"] is True
        assert result["package"] == "evil-pkg"

    def test_correlation_too_old(self, db):
        from claude_monitoring.threat_intel import correlate_install_to_connection

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, session_id, action, package_manager, package_name, command, dedup_hash)
               VALUES ('2026-04-05T10:00:00Z', 'sess1', 'install', 'npm', 'old-pkg', 'npm i old-pkg', 'corr2')"""
        )
        db.commit()
        result = correlate_install_to_connection(
            "sess1", "2026-04-05T10:05:00Z", "185.1.2.3", {}, db,
        )
        assert result is None

    def test_correlation_wrong_session(self, db):
        from claude_monitoring.threat_intel import correlate_install_to_connection

        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, session_id, action, package_manager, package_name, command, dedup_hash)
               VALUES ('2026-04-05T10:00:00Z', 'sess1', 'install', 'npm', 'pkg', 'npm i pkg', 'corr3')"""
        )
        db.commit()
        result = correlate_install_to_connection(
            "sess2", "2026-04-05T10:00:05Z", "185.1.2.3", {}, db,
        )
        assert result is None
