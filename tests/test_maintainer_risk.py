# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Tests for maintainer risk scoring and change detection."""

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


class TestEnrichedNpmMetadata:
    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_npm_maintainer_extraction(self, mock_urlopen):
        from claude_monitoring.threat_intel import fetch_npm_metadata

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "description": "Fast web framework",
                "maintainers": [
                    {"name": "dev1", "email": "dev1@x.com"},
                    {"name": "dev2", "email": "dev2@x.com"},
                ],
                "author": {"name": "Original Author"},
                "license": "MIT",
                "repository": {"url": "https://github.com/org/pkg"},
                "time": {
                    "created": "2020-01-01T00:00:00Z",
                    "1.0.0": "2020-01-01T00:00:00Z",
                    "2.0.0": "2026-04-01T00:00:00Z",
                },
                "dist-tags": {"latest": "2.0.0"},
                "versions": {
                    "1.0.0": {"_npmUser": {"name": "dev1"}, "scripts": {}},
                    "2.0.0": {"_npmUser": {"name": "dev2"}, "scripts": {"postinstall": "node setup.js"}},
                },
            }
        ).encode()
        mock_urlopen.return_value = mock_resp
        meta = fetch_npm_metadata("test-pkg")
        assert meta is not None
        assert meta["maintainer_count"] == 2
        assert meta["publisher"] == "dev2"
        assert meta["has_install_scripts"] is True
        assert meta["version_count"] == 2

    @patch("claude_monitoring.threat_intel.urllib.request.urlopen")
    def test_npm_publisher_change_detected(self, mock_urlopen):
        from claude_monitoring.threat_intel import fetch_npm_metadata

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {
                "description": "x",
                "maintainers": [{"name": "attacker"}],
                "author": {"name": "original"},
                "license": "MIT",
                "repository": {},
                "time": {
                    "created": "2020-01-01T00:00:00Z",
                    "1.0.0": "2020-01-01T00:00:00Z",
                    "2.0.0": "2026-04-05T00:00:00Z",
                },
                "dist-tags": {"latest": "2.0.0"},
                "versions": {
                    "1.0.0": {"_npmUser": {"name": "original-dev"}, "scripts": {}},
                    "2.0.0": {"_npmUser": {"name": "attacker"}, "scripts": {}},
                },
            }
        ).encode()
        mock_urlopen.return_value = mock_resp
        meta = fetch_npm_metadata("hijacked-pkg")
        assert meta["maintainer_changed"] is True
        assert meta["publisher"] == "attacker"
        assert meta["previous_publisher"] == "original-dev"


class TestMaintainerRiskScoring:
    def test_maintainer_change_recent(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "maintainer_changed": True,
            "maintainer_change_age_days": 3,
            "first_published": "2020-01-01T00:00:00+00:00",
            "has_description": True,
            "has_repository": True,
        }
        score, reasons = assess_registry_risk("pkg", "npm", meta)
        assert score >= 5
        assert any("maintainer" in r.lower() for r in reasons)

    def test_maintainer_change_old(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "maintainer_changed": True,
            "maintainer_change_age_days": 60,
            "first_published": "2020-01-01T00:00:00+00:00",
            "has_description": True,
            "has_repository": True,
        }
        score, reasons = assess_registry_risk("pkg", "npm", meta)
        assert score >= 1
        assert score < 5

    def test_no_maintainer_change(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "maintainer_changed": False,
            "first_published": "2020-01-01T00:00:00+00:00",
            "has_description": True,
            "has_repository": True,
        }
        score, reasons = assess_registry_risk("pkg", "npm", meta)
        assert not any("maintainer" in r.lower() for r in reasons)

    def test_single_maintainer(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "maintainer_count": 1,
            "first_published": "2020-01-01T00:00:00+00:00",
            "has_description": True,
            "has_repository": True,
        }
        score, reasons = assess_registry_risk("pkg", "npm", meta)
        assert any("single maintainer" in r.lower() for r in reasons)

    def test_no_source_repo(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "first_published": "2020-01-01T00:00:00+00:00",
            "has_description": True,
            "has_repository": False,
            "has_source_repo": False,
        }
        score, reasons = assess_registry_risk("pkg", "npm", meta)
        assert any("repository" in r.lower() for r in reasons)

    def test_yanked_versions(self):
        from claude_monitoring.threat_intel import assess_registry_risk

        meta = {
            "first_published": "2020-01-01T00:00:00+00:00",
            "has_description": True,
            "has_repository": True,
            "yanked_versions": ["1.0.1", "1.0.2"],
        }
        score, reasons = assess_registry_risk("pkg", "pip", meta)
        assert score >= 2
        assert any("yanked" in r.lower() for r in reasons)


class TestMaintainerHistory:
    def test_first_scan_stores(self, db):
        from claude_monitoring.threat_intel import detect_maintainer_changes

        result = detect_maintainer_changes(
            "express",
            "npm",
            {"maintainers": [{"name": "dev1"}], "publisher": "dev1", "latest_version": "5.0.0"},
            db,
        )
        assert result["changed"] is False
        row = db.execute("SELECT * FROM package_maintainer_history WHERE package_name='express'").fetchone()
        assert row is not None

    def test_no_change(self, db):
        from claude_monitoring.threat_intel import detect_maintainer_changes

        meta = {"maintainers": [{"name": "dev1"}], "publisher": "dev1", "latest_version": "5.0.0"}
        detect_maintainer_changes("express", "npm", meta, db)
        result = detect_maintainer_changes(
            "express", "npm", {"maintainers": [{"name": "dev1"}], "publisher": "dev1", "latest_version": "5.0.1"}, db
        )
        assert result["changed"] is False

    def test_publisher_change_detected(self, db):
        from claude_monitoring.threat_intel import detect_maintainer_changes

        detect_maintainer_changes(
            "pkg", "npm", {"maintainers": [{"name": "dev1"}], "publisher": "dev1", "latest_version": "1.0.0"}, db
        )
        result = detect_maintainer_changes(
            "pkg",
            "npm",
            {"maintainers": [{"name": "attacker"}], "publisher": "attacker", "latest_version": "1.0.1"},
            db,
        )
        assert result["changed"] is True
        assert any("publisher" in c.lower() for c in result["changes"])

    def test_new_maintainer_detected(self, db):
        from claude_monitoring.threat_intel import detect_maintainer_changes

        detect_maintainer_changes(
            "pkg", "npm", {"maintainers": [{"name": "dev1"}], "publisher": "dev1", "latest_version": "1.0.0"}, db
        )
        result = detect_maintainer_changes(
            "pkg",
            "npm",
            {"maintainers": [{"name": "dev1"}, {"name": "newguy"}], "publisher": "dev1", "latest_version": "1.0.1"},
            db,
        )
        assert result["changed"] is True
        assert any("added" in c.lower() for c in result["changes"])
