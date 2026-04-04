"""Tests for supply chain dependency monitoring."""

import json
import sqlite3

import pytest

from claude_monitoring.supply_chain import (
    assess_risk,
    parse_install_command,
)


class TestParseNpmInstall:
    def test_basic(self):
        result = parse_install_command("npm install foo bar@2.0 --save-dev")
        assert len(result) == 2
        foo = next(p for p in result if p["name"] == "foo")
        bar = next(p for p in result if p["name"] == "bar")
        assert foo["pinned"] is False
        assert foo["version"] == "latest"
        assert bar["pinned"] is True
        assert bar["version"] == "2.0"
        assert foo["manager"] == "npm"

    def test_npm_i_shorthand(self):
        result = parse_install_command("npm i express")
        assert len(result) == 1
        assert result[0]["name"] == "express"
        assert result[0]["manager"] == "npm"

    def test_yarn_add(self):
        result = parse_install_command("yarn add react react-dom@18.2.0")
        assert len(result) == 2
        rd = next(p for p in result if p["name"] == "react-dom")
        assert rd["version"] == "18.2.0"
        assert rd["manager"] == "yarn"

    def test_pnpm_add(self):
        result = parse_install_command("pnpm add vite")
        assert len(result) == 1
        assert result[0]["manager"] == "pnpm"

    def test_scoped_package(self):
        result = parse_install_command("npm install @types/node@20.0.0")
        assert len(result) == 1
        assert result[0]["name"] == "@types/node"
        assert result[0]["version"] == "20.0.0"


class TestParsePipInstall:
    def test_basic(self):
        result = parse_install_command("pip install requests==2.31.0 flask")
        assert len(result) == 2
        req = next(p for p in result if p["name"] == "requests")
        fl = next(p for p in result if p["name"] == "flask")
        assert req["pinned"] is True
        assert req["version"] == "2.31.0"
        assert fl["pinned"] is False
        assert req["manager"] == "pip"

    def test_requirements_file(self):
        result = parse_install_command("pip install -r requirements.txt")
        assert len(result) == 1
        assert result[0]["name"] == "(from requirements.txt)"
        assert result[0]["pinned"] is True

    def test_pip3(self):
        result = parse_install_command("pip3 install numpy>=1.24")
        assert len(result) == 1
        assert result[0]["name"] == "numpy"
        assert result[0]["pinned"] is True

    def test_editable_install(self):
        result = parse_install_command("pip install -e .")
        assert len(result) == 1
        assert result[0]["name"] == "(editable: .)"

    def test_index_url_skipped(self):
        result = parse_install_command(
            "pip install --index-url https://custom.pypi.org/simple/ my-pkg"
        )
        assert len(result) == 1
        assert result[0]["name"] == "my-pkg"

    def test_version_operators(self):
        for op in ["==", ">=", "<=", "~=", "!="]:
            result = parse_install_command(f"pip install pkg{op}1.0")
            assert len(result) == 1
            assert result[0]["pinned"] is True


class TestParseOtherManagers:
    def test_cargo_add(self):
        result = parse_install_command("cargo add serde --features derive")
        assert len(result) == 1
        assert result[0]["name"] == "serde"
        assert result[0]["manager"] == "cargo"

    def test_go_get(self):
        result = parse_install_command(
            "go get github.com/gin-gonic/gin@v1.9.0"
        )
        assert len(result) == 1
        assert result[0]["name"] == "github.com/gin-gonic/gin"
        assert result[0]["version"] == "v1.9.0"
        assert result[0]["pinned"] is True

    def test_brew_install(self):
        result = parse_install_command("brew install jq yq")
        assert len(result) == 2
        names = {p["name"] for p in result}
        assert names == {"jq", "yq"}
        assert result[0]["manager"] == "brew"

    def test_apt_install(self):
        result = parse_install_command("apt-get install -y curl wget")
        assert len(result) == 2
        names = {p["name"] for p in result}
        assert names == {"curl", "wget"}

    def test_npx(self):
        result = parse_install_command("npx create-next-app my-app")
        assert len(result) == 1
        assert result[0]["name"] == "create-next-app"
        assert result[0]["manager"] == "npx"

    def test_gem_install(self):
        result = parse_install_command("gem install rails")
        assert len(result) == 1
        assert result[0]["name"] == "rails"
        assert result[0]["manager"] == "gem"


class TestNoFalsePositives:
    def test_npm_run(self):
        assert parse_install_command("npm run build") == []

    def test_pip_version(self):
        assert parse_install_command("pip --version") == []

    def test_ls(self):
        assert parse_install_command("ls -la") == []

    def test_npm_test(self):
        assert parse_install_command("npm test") == []

    def test_cargo_build(self):
        assert parse_install_command("cargo build --release") == []

    def test_empty(self):
        assert parse_install_command("") == []

    def test_none(self):
        assert parse_install_command(None) == []


class TestAssessRisk:
    def test_typosquat(self):
        risks = assess_risk({"name": "requets", "manager": "pip"})
        assert any(r.startswith("typosquat:") for r in risks)
        assert "typosquat:requests" in risks

    def test_typosquat_axios(self):
        risks = assess_risk({"name": "axois", "manager": "npm"})
        assert "typosquat:axios" in risks

    def test_unpinned(self):
        risks = assess_risk({"name": "foo", "pinned": False, "manager": "npm"})
        assert "unpinned" in risks

    def test_pinned_no_flag(self):
        risks = assess_risk({"name": "foo", "pinned": True, "manager": "npm"})
        assert "unpinned" not in risks

    def test_npx_remote_exec(self):
        risks = assess_risk({"name": "x", "manager": "npx"})
        assert "remote_exec" in risks

    def test_scoped_package(self):
        risks = assess_risk({"name": "@company/pkg", "manager": "npm"})
        assert "scoped" in risks

    def test_clean_package(self):
        risks = assess_risk(
            {"name": "requests", "pinned": True, "manager": "pip"}
        )
        assert risks == []


class TestApiEndpoint:
    @pytest.fixture
    def db(self, tmp_path):
        from claude_monitoring.db import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def test_table_exists(self, db):
        row = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='agent_dependencies'"
        ).fetchone()
        assert row is not None

    def test_insert_and_query(self, db):
        db.execute(
            """INSERT INTO agent_dependencies
               (timestamp, session_id, agent_type, action, package_manager,
                package_name, package_version, pinned, registry_url, command, risk_flags, dedup_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "2026-04-04T10:00:00Z",
                "sess1",
                "claude_code",
                "install",
                "npm",
                "express",
                "4.18.0",
                1,
                "npmjs.org",
                "npm install express@4.18.0",
                "[]",
                "hash1",
            ),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM agent_dependencies WHERE package_name='express'"
        ).fetchone()
        assert row is not None
        assert row["package_version"] == "4.18.0"
        assert row["pinned"] == 1

    def test_dedup_constraint(self, db):
        for _ in range(2):
            db.execute(
                """INSERT OR IGNORE INTO agent_dependencies
                   (timestamp, action, package_manager, package_name, dedup_hash)
                   VALUES ('t', 'install', 'npm', 'foo', 'dup-hash')"""
            )
        db.commit()
        count = db.execute(
            "SELECT COUNT(*) FROM agent_dependencies WHERE dedup_hash='dup-hash'"
        ).fetchone()[0]
        assert count == 1


class TestBackfill:
    @pytest.fixture
    def db(self, tmp_path):
        from claude_monitoring.db import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def test_backfill_from_events(self, db):
        from claude_monitoring.supply_chain import backfill_dependencies

        # Insert tool_use events with install commands
        commands = [
            "npm install express@4.18.0",
            "pip install requests==2.31.0 flask",
            "cargo add serde",
        ]
        for i, cmd in enumerate(commands):
            db.execute(
                """INSERT INTO events
                   (timestamp, session_id, event_type, source_layer, data_json, dedup_hash)
                   VALUES (?, ?, 'tool_use', 'jsonl', ?, ?)""",
                (
                    f"2026-04-04T10:0{i}:00Z",
                    "sess1",
                    json.dumps({"name": "Bash", "command": cmd}),
                    f"ev-hash-{i}",
                ),
            )
        db.commit()

        count = backfill_dependencies(db)
        assert count >= 4  # express + requests + flask + serde

        rows = db.execute(
            "SELECT * FROM agent_dependencies ORDER BY package_name"
        ).fetchall()
        names = {r["package_name"] for r in rows}
        assert "express" in names
        assert "requests" in names
        assert "flask" in names
        assert "serde" in names
