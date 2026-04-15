"""Tests for supply chain dependency monitoring."""

import json
import sqlite3

import pytest

from claude_monitoring.supply_chain import (
    assess_risk,
    categorize_package,
    extract_project,
    parse_install_command,
)

# ── Parser: core functionality ──────────────────────────────


class TestParseNpmInstall:
    def test_basic(self):
        result = parse_install_command("npm install foo bar@2.0 --save-dev")
        assert len(result) == 2
        foo = next(p for p in result if p["name"] == "foo")
        bar = next(p for p in result if p["name"] == "bar")
        assert foo["pinned"] is False
        assert bar["pinned"] is True
        assert bar["version"] == "2.0"

    def test_npm_i_shorthand(self):
        result = parse_install_command("npm i express")
        assert len(result) == 1
        assert result[0]["name"] == "express"

    def test_yarn_add(self):
        result = parse_install_command("yarn add react react-dom@18.2.0")
        assert len(result) == 2
        rd = next(p for p in result if p["name"] == "react-dom")
        assert rd["version"] == "18.2.0"

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

    def test_requirements_file(self):
        result = parse_install_command("pip install -r requirements.txt")
        assert len(result) == 1
        assert "requirements.txt" in result[0]["name"]
        assert result[0]["pinned"] is True

    def test_pip3(self):
        result = parse_install_command("pip3 install numpy>=1.24")
        assert len(result) == 1
        assert result[0]["name"] == "numpy"
        assert result[0]["pinned"] is True

    def test_editable_install(self):
        result = parse_install_command("pip install -e .")
        assert len(result) == 1
        assert "editable" in result[0]["name"].lower()

    def test_editable_with_extras(self):
        result = parse_install_command('pip install -e ".[dev]"')
        assert len(result) == 1
        assert "editable" in result[0]["name"].lower()

    def test_index_url_skipped(self):
        result = parse_install_command("pip install --index-url https://custom.pypi.org/simple/ my-pkg")
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

    def test_go_get(self):
        result = parse_install_command("go get github.com/gin-gonic/gin@v1.9.0")
        assert len(result) == 1
        assert result[0]["name"] == "github.com/gin-gonic/gin"
        assert result[0]["version"] == "v1.9.0"
        assert result[0]["pinned"] is True

    def test_brew_install(self):
        result = parse_install_command("brew install jq yq")
        assert len(result) == 2
        assert {p["name"] for p in result} == {"jq", "yq"}

    def test_apt_install(self):
        result = parse_install_command("apt-get install -y curl wget")
        assert len(result) == 2
        assert {p["name"] for p in result} == {"curl", "wget"}

    def test_npx(self):
        result = parse_install_command("npx create-next-app my-app")
        assert len(result) == 1
        assert result[0]["name"] == "create-next-app"

    def test_gem_install(self):
        result = parse_install_command("gem install rails")
        assert len(result) == 1
        assert result[0]["name"] == "rails"


# ── Parser: shell noise filtering ───────────────────────────


class TestShellNoiseFiltering:
    def test_pipe_not_parsed(self):
        result = parse_install_command("pip install mitmproxy 2>&1 | tail -5")
        names = [p["name"] for p in result]
        assert "mitmproxy" in names
        assert "tail" not in names
        assert "|" not in names
        assert "2>&1" not in names

    def test_double_ampersand(self):
        result = parse_install_command("cd /app && pip install flask && echo done")
        names = [p["name"] for p in result]
        assert "flask" in names
        assert "cd" not in names
        assert "echo" not in names
        assert "done" not in names

    def test_redirect_stripped(self):
        result = parse_install_command("pip install boto3 2>/dev/null")
        assert len(result) == 1
        assert result[0]["name"] == "boto3"

    def test_platform_flags_skipped(self):
        result = parse_install_command("pip install --platform manylinux2014_x86_64 --python-version 3.12 cryptography")
        names = [p["name"] for p in result]
        assert names == ["cryptography"]

    def test_garbage_tokens_filtered(self):
        """Tokens like 'to', 'for', 'bi', ')"},', 'python-' must not appear."""
        result = parse_install_command("pip install to for and bi load gate quality")
        assert len(result) == 0

    def test_punctuation_tokens_filtered(self):
        result = parse_install_command('pip install quality)"}, )"}, test" npm"')
        assert len(result) == 0

    def test_truncated_fragment_filtered(self):
        result = parse_install_command("pip install python- user-local")
        assert len(result) == 0

    def test_docker_compose_prefix(self):
        result = parse_install_command("docker-compose exec -T api pip install pytest moto")
        names = [p["name"] for p in result]
        assert "pytest" in names
        assert "moto" in names
        assert "docker-compose" not in names
        assert "api" not in names

    def test_semicolon_splits(self):
        result = parse_install_command("pip install requests; pip install flask")
        # Should get requests from first segment
        names = [p["name"] for p in result]
        assert "requests" in names


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

    def test_path_not_package(self):
        result = parse_install_command("pip install -e /Users/x/Projects/foo")
        assert len(result) == 1
        assert "editable" in result[0]["name"].lower()


# ── Risk assessment ──────────────────────────────────────────


class TestAssessRisk:
    def test_typosquat_high_score(self):
        score, reasons = assess_risk({"name": "requets", "pinned": False, "manager": "pip"})
        assert score >= 5
        assert any("typosquat" in r for r in reasons)

    def test_typosquat_axios(self):
        score, reasons = assess_risk({"name": "axois", "pinned": False, "manager": "npm"})
        assert score >= 5

    def test_high_risk_package(self):
        score, reasons = assess_risk({"name": "mitmproxy", "pinned": False, "manager": "pip"})
        assert score >= 4
        assert len(reasons) >= 2  # high_risk + unpinned at minimum

    def test_pinned_normal_package(self):
        score, reasons = assess_risk({"name": "requests", "pinned": True, "manager": "pip"})
        assert score <= 1
        assert len(reasons) == 0

    def test_unpinned_normal(self):
        score, reasons = assess_risk({"name": "requests", "pinned": False, "manager": "pip"})
        assert score >= 1
        assert any("unpinned" in r for r in reasons)

    def test_npx_remote_exec(self):
        score, reasons = assess_risk({"name": "create-next-app", "manager": "npx"})
        assert score >= 3

    def test_financial_package(self):
        score, reasons = assess_risk({"name": "alpaca-trade-api", "pinned": True, "manager": "pip"})
        assert score >= 2
        assert any("financial" in r for r in reasons)


# ── Categorization ───────────────────────────────────────────


class TestCategorization:
    def test_pip_is_package(self):
        assert categorize_package("requests", "pip") == "package"

    def test_npx_is_tool_exec(self):
        assert categorize_package("tsc", "npx") == "tool_exec"

    def test_brew_is_build_tool(self):
        assert categorize_package("jq", "brew") == "build_tool"

    def test_apt_is_build_tool(self):
        assert categorize_package("curl", "apt") == "build_tool"

    def test_npm_is_package(self):
        assert categorize_package("express", "npm") == "package"

    def test_cargo_is_package(self):
        assert categorize_package("serde", "cargo") == "package"


# ── Project extraction ───────────────────────────────────────


class TestProjectExtraction:
    def test_documents_path(self):
        assert extract_project("/Users/x/Documents/talosAI/ui") == "talosAI"

    def test_projects_path(self):
        p = extract_project("/Users/x/Projects/ai-runtime-monitor-enterprise/src")
        assert p == "ai-runtime-monitor-enterprise"

    def test_no_match(self):
        assert extract_project("/tmp/build") is None

    def test_none(self):
        assert extract_project(None) is None

    def test_home_path(self):
        assert extract_project("~/Documents/myproj/src") == "myproj"


# ── DB + Backfill ────────────────────────────────────────────


class TestApiEndpoint:
    @pytest.fixture
    def db(self, tmp_path):
        from claude_monitoring.db import init_db

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def test_table_exists(self, db):
        row = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='agent_dependencies'").fetchone()
        assert row is not None

    def test_category_column_exists(self, db):
        row = db.execute("PRAGMA table_info(agent_dependencies)").fetchall()
        cols = {r["name"] for r in row}
        assert "category" in cols
        assert "project" in cols

    def test_dedup_constraint(self, db):
        for _ in range(2):
            db.execute(
                """INSERT OR IGNORE INTO agent_dependencies
                   (timestamp, action, package_manager, package_name, dedup_hash)
                   VALUES ('t', 'install', 'npm', 'foo', 'dup-hash')"""
            )
        db.commit()
        count = db.execute("SELECT COUNT(*) FROM agent_dependencies WHERE dedup_hash='dup-hash'").fetchone()[0]
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
        assert count >= 4

        rows = db.execute("SELECT * FROM agent_dependencies ORDER BY package_name").fetchall()
        names = {r["package_name"] for r in rows}
        assert "express" in names
        assert "requests" in names
        assert "flask" in names
        assert "serde" in names

    def test_backfill_no_shell_noise(self, db):
        from claude_monitoring.supply_chain import backfill_dependencies

        db.execute(
            """INSERT INTO events
               (timestamp, session_id, event_type, source_layer, data_json, dedup_hash)
               VALUES (?, ?, 'tool_use', 'jsonl', ?, ?)""",
            (
                "2026-04-04T10:00:00Z",
                "sess1",
                json.dumps({"name": "Bash", "command": "pip install mitmproxy 2>&1 | tail -5"}),
                "ev-noise",
            ),
        )
        db.commit()
        backfill_dependencies(db)
        names = [r[0] for r in db.execute("SELECT package_name FROM agent_dependencies").fetchall()]
        assert "mitmproxy" in names
        assert "tail" not in names
        assert "|" not in names
        assert "2>&1" not in names


class TestEnvironmentEnumerators:
    """Launchd-safety regression: the environment scanners must NOT rely
    on a bare ``pip`` or ``brew`` executable lookup via PATH. Under
    launchd, PATH is stripped to a minimal set that usually doesn't
    include pip or /opt/homebrew/bin, and we saw the environment phase
    silently return 0 packages in production because of it."""

    def test_get_pip_packages_uses_sys_executable(self):
        from unittest.mock import patch

        from claude_monitoring import supply_chain

        captured_cmd = []

        def fake_run(cmd, **kw):
            captured_cmd.append(cmd)

            class R:
                stdout = '[{"name": "requests", "version": "2.31.0"}]'

            return R()

        with patch("claude_monitoring.supply_chain.subprocess.run", side_effect=fake_run):
            result = supply_chain.get_pip_packages()

        # First arg must be an absolute path (sys.executable), not the
        # string "pip" — a bare "pip" would be a PATH lookup and break
        # under launchd.
        assert captured_cmd, "subprocess.run was never called"
        assert captured_cmd[0][0] != "pip"
        assert captured_cmd[0][1:4] == ["-m", "pip", "list"]
        assert result == [{"name": "requests", "version": "2.31.0", "manager": "pip"}]

    def test_get_brew_packages_uses_absolute_path(self):
        from unittest.mock import patch

        from claude_monitoring import supply_chain

        captured_cmd = []

        def fake_run(cmd, **kw):
            captured_cmd.append(cmd)

            class R:
                stdout = "htop 3.2.2\nabseil 20260107.1"

            return R()

        with (
            patch("os.path.exists", side_effect=lambda p: p == "/opt/homebrew/bin/brew"),
            patch("claude_monitoring.supply_chain.subprocess.run", side_effect=fake_run),
        ):
            result = supply_chain.get_brew_packages()

        assert captured_cmd, "subprocess.run was never called"
        assert captured_cmd[0][0] == "/opt/homebrew/bin/brew"
        names = [p["name"] for p in result]
        assert "htop" in names
        assert "abseil" in names

    def test_get_brew_packages_returns_empty_when_brew_absent(self):
        from unittest.mock import patch

        from claude_monitoring import supply_chain

        with (
            patch("os.path.exists", return_value=False),
            patch("shutil.which", return_value=None),
        ):
            assert supply_chain.get_brew_packages() == []
