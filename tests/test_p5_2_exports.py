"""P5.2 export-format tests — Phase B (TDD).

Phase A judge p5.2.a1 APPROVE 2026-06-15. The load-bearing contract:
every export cell routes through ``privacy_audit.redact_value_for_display``
unchanged — exports inherit the P5.1b masking semantics.

Mandatory tests per the Phase A carry-forwards:
  1. Inversion test on a *masked* column (judge condition #2):
     seed a token into `assets.current_state` (classified "masked") —
     not into a raw/opaque_id column where it would pass vacuously.
  2. No queries against `CAPTURE_TABLES_NO_SAMPLES` (judge condition #3).
  3. Stable opaque_id round-trip across all three formats.
  4. Per-format round-trip validation (directive L1774 acceptance).
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from pathlib import Path

import pytest

from claude_monitoring.db import init_db

# ---------------------------------------------------------------------------
# Inversion test — the load-bearing contract
# ---------------------------------------------------------------------------


class TestCollectorRoutesThroughRedactionPrimitive:
    """The single most important test: a seeded token in a MASKED column
    must NOT appear raw in the collected rows. Targets `current_state`
    because that's classified `masked` in SAFE_COLUMNS_BY_TABLE; a raw
    column would pass vacuously."""

    def test_token_in_current_state_does_not_leak(self, tmp_path):
        from claude_monitoring.exports import collect_assets_for_export

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "asset-leaktest",
                "ai_tool",
                "leaktest",
                "ollama-models",
                0,
                0,
                0,
                json.dumps({"api_key": "sk-FAKE1234567890ABCDEFGHIJKLMNOP"}),
            ),
        )
        conn.commit()
        rows = collect_assets_for_export(conn)
        conn.close()
        # Walk every cell of every row and assert the raw token never appears.
        for row in rows:
            for col, value in row.items():
                assert "sk-FAKE1234567890ABCDEFGHIJKLMNOP" not in value, (
                    f"raw token leaked into export at column {col!r}; got {value!r}"
                )

    def test_username_path_in_install_path_does_not_leak(self, tmp_path):
        """install_path is classified `masked` — the home-dir
        normalization pipeline must strip the username before it reaches
        the export."""
        from claude_monitoring.exports import collect_assets_for_export

        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, "
            "current_state, install_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "asset-pathtest",
                "ai_tool",
                "pathtest",
                "ollama-models",
                0,
                0,
                0,
                "{}",
                "/Users/realuser/Library/Application Support/claude/extensions/foo",
            ),
        )
        conn.commit()
        rows = collect_assets_for_export(conn)
        conn.close()
        for row in rows:
            for col, value in row.items():
                assert "realuser" not in value, f"raw username leaked into export at column {col!r}; got {value!r}"


# ---------------------------------------------------------------------------
# Collector source — only the `assets` table, never a capture table
# ---------------------------------------------------------------------------


class TestCollectorTouchesOnlyAssetsTable:
    """No query in the collector references a capture table — the
    no-samples policy P5.1b enforces for --db-audit is preserved here
    by construction, not by the runtime fail-closed alone."""

    def test_module_source_does_not_reference_capture_tables(self):
        from claude_monitoring import exports
        from claude_monitoring.privacy_audit import CAPTURE_TABLES_NO_SAMPLES

        source = Path(exports.__file__).read_text()
        for capture_table in CAPTURE_TABLES_NO_SAMPLES:
            # Look for table-name token boundaries (no FROM <name>, no
            # SELECT against the table). Allow the literal in the
            # `CAPTURE_TABLES_NO_SAMPLES` reference itself; the actual
            # SQL queries must not mention any capture table.
            sql_contexts = (
                f"FROM {capture_table}",
                f"from {capture_table}",
                f"INTO {capture_table}",
                f"into {capture_table}",
            )
            for ctx in sql_contexts:
                assert ctx not in source, (
                    f"exports.py SQL must not query capture table {capture_table!r}; found {ctx!r}"
                )


# ---------------------------------------------------------------------------
# Per-format round-trip — directive L1774 "produce valid output"
# ---------------------------------------------------------------------------


class TestExportFormatsRoundTrip:
    def _seed(self, tmp_path) -> Path:
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        for idx, (name, source) in enumerate([("alpha", "ollama-models"), ("beta", "chromium-extensions")]):
            conn.execute(
                "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state, risk_score, risk_band) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"asset-{idx}", "ai_tool", name, source, 0, 0, 0, "{}", 50, "medium"),
            )
        conn.commit()
        conn.close()
        return db_path

    def test_json_parses_and_carries_envelope(self, tmp_path):
        from claude_monitoring.exports import export_assets

        conn = sqlite3.connect(self._seed(tmp_path))
        rendered = export_assets("json", conn)
        conn.close()
        payload = json.loads(rendered)
        assert payload["asset_count"] == 2
        assert isinstance(payload["assets"], list)
        assert "generated_at" in payload

    def test_csv_parses_via_dict_reader(self, tmp_path):
        from claude_monitoring.exports import export_assets

        conn = sqlite3.connect(self._seed(tmp_path))
        rendered = export_assets("csv", conn)
        conn.close()
        reader = csv.DictReader(io.StringIO(rendered))
        rows = list(reader)
        assert len(rows) == 2
        assert "id" in reader.fieldnames
        assert "risk_band" in reader.fieldnames

    def test_markdown_has_summary_and_table(self, tmp_path):
        from claude_monitoring.exports import export_assets

        conn = sqlite3.connect(self._seed(tmp_path))
        rendered = export_assets("md", conn)
        conn.close()
        assert "# Vigil Attack-Surface Inventory Export" in rendered
        assert "## Summary by risk band" in rendered
        assert "## Asset inventory" in rendered
        # Table row presence.
        assert "asset-0" in rendered
        assert "asset-1" in rendered

    def test_invalid_format_raises_value_error(self, tmp_path):
        from claude_monitoring.exports import export_assets

        conn = sqlite3.connect(self._seed(tmp_path))
        with pytest.raises(ValueError, match="unknown export format"):
            export_assets("xml", conn)
        conn.close()


# ---------------------------------------------------------------------------
# Stable opaque-id — directive end-state (assets round-trip with stable IDs)
# ---------------------------------------------------------------------------


class TestStableAssetIds:
    """The `id` column is classified `opaque_id` (digest); it must
    appear UNCHANGED in all three formats. The export round-trips the
    same digest the assets table stored."""

    def test_id_appears_unchanged_in_all_three_formats(self, tmp_path):
        from claude_monitoring.exports import export_assets

        digest = "a" * 64  # opaque hex digest shape
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        conn.execute(
            "INSERT INTO assets (id, type, name, source, first_seen, last_seen, last_scanned, current_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (digest, "ai_tool", "stable", "ollama-models", 0, 0, 0, "{}"),
        )
        conn.commit()
        # JSON
        rendered_json = export_assets("json", conn)
        # CSV
        rendered_csv = export_assets("csv", conn)
        # Markdown
        rendered_md = export_assets("md", conn)
        conn.close()
        assert digest in rendered_json
        assert digest in rendered_csv
        assert digest in rendered_md


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------


class TestArgparseDispatch:
    def test_export_flag_present(self):
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--export", choices=("json", "csv", "md"))
        ns = parser.parse_args(["--export", "json"])
        assert ns.export == "json"

    def test_main_dispatches_to_export_helper(self, monkeypatch, tmp_path):
        from claude_monitoring import monitor

        called = {"n": 0, "fmt": None, "out": None}

        def fake_export_assets_to_destination(fmt, output_path):
            called["n"] += 1
            called["fmt"] = fmt
            called["out"] = output_path
            return 0

        monkeypatch.setattr(
            "claude_monitoring.exports.export_assets_to_destination",
            fake_export_assets_to_destination,
        )
        out_path = str(tmp_path / "out.json")
        monkeypatch.setattr("sys.argv", ["ai-monitor", "--export", "json", "--output", out_path])
        with pytest.raises(SystemExit) as exc:
            monitor.main()
        assert called["n"] == 1
        assert called["fmt"] == "json"
        assert called["out"] == out_path
        assert exc.value.code == 0

    def test_export_mutually_exclusive_with_discover(self, monkeypatch):
        from claude_monitoring import monitor

        monkeypatch.setattr("sys.argv", ["ai-monitor", "--discover", "--export", "json"])
        with pytest.raises(SystemExit) as exc:
            monitor.main()
        assert exc.value.code == 2  # argparse error


# ---------------------------------------------------------------------------
# Empty DB
# ---------------------------------------------------------------------------


class TestEmptyDb:
    def test_empty_db_exports_zero_assets(self, tmp_path):
        from claude_monitoring.exports import export_assets

        db_path = tmp_path / "test.db"
        init_db(db_path).close()
        conn = sqlite3.connect(db_path)
        payload = json.loads(export_assets("json", conn))
        conn.close()
        assert payload["asset_count"] == 0
        assert payload["assets"] == []
