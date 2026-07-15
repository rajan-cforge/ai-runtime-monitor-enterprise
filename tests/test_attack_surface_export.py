"""AS Visual Refresh PR-1 — tests for render_attack_surface_export.

Covers all six branches of ``render_attack_surface_export``:
- Format alias normalization (ndjson→json, markdown→md, JSON alias miss).
- Success paths for canonical formats (json, csv, md).
- Rejection paths for unknown formats (400 status).
- Render-failure fallback (500 status).

Also asserts the ``_send_download_payload`` handler-side helper is wired
into ``_api_export`` for the ``attack-surface`` type, so the coverage
ratchet on ``dashboard_handler.py`` reflects the new elif branch.
"""

from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from claude_monitoring.attack_surface.dashboard_api import render_attack_surface_export
from claude_monitoring.persistence.migrations import apply_migrations


@pytest.fixture()
def _migrated_conn():
    """Fresh in-memory DB with full migration chain applied."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    apply_migrations(conn)
    yield conn
    conn.close()


class TestFormatVocabularyNormalization:
    """Frontend uses ``markdown``/``ndjson``; ``exports.supported_formats()``
    canonical vocabulary is ``("json","csv","md")``. Aliases MUST normalize
    before the guard check, or valid clicks fail with 400."""

    def test_markdown_alias_normalizes_to_md(self, _migrated_conn):
        body, status = render_attack_surface_export("markdown", _migrated_conn)
        assert status == 200
        assert body["content_type"] == "text/markdown; charset=utf-8"
        assert body["filename"].endswith(".md")

    def test_ndjson_alias_normalizes_to_json(self, _migrated_conn):
        body, status = render_attack_surface_export("ndjson", _migrated_conn)
        assert status == 200
        assert body["content_type"] == "application/json; charset=utf-8"
        assert body["filename"].endswith(".json")

    def test_canonical_json_passes_through(self, _migrated_conn):
        body, status = render_attack_surface_export("json", _migrated_conn)
        assert status == 200
        assert body["content_type"] == "application/json; charset=utf-8"
        assert body["filename"].endswith(".json")

    def test_canonical_csv_passes_through(self, _migrated_conn):
        body, status = render_attack_surface_export("csv", _migrated_conn)
        assert status == 200
        assert body["content_type"] == "text/csv; charset=utf-8"
        assert body["filename"].endswith(".csv")


class TestUnknownFormatRejection:
    """Guard against ``exports.supported_formats()`` — anything not in
    ``{"json","csv","md"}`` after alias normalization returns 400 without
    calling ``export_assets``."""

    def test_unknown_format_returns_400(self, _migrated_conn):
        body, status = render_attack_surface_export("xml", _migrated_conn)
        assert status == 400
        assert "Unknown export format" in body["error"]
        assert "'xml'" in body["error"]

    def test_case_sensitive_json_rejected(self, _migrated_conn):
        """Vocabulary matches CLI ``--export`` choices which are
        lowercase — uppercase must not silently work."""
        body, status = render_attack_surface_export("JSON", _migrated_conn)
        assert status == 400

    def test_empty_string_rejected(self, _migrated_conn):
        body, status = render_attack_surface_export("", _migrated_conn)
        assert status == 400


class TestRenderFailureFallback:
    """If ``export_assets`` raises for any reason (bad schema, IO error,
    etc.), the wrapper must return a 500 envelope rather than propagate.
    Guarantees the handler always has a status+body to send back."""

    def test_render_failure_returns_500(self, monkeypatch, _migrated_conn):
        from claude_monitoring import exports as _exports

        def _boom(_fmt, _conn):
            raise RuntimeError("simulated render failure")

        monkeypatch.setattr(_exports, "export_assets", _boom)
        body, status = render_attack_surface_export("json", _migrated_conn)
        assert status == 500
        assert "export failed" in body["error"]
        assert "simulated render failure" in body["error"]


class TestFilenameShape:
    """Filename format: ``vigil_attack_surface_YYYY-MM-DD.<ext>``.
    Anchors the download UX contract."""

    def test_filename_prefix(self, _migrated_conn):
        body, _ = render_attack_surface_export("json", _migrated_conn)
        assert body["filename"].startswith("vigil_attack_surface_")

    def test_filename_extension_matches_canonical_format(self, _migrated_conn):
        for fmt, expected_ext in (("json", ".json"), ("csv", ".csv"), ("markdown", ".md")):
            body, _ = render_attack_surface_export(fmt, _migrated_conn)
            assert body["filename"].endswith(expected_ext), f"{fmt!r} → {body['filename']!r}"


class TestHandlerElifWired:
    """Handler-side coverage: assert the attack-surface elif branch
    in ``_api_export`` calls ``render_attack_surface_export`` and routes
    through ``_send_download_payload``. Static-source check so we don't
    have to stand up a full HTTP handler."""

    def test_api_export_dispatches_attack_surface(self):
        import inspect

        from claude_monitoring import dashboard_handler as _dh

        src = inspect.getsource(_dh.DashboardHandler._api_export)
        assert "attack-surface" in src, "_api_export must dispatch attack-surface type"
        assert "render_attack_surface_export" in src, (
            "_api_export attack-surface branch must call render_attack_surface_export"
        )
        assert "_send_download_payload" in src, (
            "_api_export attack-surface branch must send via _send_download_payload"
        )

    def test_send_download_payload_defined(self):
        from claude_monitoring.dashboard_handler import DashboardHandler

        assert hasattr(DashboardHandler, "_send_download_payload"), (
            "_send_download_payload helper must exist on DashboardHandler"
        )


class TestExportHTTPIntegration:
    """Live-handler coverage — actually invokes _api_export's
    attack-surface elif + _send_download_payload. Same fixture pattern
    as tests/test_dashboard_p8E_settings_drawer.py."""

    @pytest.fixture()
    def _api_server(self, tmp_path, monkeypatch):
        import threading
        from http.server import HTTPServer

        from claude_monitoring.db import init_db

        monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir(exist_ok=True)
        init_db(db_path).close()
        with (
            patch("claude_monitoring.monitor.DB_PATH", db_path),
            patch("claude_monitoring.monitor.OUTPUT_DIR", output_dir),
            patch("claude_monitoring.config.get_db_path", return_value=db_path),
            patch("claude_monitoring.config.get_output_dir", return_value=output_dir),
            patch("claude_monitoring.db.get_db_path", return_value=db_path),
            patch("claude_monitoring.db.get_output_dir", return_value=output_dir),
        ):
            from claude_monitoring.monitor import DashboardHandler

            server = HTTPServer(("127.0.0.1", 0), DashboardHandler)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            yield f"http://127.0.0.1:{port}"
            server.shutdown()

    def test_export_json_returns_200_with_attachment_headers(self, _api_server):
        from urllib.request import urlopen

        resp = urlopen(f"{_api_server}/api/export?type=attack-surface&format=json")
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "application/json; charset=utf-8"
        cd = resp.headers["Content-Disposition"]
        assert cd.startswith('attachment; filename="vigil_attack_surface_')
        assert cd.endswith('.json"')
        body = resp.read()
        assert int(resp.headers["Content-Length"]) == len(body)

    def test_export_csv_returns_200_with_correct_extension(self, _api_server):
        from urllib.request import urlopen

        resp = urlopen(f"{_api_server}/api/export?type=attack-surface&format=csv")
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "text/csv; charset=utf-8"
        assert resp.headers["Content-Disposition"].endswith('.csv"')

    def test_export_markdown_normalized_to_md(self, _api_server):
        """Frontend sends format=markdown; server normalizes to md and
        returns text/markdown content-type + .md filename."""
        from urllib.request import urlopen

        resp = urlopen(f"{_api_server}/api/export?type=attack-surface&format=markdown")
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "text/markdown; charset=utf-8"
        assert resp.headers["Content-Disposition"].endswith('.md"')

    def test_export_unknown_format_returns_400(self, _api_server):
        import urllib.error as _err
        from urllib.request import urlopen

        try:
            urlopen(f"{_api_server}/api/export?type=attack-surface&format=xml")
            raise AssertionError("expected 400")
        except _err.HTTPError as e:
            assert e.code == 400
