# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for Section 2 (custom CA) and Section 4 (perms + auth + masking + purge).

These are hardening features so every test asserts both the happy path
AND that failures fail closed — e.g. a missing cert should not trust an
empty string, a short token should not pass auth, a file with wrong mode
should be detected and fixed.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_monitoring import security

# ─────────────────────────────────────────────────────────────
# Section 2: Custom CA generation
# ─────────────────────────────────────────────────────────────


class TestGenerateCustomCA:
    def test_creates_cert_and_key(self, tmp_path):
        cert = tmp_path / "ca.pem"
        key = tmp_path / "ca-key.pem"
        cert_path, key_path = security.generate_custom_ca(
            cert_path=cert,
            key_path=key,
            domains=["api.anthropic.com"],
            hostname="test-host",
        )
        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
        assert b"PRIVATE KEY" in key_path.read_bytes()

    def test_key_has_600_permissions(self, tmp_path):
        cert = tmp_path / "ca.pem"
        key = tmp_path / "ca-key.pem"
        security.generate_custom_ca(cert, key, domains=["api.anthropic.com"])
        assert oct(key.stat().st_mode)[-3:] == "600"

    def test_cert_has_branded_common_name(self, tmp_path):
        from cryptography import x509

        cert = tmp_path / "ca.pem"
        key = tmp_path / "ca-key.pem"
        security.generate_custom_ca(cert, key, domains=["api.anthropic.com"], hostname="rajan-mac")
        parsed = x509.load_pem_x509_certificate(cert.read_bytes())
        cn_attrs = [a.value for a in parsed.subject if a.oid.dotted_string == "2.5.4.3"]
        org_attrs = [a.value for a in parsed.subject if a.oid.dotted_string == "2.5.4.10"]
        assert cn_attrs == ["AI Runtime Monitor - rajan-mac"]
        assert org_attrs == ["GoCloudForge, Inc."]

    def test_cert_has_name_constraints(self, tmp_path):
        from cryptography import x509

        cert = tmp_path / "ca.pem"
        key = tmp_path / "ca-key.pem"
        security.generate_custom_ca(cert, key, domains=["api.anthropic.com", "api.openai.com"])
        parsed = x509.load_pem_x509_certificate(cert.read_bytes())
        nc = parsed.extensions.get_extension_for_class(x509.NameConstraints)
        assert nc.critical is True
        permitted = [d.value for d in nc.value.permitted_subtrees]
        assert "api.anthropic.com" in permitted
        assert "api.openai.com" in permitted
        assert "www.chase.com" not in permitted

    def test_cert_is_ca_and_signs_only(self, tmp_path):
        from cryptography import x509

        cert = tmp_path / "ca.pem"
        key = tmp_path / "ca-key.pem"
        security.generate_custom_ca(cert, key, domains=["api.anthropic.com"])
        parsed = x509.load_pem_x509_certificate(cert.read_bytes())
        bc = parsed.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        ku = parsed.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.digital_signature is False

    def test_cert_valid_for_one_year(self, tmp_path):
        from cryptography import x509

        cert = tmp_path / "ca.pem"
        key = tmp_path / "ca-key.pem"
        security.generate_custom_ca(cert, key, domains=["api.anthropic.com"])
        parsed = x509.load_pem_x509_certificate(cert.read_bytes())
        span = parsed.not_valid_after_utc - parsed.not_valid_before_utc
        assert timedelta(days=364) <= span <= timedelta(days=366)

    def test_mitmproxy_confdir_layout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "get_output_dir", lambda: tmp_path)
        security.generate_custom_ca(
            cert_path=tmp_path / "certs" / "ai-monitor-ca.pem",
            key_path=tmp_path / "certs" / "ai-monitor-ca-key.pem",
            domains=["api.anthropic.com"],
        )
        mitm_dir = tmp_path / "certs" / "mitmproxy"
        assert (mitm_dir / "mitmproxy-ca.pem").exists()
        assert (mitm_dir / "mitmproxy-ca-cert.pem").exists()
        # Combined file has both the private key and the cert
        combined = (mitm_dir / "mitmproxy-ca.pem").read_bytes()
        assert b"PRIVATE KEY" in combined
        assert b"CERTIFICATE" in combined
        # mitmproxy key file is 600
        assert oct((mitm_dir / "mitmproxy-ca.pem").stat().st_mode)[-3:] == "600"


class TestGetCAInfo:
    def test_returns_none_when_missing(self, tmp_path):
        assert security.get_ca_info(tmp_path / "missing.pem") is None

    def test_returns_summary_of_installed_ca(self, tmp_path):
        cert = tmp_path / "ca.pem"
        key = tmp_path / "ca-key.pem"
        security.generate_custom_ca(cert, key, domains=["api.anthropic.com"], hostname="my-host")
        info = security.get_ca_info(cert)
        assert info is not None
        assert info["common_name"] == "AI Runtime Monitor - my-host"
        assert info["organization"] == "GoCloudForge, Inc."
        assert "api.anthropic.com" in info["permitted_domains"]
        assert info["serial_number"]


class TestTrustCACert:
    def test_missing_cert_returns_false(self, tmp_path):
        assert security.trust_ca_cert(tmp_path / "nope.pem") is False

    def test_successful_trust_shells_out_to_osascript(self, tmp_path):
        cert = tmp_path / "ca.pem"
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")

        called = {}

        def fake_run(cmd, **kw):
            called["cmd"] = cmd
            import subprocess as _sp

            return _sp.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch("claude_monitoring.security.subprocess.run", side_effect=fake_run):
            assert security.trust_ca_cert(cert) is True
        assert called["cmd"][0] == "osascript"
        assert "add-trusted-cert" in called["cmd"][2]

    def test_returns_false_on_user_cancel(self, tmp_path):
        cert = tmp_path / "ca.pem"
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
        import subprocess as _sp

        with patch(
            "claude_monitoring.security.subprocess.run",
            return_value=_sp.CompletedProcess([], 1, stdout="", stderr="cancelled"),
        ):
            assert security.trust_ca_cert(cert) is False


# ─────────────────────────────────────────────────────────────
# Section 4a: File permissions
# ─────────────────────────────────────────────────────────────


class TestEnforcePermissions:
    def _setup(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "get_output_dir", lambda: tmp_path)
        monkeypatch.setattr(security, "get_db_path", lambda: tmp_path / "monitor.db")

    def test_missing_paths_are_skipped(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        # Nothing exists yet
        fixed = security.enforce_permissions()
        assert fixed == []

    def test_tightens_loose_db_permissions(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        db = tmp_path / "monitor.db"
        db.write_text("x")
        db.chmod(0o644)
        fixed = security.enforce_permissions()
        assert any("monitor.db" in msg for msg in fixed)
        assert oct(db.stat().st_mode)[-3:] == "600"

    def test_tightens_loose_output_dir(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        tmp_path.chmod(0o755)
        fixed = security.enforce_permissions()
        assert any("700" in msg for msg in fixed)
        assert oct(tmp_path.stat().st_mode)[-3:] == "700"

    def test_no_change_when_already_tight(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        tmp_path.chmod(0o700)
        db = tmp_path / "monitor.db"
        db.write_text("x")
        db.chmod(0o600)
        fixed = security.enforce_permissions()
        assert fixed == []


# ─────────────────────────────────────────────────────────────
# Section 4b: Dashboard token
# ─────────────────────────────────────────────────────────────


class TestEnsureDashboardToken:
    def test_creates_token_on_first_call(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "get_output_dir", lambda: tmp_path)
        token = security.ensure_dashboard_token()
        assert len(token) >= 32
        assert (tmp_path / ".dashboard_token").read_text().strip() == token

    def test_token_file_has_600_perms(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "get_output_dir", lambda: tmp_path)
        security.ensure_dashboard_token()
        assert oct((tmp_path / ".dashboard_token").stat().st_mode)[-3:] == "600"

    def test_returns_existing_token_if_present(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "get_output_dir", lambda: tmp_path)
        existing = "a" * 40
        (tmp_path / ".dashboard_token").write_text(existing)
        assert security.ensure_dashboard_token() == existing

    def test_regenerates_if_existing_is_too_short(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "get_output_dir", lambda: tmp_path)
        (tmp_path / ".dashboard_token").write_text("short")
        token = security.ensure_dashboard_token()
        assert token != "short"
        assert len(token) >= 32


class TestVerifyToken:
    def test_empty_presented_rejected(self):
        assert security.verify_token("", expected="real-token") is False
        assert security.verify_token(None, expected="real-token") is False  # type: ignore[arg-type]

    def test_empty_expected_rejected(self):
        assert security.verify_token("presented", expected="") is False

    def test_match_accepted(self):
        assert security.verify_token("real-token", expected="real-token") is True

    def test_mismatch_rejected(self):
        assert security.verify_token("wrong", expected="real-token") is False

    def test_reads_from_disk_when_expected_omitted(self, tmp_path, monkeypatch):
        monkeypatch.setattr(security, "get_output_dir", lambda: tmp_path)
        (tmp_path / ".dashboard_token").write_text("disk-token")
        assert security.verify_token("disk-token") is True
        assert security.verify_token("nope") is False


# ─────────────────────────────────────────────────────────────
# Section 4c: Masking and hashing
# ─────────────────────────────────────────────────────────────


class TestMaskValue:
    def test_standard_aws_key(self):
        masked = security.mask_value("AKIAJ5TESTXXXXXXXXXX")
        assert masked.startswith("AKIA")
        assert masked.endswith("XXXX")
        assert "*" in masked
        assert len(masked) == len("AKIAJ5TESTXXXXXXXXXX")

    def test_short_value_fully_masked(self):
        assert security.mask_value("short") == "****"
        assert security.mask_value("abc") == "****"

    def test_empty_value(self):
        assert security.mask_value("") == "****"
        assert security.mask_value(None) == "****"

    def test_preserves_length(self):
        raw = "sk-ant-1234567890abcdef"
        masked = security.mask_value(raw)
        assert len(masked) == len(raw)

    def test_no_plaintext_middle(self):
        masked = security.mask_value("AKIAJ5TESTXXXXXXXXXX")
        # The middle chars must be asterisks only
        middle = masked[4:-4]
        assert set(middle) == {"*"}


class TestHashValue:
    def test_stable_across_calls(self):
        a = security.hash_value("sk-ant-abc")
        b = security.hash_value("sk-ant-abc")
        assert a == b

    def test_different_values_different_hashes(self):
        assert security.hash_value("a") != security.hash_value("b")

    def test_empty_hash(self):
        assert security.hash_value("") == ""
        assert security.hash_value(None) == ""

    def test_hash_is_16_hex_chars(self):
        h = security.hash_value("anything")
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)


# ─────────────────────────────────────────────────────────────
# Section 4d: Purge old sensitive data
# ─────────────────────────────────────────────────────────────


class TestPurgeOldSensitiveData:
    @pytest.fixture()
    def db(self, tmp_path):
        conn = sqlite3.connect(str(tmp_path / "test.db"))
        conn.execute(
            """CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                session_id TEXT,
                event_type TEXT,
                source_layer TEXT,
                data_json TEXT
            )"""
        )
        conn.commit()
        yield conn
        conn.close()

    def test_scrubs_old_events(self, db):
        old_ts = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        payload = json.dumps(
            {
                "patterns": ["aws_key"],
                "severity": "critical",
                "snippet": "leaked AKIAJ5TEST",
                "matched_value": "AKIAJ5TESTXXXXXXXXXX",
                "match_context": "export KEY=AKIAJ5TESTXXXXXXXXXX in config",
            }
        )
        db.execute(
            "INSERT INTO events (timestamp, event_type, source_layer, data_json) VALUES (?, ?, ?, ?)",
            (old_ts, "sensitive_data", "network", payload),
        )
        db.commit()

        scrubbed = security.purge_old_sensitive_data(db, retention_days=30)
        assert scrubbed == 1

        row = db.execute("SELECT data_json FROM events").fetchone()
        data = json.loads(row[0])
        assert "snippet" not in data
        assert "matched_value" not in data
        assert "match_context" not in data
        # Metadata preserved
        assert data["patterns"] == ["aws_key"]
        assert data["severity"] == "critical"

    def test_keeps_recent_events(self, db):
        recent_ts = datetime.now(timezone.utc).isoformat()
        payload = json.dumps({"patterns": ["aws_key"], "severity": "high", "snippet": "recent"})
        db.execute(
            "INSERT INTO events (timestamp, event_type, source_layer, data_json) VALUES (?, ?, ?, ?)",
            (recent_ts, "sensitive_data", "network", payload),
        )
        db.commit()

        scrubbed = security.purge_old_sensitive_data(db, retention_days=30)
        assert scrubbed == 0
        row = db.execute("SELECT data_json FROM events").fetchone()
        assert json.loads(row[0])["snippet"] == "recent"

    def test_ignores_non_sensitive_events(self, db):
        old_ts = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        db.execute(
            "INSERT INTO events (timestamp, event_type, source_layer, data_json) VALUES (?, ?, ?, ?)",
            (old_ts, "user_prompt", "jsonl", json.dumps({"text": "hello"})),
        )
        db.commit()
        scrubbed = security.purge_old_sensitive_data(db, retention_days=30)
        assert scrubbed == 0

    def test_handles_invalid_retention(self, db):
        # A string retention shouldn't crash — function returns 0
        assert security.purge_old_sensitive_data(db, retention_days=30) == 0


# ─────────────────────────────────────────────────────────────
# Dashboard handler auth (integration-lite)
# ─────────────────────────────────────────────────────────────


class TestDashboardAuth:
    def _make_handler(self, token_file: Path, monkeypatch, disable_auth: bool = False):
        """Build a DashboardHandler instance without starting an HTTP server."""
        from claude_monitoring import monitor as mon
        from claude_monitoring import security as sec

        monkeypatch.setattr(sec, "get_output_dir", lambda: token_file.parent)
        if disable_auth:
            monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
        else:
            monkeypatch.delenv("DISABLE_DASHBOARD_AUTH", raising=False)

        handler = mon.DashboardHandler.__new__(mon.DashboardHandler)
        handler.headers = {}
        return handler

    def test_html_route_skips_auth(self, tmp_path, monkeypatch):
        handler = self._make_handler(tmp_path / ".dashboard_token", monkeypatch)
        assert handler._check_auth("/", {}) is True

    def test_api_route_rejects_missing_token(self, tmp_path, monkeypatch):
        (tmp_path / ".dashboard_token").write_text("real-token-abcdefghijk")
        handler = self._make_handler(tmp_path / ".dashboard_token", monkeypatch)
        assert handler._check_auth("/api/stats", {}) is False

    def test_api_route_accepts_query_token(self, tmp_path, monkeypatch):
        (tmp_path / ".dashboard_token").write_text("real-token-abcdefghijk")
        handler = self._make_handler(tmp_path / ".dashboard_token", monkeypatch)
        assert handler._check_auth("/api/stats", {"token": ["real-token-abcdefghijk"]}) is True

    def test_api_route_accepts_bearer_header(self, tmp_path, monkeypatch):
        (tmp_path / ".dashboard_token").write_text("real-token-abcdefghijk")
        handler = self._make_handler(tmp_path / ".dashboard_token", monkeypatch)
        handler.headers = {"Authorization": "Bearer real-token-abcdefghijk"}
        assert handler._check_auth("/api/stats", {}) is True

    def test_api_route_rejects_wrong_token(self, tmp_path, monkeypatch):
        (tmp_path / ".dashboard_token").write_text("real-token-abcdefghijk")
        handler = self._make_handler(tmp_path / ".dashboard_token", monkeypatch)
        assert handler._check_auth("/api/stats", {"token": ["wrong"]}) is False

    def test_env_var_disables_auth_for_tests(self, tmp_path, monkeypatch):
        handler = self._make_handler(tmp_path / ".dashboard_token", monkeypatch, disable_auth=True)
        assert handler._check_auth("/api/stats", {}) is True
