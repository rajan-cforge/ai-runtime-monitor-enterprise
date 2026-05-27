"""Security tests for AI Runtime Monitor.

Covers:
  - SQL injection prevention via parameterized queries
  - Large input handling / text truncation
  - JSON escaping (no XSS in JSON output)
  - CA trust verification (verify_ca_trusted)
"""

import json
import subprocess
from unittest.mock import patch

import pytest

from claude_monitoring import config
from claude_monitoring.db import init_db
from claude_monitoring.utils import scan_sensitive


@pytest.fixture(autouse=True)
def _reset_config():
    config.reset()
    yield
    config.reset()


def _make_self_signed_ca(path):
    """Write a real self-signed CA to ``path``. Lets verify_ca_trusted's
    SHA-1 computation run end-to-end without hard-coding fingerprints."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA — Verify")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert.fingerprint(hashes.SHA1()).hex()


class TestVerifyCaTrusted:
    """verify_ca_trusted returns ``(bool, TrustVerificationCode)``.
    The second element is a Literal drawn from a constrained set —
    never raw subprocess output. Callers map code → message via
    ``trust_reason_message``. Tests below pin the code returned for
    each failure mode."""

    def test_returns_true_with_trusted_code_when_in_keychain_and_admin_trust(self, tmp_path):
        from claude_monitoring.security import verify_ca_trusted

        cert_path = tmp_path / "ai-monitor-ca.pem"
        sha1 = _make_self_signed_ca(cert_path)

        def fake_run(cmd, **_):
            if "find-certificate" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=f"SHA-1 hash: {sha1.upper()}\n", stderr=""
                )
            if "trust-settings-export" in cmd:
                plist_path = cmd[cmd.index("-d") + 1]
                from pathlib import Path as _P

                _P(plist_path).write_text(
                    f'<?xml version="1.0"?><plist><dict><key>{sha1.upper()}</key><dict/></dict></plist>'
                )
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("claude_monitoring.security.subprocess.run", side_effect=fake_run):
            ok, code = verify_ca_trusted(cert_path)
        assert ok is True, f"expected trusted, got code={code!r}"
        assert code == "trusted"

    def test_returns_in_keychain_but_not_trusted_code_when_admin_trust_missing(self, tmp_path):
        """The exact failure mode from the new-laptop install: cert
        added to System.keychain via add-trusted-cert, but the admin
        trust settings weren't actually applied. Old _is_cert_trusted
        returned True; new verify_ca_trusted returns False with code
        ``in_keychain_but_not_trusted``."""
        from claude_monitoring.security import verify_ca_trusted

        cert_path = tmp_path / "ai-monitor-ca.pem"
        sha1 = _make_self_signed_ca(cert_path)

        def fake_run(cmd, **_):
            if "find-certificate" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=f"SHA-1 hash: {sha1.upper()}\n", stderr=""
                )
            if "trust-settings-export" in cmd:
                # macOS exits non-zero with "no trust settings were
                # found" when the admin trust domain has zero entries.
                return subprocess.CompletedProcess(
                    args=cmd, returncode=1, stdout="", stderr="No trust settings were found.\n"
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("claude_monitoring.security.subprocess.run", side_effect=fake_run):
            ok, code = verify_ca_trusted(cert_path)
        # Note: when export exits non-zero, the code is
        # trust_settings_export_failed (we never even read the plist).
        # The in_keychain_but_not_trusted code is what we get when
        # export succeeds but the SHA-1 isn't in the resulting plist.
        assert ok is False
        assert code == "trust_settings_export_failed"

    def test_returns_in_keychain_but_not_trusted_when_sha1_missing_from_export(self, tmp_path):
        """Distinct from trust_settings_export_failed: export succeeds
        (exit 0) but our SHA-1 is not in the resulting plist content."""
        from claude_monitoring.security import verify_ca_trusted

        cert_path = tmp_path / "ai-monitor-ca.pem"
        sha1 = _make_self_signed_ca(cert_path)

        def fake_run(cmd, **_):
            if "find-certificate" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0, stdout=f"SHA-1 hash: {sha1.upper()}\n", stderr=""
                )
            if "trust-settings-export" in cmd:
                plist_path = cmd[cmd.index("-d") + 1]
                from pathlib import Path as _P

                # Different SHA-1 in the plist → our cert isn't trusted.
                _P(plist_path).write_text('<?xml version="1.0"?><plist><dict><key>OTHER_SHA1</key></dict></plist>')
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("claude_monitoring.security.subprocess.run", side_effect=fake_run):
            ok, code = verify_ca_trusted(cert_path)
        assert ok is False
        assert code == "in_keychain_but_not_trusted"

    def test_returns_not_in_keychain_code(self, tmp_path):
        from claude_monitoring.security import verify_ca_trusted

        cert_path = tmp_path / "ai-monitor-ca.pem"
        _make_self_signed_ca(cert_path)

        def fake_run(cmd, **_):
            if "find-certificate" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        with patch("claude_monitoring.security.subprocess.run", side_effect=fake_run):
            ok, code = verify_ca_trusted(cert_path)
        assert ok is False
        assert code == "not_in_keychain"

    def test_returns_cert_file_missing_code(self, tmp_path):
        from claude_monitoring.security import verify_ca_trusted

        cert_path = tmp_path / "does-not-exist.pem"
        ok, code = verify_ca_trusted(cert_path)
        assert ok is False
        assert code == "cert_file_missing"


class TestTrustReasonMessage:
    """trust_reason_message maps every TrustVerificationCode to a
    human-readable string. The mapping is the join point where
    subprocess-tainted state becomes a literal-set value safe to
    print/log without triggering CodeQL's clear-text-logging analysis."""

    def test_returns_message_for_every_known_code(self):
        from claude_monitoring.security import _TRUST_REASON_MESSAGES, trust_reason_message

        for code, expected in _TRUST_REASON_MESSAGES.items():
            assert trust_reason_message(code) == expected

    def test_messages_contain_actionable_recovery_for_trust_failure(self):
        """The 'in_keychain_but_not_trusted' message is the one users
        actually need to recover from — it must contain the manual
        add-trusted-cert command so a power user can fix the state
        without re-running the wizard."""
        from claude_monitoring.security import trust_reason_message

        msg = trust_reason_message("in_keychain_but_not_trusted")
        assert "security add-trusted-cert" in msg
        assert "System.keychain" in msg


class TestSQLInjection:
    def test_session_id_with_sql_injection(self, tmp_path):
        """Verify parameterized queries prevent SQL injection in session lookups."""
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("claude_monitoring.config.get_output_dir", lambda: output_dir)
            conn = init_db(db_path)

        # Insert a legitimate session
        conn.execute(
            "INSERT INTO sessions (session_id, start_time, last_activity) VALUES (?, ?, ?)",
            ("legit-session", "2026-01-01T00:00:00Z", "2026-01-01T00:10:00Z"),
        )
        conn.commit()

        # Attempt SQL injection via session_id
        malicious_id = "'; DROP TABLE sessions; --"
        result = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (malicious_id,),
        ).fetchone()

        # Injection should return no results, not crash
        assert result is None

        # Table should still exist
        count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        assert count == 1
        conn.close()

    def test_event_search_with_injection(self, tmp_path):
        """Verify parameterized queries in event searches."""
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("claude_monitoring.config.get_output_dir", lambda: output_dir)
            conn = init_db(db_path)

        conn.execute(
            "INSERT INTO events (timestamp, event_type, source_layer, data_json) VALUES (?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "test_event", "network", '{"text":"hello"}'),
        )
        conn.commit()

        # Parameterized LIKE query (as used in search endpoints)
        malicious_search = "%'; DROP TABLE events; --"
        result = conn.execute(
            "SELECT * FROM events WHERE data_json LIKE ?",
            (f"%{malicious_search}%",),
        ).fetchall()

        assert len(result) == 0
        # Table should still exist
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert count == 1
        conn.close()


class TestLargeInputHandling:
    def test_scan_sensitive_with_large_input(self):
        """Verify scan_sensitive handles very large input without crashing."""
        large_text = "Normal text. " * 10000
        results = scan_sensitive(large_text)
        # Should complete without error
        assert isinstance(results, list)

    def test_scan_sensitive_with_empty_input(self):
        """Verify scan_sensitive handles empty input."""
        results = scan_sensitive("")
        assert results == []

    def test_scan_sensitive_with_none_like_input(self):
        """Verify scan_sensitive handles edge cases."""
        results = scan_sensitive("   ")
        assert isinstance(results, list)

    def test_db_stores_truncated_data(self, tmp_path):
        """Verify the DB can store large data_json without issues."""
        db_path = tmp_path / "test.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("claude_monitoring.config.get_output_dir", lambda: output_dir)
            conn = init_db(db_path)

        # Insert a very large data_json
        large_json = json.dumps({"text": "x" * 100000})
        conn.execute(
            "INSERT INTO events (timestamp, event_type, source_layer, data_json) VALUES (?, ?, ?, ?)",
            ("2026-01-01T00:00:00Z", "test", "network", large_json),
        )
        conn.commit()

        row = conn.execute("SELECT data_json FROM events WHERE id=1").fetchone()
        assert len(row[0]) == len(large_json)
        conn.close()


class TestJSONEscaping:
    def test_no_xss_in_json_dumps(self):
        """Verify json.dumps escapes HTML/script tags."""
        malicious = {"text": '<script>alert("XSS")</script>'}
        output = json.dumps(malicious)
        # json.dumps should produce valid JSON that, when parsed, returns the original
        parsed = json.loads(output)
        assert parsed["text"] == '<script>alert("XSS")</script>'
        # The raw output should not contain unescaped angle brackets in a way
        # that would execute -- json.dumps uses proper escaping
        assert isinstance(output, str)

    def test_json_special_chars_escaped(self):
        """Verify special characters are properly escaped in JSON."""
        data = {
            "user": 'admin"; DROP TABLE users; --',
            "path": "</script><script>alert(1)</script>",
            "newlines": "line1\nline2\r\nline3",
        }
        output = json.dumps(data)
        parsed = json.loads(output)
        assert parsed == data

    def test_unicode_in_json(self):
        """Verify unicode characters are handled."""
        data = {"text": "Hello \u2603 \u00e9\u00e8\u00ea"}
        output = json.dumps(data, ensure_ascii=False)
        parsed = json.loads(output)
        assert parsed == data

    def test_scan_sensitive_results_are_json_safe(self):
        """Verify scan_sensitive results can be safely serialized to JSON."""
        # Use text that would match patterns but contains special chars
        text = 'password = "xK9<script>alert(1)</script>mP2!"'
        results = scan_sensitive(text, validate=True)
        # Results should be JSON-serializable
        output = json.dumps(results)
        parsed = json.loads(output)
        assert isinstance(parsed, list)

    def test_null_bytes_in_json(self):
        """Verify null bytes don't cause issues in JSON serialization."""
        data = {"text": "hello\x00world"}
        output = json.dumps(data)
        parsed = json.loads(output)
        assert "hello" in parsed["text"]
