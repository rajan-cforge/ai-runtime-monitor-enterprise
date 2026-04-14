# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for the abuse.ch CSV parsers.

These fetchers switched from the auth-required JSON APIs to the public
CSV exports after abuse.ch started returning HTTP 401 on anonymous JSON
requests. The tests exercise:

- ThreatFox CSV parsing (ip:port + domain IOCs, comment skipping,
  malformed rows, success/failure status recording)
- URLhaus CSV parsing (URL → hostname extraction, row truncation,
  empty URL handling)
"""

from __future__ import annotations

import urllib.error
from unittest.mock import patch

from claude_monitoring import threat_intel
from claude_monitoring.db import init_db

# ─────────────────────────────────────────────────────────────
# Fixture data
# ─────────────────────────────────────────────────────────────

THREATFOX_CSV = b"""\
################################################################
# ThreatFox IOCs                                               #
################################################################
#
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
"2026-04-14 15:56:50", "1790856", "evil.example.com", "domain", "payload_delivery", "js.clearfake", "None", "ClearFake", "2026-04-14 15:58:39", "100", "False", "None", "ClearFake", "0", "threatcat_ch"
"2026-04-14 15:50:00", "1790855", "1.2.3.4:4444", "ip:port", "botnet_cc", "win.vidar", "None", "Vidar", "", "75", "False", "None", "kdozia", "0", "abuse_ch"
"2026-04-14 15:40:00", "1790854", "bad.example.org", "domain", "botnet_cc", "win.acr_stealer", "None", "ACR Stealer", "", "100", "False", "None", "ACRStealer", "0", "abuse_ch"
"2026-04-14 15:30:00", "1790853", "abc123def456", "sha256_hash", "payload", "win.redline", "None", "RedLine", "", "75", "False", "None", "redline", "0", "TheRavenFile"
"short","row"
"""

URLHAUS_CSV = b"""\
################################################################
# URLhaus Database Dump                                        #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3821497","2026-04-14 16:02:21","http://evil1.example/bin.sh","online","2026-04-14 16:02:21","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3821497/","geenensp"
"3821496","2026-04-14 16:02:19","https://evil2.example/payload","online","2026-04-14 16:02:19","malware_download","ClearFake","https://urlhaus.abuse.ch/url/3821496/","anonymous"
"3821495","2026-04-14 16:00:19","","online","","","","https://urlhaus.abuse.ch/url/3821495/","geenensp"
"""


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload


# ─────────────────────────────────────────────────────────────
# ThreatFox parser
# ─────────────────────────────────────────────────────────────


class TestThreatFoxParser:
    def test_parses_ip_and_domain_rows(self):
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(THREATFOX_CSV),
        ):
            result = threat_intel.fetch_threatfox_iocs()

        assert "evil.example.com" in result["domains"]
        assert "bad.example.org" in result["domains"]
        assert "1.2.3.4" in result["ips"]
        # sha256_hash and "url" types are not stored (we only correlate
        # against outbound ip/domain connections)
        assert result["domains"]["evil.example.com"]["malware"] == "ClearFake"
        assert result["domains"]["evil.example.com"]["confidence"] == 100
        assert result["ips"]["1.2.3.4"]["threat_type"] == "botnet_cc"

    def test_skips_header_and_comment_rows(self):
        # The fixture has 6 comment/header lines before the first data row
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(THREATFOX_CSV),
        ):
            result = threat_intel.fetch_threatfox_iocs()
        # 2 domains + 1 ip + sha256 skipped + "short,row" skipped
        assert len(result["domains"]) == 2
        assert len(result["ips"]) == 1

    def test_handles_malformed_short_row(self):
        # "short","row" is only 2 columns, should be skipped without crashing
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(THREATFOX_CSV),
        ):
            # Should not raise
            threat_intel.fetch_threatfox_iocs()

    def test_records_failure_on_http_error(self, tmp_path):
        db_path = tmp_path / "t.db"
        conn = init_db(db_path)
        conn.row_factory = __import__("sqlite3").Row
        err = urllib.error.HTTPError(
            url="https://threatfox.abuse.ch/export/csv/recent/",
            code=503,
            msg="Service Unavailable",
            hdrs=None,  # type: ignore[arg-type]
            fp=None,
        )
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            side_effect=err,
        ):
            result = threat_intel.fetch_threatfox_iocs(db=conn)
        assert result == {"ips": {}, "domains": {}}
        row = conn.execute("SELECT last_error, last_success FROM intel_source_status WHERE name='threatfox'").fetchone()
        assert row is not None
        assert "503" in (row["last_error"] or "") or "Service Unavailable" in (row["last_error"] or "")
        assert row["last_success"] is None
        conn.close()

    def test_success_path_does_not_touch_status_without_db(self):
        # When db=None, parser just returns the dict, no status write
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(THREATFOX_CSV),
        ):
            # Should not raise — the point is the db arg stays optional
            result = threat_intel.fetch_threatfox_iocs()
        assert isinstance(result, dict)

    def test_store_iocs_records_success_status(self, tmp_path):
        db_path = tmp_path / "t.db"
        conn = init_db(db_path)
        conn.row_factory = __import__("sqlite3").Row
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(THREATFOX_CSV),
        ):
            result = threat_intel.fetch_threatfox_iocs()
        threat_intel.store_iocs(conn, result)
        row = conn.execute(
            "SELECT last_success, last_error, record_count FROM intel_source_status WHERE name='threatfox'"
        ).fetchone()
        assert row is not None
        assert row["last_success"] is not None
        assert row["last_error"] is None
        assert row["record_count"] == 3  # 2 domains + 1 ip
        conn.close()


# ─────────────────────────────────────────────────────────────
# URLhaus parser
# ─────────────────────────────────────────────────────────────


class TestURLhausParser:
    def test_parses_urls_to_domain_iocs(self, tmp_path):
        db_path = tmp_path / "t.db"
        conn = init_db(db_path)
        conn.row_factory = __import__("sqlite3").Row
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(URLHAUS_CSV),
        ):
            count = threat_intel.fetch_urlhaus_iocs(conn)
        assert count == 2  # 2 valid URLs, 1 empty URL skipped
        rows = conn.execute(
            "SELECT ioc_value, source FROM threat_iocs WHERE source='urlhaus' ORDER BY ioc_value"
        ).fetchall()
        hostnames = {r["ioc_value"] for r in rows}
        assert "evil1.example" in hostnames
        assert "evil2.example" in hostnames
        conn.close()

    def test_skips_url_with_no_hostname(self, tmp_path):
        db_path = tmp_path / "t.db"
        conn = init_db(db_path)
        conn.row_factory = __import__("sqlite3").Row
        # Fixture has one row with url=""
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(URLHAUS_CSV),
        ):
            threat_intel.fetch_urlhaus_iocs(conn)
        # Only 2 rows stored, not 3
        n = conn.execute("SELECT COUNT(*) as c FROM threat_iocs WHERE source='urlhaus'").fetchone()["c"]
        assert n == 2
        conn.close()

    def test_records_success_status(self, tmp_path):
        db_path = tmp_path / "t.db"
        conn = init_db(db_path)
        conn.row_factory = __import__("sqlite3").Row
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(URLHAUS_CSV),
        ):
            threat_intel.fetch_urlhaus_iocs(conn)
        row = conn.execute(
            "SELECT last_success, last_error, record_count FROM intel_source_status WHERE name='urlhaus'"
        ).fetchone()
        assert row is not None
        assert row["last_success"] is not None
        assert row["last_error"] is None
        assert row["record_count"] == 2
        conn.close()

    def test_records_failure_on_http_error(self, tmp_path):
        db_path = tmp_path / "t.db"
        conn = init_db(db_path)
        conn.row_factory = __import__("sqlite3").Row
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            count = threat_intel.fetch_urlhaus_iocs(conn)
        assert count == 0
        row = conn.execute("SELECT last_error, last_success FROM intel_source_status WHERE name='urlhaus'").fetchone()
        assert row is not None
        assert "connection refused" in (row["last_error"] or "")
        assert row["last_success"] is None
        conn.close()

    def test_truncates_at_500_rows(self, tmp_path):
        db_path = tmp_path / "t.db"
        conn = init_db(db_path)
        conn.row_factory = __import__("sqlite3").Row
        # Build a CSV with 600 rows
        header = b"# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        rows = []
        for i in range(600):
            rows.append(
                f'"{i}","2026-04-14 16:00:00","http://host{i}.example/x","online",'
                f'"2026-04-14 16:00:00","malware","tag","https://urlhaus.abuse.ch/url/{i}/","anon"\n'.encode()
            )
        big_csv = header + b"".join(rows)
        with patch(
            "claude_monitoring.threat_intel.urllib.request.urlopen",
            return_value=_FakeResponse(big_csv),
        ):
            count = threat_intel.fetch_urlhaus_iocs(conn)
        assert count == 500
        conn.close()
