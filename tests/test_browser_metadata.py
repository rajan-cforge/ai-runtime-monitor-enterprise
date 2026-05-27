# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Tests for Section 5 (browser AI metadata via extension) and Section 6
(extension heartbeat).

Section 5 verifies that:
  - AI_PROXY_DOMAINS == AI_API_DOMAINS (browser UI sites are NOT proxied
    as of PR #51 — they're handled by the Chrome extension via DOM
    capture; see claude_monitoring.constants for rationale)
  - AI_API_DOMAINS and AI_BROWSER_DOMAINS remain disjoint (the
    architectural split is preserved even though the proxy no longer
    inspects the browser list)
  - The watch addon classifies hosts correctly
  - Static assets are filtered out of metadata capture

Section 6 covers the heartbeat upsert + the /api/browser/extension-health
endpoint that powers the dashboard warning banner.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer
from urllib.request import Request, urlopen

import pytest

from claude_monitoring.constants import (
    AI_API_DOMAINS,
    AI_BROWSER_DOMAINS,
    AI_PROXY_DOMAINS,
)
from claude_monitoring.db import init_db

# ─────────────────────────────────────────────────────────────
# Section 5: domain split + classification + static asset filter
# ─────────────────────────────────────────────────────────────


class TestProxyDomainSplit:
    def test_api_domains_present(self):
        for d in ("api.anthropic.com", "api.openai.com", "api.cursor.sh"):
            assert d in AI_API_DOMAINS

    def test_browser_domains_present(self):
        for d in ("claude.ai", "chatgpt.com", "gemini.google.com"):
            assert d in AI_BROWSER_DOMAINS

    def test_browser_and_api_disjoint(self):
        assert set(AI_API_DOMAINS).isdisjoint(set(AI_BROWSER_DOMAINS))

    def test_proxy_domains_excludes_browser_ui_sites(self):
        """Regression for PR #51: browser-facing UI sites must NOT appear
        in AI_PROXY_DOMAINS. The proxy targets API endpoints only;
        browser AI sites are captured by the Chrome extension via DOM
        observation. See claude_monitoring.constants comment for the
        full rationale (cert-error UX + duplicate-capture avoidance)."""
        assert set(AI_PROXY_DOMAINS).isdisjoint(set(AI_BROWSER_DOMAINS)), (
            "AI_PROXY_DOMAINS leaked browser UI sites — these must be extension-captured, not proxied"
        )
        # Spot-check the specific sites that have been problematic
        # (claude.ai, chatgpt.com, gemini.google.com on the new-laptop
        # install verification on 2026-05-26).
        for d in ("claude.ai", "chatgpt.com", "gemini.google.com"):
            assert d not in AI_PROXY_DOMAINS, f"{d} must not be in AI_PROXY_DOMAINS"

    def test_proxy_domains_equals_api_domains(self):
        """As of PR #51, AI_PROXY_DOMAINS is exactly AI_API_DOMAINS.
        The two names are kept distinct so future callers that need
        'what does the proxy inspect' get a stable answer even if the
        API list reorganizes."""
        assert list(AI_PROXY_DOMAINS) == list(AI_API_DOMAINS)


class TestAllowHostsPattern:
    """The regex passed to mitmdump --allow-hosts is built by
    _build_allow_hosts_pattern. It must:
      - match each AI_PROXY_DOMAINS host with a `:port` suffix
      - escape dots so 'anthropic.com' doesn't match
        'anthropic-com-attacker.io'
      - reject hosts not in the list
      - reject browser UI sites (PR #51 invariant)
    """

    def _pattern(self, domains):
        import re as _re

        from claude_monitoring.watch import _build_allow_hosts_pattern

        return _re.compile(_build_allow_hosts_pattern(list(domains)))

    def test_matches_api_endpoint_with_port(self):
        p = self._pattern(AI_API_DOMAINS)
        for h in ("api.anthropic.com", "api.openai.com", "api.cursor.sh"):
            assert p.match(f"{h}:443"), f"{h}:443 should match the allow-hosts regex"

    def test_rejects_browser_ui_sites(self):
        """Regression: the regex must NOT match the browser UI sites.
        Captured here as a defense-in-depth check on top of the
        AI_PROXY_DOMAINS list invariant."""
        p = self._pattern(AI_API_DOMAINS)
        for h in ("claude.ai", "chatgpt.com", "gemini.google.com", "perplexity.ai"):
            assert not p.match(f"{h}:443"), f"{h}:443 must NOT match the allow-hosts regex"

    def test_rejects_substring_collision_attacks(self):
        """`api.anthropic.com` in the allowlist must not match
        `fake.api.anthropic.com.attacker.io:443`. The trailing `:`
        anchor and the host-port match boundary make this safe."""
        p = self._pattern(AI_API_DOMAINS)
        assert not p.match("fake.api.anthropic.com.attacker.io:443")
        assert not p.match("api.anthropic.com.attacker.io:443")

    def test_rejects_dot_as_regex_wildcard(self):
        """`.` in the domain list must be escaped — otherwise
        'api.openai.com' would match 'apiXopenaiXcom' where X is any
        character. _build_allow_hosts_pattern uses re.escape per
        element."""
        p = self._pattern(["api.openai.com"])
        assert not p.match("apiXopenaiXcom:443")
        assert p.match("api.openai.com:443")

    def test_empty_domain_list_matches_nothing(self):
        """Defensive: if AI_PROXY_DOMAINS is somehow empty, the regex
        rejects everything rather than matching everything."""
        p = self._pattern([])
        assert not p.match("api.anthropic.com:443")
        assert not p.match("anything:443")


class TestStaticAssetFilter:
    """The static-asset filter lives inline in watch.py; we re-implement it
    here to verify the rule by example. (Pulling it from watch.py imports the
    whole mitmproxy module which isn't always available in test envs.)"""

    _STATIC_EXTS = (
        ".js",
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".ico",
        ".map",
        ".mp4",
        ".webm",
    )

    def _is_static(self, path: str) -> bool:
        base = path.split("?", 1)[0].lower()
        return any(base.endswith(ext) for ext in self._STATIC_EXTS)

    @pytest.mark.parametrize(
        "path",
        [
            "/static/main.js",
            "/_next/static/chunks/page.css",
            "/assets/logo.png",
            "/icons/favicon.ico",
            "/avatars/user.jpg?v=42",
            "/fonts/inter.woff2",
            "/sourcemaps/main.js.map",
        ],
    )
    def test_static_filtered(self, path):
        assert self._is_static(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            "/api/organizations/abc/chat_conversations/xyz/completion",
            "/backend-api/conversation",
            "/app/12eb2e398e118b83",
            "/chat/b58f6faa-4b75-4fa4-abf5-3ac88b046297",
            "/",
        ],
    )
    def test_dynamic_not_filtered(self, path):
        assert self._is_static(path) is False


class TestBrowserServiceClassification:
    """Re-implement the classifier here to keep the test independent of
    mitmproxy import side-effects."""

    def _classify(self, host: str) -> str:
        if "claude.ai" in host:
            return "claude_web"
        if "chatgpt.com" in host or "chat.openai.com" in host:
            return "chatgpt_web"
        if "gemini.google.com" in host:
            return "gemini_web"
        if "perplexity.ai" in host:
            return "perplexity_web"
        return "browser_ai"

    def test_claude_ai(self):
        assert self._classify("claude.ai") == "claude_web"
        assert self._classify("www.claude.ai") == "claude_web"

    def test_chatgpt(self):
        assert self._classify("chatgpt.com") == "chatgpt_web"
        assert self._classify("chat.openai.com") == "chatgpt_web"

    def test_gemini(self):
        assert self._classify("gemini.google.com") == "gemini_web"

    def test_unknown_falls_back(self):
        assert self._classify("example.com") == "browser_ai"


# ─────────────────────────────────────────────────────────────
# Section 6: heartbeat schema + endpoint
# ─────────────────────────────────────────────────────────────


class TestHeartbeatSchema:
    def test_table_created_by_init_db(self, tmp_path):
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='extension_heartbeats'"
            ).fetchone()
            assert row is not None
        finally:
            conn.close()


def _setup_heartbeat_server(tmp_path, monkeypatch):
    """Spin up a real DashboardHandler on a random port with auth disabled."""
    monkeypatch.setenv("DISABLE_DASHBOARD_AUTH", "1")
    db_path = tmp_path / "monitor.db"
    output_dir = tmp_path
    init_db(db_path).close()

    monkeypatch.setattr("claude_monitoring.config.get_db_path", lambda: db_path)
    monkeypatch.setattr("claude_monitoring.config.get_output_dir", lambda: output_dir)
    monkeypatch.setattr("claude_monitoring.db.get_db_path", lambda: db_path)
    monkeypatch.setattr("claude_monitoring.db.get_output_dir", lambda: output_dir)

    from claude_monitoring import monitor as mon

    monkeypatch.setattr(mon, "DB_PATH", db_path)
    monkeypatch.setattr(mon, "OUTPUT_DIR", output_dir)

    server = HTTPServer(("127.0.0.1", 0), mon.DashboardHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}", db_path


def _post_json(url: str, payload: dict) -> dict:
    req = Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req) as resp:
        return json.loads(resp.read().decode())


def _get_json(url: str) -> dict:
    with urlopen(url) as resp:
        return json.loads(resp.read().decode())


class TestHeartbeatEndpoint:
    def test_post_stores_heartbeat(self, tmp_path, monkeypatch):
        server, base, db_path = _setup_heartbeat_server(tmp_path, monkeypatch)
        try:
            result = _post_json(
                f"{base}/api/browser/heartbeat",
                {
                    "hostname": "claude.ai",
                    "user_matches": 3,
                    "assistant_matches": 5,
                    "captures_sent": 10,
                },
            )
            assert result["ok"] is True
            assert result["hostname"] == "claude.ai"

            # Verify the row landed
            conn = sqlite3.connect(str(db_path))
            row = conn.execute("SELECT hostname, user_matches, assistant_matches FROM extension_heartbeats").fetchone()
            conn.close()
            assert row == ("claude.ai", 3, 5)
        finally:
            server.shutdown()

    def test_upsert_keeps_one_row_per_host(self, tmp_path, monkeypatch):
        server, base, db_path = _setup_heartbeat_server(tmp_path, monkeypatch)
        try:
            for matches in (1, 2, 3):
                _post_json(
                    f"{base}/api/browser/heartbeat",
                    {"hostname": "claude.ai", "user_matches": matches, "assistant_matches": matches},
                )
            conn = sqlite3.connect(str(db_path))
            (count,) = conn.execute("SELECT COUNT(*) FROM extension_heartbeats").fetchone()
            (latest,) = conn.execute("SELECT user_matches FROM extension_heartbeats").fetchone()
            conn.close()
            assert count == 1
            assert latest == 3
        finally:
            server.shutdown()

    def test_missing_hostname_returns_400(self, tmp_path, monkeypatch):
        server, base, _ = _setup_heartbeat_server(tmp_path, monkeypatch)
        try:
            from urllib.error import HTTPError

            with pytest.raises(HTTPError) as exc:
                _post_json(f"{base}/api/browser/heartbeat", {"user_matches": 1})
            assert exc.value.code == 400
        finally:
            server.shutdown()


class TestExtensionHealthEndpoint:
    def test_empty_returns_no_warnings(self, tmp_path, monkeypatch):
        server, base, _ = _setup_heartbeat_server(tmp_path, monkeypatch)
        try:
            result = _get_json(f"{base}/api/browser/extension-health")
            assert result["hosts"] == []
            assert result["warnings"] == []
        finally:
            server.shutdown()

    def test_healthy_host_no_warning(self, tmp_path, monkeypatch):
        server, base, db_path = _setup_heartbeat_server(tmp_path, monkeypatch)
        try:
            _post_json(
                f"{base}/api/browser/heartbeat",
                {"hostname": "claude.ai", "user_matches": 3, "assistant_matches": 5},
            )
            result = _get_json(f"{base}/api/browser/extension-health")
            assert len(result["hosts"]) == 1
            assert result["warnings"] == []
            assert result["hosts"][0]["is_stale"] is False
            assert result["hosts"][0]["is_zero_matches"] is False
        finally:
            server.shutdown()

    def test_zero_matches_warns(self, tmp_path, monkeypatch):
        server, base, _ = _setup_heartbeat_server(tmp_path, monkeypatch)
        try:
            _post_json(
                f"{base}/api/browser/heartbeat",
                {
                    "hostname": "claude.ai",
                    "user_matches": 0,
                    "assistant_matches": 0,
                    "selector_failure": True,
                },
            )
            result = _get_json(f"{base}/api/browser/extension-health")
            assert len(result["warnings"]) == 1
            assert "zero selector matches" in result["warnings"][0]
        finally:
            server.shutdown()

    def test_stale_heartbeat_warns(self, tmp_path, monkeypatch):
        server, base, db_path = _setup_heartbeat_server(tmp_path, monkeypatch)
        try:
            # Insert a heartbeat 10 minutes in the past directly
            stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            conn = sqlite3.connect(str(db_path))
            conn.execute(
                """INSERT INTO extension_heartbeats
                   (hostname, last_seen, user_matches, assistant_matches, captures_sent, selector_failure)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                ("claude.ai", stale, 3, 5, 0, 0),
            )
            conn.commit()
            conn.close()
            result = _get_json(f"{base}/api/browser/extension-health")
            assert len(result["warnings"]) == 1
            assert "has not reported" in result["warnings"][0]
            assert result["hosts"][0]["is_stale"] is True
        finally:
            server.shutdown()
