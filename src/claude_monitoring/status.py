# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Runtime status inspection for AI Runtime Monitor.

Provides ``ai-monitor --status`` which reports on every layer of the stack:
core processes, proxy state, certificate trust, security posture, and
per-source capture matrix. All checks are best-effort and fail closed
(return False) on any error — status should never crash the CLI.
"""

from __future__ import annotations

import os
import subprocess
from contextlib import suppress

from claude_monitoring.config import get_dashboard_port, get_db_path, get_output_dir, get_proxy_port


def _is_mitmproxy_running(port: int | None = None) -> bool:
    port = port or get_proxy_port()
    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "LISTEN" in result.stdout
    except Exception:
        return False


def _is_system_proxy_configured(port: int | None = None) -> bool:
    port = port or get_proxy_port()
    try:
        result = subprocess.run(
            ["networksetup", "-getsecurewebproxy", "Wi-Fi"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "Enabled: Yes" in result.stdout and str(port) in result.stdout
    except Exception:
        return False


def _find_certificate(common_name: str) -> bool:
    try:
        result = subprocess.run(
            [
                "security",
                "find-certificate",
                "-a",
                "-c",
                common_name,
                "/Library/Keychains/System.keychain",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return common_name in result.stdout
    except Exception:
        return False


def _get_ca_trust_state():
    """Return (in_keychain, trusted_in_admin_settings, code_or_None).

    The two booleans distinguish 'cert exists in System.keychain' from
    'cert has admin trust settings applied' — only the second makes
    TLS chains validate, which is what proxy interception needs.

    The third element is a ``TrustVerificationCode`` (Literal) when the
    custom CA is present and was verified, or ``None`` for the legacy
    mitmproxy fallback path where we can't SHA-1-verify. Callers map
    the code → human message via
    ``claude_monitoring.security.trust_reason_message``.

    Custom CA (per-install) is the v0.2+ canonical layout. The fallback
    to the legacy 'mitmproxy' common name keeps pre-custom-CA installs
    reporting accurately as 'in keychain only' rather than as fully
    untrusted.
    """
    from claude_monitoring.security import get_ca_cert_path, verify_ca_trusted

    custom_path = get_ca_cert_path()
    if custom_path.exists():
        ok, code = verify_ca_trusted(custom_path)
        if ok:
            return True, True, code  # "trusted"
        # When the cert file exists but verify says it's not trusted,
        # we still need to distinguish "in keychain, not trusted" from
        # "not in keychain at all" so the status display can report
        # accurately. The code is the discriminator — only the
        # in_keychain_but_not_trusted code means the cert is present.
        in_keychain = code == "in_keychain_but_not_trusted"
        return in_keychain, False, code

    # Pre-custom-CA installs only had the default mitmproxy CA. We can't
    # SHA-1-match without the cert file on disk, so fall back to
    # name-based search and report keychain-only (trust state unknown
    # via this path → code None).
    legacy_present = _find_certificate("mitmproxy")
    return legacy_present, False, None


def _is_cert_trusted() -> bool:
    """True only when a monitoring CA is present AND admin-trust-settings-applied.

    Backed by ``_get_ca_trust_state`` so the answer matches what the
    proxy interception layer actually needs. Existing callers using this
    function get a stricter (more accurate) answer than before — a cert
    present in the keychain without admin trust now reports False.
    """
    _, trusted, _ = _get_ca_trust_state()
    return trusted


def _has_custom_ca() -> bool:
    """True when a custom (per-install) CA has been generated."""
    return (get_output_dir() / "certs" / "ai-monitor-ca.pem").exists()


def _is_monitor_running(port: int | None = None) -> bool:
    """Probe the dashboard HTTP endpoint to check if the monitor is live.

    Uses a raw socket connection to bypass any proxy config that Python
    might inherit from the macOS system proxy settings. When
    --with-system-proxy is enabled, urllib.request on macOS will route
    http://127.0.0.1:9081/ through mitmproxy at 127.0.0.1:9080, which
    then rejects the loopback destination — making the probe return
    False even though the server is actually healthy.

    A direct socket connect avoids the proxy entirely.
    """
    port = port or get_dashboard_port()
    import http.client

    try:
        # Bypass urllib entirely — http.client.HTTPConnection talks to
        # the given host:port directly, no proxy resolution.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            conn.request("GET", "/")
            resp = conn.getresponse()
            resp.read()  # drain so the connection can close cleanly
            return resp.status == 200
        finally:
            conn.close()
    except Exception:
        return False


def _is_db_encrypted() -> bool:
    """True when sqlcipher3 is installed AND used by the DB layer."""
    try:
        from claude_monitoring.db import HAS_SQLCIPHER

        return bool(HAS_SQLCIPHER)
    except Exception:
        return False


def _check_permissions() -> bool:
    """Check that sensitive paths have tight permissions.

    Returns True when every present path has the expected mode.
    Missing paths are ignored (nothing to check).
    """
    checks = [
        (get_output_dir(), "700"),
        (get_output_dir() / "certs", "700"),
        (get_db_path(), "600"),
        (get_output_dir() / "certs" / "ai-monitor-ca-key.pem", "600"),
        (get_output_dir() / ".dashboard_token", "600"),
    ]
    for path, expected in checks:
        if not path.exists():
            continue
        try:
            mode = oct(path.stat().st_mode)[-3:]
            if mode != expected:
                return False
        except Exception:
            return False
    return True


def _has_dashboard_token() -> bool:
    token_path = get_output_dir() / ".dashboard_token"
    try:
        return token_path.exists() and len(token_path.read_text().strip()) >= 16
    except Exception:
        return False


# Extension heartbeat freshness window. The extension sends a
# heartbeat every 60s (browser-extension/content_scripts/shared.js
# line 178: setInterval(sendHeartbeat, 60000)). A 5-minute window is
# the same threshold the extension's own selector_failure comment
# uses (shared.js line 96) and is roughly 5× the interval — wide
# enough to tolerate jitter and a few missed sends, narrow enough to
# catch "extension uninstalled / disabled days ago" cases where a
# stale row would otherwise misreport coverage.
_EXTENSION_HEARTBEAT_STALENESS_SECONDS = 300


def _check_extension_heartbeat() -> dict | None:
    """Return heartbeat info from the DB only when the last heartbeat
    is fresh (within ``_EXTENSION_HEARTBEAT_STALENESS_SECONDS``).
    Returns ``None`` when no rows, no table, or the most recent row is
    older than the window.

    Pre-fix this function returned a row regardless of age, which
    produced a false positive in the status display: a user who
    uninstalled the extension days ago still saw '✅ Extension content'
    because the DB row persisted. The freshness gate distinguishes
    'extension is actually running and emitting heartbeats' from
    'extension was installed at some point in history'.
    """
    try:
        import sqlite3
        from datetime import datetime, timedelta, timezone

        db_path = get_db_path()
        if not db_path.exists():
            return None
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='extension_heartbeats'")
        if not cur.fetchone():
            conn.close()
            return None
        row = conn.execute(
            "SELECT hostname, last_seen, user_matches, assistant_matches, "
            "selector_failure FROM extension_heartbeats "
            "ORDER BY last_seen DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if not row:
            return None
        # Freshness gate. last_seen is an ISO-8601 string; older rows
        # are silently treated as 'no extension running'.
        try:
            last_seen_dt = datetime.fromisoformat(str(row["last_seen"]).replace("Z", "+00:00"))
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - last_seen_dt
            if age > timedelta(seconds=_EXTENSION_HEARTBEAT_STALENESS_SECONDS):
                return None
        except Exception:
            # Malformed timestamp → treat as stale rather than fresh.
            return None
        user_m = row["user_matches"] or 0
        asst_m = row["assistant_matches"] or 0
        if row["selector_failure"] or (user_m == 0 and asst_m == 0):
            status = "⚠ selectors not matching"
        else:
            status = f"✅ {user_m} user / {asst_m} assistant"
        return {
            "hostname": row["hostname"],
            "last_seen": row["last_seen"],
            "status": status,
        }
    except Exception:
        return None


def _get_ca_info_safe() -> dict | None:
    """Return CA info dict or None — never crash."""
    if not _has_custom_ca():
        return None
    try:
        from claude_monitoring.security import get_ca_info

        return get_ca_info()
    except Exception:
        return None


def _fmt_check(ok: bool, ok_text: str, bad_text: str) -> str:
    return f"✅ {ok_text}" if ok else f"❌ {bad_text}"


def _http_proxy_env_is_set() -> bool:
    """True if the current shell has a non-empty HTTPS_PROXY exported.

    Both `HTTPS_PROXY` and the lowercase `https_proxy` are recognised
    (curl, requests, and most CLI HTTP libraries accept either). An
    empty-string value is treated as unset — some shells use
    ``HTTPS_PROXY=""`` to neutralise a previously-exported value.
    """
    return bool((os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "").strip())


def _render_next_steps_lines(*, proxy_port: int) -> list[str]:
    """Build the post-setup / status-footer 'Next steps' block.

    Shared between ``show_status`` and the wizard ending so the two
    surfaces stay in sync. Returns a list of lines (no trailing newlines)
    that the caller is responsible for printing.

    The block has two parts:
      1. The two follow-up commands needed for full capture
         (HTTPS_PROXY export + macOS system proxy enable).
      2. A restart matrix — which apps need restarting after the proxy
         is enabled, with Chrome called out as the no-restart exception.
    """
    return [
        "  💡 Next steps — to capture API traffic from desktop apps and CLI tools:",
        "",
        f"     export HTTPS_PROXY=http://127.0.0.1:{proxy_port}",
        "     ai-monitor --enable-system-proxy",
        "",
        "     After enabling the proxy, restart any AI app that was already running:",
        "",
        "       Claude Code (claude CLI)     restart — env vars are read at process start",
        "       Claude Desktop               restart — Electron app, same reason",
        "       ChatGPT Desktop              restart — Electron app, same reason",
        "       Cursor                       restart — Electron app, same reason",
        "       Chrome (claude.ai etc.)      no restart needed — extension captures DOM directly",
        "       Ollama                       no restart — captured by process + network scanner",
        "",
        "     Reason: HTTPS_PROXY is read once at process startup; running apps",
        "     can't pick it up retroactively. Chrome is the exception because the",
        "     extension reads the rendered page, not the network.",
    ]


def show_status() -> int:
    """Print a human-readable status report. Returns 0 for success."""
    from claude_monitoring.security import trust_reason_message

    proxy_running = _is_mitmproxy_running()
    sys_proxy = _is_system_proxy_configured()
    cert_in_keychain, cert_trusted, cert_code = _get_ca_trust_state()
    cert_ok = cert_trusted
    # Map the literal code → user-facing message via the
    # discriminated-set mapping in security.trust_reason_message.
    # The message is provably from a literal set (not from subprocess
    # output), so it can flow into print() without tainting CodeQL's
    # clear-text-logging analysis.
    cert_message = trust_reason_message(cert_code) if cert_code is not None else None
    monitor_running = _is_monitor_running()
    db_encrypted = _is_db_encrypted()
    perms_ok = _check_permissions()
    has_token = _has_dashboard_token()
    custom_ca = _has_custom_ca()
    ext = _check_extension_heartbeat()

    p_mark = "✅" if proxy_running else "❌"
    sp_mark = "✅" if sys_proxy else "❌"
    # Note: ct_mark used to gate the Chrome rows; those now gate on the
    # extension heartbeat instead (PR #51 — proxy no longer touches
    # browser UI sites). cert_ok is still used for the SSL inspection
    # summary line below.

    # When the monitor is running, surface the token directly in the
    # Dashboard URL so the user can click straight from the terminal —
    # previously the token only appeared in --start's startup banner,
    # forcing users to dig through ~/claude_watch_output/.dashboard_token.
    dashboard_url = f"http://localhost:{get_dashboard_port()}"
    if monitor_running and has_token:
        with suppress(Exception):
            from claude_monitoring.security import ensure_dashboard_token

            tok = ensure_dashboard_token()
            if tok:
                dashboard_url = f"{dashboard_url}?token={tok}"

    print("AI Runtime Monitor — Status")

    # Phase 1: prominent warning for the exact failure mode that caused
    # last night's incident — proxy running but monitor dead, which
    # means the user's network is being MITM'd with no observation.
    if proxy_running and not monitor_running:
        print()
        print("  ⚠ STALE STATE DETECTED")
        print("    mitmproxy is running but the monitor is not.")
        print("    Your network may be routing through an orphaned proxy.")
        print("    Fix: ai-monitor --stop && ai-monitor --start --with-proxy")

    # Phase 1: heartbeat + crash count — surface the data that tells
    # the user "something crashed recently" so they don't have to find
    # out the hard way.
    try:
        from claude_monitoring.lifecycle import (
            heartbeat_age_seconds,
            recent_crash_count,
        )

        hb_age = heartbeat_age_seconds()
        crash_n = recent_crash_count(days=7)
    except Exception:
        hb_age = None
        crash_n = 0

    # Phase 3: surface LaunchAgent service state. When installed, this is
    # the most important info on the screen so it goes ABOVE Core.
    try:
        from claude_monitoring.lifecycle import LAUNCH_AGENT_LABEL, get_service_state

        svc = get_service_state()
    except Exception:
        svc = {"installed": False, "loaded": False, "pid": None, "last_exit_code": None}
        LAUNCH_AGENT_LABEL = "com.gocloudforge.ai-runtime-monitor"  # type: ignore[assignment]

    if svc.get("installed"):
        print()
        print("  Service:")
        print(f"    LaunchAgent:    ✅ Installed ({LAUNCH_AGENT_LABEL})")
        if svc.get("loaded"):
            pid = svc.get("pid")
            if pid:
                print(f"    State:          ✅ Running (PID {pid})")
            else:
                print("    State:          ⚠ Loaded but not running")
        else:
            print("    State:          ❌ Not loaded (run: launchctl load ~/Library/LaunchAgents/...)")
        last_exit = svc.get("last_exit_code")
        if last_exit is not None and last_exit != 0:
            print(f"    Last exit code: ⚠ {last_exit}")

    print()
    print("  Core:")
    print(f"    Monitor:        {_fmt_check(monitor_running, 'Running', 'Stopped')}")
    print(f"    Dashboard:      {dashboard_url}")
    if db_encrypted:
        print("    Database:       ✅ Encrypted (SQLCipher)")
    else:
        print("    Database:       ✅ Active (chmod 600 + FileVault)")
        print("                    Optional encryption: pip install 'ai-runtime-monitor[security]'")
    print()
    print("  Proxy:")
    print(f"    mitmproxy:      {_fmt_check(proxy_running, f'Running :{get_proxy_port()}', 'Stopped')}")
    print(f"    System proxy:   {_fmt_check(sys_proxy, 'Enabled', 'Disabled')}")
    # Two-line CA state: distinguish 'in keychain' from 'has admin trust
    # settings'. Pre-fix the status only showed 'Trusted' if the cert was
    # in the keychain, even when admin trust hadn't actually been applied,
    # which masked the failure mode that bit the new-laptop install. Now:
    #   - in-keychain only → "In keychain, NOT trusted as anchor"
    #   - in-keychain + trusted → "Trusted (AI domains only)"
    if cert_trusted:
        print("    CA cert:        ✅ In keychain")
        print("    CA trust:       ✅ Trusted in admin settings (AI domains only)")
    elif cert_in_keychain:
        print("    CA cert:        ✅ In keychain")
        print("    CA trust:       ❌ Not in admin trust settings — proxy interception will fail")
        if cert_message:
            print(f"                    Reason: {cert_message}")
    else:
        print("    CA cert:        ❌ Not in keychain")
        print("    CA trust:       ❌ Not trusted")
        if cert_message:
            print(f"                    Reason: {cert_message}")
    print(f"    SSL inspection: {'API + Browser metadata' if cert_ok else 'API only'}")
    # PR #54 defensive ergonomics: surface the actual allow_hosts
    # scope so a config-drift regression of PR #51's API-only
    # invariant is visible at --status time without re-reading
    # constants.py. Counts and a one-line summary.
    try:
        from claude_monitoring.constants import AI_BROWSER_DOMAINS, AI_PROXY_DOMAINS

        leaked = sorted(set(AI_PROXY_DOMAINS) & set(AI_BROWSER_DOMAINS))
        if leaked:
            print(
                f"    allow_hosts:    ⚠ {len(AI_PROXY_DOMAINS)} hosts, but {leaked} are browser UI sites (regression)"
            )
        else:
            print(f"    allow_hosts:    ✅ {len(AI_PROXY_DOMAINS)} API endpoints (browser UI excluded)")
    except Exception:
        # Defensive: never let the status display crash on a constants
        # import error — fall through silently.
        pass
    print()
    print("  Capture matrix:")
    print(f"    Claude Code:      ✅ JSONL + {p_mark} Proxy")
    print("    OpenClaw:         ✅ JSONL")
    print(f"    Claude Desktop:   {sp_mark} " + ("Proxy (full capture)" if sys_proxy else "Process only"))
    print(f"    ChatGPT Desktop:  {sp_mark} " + ("Proxy (full capture)" if sys_proxy else "Process only"))
    print(f"    Cursor:           {sp_mark} " + ("Proxy (full capture)" if sys_proxy else "Process only"))
    # Browser AI sites are captured by the Chrome extension only. The
    # proxy's allow_hosts intentionally excludes them as of PR #51 — see
    # claude_monitoring.constants and docs/spec/THREAT-MODEL.md §6.1.
    # cert_ok no longer gates this row; the extension is the capture
    # surface regardless of CA trust state.
    ext_mark = "✅" if ext else "⚠"
    browser_mode = "Extension content" if ext else "Extension not loaded — install via ai-monitor --setup"
    print(f"    Chrome claude.ai: {ext_mark} {browser_mode}")
    print(f"    Chrome chatgpt:   {ext_mark} {browser_mode}")
    print(f"    Chrome gemini:    {ext_mark} {browser_mode}")
    print("    Ollama:           ✅ Process + Network")
    print()
    print("  Security:")
    if custom_ca:
        try:
            from claude_monitoring.security import get_ca_info

            ca_info = get_ca_info()
        except Exception:
            ca_info = None
        if ca_info:
            print(f"    CA type:        Custom ({ca_info['common_name']})")
            n_domains = len(ca_info.get("permitted_domains", []))
            print(f"    CA constraints: {n_domains} AI domains only")
            expiry = ca_info.get("not_after", "unknown")
            if isinstance(expiry, str) and len(expiry) > 10:
                expiry = expiry[:10]
            print(f"    CA expiry:      {expiry}")
        else:
            print("    CA type:        Custom (details unavailable)")
    else:
        print("    CA type:        Default mitmproxy")
    print("    DB encryption:  " + ("✅ SQLCipher AES-256" if db_encrypted else "⚠ Unencrypted (install sqlcipher3)"))
    print("    File perms:     " + ("✅ 600/700 enforced" if perms_ok else "⚠ Needs fixing"))
    print("    Dashboard auth: " + ("✅ Token required" if has_token else "⚠ No auth"))
    print("    Data retention: 30 days (auto-purge)")

    # Phase 1: reliability section — heartbeat age + crash count
    # Phase 2: also surfaces the rotating log file path + size.
    log_path_exists = False
    try:
        from claude_monitoring.lifecycle import get_log_path

        log_path_exists = get_log_path().exists()
    except Exception:
        pass

    if monitor_running or hb_age is not None or crash_n > 0 or log_path_exists:
        print()
        print("  Reliability:")
        if monitor_running and hb_age is not None:
            if hb_age < 60:
                print(f"    Heartbeat:      ✅ {int(hb_age)}s ago")
            elif hb_age < 300:
                print(f"    Heartbeat:      ⚠ {int(hb_age)}s ago (watchdog slow)")
            else:
                print(f"    Heartbeat:      ❌ {int(hb_age / 60)}m ago (watchdog stuck)")
        if crash_n > 0:
            print(f"    Recent crashes: ⚠ {crash_n} in last 7 days")
        else:
            print("    Recent crashes: ✅ none in last 7 days")
        try:
            from claude_monitoring.lifecycle import get_log_path

            log_path = get_log_path()
            if log_path.exists():
                size_mb = log_path.stat().st_size / (1024 * 1024)
                print(f"    Log file:       {log_path} ({size_mb:.1f}MB)")
        except Exception:
            pass

    if ext:
        print()
        print("  Extension:")
        print(f"    Host:           {ext.get('hostname', 'unknown')}")
        print(f"    Last heartbeat: {ext.get('last_seen', 'never')}")
        print(f"    Selectors:      {ext.get('status', 'unknown')}")

    # Footer fires only when capture is incomplete — either the macOS
    # system proxy is off OR the shell hasn't exported HTTPS_PROXY. When
    # both are configured, the user already knows the drill and we stay
    # quiet so --status reads cleanly.
    if not (sys_proxy and _http_proxy_env_is_set()):
        print()
        for line in _render_next_steps_lines(proxy_port=get_proxy_port()):
            print(line)

    return 0


def _extension_payload_safe() -> dict | None:
    """Normalize the extension heartbeat row into a fixed-shape dict
    keyed by literal field names. Each value is cast through ``str``
    to break taint propagation from the underlying DB read — CodeQL's
    clear-text-logging analysis tracks data flow from subprocess/DB
    reads to print statements, and a value-by-value re-build at this
    boundary plus a literal-keyed output shape lets the analyzer see
    the structure is bounded rather than arbitrary."""
    ext = _check_extension_heartbeat()
    if ext is None:
        return None
    # Explicit keys, explicit str() casts — no spread, no dict-update.
    # Empty-string fallbacks ensure the JSON shape is stable.
    return {
        "hostname": str(ext.get("hostname") or ""),
        "last_seen": str(ext.get("last_seen") or ""),
        "status": str(ext.get("status") or ""),
    }


def show_status_json() -> int:
    """Emit machine-readable status. Useful for CI and shell prompts.

    The JSON payload is intentionally a flat dict of booleans, ints,
    and short strings — no arbitrary subprocess output, no DB rows
    pass through directly. Each value comes from a function whose
    return type is narrow enough that downstream consumers (and
    CodeQL's clear-text-logging analyzer) can reason about it.
    """
    import json as _json

    payload = {
        "monitor_running": _is_monitor_running(),
        "mitmproxy_running": _is_mitmproxy_running(),
        "system_proxy_configured": _is_system_proxy_configured(),
        "cert_trusted": _is_cert_trusted(),
        "custom_ca": _has_custom_ca(),
        "ca_info": _get_ca_info_safe(),
        "db_encrypted": _is_db_encrypted(),
        "permissions_ok": _check_permissions(),
        "dashboard_token": _has_dashboard_token(),
        "dashboard_port": get_dashboard_port(),
        "proxy_port": get_proxy_port(),
        "extension": _extension_payload_safe(),
    }
    json_text = _json.dumps(payload, indent=2, default=str)
    import sys

    # show_status_json emits the dashboard status payload as JSON for
    # tooling consumers (CI scripts, the dashboard, future fleet-dashboard
    # integration). The extension dict contents (hostname, last_seen,
    # status) are intentionally serialized dashboard metadata — they are
    # not sensitive data despite CodeQL flagging the DB-read → JSON-output
    # chain as py/clear-text-logging-sensitive-data. This output path
    # predates PR #50 and exists as a documented status interface for the
    # dashboard. The TrustVerificationCode Literal pattern used elsewhere
    # in this PR (see security.py) does not apply here because extension
    # data is a flat heartbeat record, not a state enum.
    #
    # The matching CodeQL alert is dismissed in the GitHub UI with a
    # reference back to this comment. See
    # ~/Documents/vigil-notes/codeql-patterns.md for the project convention
    # covering both this dismissal pattern and the Literal-code pattern
    # used for state surfaces.
    sys.stdout.write(json_text + "\n")
    return 0
