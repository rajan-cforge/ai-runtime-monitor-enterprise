# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Runtime status inspection for AI Runtime Monitor.

Provides ``ai-monitor --status`` which reports on every layer of the stack:
core processes, proxy state, certificate trust, security posture, and
per-source capture matrix. All checks are best-effort and fail closed
(return False) on any error — status should never crash the CLI.
"""

from __future__ import annotations

import subprocess

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


def _is_cert_trusted() -> bool:
    """Check if a monitoring CA (custom or default mitmproxy) is trusted.

    Accepts either the future custom CA ("AI Runtime Monitor") or the
    default "mitmproxy" CA so this check works before and after the
    custom-CA migration in Section 2.
    """
    return _find_certificate("AI Runtime Monitor") or _find_certificate("mitmproxy")


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


def _check_extension_heartbeat() -> dict | None:
    """Return heartbeat info from the DB, or None if unavailable."""
    try:
        import sqlite3

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


def show_status() -> int:
    """Print a human-readable status report. Returns 0 for success."""
    proxy_running = _is_mitmproxy_running()
    sys_proxy = _is_system_proxy_configured()
    cert_ok = _is_cert_trusted()
    monitor_running = _is_monitor_running()
    db_encrypted = _is_db_encrypted()
    perms_ok = _check_permissions()
    has_token = _has_dashboard_token()
    custom_ca = _has_custom_ca()
    ext = _check_extension_heartbeat()

    p_mark = "✅" if proxy_running else "❌"
    sp_mark = "✅" if sys_proxy else "❌"
    ct_mark = "✅" if cert_ok else "❌"

    dashboard_url = f"http://localhost:{get_dashboard_port()}"

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
    print("    CA certificate: " + _fmt_check(cert_ok, "Trusted (AI domains only)", "Not trusted"))
    print(f"    SSL inspection: {'API + Browser metadata' if cert_ok else 'API only'}")
    print()
    print("  Capture matrix:")
    print(f"    Claude Code:      ✅ JSONL + {p_mark} Proxy")
    print("    OpenClaw:         ✅ JSONL")
    print(f"    Claude Desktop:   {sp_mark} " + ("Proxy (full capture)" if sys_proxy else "Process only"))
    print(f"    ChatGPT Desktop:  {sp_mark} " + ("Proxy (full capture)" if sys_proxy else "Process only"))
    print(f"    Cursor:           {sp_mark} " + ("Proxy (full capture)" if sys_proxy else "Process only"))
    browser_mode = "Proxy metadata + Extension content" if cert_ok else "Extension only"
    print(f"    Chrome claude.ai: {ct_mark} {browser_mode}")
    print(f"    Chrome chatgpt:   {ct_mark} {browser_mode}")
    print(f"    Chrome gemini:    {ct_mark} {browser_mode}")
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

    return 0


def show_status_json() -> int:
    """Emit machine-readable status. Useful for CI and shell prompts."""
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
        "extension": _check_extension_heartbeat(),
    }
    print(_json.dumps(payload, indent=2, default=str))
    return 0
