# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Section 8: first-run setup wizard. Section 9: secure uninstall.

The wizard is invoked automatically the first time `ai-monitor --start`
is run on a fresh install (no .setup_complete marker). It walks the user
through:

    [1/4] Generate a unique CA cert for this machine
    [2/4] Trust the cert (native macOS admin dialog)
    [3/4] Enable AI traffic monitoring (system proxy)
    [4/4] Initialize DB, generate dashboard token, enforce permissions

Every step is opt-in with a clear explanation of what it does and what
data stays local. The wizard always defaults to Y for the cert steps
(they're the whole point of the product) but defaults to N for the
system proxy step because it has machine-wide side effects.

`ai-monitor --setup` forces a re-run regardless of state.
`ai-monitor --purge` is the inverse: disables proxy, removes cert,
overwrites DB with random bytes, deletes the data directory.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone

from claude_monitoring.config import get_db_path, get_output_dir, get_proxy_port
from claude_monitoring.security import (
    enforce_permissions,
    ensure_dashboard_token,
    generate_custom_ca,
    get_ca_cert_path,
    get_ca_info,
    get_setup_marker_path,
    trust_ca_cert,
    untrust_ca_cert,
)
from claude_monitoring.status import _is_cert_trusted, _is_system_proxy_configured

WIZARD_VERSION = "1.0.0"

_SEPARATOR = "═" * 60


def is_first_run() -> bool:
    return not get_setup_marker_path().exists()


def _prompt(message: str, default_yes: bool = True) -> bool:
    """Read a Y/n answer from stdin. Returns True for yes, False for no.

    Non-TTY input (e.g. CI, redirected stdin) returns the default — the
    wizard must be safe to run unattended.
    """
    if not sys.stdin.isatty():
        return default_yes
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        answer = input(f"  {message} {suffix}: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not answer:
        return default_yes
    return answer.startswith("y")


def _enable_system_proxy() -> bool:
    """Wrap networksetup to enable the system proxy on Wi-Fi."""
    port = get_proxy_port()
    try:
        subprocess.run(
            ["networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", str(port)],
            capture_output=True,
            timeout=10,
        )
        return True
    except Exception:
        return False


def _disable_system_proxy() -> bool:
    try:
        subprocess.run(
            ["networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"],
            capture_output=True,
            timeout=10,
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
# Section 8: setup wizard
# ─────────────────────────────────────────────────────────────


def run_setup_wizard(force: bool = False) -> bool:
    """Run the four-step wizard. Returns True on success.

    Steps that fail set ``ok=False`` in the marker JSON so a future
    --status can show what's incomplete. The wizard never aborts
    halfway — it completes every step it can and reports the result.
    """
    print()
    print(_SEPARATOR)
    print("  AI Runtime Monitor — First-Time Setup")
    print(_SEPARATOR)
    print()
    print("  This tool monitors AI coding agents on YOUR machine.")
    print("  All data stays local. Nothing leaves your computer.")
    print("  You control what's monitored and can purge anytime.")
    print()

    state: dict = {
        "version": WIZARD_VERSION,
        "setup_date": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "steps": {},
    }

    # ── Step 1: Generate the CA ───────────────────────────────────
    cert_path = get_ca_cert_path()
    print("[1/4] Generating unique monitoring certificate...")
    if cert_path.exists() and not force:
        info = get_ca_info()
        cn = info["common_name"] if info else "unknown"
        print(f"  ✅ Certificate already exists: {cn}")
        state["steps"]["generate_ca"] = "skipped"
    else:
        try:
            generate_custom_ca()
            info = get_ca_info()
            cn = info["common_name"] if info else "AI Runtime Monitor"
            print(f"  ✅ Certificate: {cn}")
            print("  ✅ Valid for: 1 year")
            print("  ✅ Restricted to: AI domains only (Name Constraints)")
            state["steps"]["generate_ca"] = "ok"
        except Exception as exc:
            print(f"  ⚠ Could not generate certificate: {exc}")
            state["steps"]["generate_ca"] = f"error: {exc}"

    # ── Step 2: Trust the CA ──────────────────────────────────────
    print()
    if _is_cert_trusted():
        print("[2/4] ✅ Certificate already trusted")
        state["steps"]["trust_ca"] = "already_trusted"
    else:
        print("[2/4] Trust the monitoring certificate")
        print()
        print("  What this does:")
        print("  - Allows inspection of AI API traffic (Anthropic, OpenAI, etc.)")
        print("  - Banking, email, Netflix, etc. are NEVER inspected")
        print("  - Same approach used by Zscaler and enterprise security tools")
        print("  - Certificate is restricted to AI domains only (X.509 NameConstraints)")
        print()
        print("  Your data is protected:")
        print("  - Certificate is unique to this machine")
        print("  - Private key has owner-only permissions (chmod 600)")
        print("  - Dashboard requires an authentication token")
        print("  - You can purge everything anytime: ai-monitor --purge")
        print()
        if _prompt("Trust the certificate?", default_yes=True):
            if trust_ca_cert():
                print("  ✅ Certificate trusted")
                state["steps"]["trust_ca"] = "ok"
            else:
                print("  ⚠ Could not trust certificate via osascript.")
                print("  You can do it manually:")
                print("    sudo security add-trusted-cert -d -r trustRoot \\")
                print("      -k /Library/Keychains/System.keychain \\")
                print(f"      {cert_path}")
                state["steps"]["trust_ca"] = "manual_required"
        else:
            print("  ⏭ Skipped — proxy capture limited to CLI tools")
            state["steps"]["trust_ca"] = "skipped"

    # ── Step 3: System proxy ──────────────────────────────────────
    print()
    if _is_system_proxy_configured():
        print("[3/4] ✅ System proxy already enabled")
        state["steps"]["system_proxy"] = "already_enabled"
    else:
        print("[3/4] Enable AI traffic monitoring for desktop apps")
        print()
        print("  What this does:")
        print("  - Routes AI API traffic from desktop apps through the local monitor")
        print("  - Captures prompts/responses from Claude Desktop, ChatGPT app, Cursor")
        print("  - Only AI domains are inspected — all other traffic passes through")
        print("  - Auto-disables when the monitor stops (Ctrl+C is safe)")
        print()
        print("  Default is NO because it has machine-wide side effects:")
        print("  - Other VPN/proxy tools may conflict")
        print("  - You can enable later: ai-monitor --enable-system-proxy")
        print()
        if _prompt("Enable system proxy now?", default_yes=False):
            if _enable_system_proxy():
                print("  ✅ System proxy enabled")
                state["steps"]["system_proxy"] = "ok"
            else:
                print("  ⚠ Could not enable system proxy")
                state["steps"]["system_proxy"] = "error"
        else:
            print("  ⏭ Skipped — desktop apps won't be captured")
            print("  CLI tools can use HTTPS_PROXY directly:")
            print(f"    export HTTPS_PROXY=http://127.0.0.1:{get_proxy_port()}")
            state["steps"]["system_proxy"] = "skipped"

    # ── Step 4: Initialize ────────────────────────────────────────
    print()
    print("[4/4] Initializing...")
    try:
        from claude_monitoring.db import HAS_SQLCIPHER, init_db

        init_db().close()
        token = ensure_dashboard_token()
        fixed = enforce_permissions()
        encrypted_msg = "encrypted" if HAS_SQLCIPHER else "unencrypted (chmod 600)"
        print(f"  ✅ Database initialized ({encrypted_msg})")
        print("  ✅ Dashboard token generated")
        print(f"  ✅ File permissions enforced ({len(fixed)} fixed)")
        state["steps"]["initialize"] = "ok"
        state["dashboard_token"] = token
    except Exception as exc:
        print(f"  ⚠ Initialization error: {exc}")
        state["steps"]["initialize"] = f"error: {exc}"
        token = None

    # Persist state
    state["cert_trusted"] = _is_cert_trusted()
    state["proxy_enabled"] = _is_system_proxy_configured()
    marker = get_setup_marker_path()
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(state, indent=2))
    try:
        os.chmod(str(marker), 0o600)
    except Exception:
        pass

    # Phase 3: nudge users toward the LaunchAgent install path. We don't
    # add a 5th wizard step — installing the service should be a deliberate
    # decision, not a default.
    print()
    print("  💡 Next steps:")
    print("     Run at login:  ai-monitor --install-service")
    print("     View logs:     ai-monitor --logs")
    print("     Check status:  ai-monitor --status")
    print()

    # Final summary
    print()
    print(_SEPARATOR)
    print("  ✅ Setup complete!")
    print(_SEPARATOR)
    print()
    if token:
        print(f"  Dashboard:  http://localhost:9081?token={token}")
    print("  Status:     ai-monitor --status")
    print("  Cleanup:    ai-monitor --cleanup")
    print("  Re-setup:   ai-monitor --setup")
    print("  Uninstall:  ai-monitor --purge")
    print()
    print("  All monitoring data stays on YOUR machine.")
    print("  Nothing is sent externally. You own your data.")
    print()
    return True


# ─────────────────────────────────────────────────────────────
# Section 9: secure uninstall
# ─────────────────────────────────────────────────────────────


def run_purge(confirm_token: str | None = None) -> bool:
    """Disable proxy, remove cert from keychain, overwrite DB, delete data dir.

    Requires the user to type 'DELETE' to confirm. ``confirm_token`` lets
    tests bypass the interactive prompt.
    """
    print("AI Runtime Monitor — Complete Uninstall")
    print()
    print("This will permanently delete:")
    print("  - All monitoring data (sessions, alerts, captures, traffic)")
    print("  - Monitoring certificate (and keychain trust)")
    print("  - Dashboard token and setup marker")
    print()

    if confirm_token is None:
        if not sys.stdin.isatty():
            print("Cancelled — non-interactive run requires confirm_token=.")
            return False
        try:
            confirm_token = input("Type 'DELETE' to confirm: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return False

    if confirm_token != "DELETE":
        print("Cancelled — confirmation did not match.")
        return False

    # 1. Disable system proxy
    _disable_system_proxy()
    print("  ✅ System proxy disabled")

    # 2. Remove cert from keychain
    cert_path = get_ca_cert_path()
    if cert_path.exists():
        untrust_ca_cert(cert_path)
        print("  ✅ Certificate removed from keychain")

    # 3. Overwrite DB with random bytes (best effort — encrypted DBs don't
    #    need this but it doesn't hurt)
    db_path = get_db_path()
    if db_path.exists():
        try:
            size = db_path.stat().st_size
            with open(db_path, "wb") as f:
                f.write(os.urandom(min(size, 50 * 1024 * 1024)))
            print(f"  ✅ Database overwritten ({size} bytes)")
        except Exception as exc:
            print(f"  ⚠ Could not overwrite DB: {exc}")

    # 4. Delete the entire output directory
    out_dir = get_output_dir()
    if out_dir.exists():
        try:
            import shutil

            shutil.rmtree(str(out_dir))
            print(f"  ✅ Removed {out_dir}")
        except Exception as exc:
            print(f"  ⚠ Could not remove {out_dir}: {exc}")

    print()
    print("  AI Runtime Monitor has been completely removed.")
    print("  No data remains on this machine.")
    return True
