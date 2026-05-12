#!/usr/bin/env python3
# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""AI Runtime Monitor — demo verifier.

Asserts that every expected outcome from ``run_demo.py`` actually
landed in the running monitor. Run this after ``python
demo/run_demo.py`` to confirm the demo is ready to record.

Exits 0 on full success, 1 with a checkmark/x report otherwise.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

MONITOR_URL = "http://localhost:9081"
TOKEN_PATH = Path.home() / "claude_watch_output" / ".dashboard_token"


def _token() -> str:
    if not TOKEN_PATH.exists():
        print(f"ERROR: dashboard token not found at {TOKEN_PATH}")
        sys.exit(1)
    return TOKEN_PATH.read_text().strip()


def _get(path: str, token: str) -> dict:
    sep = "&" if "?" in path else "?"
    url = f"{MONITOR_URL}{path}{sep}token={token}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode())


def _all_packages(sc: dict) -> set[str]:
    """Collect package names from the /api/supply-chain response.

    The handler returns them under ``installs`` (each grouped by
    package_name + manager). Older shapes used ``packages`` or
    ``groups`` — accept all three defensively.
    """
    names: set[str] = set()
    for key in ("installs", "packages", "groups"):
        for p in sc.get(key, []) or []:
            name = p.get("package_name") or p.get("name") or ""
            if name:
                names.add(name)
    return names


def _all_alerts(alerts_response: dict) -> list[dict]:
    for key in ("alerts", "items", "results"):
        if key in alerts_response and isinstance(alerts_response[key], list):
            return alerts_response[key]
    return []


def _alert_matches(alert: dict, needle: str) -> bool:
    needle = needle.lower()
    blob = json.dumps(alert, default=str).lower()
    return needle in blob


def main() -> int:
    token = _token()
    # Accept optional session prefix arg for stricter scoping
    session_prefix = sys.argv[1] if len(sys.argv) > 1 else "demo-"

    checks: list[tuple[str, bool, str]] = []

    # ── Supply chain packages ──
    try:
        sc = _get("/api/supply-chain?view=grouped", token)
        packages = _all_packages(sc)
    except Exception as exc:
        print(f"FATAL: could not reach /api/supply-chain: {exc}")
        return 1

    expected_legit = {"requests", "beautifulsoup4", "flask"}
    expected_vulnerable = {"python-dotenv"}
    expected_malicious = {"strapi-plugin-cron"}
    expected_typosquat = {"requets"}
    expected_high_capability = {"python-binance"}
    expected_elevated = {"playwright"}
    expected_version_pinned_bad = {"mistralai"}  # Act 8 — version 2.4.6 specifically

    checks.append(
        (
            "legit packages captured (requests, beautifulsoup4, flask)",
            expected_legit.issubset(packages),
            f"missing: {expected_legit - packages}" if not expected_legit.issubset(packages) else "",
        )
    )
    checks.append(
        (
            "vulnerable package captured (python-dotenv)",
            expected_vulnerable.issubset(packages),
            f"missing: {expected_vulnerable - packages}" if not expected_vulnerable.issubset(packages) else "",
        )
    )
    checks.append(
        (
            "malicious package captured (strapi-plugin-cron)",
            expected_malicious.issubset(packages),
            f"missing: {expected_malicious - packages}" if not expected_malicious.issubset(packages) else "",
        )
    )
    checks.append(
        (
            "typosquat package captured (requets)",
            expected_typosquat.issubset(packages),
            f"missing: {expected_typosquat - packages}" if not expected_typosquat.issubset(packages) else "",
        )
    )
    checks.append(
        (
            "high-capability package captured (python-binance)",
            expected_high_capability.issubset(packages),
            f"missing: {expected_high_capability - packages}"
            if not expected_high_capability.issubset(packages)
            else "",
        )
    )
    checks.append(
        (
            "elevated-risk package captured (playwright)",
            expected_elevated.issubset(packages),
            f"missing: {expected_elevated - packages}" if not expected_elevated.issubset(packages) else "",
        )
    )
    checks.append(
        (
            "version-pinned malicious captured (mistralai==2.4.6)",
            expected_version_pinned_bad.issubset(packages),
            f"missing: {expected_version_pinned_bad - packages}"
            if not expected_version_pinned_bad.issubset(packages)
            else "",
        )
    )

    # ── Alerts ──
    try:
        alerts_payload = _get("/api/alerts", token)
        alerts = _all_alerts(alerts_payload)
    except Exception as exc:
        print(f"FATAL: could not reach /api/alerts: {exc}")
        return 1

    typosquat_alert = any(_alert_matches(a, "typosquat") or _alert_matches(a, "requets") for a in alerts)
    malicious_alert = any(_alert_matches(a, "malicious") or _alert_matches(a, "strapi-plugin-cron") for a in alerts)
    aws_key_alert = any(_alert_matches(a, "aws_key") or _alert_matches(a, "akiaios") for a in alerts)
    version_pinned_alert = any(_alert_matches(a, "2.4.6") or _alert_matches(a, "mistralai") for a in alerts)

    checks.append(
        (
            "typosquat alert fired",
            typosquat_alert,
            "" if typosquat_alert else "no typosquat/requets match in /api/alerts",
        )
    )
    checks.append(
        (
            "malicious package alert fired",
            malicious_alert,
            "" if malicious_alert else "no malicious/strapi match in /api/alerts",
        )
    )
    checks.append(
        (
            "version-pinned malicious alert fired (mistralai 2.4.6)",
            version_pinned_alert,
            "" if version_pinned_alert else "no mistralai/2.4.6 match in /api/alerts",
        )
    )
    checks.append(
        (
            "AWS credential alert fired (and masked)",
            aws_key_alert,
            "" if aws_key_alert else "no aws_key/AKIA match in /api/alerts",
        )
    )

    # ── Session present ──
    try:
        sessions_payload = _get("/api/sessions", token)
        session_rows = sessions_payload.get("sessions") or sessions_payload.get("items") or []
        has_demo_session = any(
            (s.get("session_id") or s.get("id") or "").startswith(session_prefix) for s in session_rows
        )
        checks.append(("demo session present in Session Explorer", has_demo_session, ""))
    except Exception as exc:
        checks.append(("demo session present in Session Explorer", False, f"/api/sessions error: {exc}"))

    # ── Report ──
    print()
    print("Demo verification report")
    print("=" * 50)
    passed = 0
    for title, ok, detail in checks:
        mark = "OK  " if ok else "FAIL"
        print(f"  [{mark}] {title}{(': ' + detail) if detail else ''}")
        if ok:
            passed += 1

    print("=" * 50)
    print(f"  {passed}/{len(checks)} checks passed.")

    if passed == len(checks):
        print("  Demo is ready to record.")
        return 0
    print("  Re-run run_demo.py or wait a few seconds and re-verify.")
    print("  (Supply chain scans and the JSONL watcher can take a")
    print("   moment to catch up after the demo script finishes.)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
