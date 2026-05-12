#!/usr/bin/env python3
# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""AI Runtime Monitor -- live demo orchestrator.

Simulates a developer using an AI coding agent that installs packages,
one of which is malicious. The monitor catches everything.

This script writes synthetic JSONL files to
``~/.claude/projects/demo-scraper/`` -- the exact same path the monitor's
JSONLSessionWatcher reads for real Claude Code sessions. The watcher
processes our synthetic events through the same pipeline
(``_check_supply_chain`` -> ``parse_install_command`` -> ``store_dependency``
-> alerts), so the demo exercises shipping code end to end with zero
demo-only patches.

Scenarios:
    1. Legit installs: requests, beautifulsoup4, flask
    2. Vulnerable package: python-dotenv
    3. Malicious package: strapi-plugin-cron
    4. High-capability: python-binance (crypto/financial API)
    5. Credential leak: AWS key in a claude.ai response (browser ingest)
    6. Typosquat: requets (similar to requests)
    7. Elevated risk: playwright (browser automation)

Usage:
    python demo/run_demo.py              # runs against the already-running monitor
    python demo/run_demo.py --no-docker  # skip the real pip installs in Docker
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

# -- Configuration --

MONITOR_URL = "http://localhost:9081"
TOKEN_PATH = Path.home() / "claude_watch_output" / ".dashboard_token"
DEMO_PROJECT_DIR = Path.home() / ".claude" / "projects" / "demo-scraper"
CONTAINER = "ai-demo-sandbox"
DEMO_CWD = "/tmp/demo-scraper"
MODEL = "claude-sonnet-4-5"

DEMO_SESSION_ID = f"demo-{int(time.time())}"
BROWSER_CONV_ID = f"{DEMO_SESSION_ID}-browser"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _token() -> str:
    if not TOKEN_PATH.exists():
        print(f"ERROR: dashboard token not found at {TOKEN_PATH}")
        print("Is the monitor running? Try: ai-monitor --status")
        sys.exit(1)
    return TOKEN_PATH.read_text().strip()


TOKEN: str = ""


def _get_json(path: str) -> dict:
    url = f"{MONITOR_URL}{path}"
    if "?" in path:
        url += f"&token={TOKEN}"
    else:
        url += f"?token={TOKEN}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode())


def _post_json(path: str, payload: dict) -> dict:
    url = f"{MONITOR_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        print(f"  [HTTP {exc.code}] {body[:200]}")
        return {}


def _user_line(text: str) -> str:
    record = {
        "type": "user",
        "uuid": str(uuid.uuid4()),
        "sessionId": DEMO_SESSION_ID,
        "timestamp": _now_iso(),
        "cwd": DEMO_CWD,
        "message": {"role": "user", "content": text},
    }
    return json.dumps(record)


def _assistant_line(
    text: str,
    bash_command: str | None = None,
    in_tokens: int = 200,
    out_tokens: int = 80,
) -> str:
    content: list[dict] = [{"type": "text", "text": text}]
    if bash_command is not None:
        content.append(
            {
                "type": "tool_use",
                "id": f"toolu_{uuid.uuid4().hex[:12]}",
                "name": "Bash",
                "input": {"command": bash_command},
            }
        )
    record = {
        "type": "assistant",
        "uuid": str(uuid.uuid4()),
        "sessionId": DEMO_SESSION_ID,
        "timestamp": _now_iso(),
        "message": {
            "role": "assistant",
            "content": content,
            "model": MODEL,
            "usage": {
                "input_tokens": in_tokens,
                "output_tokens": out_tokens,
            },
            "stop_reason": "tool_use" if bash_command else "end_turn",
        },
    }
    return json.dumps(record)


def _append_jsonl(jsonl_path: Path, *lines: str) -> None:
    with jsonl_path.open("a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    # Small flush pause so the watcher sees each batch separately.
    time.sleep(0.4)


def _docker_run(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a command inside the docker sandbox via subprocess.run."""
    return subprocess.run(
        ["docker", "exec", CONTAINER, *cmd],
        capture_output=True,
        text=True,
        timeout=120,
    )


def _real_install(package: str, version: str | None = None) -> None:
    pkg = f"{package}=={version}" if version else package
    print(f"    [docker] pip install {pkg}")
    result = _docker_run(["pip", "install", "--no-cache-dir", "--disable-pip-version-check", pkg])
    if result.returncode != 0:
        print(f"    [docker] install returned {result.returncode} (non-fatal)")


def _verify_monitor_running() -> None:
    try:
        _get_json("/api/stats")
    except Exception as exc:
        print(f"ERROR: cannot reach monitor at {MONITOR_URL}: {exc}")
        print("Is it running? Try: ai-monitor --status")
        sys.exit(1)


def _verify_sandbox_running(required: bool) -> bool:
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={CONTAINER}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        running = CONTAINER in (result.stdout or "")
    except Exception:
        running = False
    if required and not running:
        print(f"ERROR: Docker container '{CONTAINER}' is not running.")
        print("Run: cd demo && docker compose up -d")
        sys.exit(1)
    return running


def _banner(title: str) -> None:
    bar = "=" * 60
    print()
    print(bar)
    print(f"  {title}")
    print(bar)


def _pause(seconds: float, msg: str = "") -> None:
    if msg:
        print(f"  [wait] {msg}")
    time.sleep(seconds)


def act_1_legit_packages(jsonl_path: Path, use_docker: bool) -> None:
    _banner("ACT 1 -- Developer asks Claude to build a web scraper")
    _append_jsonl(
        jsonl_path,
        _user_line(
            "Build me a Python web scraper that extracts product prices "
            "from e-commerce sites and stores them in SQLite."
        ),
        _assistant_line(
            "I'll set up the project with the required dependencies. "
            "Installing HTTP client, HTML parser, and a lightweight API:",
            bash_command="pip install requests beautifulsoup4 flask",
            in_tokens=312,
            out_tokens=145,
        ),
    )
    if use_docker:
        for pkg in ("requests", "beautifulsoup4", "flask"):
            _real_install(pkg)
    print("  [ok] Dashboard: Supply Chain shows 3 STANDARD-risk packages")
    _pause(2, "Letting the watcher catch up...")


def act_2_vulnerable_package(jsonl_path: Path, use_docker: bool) -> None:
    _banner("ACT 2 -- Claude installs a package with known CVEs")
    _append_jsonl(
        jsonl_path,
        _user_line("We need to load environment variables from a .env file."),
        _assistant_line(
            "Installing python-dotenv:",
            bash_command="pip install python-dotenv",
            in_tokens=180,
            out_tokens=60,
        ),
    )
    if use_docker:
        _real_install("python-dotenv")
    print("  [warn] Dashboard: python-dotenv may show CVE badges after next scan")
    _pause(2)


def act_3_malicious_package(jsonl_path: Path) -> None:
    _banner("ACT 3 -- Claude installs a MALICIOUS package")
    _append_jsonl(
        jsonl_path,
        _user_line("I also need scheduled task support. Add strapi-plugin-cron for that?"),
        _assistant_line(
            "Installing strapi-plugin-cron for cron-like scheduling. "
            "This will handle scheduled task management for our scraper:",
            bash_command="npm install strapi-plugin-cron",
            in_tokens=210,
            out_tokens=95,
        ),
    )
    print("  [!] Dashboard: CRITICAL -- strapi-plugin-cron (KNOWN_MALICIOUS_PACKAGES)")
    print("  [!] Alert fired: malicious package detected")
    _pause(3, "Threat intel + supply chain rules firing...")


def act_4_high_capability(jsonl_path: Path, use_docker: bool) -> None:
    _banner("ACT 4 -- Claude installs a HIGH-CAPABILITY package")
    _append_jsonl(
        jsonl_path,
        _user_line("Let's add live price tracking from crypto exchanges too."),
        _assistant_line(
            "Installing python-binance for real-time crypto data:",
            bash_command="pip install python-binance",
            in_tokens=160,
            out_tokens=55,
        ),
    )
    if use_docker:
        _real_install("python-binance")
    print("  [warn] Dashboard: HIGH CAPABILITY -- financial API access flagged")
    _pause(2)


def act_5_credential_leak() -> None:
    _banner("ACT 5 -- Claude leaks AWS credentials in a claude.ai response")
    now = _now_iso()
    events = [
        {
            "service": "claude.ai",
            "url": f"https://claude.ai/chat/{BROWSER_CONV_ID}",
            "type": "user_prompt",
            "text": "Connect my scraper to our AWS S3 bucket for storage.",
            "timestamp": now,
            "conversation_id": BROWSER_CONV_ID,
            "title": "Demo: AWS S3 integration",
        },
        {
            "service": "claude.ai",
            "url": f"https://claude.ai/chat/{BROWSER_CONV_ID}",
            "type": "assistant_response",
            "text": (
                "Here's the S3 configuration for your scraper:\n\n"
                "import boto3\n\n"
                "s3 = boto3.client('s3',\n"
                "    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',\n"
                "    aws_secret_access_key="
                "'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
                ")\n\n"
                "This connects to your production bucket. Keep the "
                "credentials secret and rotate them regularly."
            ),
            "timestamp": now,
            "conversation_id": BROWSER_CONV_ID,
            "title": "Demo: AWS S3 integration",
        },
    ]
    result = _post_json("/api/browser/ingest", {"events": events})
    stored = result.get("stored", 0)
    alerts = result.get("alerts", 0)
    print(f"  Ingested {stored} events, {alerts} alerts fired")
    print("  [warn] Dashboard: AWS credential alert -- MASKED in storage")
    _pause(2, "Sensitive data validators running...")


def act_6_typosquat(jsonl_path: Path) -> None:
    _banner("ACT 6 -- Claude installs a TYPOSQUATTED package")
    # Using 'requets' (missing an 's') which is in the hardcoded
    # KNOWN_TYPOSQUATS list in supply_chain.py.
    _append_jsonl(
        jsonl_path,
        _user_line("Also add the requests library for HTTP calls."),
        _assistant_line(
            "Installing requets:",
            bash_command="pip install requets",
            in_tokens=150,
            out_tokens=45,
        ),
    )
    print("  [!] Dashboard: TYPOSQUAT -- 'requets' similar to 'requests'")
    _pause(3, "Typosquat detection running...")


def act_7_browser_automation(jsonl_path: Path, use_docker: bool) -> None:
    _banner("ACT 7 -- Claude installs browser automation (elevated risk)")
    _append_jsonl(
        jsonl_path,
        _user_line("Some sites need JavaScript rendering. Add Playwright."),
        _assistant_line(
            "Installing Playwright for headless browser scraping:",
            bash_command="pip install playwright",
            in_tokens=175,
            out_tokens=70,
        ),
    )
    if use_docker:
        _real_install("playwright")
    print("  [warn] Dashboard: ELEVATED -- browser automation capability flagged")
    _pause(2)


def act_8_version_pinned_backdoor(jsonl_path: Path) -> None:
    """Real-world inspired scenario: mistralai==2.4.6 (reported May 2026
    to ship a backdoor that executes during import time). Demonstrates
    version-pinned malicious detection — name alone is a legitimate
    package, but this specific release is on the known-bad list.

    No real install — the alleged payload contacts a hardcoded IP and
    drops a script in /tmp on Linux during ``import mistralai``. We
    record the JSONL event so the monitor's _check_supply_chain hits
    KNOWN_MALICIOUS_VERSIONS and fires CRITICAL at capture time.
    """
    _banner("ACT 8 -- Claude pins a KNOWN-COMPROMISED version (mistralai==2.4.6)")
    _append_jsonl(
        jsonl_path,
        _user_line(
            "Let's add multi-model fallback. Install the Mistral SDK — pin "
            "to 2.4.6 since that's what our other service is using."
        ),
        _assistant_line(
            "Pinning to the requested version:",
            bash_command="pip install mistralai==2.4.6",
            in_tokens=185,
            out_tokens=55,
        ),
    )
    print("  [!] Dashboard: CRITICAL -- mistralai 2.4.6 (KNOWN_MALICIOUS_VERSIONS)")
    print("  [!] Reason: import-time RCE reported May 2026")
    print("  [!] Note: name alone (mistralai) is legitimate -- only 2.4.6 flagged")
    _pause(3, "Version-pinned malicious detection running...")


def run_demo(use_docker: bool) -> None:
    global TOKEN
    TOKEN = _token()

    _verify_monitor_running()
    _verify_sandbox_running(required=use_docker)

    DEMO_PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    jsonl_path = DEMO_PROJECT_DIR / f"{DEMO_SESSION_ID}.jsonl"
    # Create the file so the watcher picks it up before the first append.
    jsonl_path.touch()

    print()
    print("AI Runtime Monitor -- LIVE DEMO")
    print(f"   Session ID: {DEMO_SESSION_ID}")
    print(f"   JSONL file: {jsonl_path}")
    print(f"   Dashboard:  {MONITOR_URL}/?token={TOKEN}")
    use_docker_str = "yes" if use_docker else "no (see --no-docker)"
    print(f"   Docker:    {use_docker_str}")
    print()

    act_1_legit_packages(jsonl_path, use_docker)
    act_2_vulnerable_package(jsonl_path, use_docker)
    act_3_malicious_package(jsonl_path)
    act_4_high_capability(jsonl_path, use_docker)
    act_5_credential_leak()
    act_6_typosquat(jsonl_path)
    act_7_browser_automation(jsonl_path, use_docker)
    act_8_version_pinned_backdoor(jsonl_path)

    _banner("DEMO COMPLETE")
    print(f"  Dashboard: {MONITOR_URL}/?token={TOKEN}")
    print()
    print("  Investigation trail:")
    print(f"  1. Session Explorer -> find '{DEMO_SESSION_ID}'")
    print("  2. 8 conversation turns captured (user + assistant)")
    print("  3. Supply Chain -> 8 packages with risk scoring")
    print("  4. Alerts -> 2 critical malicious + typosquat + AWS key")
    print("  5. Activity Timeline -> all 8 scenarios in order")
    print()
    print("  What you just watched the monitor catch:")
    print("  [ok] 4 legitimate packages scanned")
    print("  [!] 1 MALICIOUS pinned-version (mistralai==2.4.6, import-time RCE)")
    print("  [!] 1 MALICIOUS package (strapi-plugin-cron)")
    print("  [!] 1 typosquat (requets)")
    print("  [!] 1 elevated-risk (playwright)")
    print("  [!!] 1 credential leak (AWS key, masked)")
    print("  [!!] 1 high-capability (python-binance)")
    print()
    print("Run verify_demo.py to assert all expected outcomes.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--no-docker",
        action="store_true",
        help="Skip real pip installs inside the Docker sandbox.",
    )
    args = parser.parse_args()
    run_demo(use_docker=not args.no_docker)


if __name__ == "__main__":
    main()
