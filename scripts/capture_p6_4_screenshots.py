"""Boot a self-contained dashboard server with a seeded temp DB.

Used by the P6.4 fixture-capture workflow. Combined with Playwright MCP
(`browser_navigate` → `browser_evaluate('switchTab(\"traffic\")')` →
`browser_take_screenshot`), this script provides the dashboard the
operator sees on the API Traffic tab in three states:

  * ``empty``      — fresh DB, no api_calls rows
  * ``chat-only``  — four chat rows including a tokens=0 envelope-only case
  * ``show-all``   — same four chat rows plus four infra noise rows

Usage::

    PYTHONPATH=src python scripts/capture_p6_4_screenshots.py \\
        --mode chat-only --port 9099

Serves until killed. Stdout prints ``READY <url>`` when the dashboard
is reachable; the caller can grep for that line to know when to point
the browser at it.

The fixtures are visual sanity checks of the new atbl shape (8-column
table, .cstate badges, .srcbadge column). They are NOT pixel-diffed in
CI — they pin the rendered output at a point in time so reviewers can
eyeball the change without booting the dashboard.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import tempfile
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

os.environ["DISABLE_DASHBOARD_AUTH"] = "1"

from claude_monitoring import config as config_module  # noqa: E402
from claude_monitoring.dashboard_handler import DashboardHandler  # noqa: E402
from claude_monitoring.db import init_db  # noqa: E402


def _seed_db(path: Path, mode: str) -> None:
    init_db(str(path))
    if mode == "empty":
        return
    conn = sqlite3.connect(str(path))
    now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

    def insert(row: dict) -> None:
        cols = ",".join(row.keys())
        placeholders = ",".join("?" * len(row))
        conn.execute(
            f"INSERT INTO api_calls ({cols}) VALUES ({placeholders})",
            tuple(row.values()),
        )

    base_chat = [
        {
            "timestamp": now,
            "session_id": "sess-aaaa1111",
            "destination_host": "api.anthropic.com",
            "destination_service": "anthropic",
            "endpoint_path": "/v1/messages",
            "http_method": "POST",
            "http_status": 200,
            "model": "claude-sonnet-4-6",
            "input_tokens": 1842,
            "output_tokens": 327,
            "latency_ms": 1240,
            "estimated_cost_usd": 0.0091,
            "last_user_msg_preview": "Review the P6.4 plan and call out anything missing.",
            "assistant_msg_preview": "The plan covers the three-counter header, the noise...",
            "stop_reason": "end_turn",
        },
        {
            "timestamp": now,
            "session_id": "sess-bbbb2222",
            "destination_host": "api.anthropic.com",
            "destination_service": "anthropic",
            "endpoint_path": "/v1/messages",
            "http_method": "POST",
            "http_status": 200,
            "model": "claude-sonnet-4-6",
            "input_tokens": 624,
            "output_tokens": 88,
            "latency_ms": 890,
            "estimated_cost_usd": 0.0021,
            "last_user_msg_preview": "Continue.",
            "assistant_msg_preview": "Acknowledged. Proceeding with Phase B.",
            "stop_reason": "end_turn",
        },
        {
            "timestamp": now,
            "session_id": "sess-cccc3333",
            "destination_host": "api.openai.com",
            "destination_service": "openai",
            "endpoint_path": "/v1/chat/completions",
            "http_method": "POST",
            "http_status": 200,
            "model": "gpt-4o",
            "input_tokens": 412,
            "output_tokens": 215,
            "latency_ms": 1102,
            "estimated_cost_usd": 0.0034,
            "last_user_msg_preview": "Cross-check the contract against the merged spec.",
            "assistant_msg_preview": "The merged spec retains the chat-call LIKE filter...",
            "stop_reason": "stop",
        },
        # Envelope-only chat call — tokens=0 (parser failed); visible but
        # cstate shows "envelope only" not "captured".
        {
            "timestamp": now,
            "session_id": "sess-dddd4444",
            "destination_host": "api.anthropic.com",
            "destination_service": "anthropic",
            "endpoint_path": "/v1/messages",
            "http_method": "POST",
            "http_status": 200,
            "model": "claude-sonnet-4-6",
            "input_tokens": 0,
            "output_tokens": 0,
            "latency_ms": 1450,
            "stop_reason": None,
        },
    ]
    for row in base_chat:
        insert(row)

    if mode == "show-all":
        infra = [
            {
                "timestamp": now,
                "destination_host": "api.anthropic.com",
                "destination_service": "anthropic",
                "endpoint_path": "/v1/organizations/me/profile",
                "http_method": "GET",
                "http_status": 200,
                "latency_ms": 78,
            },
            {
                "timestamp": now,
                "destination_host": "api.anthropic.com",
                "destination_service": "anthropic",
                "endpoint_path": "/v1/environments/check",
                "http_method": "GET",
                "http_status": 200,
                "latency_ms": 32,
            },
            {
                "timestamp": now,
                "destination_host": "api.openai.com",
                "destination_service": "openai",
                "endpoint_path": "/v1/messages",
                "http_method": "POST",
                "http_status": 401,
                "latency_ms": 56,
            },
            {
                "timestamp": now,
                "destination_host": "oauth.anthropic.com",
                "destination_service": "anthropic",
                "endpoint_path": "/oauth/token/refresh",
                "http_method": "POST",
                "http_status": 200,
                "latency_ms": 120,
            },
        ]
        for row in infra:
            insert(row)
    conn.commit()
    conn.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=["empty", "chat-only", "show-all"])
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()

    tmp = tempfile.mkdtemp(prefix=f"p6_4_{args.mode}_")
    db_path = Path(tmp) / "monitor.db"
    _seed_db(db_path, args.mode)
    config_module.set_cli_overrides(output_dir=str(db_path.parent))

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"READY http://127.0.0.1:{args.port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
