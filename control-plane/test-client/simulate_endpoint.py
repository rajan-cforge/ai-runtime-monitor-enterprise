#!/usr/bin/env python3
"""Simulate an AI monitoring endpoint sending data to the control plane."""

import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

CP_URL = os.environ.get("CP_URL", "http://localhost:9090")
CP_API_KEY = os.environ.get("CP_API_KEY", "test-key-123")
HOSTNAME = os.environ.get("SIM_HOSTNAME", "Docker-TestClient")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "30"))

# Simulated sessions
SESSIONS = [
    {
        "id": "sim-cc-001",
        "model": "claude-sonnet-4-6",
        "agent_type": "claude_code",
        "title": "Refactor auth middleware",
        "cwd": "~/Projects/webapp",
    },
    {
        "id": "sim-cursor-001",
        "model": "claude-sonnet-4-6",
        "agent_type": "cursor",
        "title": "Fix database migration",
        "cwd": "~/Projects/api-server",
    },
    {
        "id": "sim-oc-001",
        "model": "claude-sonnet-4-6",
        "agent_type": "openclaw",
        "title": "OpenClaw · Telegram: what's the weather?",
        "cwd": "~/.openclaw/workspace",
    },
]

TOOLS = ["Bash", "Read", "Write", "Edit", "Grep", "Glob", "WebFetch", "WebSearch", "Agent"]
ALERT_PATTERNS = [
    {"severity": "high", "patterns": ["password_in_code"], "context": "tool:Bash"},
    {"severity": "medium", "patterns": ["phone_number"], "context": "user_prompt"},
    {"severity": "low", "patterns": ["env_file"], "context": "tool:Write"},
    {"severity": "critical", "patterns": ["aws_key"], "context": "assistant_response"},
]

event_counter = 0
api_call_counter = 0


def make_events(session, count=5):
    """Generate random events for a session."""
    global event_counter
    events = []
    for _ in range(count):
        event_counter += 1
        tool = random.choice(TOOLS)
        events.append(
            {
                "client_event_id": event_counter,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": session["id"],
                "event_type": "tool_use",
                "source_layer": "jsonl",
                "data_json": {"name": tool, "input_preview": f"{tool} operation"},
            }
        )
    # Add a token_usage event
    event_counter += 1
    inp = random.randint(100, 5000)
    outp = random.randint(50, 2000)
    events.append(
        {
            "client_event_id": event_counter,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session["id"],
            "event_type": "token_usage",
            "source_layer": "jsonl",
            "data_json": {"model": session["model"], "input_tokens": inp, "output_tokens": outp},
        }
    )
    return events, inp, outp


def make_api_call(session, inp, outp):
    """Generate an API call record."""
    global api_call_counter
    api_call_counter += 1
    cost = inp * 0.000003 + outp * 0.000015
    return {
        "client_call_id": api_call_counter,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session["id"],
        "model": session["model"],
        "destination_service": "anthropic_api",
        "input_tokens": inp,
        "output_tokens": outp,
        "estimated_cost_usd": round(cost, 6),
    }


def maybe_alert(session):
    """Occasionally generate a security alert."""
    global event_counter
    if random.random() > 0.3:  # 30% chance per cycle
        return []
    alert_template = random.choice(ALERT_PATTERNS)
    event_counter += 1
    return [
        {
            "client_event_id": event_counter,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session["id"],
            "severity": alert_template["severity"],
            "patterns": alert_template["patterns"],
            "context": alert_template["context"],
            "snippet": f"Simulated {alert_template['patterns'][0]} detection",
            "validated": random.choice([True, False]),
            "confidence": random.choice(["high", "medium", "low"]),
        }
    ]


def main():
    print(f"[SimClient] Starting endpoint simulator: {HOSTNAME}")
    print(f"[SimClient] CP URL: {CP_URL}")
    print(f"[SimClient] Sync interval: {SYNC_INTERVAL}s")

    # Wait for CP to be ready
    for attempt in range(30):
        try:
            r = requests.get(f"{CP_URL}/health", timeout=5)
            if r.status_code == 200:
                print("[SimClient] CP is ready")
                break
        except Exception:
            pass
        print(f"[SimClient] Waiting for CP... (attempt {attempt + 1})")
        time.sleep(2)
    else:
        print("[SimClient] CP not reachable after 60s, exiting")
        sys.exit(1)

    # Accumulate session stats
    session_stats = {s["id"]: {"inp": 0, "outp": 0, "turns": 0, "cost": 0} for s in SESSIONS}

    while True:
        try:
            # Pick 1-2 random sessions to generate data for
            active = random.sample(SESSIONS, k=random.randint(1, min(2, len(SESSIONS))))

            all_events = []
            all_api_calls = []
            all_alerts = []
            session_payloads = []

            for session in active:
                stats = session_stats[session["id"]]
                events, inp, outp = make_events(session, count=random.randint(2, 8))
                all_events.extend(events)

                api_call = make_api_call(session, inp, outp)
                all_api_calls.append(api_call)

                alerts = maybe_alert(session)
                all_alerts.extend(alerts)

                stats["inp"] += inp
                stats["outp"] += outp
                stats["turns"] += 1
                stats["cost"] += api_call["estimated_cost_usd"]

                session_payloads.append(
                    {
                        "client_session_id": session["id"],
                        "start_time": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 24))).isoformat(),
                        "cwd": session["cwd"],
                        "model": session["model"],
                        "agent_type": session["agent_type"],
                        "title": session["title"],
                        "total_input_tokens": stats["inp"],
                        "total_output_tokens": stats["outp"],
                        "total_turns": stats["turns"],
                        "total_cost": round(stats["cost"], 4),
                        "last_activity": datetime.now(timezone.utc).isoformat(),
                    }
                )

            payload = {
                "endpoint": {
                    "hostname": HOSTNAME,
                    "os": "Linux 6.1.0 x86_64",
                    "ip": "172.17.0.3",
                    "monitor_version": "0.2.0",
                },
                "sessions": session_payloads,
                "events": all_events,
                "api_calls": all_api_calls,
                "alerts": all_alerts,
                "watermarks": {
                    "events": event_counter,
                    "api_calls": api_call_counter,
                    "sessions": len(SESSIONS),
                },
            }

            r = requests.post(
                f"{CP_URL}/api/v1/ingest",
                json=payload,
                headers={
                    "X-API-Key": CP_API_KEY,
                    "X-Endpoint-Key": CP_API_KEY,
                    "Content-Type": "application/json",
                },
                timeout=10,
            )

            if r.status_code in (200, 202):
                result = r.json()
                print(f"[SimClient] Synced: {result['stored']} (endpoint: {result['endpoint_id'][:8]}...)")
            else:
                print(f"[SimClient] Error: HTTP {r.status_code}: {r.text[:200]}")

        except requests.ConnectionError:
            print("[SimClient] CP unreachable, retrying...")
        except Exception as e:
            print(f"[SimClient] Error: {e}")

        time.sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    main()
