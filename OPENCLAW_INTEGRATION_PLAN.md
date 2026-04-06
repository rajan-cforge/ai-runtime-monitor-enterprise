# OpenClaw Integration Plan: AI Runtime Monitor → Agent Control Plane

## Strategic Context

**Goal:** Extend AI Runtime Monitor to become the observability and security layer for OpenClaw agents. Build 3 deliverables that demonstrate a unified "agent control plane" to pitch to Naveen for funding.

**Your existing assets:**
- AI Runtime Monitor (observability — "Datadog for OpenClaw")
- TalosAI (security/compliance — "Agent Firewall")
- ACMS (memory — "Databricks for OpenClaw")

**Deliverables (in build order):**
1. **Phase 1:** OpenClaw process/network detection in AI Runtime Monitor (1 weekend)
2. **Phase 2:** `clawguard` — an OpenClaw skill that exposes monitor alerts to agents (1 weekend)
3. **Phase 3:** `clawmemory` — an OpenClaw skill wrapping ACMS for persistent agent memory (1 weekend)

---

## Phase 1: OpenClaw Detection in AI Runtime Monitor

### 1.1 Add OpenClaw to Process Detection

**File: `src/claude_monitoring/constants.py`**

Add OpenClaw process signatures to `AI_PROCESS_EXACT`:

```python
AI_PROCESS_EXACT = {
    "claude",
    "Claude",
    "ChatGPT",
    "ChatGPTHelper",
    "Ollama",
    "ollama",
    "Cursor",
    "Windsurf",
    # --- OpenClaw ---
    "openclaw",
    "OpenClaw",
}
```

Add OpenClaw patterns to `AI_PROCESS_PATTERNS`:

```python
AI_PROCESS_PATTERNS = {
    # ... existing patterns ...
    "openclaw": {"exclude": []},
    "moltbot": {"exclude": []},      # legacy name
    "clawdbot": {"exclude": []},     # original name
}
```

### 1.2 Add OpenClaw Gateway to AI_HOSTS

OpenClaw's Gateway runs on `ws://127.0.0.1:18789` by default. The Pi agent runtime uses RPC mode. Add these to `AI_HOSTS` in `constants.py`:

```python
AI_HOSTS = {
    # ... existing hosts ...

    # OpenClaw
    "localhost:18789": "openclaw_gateway",
    "127.0.0.1:18789": "openclaw_gateway",
    # OpenClaw might call any LLM API, which we already track.
    # But we should also detect ClawHub skill registry calls:
    "clawhub.com": "openclaw_clawhub",
    "api.clawhub.com": "openclaw_clawhub",
    "registry.openclaw.com": "openclaw_registry",
}
```

Add to `SERVICE_CLASSIFICATION`:

```python
SERVICE_CLASSIFICATION = {
    # ... existing ...
    ".openclaw.com": "OpenClaw",
    ".clawhub.com": "ClawHub",
}
```

### 1.3 Track OpenClaw Skill Calls

OpenClaw skills are invoked as tool calls. The monitor already tracks MCP tool calls via `mcp__` prefix detection in `monitor.py` line 590. OpenClaw skill calls follow a similar pattern.

**File: `src/claude_monitoring/constants.py`**

Add OpenClaw tool tracking to `TOOL_NAMES`:

```python
TOOL_NAMES = {
    # ... existing ...
    "mcp__",
    # --- OpenClaw skill calls ---
    "skill__",          # OpenClaw skill invocation prefix
    "openclaw__",       # OpenClaw system calls
    "claw_browser",     # OpenClaw browser tool
    "claw_canvas",      # OpenClaw canvas tool
    "claw_cron",        # OpenClaw cron/scheduler
}
```

### 1.4 Add OpenClaw Session Detection

OpenClaw stores sessions locally. We need a new watcher class that tails OpenClaw's session data the same way `JSONLSessionWatcher` tails Claude's JSONL files.

**File: `src/claude_monitoring/monitor.py`** — Add new class after `JSONLSessionWatcher`:

```python
class OpenClawSessionWatcher:
    """Watches OpenClaw session logs for agent activity.

    OpenClaw stores session data in its workspace directories.
    This watcher detects:
    - Skill invocations and their results
    - Tool calls (browser, canvas, cron)
    - Channel messages (WhatsApp, Telegram, Slack, etc.)
    - Token usage across models
    - Sensitive data in agent conversations
    """

    def __init__(self):
        self.db = get_thread_db()
        self._stop = threading.Event()
        self._file_positions = {}

    def stop(self):
        self._stop.set()

    def _find_openclaw_dirs(self):
        """Locate OpenClaw workspace directories."""
        candidates = [
            Path.home() / ".openclaw",
            Path.home() / ".config" / "openclaw",
            Path.home() / "openclaw",
        ]
        found = []
        for d in candidates:
            if d.exists() and d.is_dir():
                found.append(d)
        return found

    def scan_sessions(self):
        """Scan OpenClaw directories for session activity."""
        for oc_dir in self._find_openclaw_dirs():
            # Look for session log files
            for log_file in oc_dir.rglob("*.log"):
                self._tail_log(log_file)
            for json_file in oc_dir.rglob("*.json"):
                if "session" in json_file.name.lower():
                    self._process_session_file(json_file)

    def _tail_log(self, log_path):
        """Tail an OpenClaw log file for new entries."""
        path_str = str(log_path)
        try:
            file_size = os.path.getsize(path_str)
        except OSError:
            return

        last_pos = self._file_positions.get(path_str, 0)
        if file_size <= last_pos:
            return

        try:
            with open(path_str, encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                new_data = f.read()
                self._file_positions[path_str] = f.tell()
        except OSError:
            return

        for line in new_data.strip().split("\n"):
            if not line.strip():
                continue
            self._process_log_line(line, log_path)

    def _process_log_line(self, line, source_path):
        """Process a single OpenClaw log line.

        TODO: Adapt to actual OpenClaw log format once we install
        and run it. For now, look for JSON-structured lines and
        detect skill calls, tool usage, and sensitive patterns.
        """
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Not JSON - check for sensitive patterns in raw text
            matches = scan_sensitive(line)
            if matches:
                self._store_alert(matches, line, str(source_path))
            return

        # Extract session and event data
        event_type = record.get("type", record.get("event", ""))
        session_id = record.get("session_id", record.get("sessionId", ""))
        timestamp = record.get("timestamp", now_iso())

        if event_type in ("skill_call", "tool_call", "skill_invoke"):
            skill_name = record.get("skill", record.get("name", ""))
            self._store_event(timestamp, session_id, "openclaw_skill",
                "openclaw", {
                    "skill": skill_name,
                    "input_preview": json.dumps(
                        record.get("input", {}), default=str
                    )[:200],
                })

        # Scan all content for sensitive data
        content = json.dumps(record, default=str)
        matches = scan_sensitive(content)
        if matches:
            self._store_alert(matches, content[:200], str(source_path))

    def _process_session_file(self, json_path):
        """Process an OpenClaw session JSON file."""
        # Implementation depends on OpenClaw's actual file format
        pass

    def _store_event(self, timestamp, session_id, event_type, source, data):
        """Store event in database and push to live feed."""
        data_json = json.dumps(data, default=str)
        try:
            self.db.execute(
                "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?,?,?,?,?)",
                (timestamp, session_id or "openclaw", event_type, source, data_json),
            )
            self.db.commit()
        except Exception:
            pass
        push_live_event({
            "timestamp": timestamp,
            "session_id": session_id,
            "event_type": event_type,
            "source": source,
            "summary": f"OpenClaw: {data.get('skill', event_type)}",
        })

    def _store_alert(self, matches, snippet, source):
        """Store a sensitive data alert from OpenClaw activity."""
        matches_filtered = [m for m in matches
            if not _is_known_example(m["name"], snippet)]
        if not matches_filtered:
            return
        severity = min(
            (m["severity"] for m in matches_filtered),
            key=lambda s: SEVERITY_ORDER.get(s, 99)
        )
        try:
            self.db.execute(
                "INSERT INTO events (timestamp, session_id, event_type, source_layer, data_json) VALUES (?,?,?,?,?)",
                (now_iso(), "openclaw", "sensitive_data", "openclaw",
                 json.dumps({
                     "patterns": [m["name"] for m in matches_filtered],
                     "severity": severity,
                     "categories": list(set(m["category"] for m in matches_filtered)),
                     "context": f"openclaw:{source}",
                     "snippet": snippet[:200],
                 })),
            )
            self.db.commit()
        except Exception:
            pass

    def run_loop(self):
        """Continuous scanning loop (every 5 seconds)."""
        while not self._stop.is_set():
            self.scan_sessions()
            self._stop.wait(5)
```

### 1.5 Wire Into start_monitoring()

In `monitor.py`, add the OpenClaw watcher to the `start_monitoring()` function alongside the other watchers:

```python
# After chrome_watcher initialization:

# Layer 5: OpenClaw Agent Watcher
openclaw_watcher = OpenClawSessionWatcher()
openclaw_thread = threading.Thread(
    target=openclaw_watcher.run_loop,
    daemon=True,
    name="OpenClawWatcher"
)

# In the start block:
openclaw_thread.start()
openclaw_dirs = openclaw_watcher._find_openclaw_dirs()
if openclaw_dirs:
    print(f"  OpenClaw watcher: active ({len(openclaw_dirs)} workspace(s))")
else:
    print("  OpenClaw watcher: no OpenClaw installation detected")

# In signal_handler:
openclaw_watcher.stop()
```

### 1.6 Add OpenClaw-Specific Sensitive Patterns

**File: `src/claude_monitoring/constants.py`** — Add to `SENSITIVE_PATTERNS`:

```python
SENSITIVE_PATTERNS = {
    # ... existing patterns ...

    # OpenClaw-specific
    "openclaw_skill_key": {
        "pattern": r"(?i)openclaw[_-]?(?:skill|api)[_-]?(?:key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
        "severity": "critical",
        "category": "credential",
    },
    "telegram_bot_token": {
        "pattern": r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
        "severity": "critical",
        "category": "credential",
    },
    "whatsapp_session": {
        "pattern": r"(?i)whatsapp[_-]?(?:session|auth|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
        "severity": "high",
        "category": "credential",
    },
}
```

### 1.7 Add `/api/openclaw` Dashboard Endpoint

**File: `src/claude_monitoring/monitor.py`** — In the `DashboardHandler` class, add a new API route:

```python
elif path == "/api/openclaw":
    # OpenClaw-specific activity summary
    db = get_thread_db()
    events = db.execute(
        """SELECT timestamp, event_type, data_json
           FROM events
           WHERE source_layer = 'openclaw'
           ORDER BY timestamp DESC
           LIMIT ?""",
        (int(params.get("limit", ["50"])[0]),)
    ).fetchall()

    result = []
    for e in events:
        data = json.loads(e["data_json"])
        result.append({
            "timestamp": e["timestamp"],
            "event_type": e["event_type"],
            **data,
        })
    self._json_response(result)
```

### Phase 1 Verification Steps

```bash
# 1. Install OpenClaw
npm install -g @anthropic/openclaw   # or whatever the actual install command is
# OR clone from GitHub:
git clone https://github.com/openclaw/openclaw.git
cd openclaw && npm install

# 2. Run AI Runtime Monitor
cd ~/ai-runtime-monitor
pip3 install -e .
ai-monitor --start

# 3. Run an OpenClaw agent in another terminal
openclaw --start

# 4. Verify detection
# Open http://localhost:9081
# - System tab should show OpenClaw process
# - Live Feed should show OpenClaw events
# - Alerts tab should catch any sensitive data in agent conversations
```

---

## Phase 2: ClawGuard — OpenClaw Security Skill

This is an OpenClaw skill that lets any OpenClaw agent query AI Runtime Monitor for security alerts, sensitive data exposure, and compliance status.

### 2.1 Skill Directory Structure

```
clawguard/
├── SKILL.md              # Skill metadata and instructions
├── package.json          # Node.js dependencies (if needed)
├── tools/
│   ├── check_alerts.py   # Query alerts from monitor DB
│   ├── audit_session.py  # Full audit trail for a session
│   ├── scan_skill.py     # Scan another skill for security risks
│   └── compliance.py     # Compliance status (connects to TalosAI)
└── README.md
```

### 2.2 SKILL.md

```markdown
---
name: clawguard
description: Security monitoring and audit trail for OpenClaw agents.
  Provides real-time alerts on sensitive data exposure, credential leaks,
  and unauthorized tool calls. Connects to AI Runtime Monitor for
  full observability and to TalosAI for compliance posture.
author: GoCloudForge
version: 0.1.0
tags: [security, audit, compliance, monitoring, dlp]
---

# ClawGuard — Agent Security Skill

## Available Tools

### check_alerts
Query active security alerts from AI Runtime Monitor.
Returns sensitive data detections, credential exposures, and policy violations.

Usage: "Check for any security alerts"
Parameters:
  - severity: critical|high|medium|low (optional, default: all)
  - limit: number of alerts to return (default: 20)

### audit_session
Generate a full audit trail for a specific session.
Returns every tool call, file access, network connection, and sensitive pattern.

Usage: "Audit my last session" or "Show audit trail for session <id>"
Parameters:
  - session_id: session identifier (optional, defaults to most recent)

### scan_skill
Analyze another OpenClaw skill directory for security risks.
Checks for: hardcoded credentials, data exfiltration patterns,
suspicious network calls, prompt injection vectors.

Usage: "Scan the email-sender skill for security risks"
Parameters:
  - skill_path: path to the skill directory to scan

### compliance_status
Get current compliance posture from TalosAI.
Returns SOC2, ISO 27001, and ISO 42001 compliance scores.

Usage: "What is our compliance status?"
```

### 2.3 Tool Implementation: check_alerts.py

```python
#!/usr/bin/env python3
"""ClawGuard: Query security alerts from AI Runtime Monitor."""

import json
import sqlite3
import sys
from pathlib import Path


def get_db_path():
    """Find the AI Runtime Monitor database."""
    candidates = [
        Path.home() / "claude_watch_output" / "monitor.db",
        Path.home() / ".config" / "ai-runtime-monitor" / "monitor.db",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def check_alerts(severity=None, limit=20, session_id=None):
    """Query alerts from the monitor database.

    Args:
        severity: Filter by severity (critical/high/medium/low)
        limit: Max alerts to return
        session_id: Filter by session

    Returns:
        List of alert dicts
    """
    db_path = get_db_path()
    if not db_path:
        return {"error": "AI Runtime Monitor database not found. Is ai-monitor running?"}

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    query = """
        SELECT timestamp, session_id, data_json
        FROM events
        WHERE event_type = 'sensitive_data'
    """
    params = []

    if severity:
        query += " AND json_extract(data_json, '$.severity') = ?"
        params.append(severity)

    if session_id:
        query += " AND session_id = ?"
        params.append(session_id)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    alerts = []
    for row in rows:
        data = json.loads(row["data_json"])
        alerts.append({
            "timestamp": row["timestamp"],
            "session_id": row["session_id"],
            "severity": data.get("severity", "unknown"),
            "patterns": data.get("patterns", []),
            "categories": data.get("categories", []),
            "context": data.get("context", ""),
            "snippet": data.get("snippet", "")[:100],
        })

    summary = {
        "total_alerts": len(alerts),
        "critical": sum(1 for a in alerts if a["severity"] == "critical"),
        "high": sum(1 for a in alerts if a["severity"] == "high"),
        "medium": sum(1 for a in alerts if a["severity"] == "medium"),
        "low": sum(1 for a in alerts if a["severity"] == "low"),
    }

    return {"summary": summary, "alerts": alerts}


if __name__ == "__main__":
    severity = sys.argv[1] if len(sys.argv) > 1 else None
    result = check_alerts(severity=severity)
    print(json.dumps(result, indent=2))
```

### 2.4 Tool Implementation: audit_session.py

```python
#!/usr/bin/env python3
"""ClawGuard: Generate audit trail for a session."""

import json
import sqlite3
import sys
from pathlib import Path


def get_db_path():
    candidates = [
        Path.home() / "claude_watch_output" / "monitor.db",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def audit_session(session_id=None):
    """Generate full audit trail for a session.

    If session_id is None, audits the most recent session.
    """
    db_path = get_db_path()
    if not db_path:
        return {"error": "AI Runtime Monitor database not found."}

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Get session
    if session_id:
        session = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    else:
        session = conn.execute(
            "SELECT * FROM sessions ORDER BY last_activity DESC LIMIT 1"
        ).fetchone()

    if not session:
        return {"error": "No session found."}

    sid = session["session_id"]

    # Get all events for this session
    events = conn.execute(
        """SELECT timestamp, event_type, source_layer, data_json
           FROM events WHERE session_id = ?
           ORDER BY timestamp""",
        (sid,)
    ).fetchall()

    # Get connections during session timeframe
    connections = conn.execute(
        """SELECT timestamp, process_name, remote_host, remote_port, service
           FROM connections
           WHERE timestamp BETWEEN ? AND ?
           ORDER BY timestamp""",
        (session["start_time"], session["last_activity"])
    ).fetchall()

    # Get file events during session
    file_events = conn.execute(
        """SELECT timestamp, path, operation, size
           FROM file_events
           WHERE session_id = ? OR
                 (timestamp BETWEEN ? AND ?)
           ORDER BY timestamp""",
        (sid, session["start_time"], session["last_activity"])
    ).fetchall()

    # Build audit report
    tool_calls = []
    sensitive_alerts = []
    mcp_calls = []

    for e in events:
        data = json.loads(e["data_json"])
        if e["event_type"] == "tool_use":
            tool_calls.append({
                "timestamp": e["timestamp"],
                "tool": data.get("name", ""),
                "input_preview": data.get("input_preview", ""),
            })
        elif e["event_type"] == "sensitive_data":
            sensitive_alerts.append({
                "timestamp": e["timestamp"],
                "severity": data.get("severity", ""),
                "patterns": data.get("patterns", []),
                "context": data.get("context", ""),
            })
        elif e["event_type"] == "mcp_call":
            mcp_calls.append({
                "timestamp": e["timestamp"],
                "server": data.get("server", ""),
                "method": data.get("method", ""),
            })

    conn.close()

    return {
        "session": {
            "id": sid,
            "model": session["model"],
            "cwd": session["cwd"],
            "start": session["start_time"],
            "end": session["last_activity"],
            "total_turns": session["total_turns"],
            "total_input_tokens": session["total_input_tokens"],
            "total_output_tokens": session["total_output_tokens"],
        },
        "audit": {
            "total_events": len(events),
            "tool_calls": len(tool_calls),
            "sensitive_alerts": len(sensitive_alerts),
            "mcp_calls": len(mcp_calls),
            "network_connections": len(list(connections)),
            "file_operations": len(list(file_events)),
        },
        "tool_calls": tool_calls,
        "sensitive_alerts": sensitive_alerts,
        "mcp_calls": mcp_calls,
        "network_connections": [
            {"timestamp": c["timestamp"], "host": c["remote_host"],
             "port": c["remote_port"], "service": c["service"]}
            for c in connections
        ],
        "file_operations": [
            {"timestamp": f["timestamp"], "path": f["path"],
             "operation": f["operation"], "size": f["size"]}
            for f in file_events
        ],
    }


if __name__ == "__main__":
    sid = sys.argv[1] if len(sys.argv) > 1 else None
    result = audit_session(session_id=sid)
    print(json.dumps(result, indent=2))
```

### 2.5 Tool Implementation: scan_skill.py

```python
#!/usr/bin/env python3
"""ClawGuard: Scan an OpenClaw skill directory for security risks."""

import json
import os
import re
import sys
from pathlib import Path

# Import shared patterns from AI Runtime Monitor
try:
    from claude_monitoring.constants import SENSITIVE_PATTERNS
    from claude_monitoring.utils import scan_sensitive
except ImportError:
    # Fallback: inline critical patterns
    SENSITIVE_PATTERNS = {}
    def scan_sensitive(text):
        return []


RISK_PATTERNS = {
    "data_exfiltration": {
        "patterns": [
            r"fetch\s*\(['\"]https?://",      # HTTP calls to external URLs
            r"XMLHttpRequest",
            r"axios\.",
            r"requests\.(get|post|put)",
            r"urllib\.request",
            r"curl\s+",
            r"wget\s+",
        ],
        "severity": "high",
        "description": "Potential data exfiltration via network calls",
    },
    "file_system_access": {
        "patterns": [
            r"fs\.(read|write|unlink|rmdir)",
            r"open\s*\(.+['\"]w",
            r"shutil\.(copy|move|rmtree)",
            r"os\.(remove|unlink|rename)",
        ],
        "severity": "medium",
        "description": "File system modification capabilities",
    },
    "command_execution": {
        "patterns": [
            r"subprocess\.(run|call|Popen)",
            r"os\.system\(",
            r"exec\(",
            r"eval\(",
            r"child_process\.exec",
            r"spawn\(",
        ],
        "severity": "high",
        "description": "Command/code execution capabilities",
    },
    "prompt_injection": {
        "patterns": [
            r"ignore\s+(previous|above|all)\s+instructions",
            r"you\s+are\s+now\s+",
            r"disregard\s+(your|the)\s+",
            r"new\s+instructions?\s*:",
            r"system\s*:\s*you",
        ],
        "severity": "critical",
        "description": "Prompt injection patterns in skill content",
    },
    "credential_harvesting": {
        "patterns": [
            r"password|passwd|secret|api[_-]?key|token",
            r"\.env\b",
            r"credentials?\b",
            r"keychain|keyring",
        ],
        "severity": "medium",
        "description": "References to credentials or secrets",
    },
}


def scan_skill(skill_path):
    """Scan an OpenClaw skill directory for security risks.

    Args:
        skill_path: Path to the skill directory

    Returns:
        Security report dict
    """
    skill_dir = Path(skill_path)
    if not skill_dir.exists():
        return {"error": f"Skill directory not found: {skill_path}"}

    findings = []
    files_scanned = 0
    total_lines = 0

    # Scan all text files in the skill
    text_extensions = {
        ".py", ".js", ".ts", ".sh", ".bash", ".md",
        ".json", ".yaml", ".yml", ".toml", ".cfg", ".conf",
        ".txt", ".env", ".html",
    }

    for root, dirs, files in os.walk(skill_dir):
        # Skip node_modules, .git
        dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "__pycache__"}]

        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in text_extensions:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            files_scanned += 1
            lines = content.split("\n")
            total_lines += len(lines)

            # Check risk patterns
            for risk_name, risk_info in RISK_PATTERNS.items():
                for pattern in risk_info["patterns"]:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count("\n") + 1
                        findings.append({
                            "risk": risk_name,
                            "severity": risk_info["severity"],
                            "description": risk_info["description"],
                            "file": str(fpath.relative_to(skill_dir)),
                            "line": line_num,
                            "match": match.group()[:100],
                        })

            # Also run standard sensitive pattern scan
            sensitive = scan_sensitive(content)
            for s in sensitive:
                findings.append({
                    "risk": f"sensitive_data:{s['name'] if isinstance(s, dict) else s}",
                    "severity": s["severity"] if isinstance(s, dict) else "high",
                    "description": "Sensitive data pattern detected",
                    "file": str(fpath.relative_to(skill_dir)),
                    "line": 0,
                    "match": "",
                })

    # Deduplicate and summarize
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    risk_score = (
        severity_counts["critical"] * 10
        + severity_counts["high"] * 5
        + severity_counts["medium"] * 2
        + severity_counts["low"] * 1
    )

    verdict = "SAFE"
    if risk_score >= 20:
        verdict = "DANGEROUS"
    elif risk_score >= 10:
        verdict = "RISKY"
    elif risk_score >= 5:
        verdict = "CAUTION"

    return {
        "skill_path": str(skill_dir),
        "verdict": verdict,
        "risk_score": risk_score,
        "files_scanned": files_scanned,
        "total_lines": total_lines,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "findings": findings[:50],  # Cap at 50 for readability
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: scan_skill.py <skill_directory>")
        sys.exit(1)
    result = scan_skill(sys.argv[1])
    print(json.dumps(result, indent=2))
```

### 2.6 Publish to ClawHub

```bash
# After testing locally:
cd clawguard/
# Follow ClawHub publishing instructions
openclaw skill publish clawguard/
```

---

## Phase 3: ClawMemory — ACMS-Powered Agent Memory Skill

### 3.1 Skill Directory Structure

```
clawmemory/
├── SKILL.md
├── tools/
│   ├── remember.py       # Store memory via ACMS
│   ├── recall.py         # Semantic search via ACMS
│   ├── forget.py         # Propagated forgetting via ACMS
│   └── context.py        # Cross-domain context retrieval
└── README.md
```

### 3.2 SKILL.md

```markdown
---
name: clawmemory
description: Persistent, privacy-aware memory for OpenClaw agents.
  Powered by ACMS (Adaptive Cognitive Memory System).
  Gives agents the ability to learn from past interactions,
  retain context across sessions, and respect privacy boundaries
  through propagated forgetting.
author: GoCloudForge
version: 0.1.0
tags: [memory, context, knowledge, privacy, persistence]
---

# ClawMemory — Agent Memory Skill

Persistent memory with privacy controls for OpenClaw agents.
Built on ACMS: bio-inspired consolidation, 7-step security pipeline,
semantic search, propagated forgetting.

## Available Tools

### remember
Store a piece of information in long-term memory.
Automatically categorized and indexed for semantic retrieval.

### recall
Search memory using natural language.
Returns relevant memories ranked by semantic similarity.

### forget
Remove specific memories with propagated forgetting.
Related memories are also flagged for review or removal.

### context
Get cross-domain context for the current task.
Pulls relevant memories from all domains the agent has interacted with.
```

### 3.3 Tool Implementation: remember.py

```python
#!/usr/bin/env python3
"""ClawMemory: Store memories via ACMS."""

import json
import sys
from datetime import datetime, timezone

try:
    # If ACMS is installed as a package
    from acms.client import ACMSClient
    ACMS_AVAILABLE = True
except ImportError:
    ACMS_AVAILABLE = False


def get_acms_client():
    """Initialize ACMS client."""
    if not ACMS_AVAILABLE:
        return None
    try:
        return ACMSClient(base_url="http://localhost:8420")
    except Exception:
        return None


def remember(content, category=None, tags=None, importance=0.5):
    """Store a memory in ACMS.

    Args:
        content: Text content to remember
        category: Optional category (work, personal, project, etc.)
        tags: Optional list of tags
        importance: Importance score 0.0-1.0

    Returns:
        Storage confirmation with memory ID
    """
    client = get_acms_client()
    if not client:
        # Fallback: store in local SQLite
        return _local_store(content, category, tags, importance)

    try:
        result = client.store_memory(
            content=content,
            metadata={
                "source": "openclaw",
                "category": category or "general",
                "tags": tags or [],
                "importance": importance,
                "stored_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        return {
            "status": "stored",
            "memory_id": result.get("id"),
            "backend": "acms",
        }
    except Exception as e:
        return {"error": str(e), "fallback": "local"}


def _local_store(content, category, tags, importance):
    """Fallback local storage when ACMS is not available."""
    import sqlite3
    from pathlib import Path

    db_path = Path.home() / ".openclaw" / "clawmemory.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        category TEXT,
        tags TEXT,
        importance REAL DEFAULT 0.5,
        created_at TEXT NOT NULL
    )""")
    conn.execute(
        "INSERT INTO memories (content, category, tags, importance, created_at) VALUES (?,?,?,?,?)",
        (content, category, json.dumps(tags or []), importance,
         datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    mid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    return {"status": "stored", "memory_id": mid, "backend": "local"}


if __name__ == "__main__":
    content = sys.argv[1] if len(sys.argv) > 1 else "Test memory"
    result = remember(content)
    print(json.dumps(result, indent=2))
```

### 3.4 Tool Implementation: recall.py

```python
#!/usr/bin/env python3
"""ClawMemory: Semantic search via ACMS."""

import json
import sys
from pathlib import Path

try:
    from acms.client import ACMSClient
    ACMS_AVAILABLE = True
except ImportError:
    ACMS_AVAILABLE = False


def recall(query, limit=5, category=None):
    """Search memories semantically.

    Args:
        query: Natural language search query
        limit: Max results
        category: Optional category filter

    Returns:
        List of relevant memories ranked by similarity
    """
    if ACMS_AVAILABLE:
        try:
            client = ACMSClient(base_url="http://localhost:8420")
            results = client.search_memories(
                query=query,
                limit=limit,
                filters={"category": category} if category else None,
            )
            return {
                "query": query,
                "results": results,
                "backend": "acms",
                "count": len(results),
            }
        except Exception:
            pass

    # Fallback: local keyword search
    return _local_search(query, limit, category)


def _local_search(query, limit, category):
    """Fallback keyword search in local SQLite."""
    import sqlite3

    db_path = Path.home() / ".openclaw" / "clawmemory.db"
    if not db_path.exists():
        return {"query": query, "results": [], "backend": "local", "count": 0}

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Simple keyword matching (ACMS provides proper semantic search)
    words = query.lower().split()
    conditions = " OR ".join(["LOWER(content) LIKE ?" for _ in words])
    params = [f"%{w}%" for w in words]

    if category:
        conditions = f"({conditions}) AND category = ?"
        params.append(category)

    rows = conn.execute(
        f"SELECT * FROM memories WHERE {conditions} ORDER BY importance DESC LIMIT ?",
        params + [limit]
    ).fetchall()
    conn.close()

    return {
        "query": query,
        "results": [
            {
                "id": r["id"],
                "content": r["content"],
                "category": r["category"],
                "importance": r["importance"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
        "backend": "local",
        "count": len(rows),
    }


if __name__ == "__main__":
    query = sys.argv[1] if len(sys.argv) > 1 else "test"
    result = recall(query)
    print(json.dumps(result, indent=2))
```

---

## Claude Code Execution Sequence

Here is the exact sequence of commands to run with Claude Code:

### Step 0: Setup Workspace

```bash
mkdir -p ~/openclaw-projects
cd ~/openclaw-projects

# Clone your repos
git clone https://github.com/rajan-cforge/ai-runtime-monitor.git
# git clone https://github.com/rajan-cforge/acms-os.git  # if needed

# Install OpenClaw
git clone https://github.com/openclaw/openclaw.git
cd openclaw
npm install
cd ..
```

### Step 1: Modify AI Runtime Monitor (Phase 1)

Open Claude Code in `~/openclaw-projects/ai-runtime-monitor/`:

```
Claude Code prompt:
"Read the files in src/claude_monitoring/. I need you to add OpenClaw
agent detection. Specifically:

1. In constants.py:
   - Add 'openclaw' and 'OpenClaw' to AI_PROCESS_EXACT
   - Add 'openclaw', 'moltbot', 'clawdbot' to AI_PROCESS_PATTERNS
   - Add OpenClaw gateway (localhost:18789) to AI_HOSTS
   - Add 'skill__' and 'openclaw__' to TOOL_NAMES
   - Add openclaw_skill_key and telegram_bot_token to SENSITIVE_PATTERNS

2. In monitor.py:
   - Add OpenClawSessionWatcher class that scans ~/.openclaw/ for
     session logs, detects skill invocations, and runs sensitive
     pattern scanning on all agent activity
   - Wire it into start_monitoring() as a new thread
   - Add /api/openclaw endpoint to DashboardHandler

3. Run the tests to make sure nothing is broken."
```

### Step 2: Build ClawGuard Skill (Phase 2)

```
Claude Code prompt:
"Create a new directory ~/openclaw-projects/clawguard/ with an OpenClaw
skill that provides security monitoring. The skill should:

1. Have a SKILL.md with metadata
2. Have tools/ directory with:
   - check_alerts.py: queries AI Runtime Monitor's SQLite DB for
     sensitive_data events, returns severity summary and alert list
   - audit_session.py: generates full audit trail for a session
     (tool calls, file ops, network connections, sensitive patterns)
   - scan_skill.py: scans another skill directory for security risks
     (data exfiltration, command execution, prompt injection,
     credential patterns)
3. Each tool should be runnable standalone and output JSON
4. Include comprehensive tests"
```

### Step 3: Build ClawMemory Skill (Phase 3)

```
Claude Code prompt:
"Create ~/openclaw-projects/clawmemory/ as an OpenClaw skill wrapping
ACMS for persistent agent memory. The skill should:

1. Have a SKILL.md describing memory capabilities
2. Have tools/:
   - remember.py: stores memories, tries ACMS first, falls back to
     local SQLite
   - recall.py: semantic search via ACMS, keyword fallback
   - forget.py: propagated forgetting via ACMS
   - context.py: cross-domain context retrieval
3. Work standalone without ACMS (graceful degradation to local SQLite)
4. Include tests"
```

### Step 4: Integration Test

```bash
# Terminal 1: Start AI Runtime Monitor
cd ~/openclaw-projects/ai-runtime-monitor
ai-monitor --start

# Terminal 2: Start OpenClaw with clawguard skill
cd ~/openclaw-projects
openclaw --skills ./clawguard ./clawmemory

# Terminal 3: Test the skills
# In OpenClaw chat:
# "Check for security alerts"
# "Scan the email skill for risks"
# "Remember that our AWS account ID is 123456789012"
# "What do you remember about our AWS setup?"

# Verify in dashboard at http://localhost:9081:
# - OpenClaw process visible in System tab
# - Skill calls visible in Live Feed
# - Alerts visible in Alerts tab
```

---

## Demo Script for Naveen

Once all three phases are working, the pitch demo flow:

1. **Show AI Runtime Monitor dashboard** with OpenClaw agent running
   - "This is real-time observability into every action the agent takes"
2. **Trigger a ClawGuard scan** on a third-party skill
   - "This skill has data exfiltration risk. We caught it before deployment."
3. **Show the audit trail** for a session
   - "Every tool call, every file touched, every network connection. Immutable."
4. **Show ClawMemory** persisting context across sessions
   - "The agent remembers. And it forgets when you tell it to. With privacy controls."
5. **Close with the control plane narrative:**
   - "OpenClaw has a security gap that blocks enterprise adoption. We have the control plane: observability, security, compliance, and memory. All working today."

---

## Files to Modify (Summary)

| File | Changes |
|------|---------|
| `constants.py` | Add OpenClaw process names, hosts, tool names, sensitive patterns |
| `monitor.py` | Add `OpenClawSessionWatcher` class, `/api/openclaw` endpoint, wire into `start_monitoring()` |
| `config.py` | Add `openclaw` section to default config (optional) |
| NEW: `clawguard/SKILL.md` | Skill metadata |
| NEW: `clawguard/tools/check_alerts.py` | Alert query tool |
| NEW: `clawguard/tools/audit_session.py` | Audit trail tool |
| NEW: `clawguard/tools/scan_skill.py` | Skill security scanner |
| NEW: `clawmemory/SKILL.md` | Memory skill metadata |
| NEW: `clawmemory/tools/remember.py` | Memory storage |
| NEW: `clawmemory/tools/recall.py` | Semantic recall |
| NEW: `clawmemory/tools/forget.py` | Propagated forgetting |
