# 90-Second Pitch Recording — AI Runtime Monitor

Target runtime: **90 seconds**. Record with QuickTime (Cmd+Shift+5) or
Loom in 1080p.

---

## Pre-flight (once, before recording)

```bash
# 1. Monitor healthy
ai-monitor --restart && sleep 5 && ai-monitor --status
# expect: Monitor ✅ Running, mitmproxy ✅, system proxy ✅

# 2. Sandbox up
cd demo && docker compose up -d
docker ps | grep ai-demo-sandbox

# 3. Prime the dashboard with demo data
python demo/run_demo.py

# 4. Verify the demo fired
python demo/verify_demo.py
# expect: 10/10 checks passed.

# 5. Open the dashboard in Chrome, at the token URL
#    Overview tab, fullscreen. Ready to navigate.
open "http://localhost:9081/?token=$(cat ~/claude_watch_output/.dashboard_token)"
```

---

## The 90-second script

### [0:00 – 0:12] Face to camera (phone or webcam)

> "I'm Rajan. I spent 18 years in enterprise security. I scaled
> platform engineering at Portworx from $15M to $100M ARR. I'm
> building AI Runtime Monitor — the CrowdStrike for AI coding tools."

### [0:12 – 0:22] Screen — Dashboard Overview

Hover the mouse over the KPI cards in the header.

> "This is my machine right now. Every AI agent running — Claude
> Code, Claude Desktop, ChatGPT Desktop, Cursor, browser AI — is
> being monitored. Sessions, tokens, cost, alerts, in real time."

### [0:22 – 0:35] Screen — Session Explorer

Click Session Explorer. Find the `demo-*` session at the top of the
active list. Click it. Show the 7 conversation turns.

> "I asked Claude to build me a web scraper. Here's every
> conversation turn — every prompt, every tool call, every package
> it wanted to install. I can see exactly what it said and what it
> did."

### [0:35 – 0:55] Screen — Supply Chain tab

Click Supply Chain. Show the intel bar (5 green dots). Sort by risk.
Scroll to find `mistralai` first — click to expand. Then scroll to
`strapi-plugin-cron` and expand it too.

> "Claude installed 8 packages. Every single one is cross-referenced
> against OSV, ThreatFox, URLhaus, and 15,000 OpenSSF malicious
> packages."
>
> [Click mistralai row]
>
> "This one — `mistralai==2.4.6`. Reported last week to ship a
> backdoor that executes during import time, before any of your code
> runs. The package itself is legitimate — millions of developers use
> the Mistral SDK. But version 2.4.6 specifically was compromised. We
> caught it the moment Claude pinned the bad version. Not the next
> day. Not after the next OSV sync. Immediately."
>
> [Click strapi-plugin-cron row]
>
> "Same story for `strapi-plugin-cron`. Scope mismatch, zero downloads,
> no description. No other tool on the market catches either of these
> for AI agents."

### [0:55 – 1:05] Screen — Alerts tab

Click Alerts. Show the critical red alert for malicious package. Scroll
to the AWS key alert. Highlight the masked value.

> "Real-time alerts. Malicious package detected. AWS credentials
> pasted into a Claude Web conversation — automatically masked at
> capture. Typosquat caught. Every finding has an investigation
> trail back to the session."

### [1:05 – 1:15] Screen — Session Explorer, click a desktop session

Navigate back to Session Explorer. Click a `desktop_claude_desktop` or
`desktop_chatgpt_desktop` session if one exists. Show the activity
summary card (daily bar chart, top hosts).

> "Desktop apps too. Claude Desktop, ChatGPT Desktop, Cursor — full
> network activity monitoring via SSL inspection. Bytes transferred,
> peak hours, every endpoint hit."

### [1:15 – 1:25] Face to camera (or slide with prevention roadmap)

> "Detection is what we have today. What Vercel needed last week was
> prevention. One employee installed an AI tool with 'Allow All'
> permissions and it led to a $2M breach. Our roadmap: detect today,
> prevent tomorrow, reduce blast radius when something gets through."

### [1:25 – 1:30] Face to camera — close

> "85% of developers use AI coding agents. Nobody monitors them. We
> do. I'm looking for Speedrun to help take this from my machine to
> every developer's machine."

---

## Recovery options mid-recording

| Problem | Fix |
|---------|-----|
| Dashboard feels empty | Re-run `python demo/run_demo.py`; it's idempotent with a fresh session id |
| Monitor offline | `ai-monitor --restart`, wait 5s, re-open dashboard URL |
| Orphan mitmdump flapping | `sudo lsof -i :9080` then `kill <pid>`, then `--restart` |
| Need to re-record | Use `Cmd+R` (QuickTime) to start over — no state to reset |

## Post-recording

```bash
# Clean up demo artifacts (optional)
rm -rf ~/.claude/projects/demo-scraper
cd demo && docker compose down -v
```

Demo rows in `monitor.db` are fine to leave — they don't pollute real
data and make great "this is what a healthy install looks like"
evidence if someone asks to see the raw dashboard again.
