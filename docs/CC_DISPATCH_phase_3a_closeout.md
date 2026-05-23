# Claude Code Dispatch — Phase 3A Closeout

You stopped correctly. C1-FOLLOWUP is a non-finding. The probe inherited
the dashboard's monkey-patched fetch credentials and misread the server's
auth state. Server-side enforcement on /api/* is already correct.

Proceed with Option 1 (revise PR #17 to retract C1-FOLLOWUP), action the
two real findings the probe DID surface, then move to integration → main.

## Behavior contract reminder

Everything below goes through branches and PRs. No direct pushes to main.
Stop and report at each numbered checkpoint.

## Step 1: Retract C1-FOLLOWUP on docs/antfooding-day-1-phase-3a

Add one more commit to the existing PR #17 branch.

### 1.1 Update docs/AUDIT_2026-05-21.md

Replace the C1-FOLLOWUP annotation with this exact subsection text:

```markdown
## C1-FOLLOWUP — RETRACTED as non-finding (2026-05-23)

Initial antfooding probe (Claude in Chrome, 2026-05-22) reported that
all /api/* endpoints served data without server-side token enforcement.
A C1-FOLLOWUP critical was provisionally opened.

Subsequent terminal-based verification disproved the finding:

```
GET /api/stats    no token, curl:  HTTP 401  blocked
GET /api/sessions no token, curl:  HTTP 401  blocked
GET /api/feed     no token, curl:  HTTP 401  blocked
GET /api/alerts   no token, curl:  HTTP 401  blocked
GET /api/stats    with valid token: HTTP 200  allowed

POST /api/browser/ingest    no token: HTTP 200  intentionally exempt
POST /api/browser/heartbeat no token: HTTP 400  intentionally exempt
POST /api/supply-chain/scan no token: HTTP 401  blocked
```

Server-side auth is already enforced via `_check_auth()` at
`src/claude_monitoring/monitor.py:2068-2134`, which gates every path
except static HTML, favicon, and the documented browser-extension
ingestion endpoints. Token comparison uses `hmac.compare_digest` per
`src/claude_monitoring/security.py:341` (constant-time).

### Root cause of the false positive

The dashboard's `dashboard.html:557-571` monkey-patches `window.fetch`
to inject the auth token from localStorage on every `/api/*` request.
The probe ran inside a tab that had already loaded the dashboard and
acquired the token. Its `fetch('/api/stats')` calls were authenticated
silently by the monkey patch. The probe interpreted the resulting 200
responses as evidence that no auth was required.

### Lesson for future probes

Browser-driven security probes inherit credentials from any app the
tab has already loaded. To verify server-side auth state, probes must
either:
- Use `curl`, Python `requests`, or another raw HTTP client outside
  the browser, OR
- Open a fresh tab to a different origin and use `fetch('http://localhost:9081/api/*', { credentials: 'omit' })`, OR
- Strip the monkey patch before testing (delete `window.fetch`
  override, restore native fetch).

This lesson is captured in `docs/PROBE_DESIGN.md` for future antfooding
sessions.

### Status

No code change required. PR #17 commits retract the false-finding
annotation and the probe's Test 1 result.
```

### 1.2 Update docs/CLAUDE_CHROME_PROBE_2026-05-22.md

Add an "Errata" callout at the top of the file (before Test 1):

```markdown
## Errata (added 2026-05-23)

**Test 1 (C1 token auth enforcement) verdict was reversed by terminal
verification.** Server-side enforcement on /api/* is correct. The
probe's 200-response observations were artifacts of the dashboard's
monkey-patched `fetch` injecting the auth token automatically. See
`docs/AUDIT_2026-05-21.md` section "C1-FOLLOWUP — RETRACTED" for full
root cause analysis.

**Recommendation #1 (server-side token enforcement on /api/*) is
withdrawn.** No code change needed.

Other test results in this report stand. Detection-quality findings
(Recommendations 2-5) remain valid and have been routed to Lane D1
and Lane B scope per `docs/SPRINT_ONE_WEEK.md`.
```

Mark Test 1 result in the table as `RETRACTED / PASS (server-side
verified)` instead of `PARTIAL`.

### 1.3 Create docs/PROBE_DESIGN.md

New file documenting how future antfooding probes must be designed:

```markdown
# Antfooding Probe Design Notes

Lessons captured from running probes against the Vigil dashboard.

## Browser-based probes inherit app credentials

Probes that drive a Chrome tab to test server-side authentication will
silently inherit any auth tokens the app has already acquired (via
localStorage, cookies, or in-memory state). The dashboard's
`dashboard.html` monkey-patches `window.fetch` to inject the auth token
on all `/api/*` calls. A probe running `fetch('/api/stats')` from inside
that tab cannot tell whether the server requires authentication or not.

### Required practice for auth probes

When testing server-side auth state, use at least one of these:

1. **Out-of-browser HTTP client** — `curl`, Python `requests`, `gh
   api`, etc. — for ground truth.
2. **Fresh tab on different origin** with `credentials: 'omit'` and
   explicit empty headers.
3. **Strip the monkey patch** before testing:
   ```js
   delete window.fetch;  // restores native
   // OR
   const nativeFetch = window.fetch.toString().includes('original')
     ? originalFetch
     : window.fetch;
   ```

### Required practice for all probes

- Cross-verify any "no auth required" finding with curl before
  flagging as a security issue.
- Cross-verify any "data exfiltrated" finding by reproducing without
  the app's session state.
- Cross-verify any "endpoint exists" finding from server logs, not
  just network response.

## Confidence reclassification in detectors

The Day 1 probe also found that the alert detection pipeline
reclassified the same fixture hash from `low/likely_fp:true` to
`critical/likely_fp:false` based on a different search context. This
is genuine (Lane D1 D1-FP-CONSISTENCY scope), distinct from the
auth probe issue.

## What the probe pattern is still good for

Browser-driven probes remain valuable for:
- UI rendering verification (XSS regression, console errors,
  layout correctness)
- Click-through behavior
- Real-session end-to-end flow
- Sensitive-data masking visual confirmation

They are NOT a substitute for server-side auth verification.
```

### 1.4 Update Lane D1 scope in docs/SPRINT_ONE_WEEK.md

Add the three detection-quality items from the probe (these stand,
unaffected by the C1-FOLLOWUP retraction):

```markdown
### Lane D1 — additions from Day 1 antfooding probe

D1-FP-SUPPRESSOR (alert quality)
  Test fixture key suppressor. If a matched key token appears within
  50 chars of a masking demonstration pattern (->, ****, [REDACTED]),
  set likely_false_positive: true regardless of confidence. Catches
  the AKIAJ5TESTXXXXXXXXXX false positive observed in probe.

D1-DEDUP-TURN (alert quality)
  Turn-window deduplication. When multiple sensitive_data events fire
  within a 5-second window in the same session with the same pattern
  and similar hashes, consolidate into a single alert with
  keys_found: N. Currently 4 separate criticals fire for 1 logical
  CI log read.

D1-TYPOSQUAT-UI (UI consistency)
  Supply Chain registry intelligence panel: when a package is flagged
  as typosquat, suppress "Scanned — no known vulnerabilities" and
  display "N/A — typosquat flagged" instead. CVE absence is irrelevant
  for typosquat placeholders.

D1-FP-CONSISTENCY (alert quality)
  Confidence re-classification consistency. Same hash should not be
  reclassified from low/likely_fp:true to critical/likely_fp:false
  based on a different search context. Require positive contextual
  evidence (outbound send, assignment statement, credentials file
  pattern) for upward reclassification. Observed at probe Alert #2
  (hash 5acb12837d61733d).
```

### 1.5 Update Lane B scope in docs/SPRINT_ONE_WEEK.md

Add the three deeper detection improvements for post-launch:

```markdown
### Lane B — additions from Day 1 antfooding probe (post-launch scope)

LB-RESEARCH-PRIOR (alert quality)
  Research-session false-positive prior. When session title contains
  research indicators ("research", "how does", "best-in-class",
  "explore the") AND turn_number ≤ 5 AND context is tool_result,
  apply confidence: low override and mark likely_false_positive: true.
  Currently env_file detector does this via repeat heuristic; extend
  to multi-pattern clusters in research sessions.

LB-CREDENTIAL-DUMP (new alert category)
  When ≥4 credential pattern types fire simultaneously in a single
  tool_result, emit a higher-level credential_dump alert type with
  consolidated metadata. Currently this fires as N individual alerts;
  a single "CREDENTIAL DUMP — N patterns" alert is more actionable.
  Observed at probe Alert #4 (ACMS session, 6 patterns at once).

LB-CONFIDENCE-CONSISTENCY (alert state machine)
  See D1-FP-CONSISTENCY for description. If the Lane D1 fix proves
  insufficient (e.g., requires broader state-machine rework), this
  is the post-launch follow-through.
```

### 1.6 Add alert quality measurement section to docs/AUDIT_2026-05-21.md

Append at the end of the audit doc:

```markdown
## Alert quality measurement — Day 1 baseline (2026-05-22)

Sample size: 401 alerts across 9 sessions. Structured probe via
Claude in Chrome with terminal verification of sampled findings.

| Detector            | TP rate     | Sample notes                       |
|---------------------|-------------|------------------------------------|
| anthropic_key       | 100%        | 3/3 verified real .env reads       |
| aws_key             | ~88%        | 14/16 real CI log credentials      |
|                     |             | 1-2 test fixture FPs (AKIAJ5TEST*) |
| supply_chain_risk   | ~95%        | 4/4 sampled malicious packages     |
| typosquat           | 100%        | 1/1 verified (requets→requests)    |
| env_file            | ~30-40%     | Majority correctly marked likely_fp|
| github_token        | not fully traced; pattern consistent (~80-90% TP est)  |
| password_in_code    | unverified, n=2                                          |

Methodology: each detector category sampled with causal-chain trace
from event to tool call to source file. Probe report at
`docs/CLAUDE_CHROME_PROBE_2026-05-22.md`. Will be updated as antfooding
generates additional measurement data.

This table becomes the ongoing product-quality scorecard.
```

### 1.7 Commit and push

```bash
git checkout docs/antfooding-day-1-phase-3a
git pull --ff-only

# All edits above

git add docs/
GIT_AUTHOR_NAME="Rajan Yadav" GIT_AUTHOR_EMAIL="rajan.conch@gmail.com" \
GIT_COMMITTER_NAME="Rajan Yadav" GIT_COMMITTER_EMAIL="rajan.conch@gmail.com" \
git commit -m "docs(antfood): retract C1-FOLLOWUP, route detection findings to D1/LB scope

C1-FOLLOWUP retracted after terminal verification disproved the
Claude-in-Chrome probe's Test 1 finding. Server-side auth on /api/*
is already enforced correctly. Root cause of the false positive: the
dashboard monkey-patches window.fetch to inject the auth token, so
the probe inherited credentials silently and read 200 responses as
'no auth required'.

Probe report annotated with Errata. New docs/PROBE_DESIGN.md
documents the lesson for future antfooding sessions.

Detection-quality findings from the probe stand and are routed to:
- Lane D1: D1-FP-SUPPRESSOR, D1-DEDUP-TURN, D1-TYPOSQUAT-UI,
  D1-FP-CONSISTENCY
- Lane B post-launch: LB-RESEARCH-PRIOR, LB-CREDENTIAL-DUMP,
  LB-CONFIDENCE-CONSISTENCY

Added 'Alert quality measurement' baseline table to AUDIT_2026-05-21.md
with TP/FP rates per detector from the Day 1 probe sample of 401 alerts."

HTTPS_PROXY= git push origin docs/antfooding-day-1-phase-3a
```

Delete the unused branch:

```bash
git branch -D security/c1-api-auth-followup 2>/dev/null
```

**STOP after step 1.7.** Report PR #17's updated state. Wait for me
to approve the antfood-log PR.

## Step 2: Open the credential-incident PR (parallel, no dependency)

After my approval of PR #17, immediately open a parallel doc PR for
the real credential discoveries from the probe.

Branch: `docs/incident-credential-discovery-2026-05-22`. Target: main.

### 2.1 Create docs/incidents/2026-05-22-credential-discovery.md

```markdown
# Incident — Credential discovery via antfooding probe (2026-05-22)

## Summary

The Day 1 antfooding probe (Claude in Chrome) traced sensitive-data
alerts back to real credential exposures in historical Claude Code
sessions. Three categories of real exposure were found:

1. AWS access keys in talosAI GitHub Actions CI logs
2. Multi-pattern credential dump in an ACMS session
3. Anthropic API key read from a project's .env file by an agent

This is not a Vigil bug. These are real exposures Vigil detected.

## Discovered exposures

### AWS access keys (talosAI session ed3e62f3)

Three real-format AWS Access Key IDs appeared in tool_result content
from `gh run view --log-failed` calls in a Claude Code session
operating against the talosAI repository:

- AKIAUSELFJEN3L7U3HF3
- AKIAUSELFJEN7VLI55FK
- AKIAUSELFJENWMJ2JAVB

Causal chain: agent ran `gh run view <id> --log-failed 2>&1 | head -80`
to inspect failed CI runs. The run logs contained these keys, likely
from a CI step that printed environment variables or AWS STS output.

First observed: Mar 12 (probe traced back through Mar 15, 19, 20, 23).

### ACMS credential dump (session 997cb633, Turn 56)

Six credential pattern types fired simultaneously in a single
tool_result on Mar 7 18:39:
- anthropic_key
- github_token
- password_in_code
- api_key_generic
- db_connection
- base64_secret

Session prompt context: "login infor for default@acms.local?" in
working directory `/Users/rajanyadav/Documents/ACMS`. The
simultaneous fire of 6 distinct credential categories indicates a
single read of a credentials dump (likely a `.env` file or
credentials config).

### Anthropic API key (nyaymitra-ai, Turn 34)

Agent issued `grep "ANTHROPIC_API_KEY" /Users/rajanyadav/Projects/nyaymitra-ai/.env`
during e2e test setup. Key value entered the agent's context window.
This was on May 11 18:41 and the key in question may already be the
current production key for nyaymitra-ai.

## Response actions (handled out-of-band by Rajan)

This document records that response is taking place. Rotation
execution does NOT happen through Claude Code — it happens in:
- AWS IAM console (for the three AWS keys)
- Anthropic dashboard (for the nyaymitra key if still valid)
- Any other credential providers from the ACMS dump

Tracking checklist:

- [ ] Verify AKIAUSELFJEN3L7U3HF3 status; if active, disable and rotate
- [ ] Verify AKIAUSELFJEN7VLI55FK status; if active, disable and rotate
- [ ] Verify AKIAUSELFJENWMJ2JAVB status; if active, disable and rotate
- [ ] Identify the talosAI CI workflow that leaked keys; harden secret
      handling so future runs don't print env vars
- [ ] Identify the source file read in ACMS Turn 56; enumerate which
      credentials were in it; rotate any still-active
- [ ] Verify nyaymitra-ai ANTHROPIC_API_KEY status; if still in use,
      consider rotation as a precaution (it entered an agent context;
      the agent is local but the principle holds)
- [ ] Update affected GitHub Actions secrets, deployment configs,
      and any local .env files

Each checkbox is closed by Rajan editing this file directly when the
action is complete. Failures or partials are noted inline.

## Significance for Vigil

This incident is also the strongest validation signal Vigil has
produced. The product caught real credential exposures in its own
operator's history that would otherwise have remained invisible. The
pattern (agent reads credentials, credentials enter context window,
context window is later visible in tool outputs) is exactly the
threat model the product is designed to detect.

Investor-ready summary: "On Day 1 of antfooding our own product, we
discovered three categories of real credential exposures in our
own historical sessions. The product caught what would otherwise
have been invisible."
```

### 2.2 Commit and push

```bash
git checkout main
git pull
git checkout -b docs/incident-credential-discovery-2026-05-22

# Create the file above

git add docs/incidents/2026-05-22-credential-discovery.md
GIT_AUTHOR_NAME="Rajan Yadav" GIT_AUTHOR_EMAIL="rajan.conch@gmail.com" \
GIT_COMMITTER_NAME="Rajan Yadav" GIT_COMMITTER_EMAIL="rajan.conch@gmail.com" \
git commit -m "docs(incident): credential discoveries from Day 1 antfooding probe

Day 1 antfooding probe traced alerts back to real credential exposures
in historical Claude Code sessions: 3 AWS keys in talosAI CI logs,
1 multi-pattern credential dump in ACMS session, 1 Anthropic key
read by nyaymitra-ai e2e test agent.

Rotation handled out-of-band by Rajan (AWS IAM, Anthropic dashboard,
GitHub Actions secrets). Tracking checklist embedded in incident doc."

HTTPS_PROXY= git push origin docs/incident-credential-discovery-2026-05-22

gh pr create --base main --head docs/incident-credential-discovery-2026-05-22 \
  --title "docs(incident): Day 1 antfooding credential discoveries" \
  --body "..."
```

PR body should include a one-paragraph summary plus the response
checklist (so reviewers can see what's tracked).

**STOP after step 2.2.** Report both PRs are open. Wait for me to
approve both before continuing.

## Step 3: After PR #17 and incident PR both merge

Open the integration → main PR per the original plan.

- Base: main (now has the antfood evidence and incident doc)
- Head: integration/phase-3a
- Merge strategy: **rebase-merge** to preserve the 4 individual
  C-fix commits
- PR body: quote my antfooding log entry from
  docs/ANTFOODING_LOG.md, link to docs/CLAUDE_CHROME_PROBE_2026-05-22.md,
  link to docs/incidents/2026-05-22-credential-discovery.md, link to
  docs/AUDIT_2026-05-21.md C1-FOLLOWUP retraction section.

Wait for my approval before merging.

After merge, delete integration/phase-3a branch.

Phase 3A closes.

## Step 4: Phase 3B kickoff

After Phase 3A closes and you confirm main is healthy:

- Stop and report
- Wait for my "proceed" before starting Phase 3B (Quality Gates Q1)

Do NOT auto-start Phase 3B.

## Discipline reminders

- Every change goes through branch + PR (including these doc PRs)
- No direct main pushes for any reason
- Conventional commits
- No Co-Authored-By: Claude trailers
- HTTPS_PROXY= prefix on push
- Stop and report at each numbered checkpoint
- The probe inheriting credentials via monkey-patched fetch is itself
  the lesson. Future probes must verify auth state with curl or
  equivalent, not from inside the dashboard tab.
