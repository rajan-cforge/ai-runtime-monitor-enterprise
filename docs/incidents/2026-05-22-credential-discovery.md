# Incident — Credential discovery via antfooding probe (2026-05-22)

## Summary

The Day 1 antfooding probe (Claude in Chrome) traced sensitive-data
alerts back to real credential exposures in historical Claude Code
sessions. Three categories of real exposure were found:

1. AWS access keys in talosAI GitHub Actions CI logs
2. Multi-pattern credential dump in an ACMS session
3. Anthropic API key read from a project's `.env` file by an agent

This is not a Vigil bug. These are real exposures Vigil detected.

## Discovered exposures

### AWS access keys (talosAI session `ed3e62f3`)

Three real-format AWS Access Key IDs appeared in `tool_result` content
from `gh run view --log-failed` calls in a Claude Code session
operating against the talosAI repository:

- `AKIAUSELFJEN3L7U3HF3`
- `AKIAUSELFJEN7VLI55FK`
- `AKIAUSELFJENWMJ2JAVB`

Causal chain: agent ran `gh run view <id> --log-failed 2>&1 | head -80`
to inspect failed CI runs. The run logs contained these keys, likely
from a CI step that printed environment variables or AWS STS output.

First observed: Mar 12 (probe traced back through Mar 15, 19, 20, 23).

### ACMS credential dump (session `997cb633`, Turn 56)

Six credential pattern types fired simultaneously in a single
`tool_result` on Mar 7 18:39:
- `anthropic_key`
- `github_token`
- `password_in_code`
- `api_key_generic`
- `db_connection`
- `base64_secret`

Session prompt context: "login infor for default@acms.local?" in
working directory `/Users/rajanyadav/Documents/ACMS`. The simultaneous
fire of 6 distinct credential categories indicates a single read of a
credentials dump (likely a `.env` file or credentials config).

### Anthropic API key (nyaymitra-ai, Turn 34)

Agent issued `grep "ANTHROPIC_API_KEY" /Users/rajanyadav/Projects/nyaymitra-ai/.env`
during e2e test setup. Key value entered the agent's context window.
This was on May 11 18:41 and the key in question may already be the
current production key for nyaymitra-ai.

## Response actions (handled out-of-band by Rajan)

This document records that response is taking place. Rotation execution
does NOT happen through Claude Code — it happens in:
- AWS IAM console (for the three AWS keys)
- Anthropic dashboard (for the nyaymitra key if still valid)
- Any other credential providers from the ACMS dump

## Disposition (2026-05-23)

Investigation found no evidence of abuse on any discovered credential.
Disposition decision: **NOT ROTATING**. The discovered patterns become
reference data for detection-logic improvement work
(`D1-FP-SUPPRESSOR`, `D1-FP-CONSISTENCY`, `LB-CREDENTIAL-DUMP`). Some
matched values are test fixtures (`AKIA*TEST*` pattern) confirming
false-positive classes that the detection pipeline should suppress.
Some are revoked credentials in archived CI logs; their pattern shape
is useful even though the values are inert.

This decision is reversible. If active abuse is later detected on any
of these credentials via CloudTrail, GitHub audit log, or Anthropic
usage anomaly, rotate immediately and reopen this incident.

The rotation checklist is removed since no rotation is planned.

## Disposition update — 2026-05-24

All three `AKIAUSELFJEN*` access key IDs have been deleted from AWS by
the operator (Rajan Yadav) prior to flipping the repository from
private to public.

This supersedes the original "NOT ROTATING" disposition logged on
2026-05-23. The original disposition was made under the assumption
that the repository would remain private and that no abuse evidence
existed. The decision to go public required reconsidering the
residual risk: even if the keys were demonstrably inert, public
exposure of real-format key IDs creates noise for AWS abuse-detection
systems and provides zero defensible benefit to the project.

Deletion was performed via AWS IAM console on 2026-05-24 across the
affected AWS account(s). The talosAI repository's CI pipeline may
temporarily fail on workflows that referenced these keys; this
breakage is acceptable and will be repaired in a follow-up by
rotating to fresh keys in talosAI's GitHub Actions secrets.

The keys remain in this incident document and in `tests/test_*.py`
fixtures as historical reference. They cannot authenticate against
any AWS resource as of this disposition update.

## Significance for Vigil

This incident is also the strongest validation signal Vigil has
produced. The product caught real credential exposures in its own
operator's history that would otherwise have remained invisible. The
pattern (agent reads credentials → credentials enter context window →
context window is later visible in tool outputs) is exactly the threat
model the product is designed to detect.

Investor-ready summary: "On Day 1 of antfooding our own product, we
discovered three categories of real credential exposures in our own
historical sessions. The product caught what would otherwise have been
invisible."
