# Credential Liveness Detection (v0.4+ roadmap)

## Concept

When Vigil flags a credential pattern (`anthropic_key`, `aws_key`,
`github_token`, etc.), optionally probe the upstream provider to
determine whether the credential is currently live, revoked, or inert.
Use the result to refine severity and reduce false positives.

## Differentiation

Every secret scanner detects patterns. Almost none verify liveness. A
live production key in a CI log is critical. A revoked test key is
INFO. A fake fixture key is suppressed. Triage signal that no incumbent
currently provides.

## Probe inventory (initial scope)

| Provider   | Probe                                        | Cost |
|------------|----------------------------------------------|------|
| AWS        | `sts:GetCallerIdentity` (read-only, free)    | $0   |
| Anthropic  | `GET /v1/messages` with 0-token request      | $0   |
| OpenAI     | `GET /v1/models`                             | $0   |
| GitHub PAT | `GET /user`                                  | $0   |
| Stripe     | `GET /v1/balance` (read-only)                | $0   |
| Slack      | `auth.test`                                  | $0   |

## Design constraints

- **Off by default.** User opts in per provider.
- Probe activity itself is logged in Vigil as auditable events.
- Results cached (default 6h TTL). Re-probe only on demand or on alert
  re-trigger.
- Network failures classified as `INDETERMINATE`, not `REVOKED`.
- Dry-run mode shows what would be probed without making calls.
- Probing reveals to the provider that the key exists in someone's
  logs. This is itself a privacy consideration the user must accept
  when opting in.

## Output classification

Each verified credential gets a new field on the alert:

```
liveness: LIVE | REVOKED | INERT | INDETERMINATE | NOT_PROBED
```

Severity is reweighted:
- `LIVE` + production-pattern → severity unchanged (critical/high)
- `LIVE` + test-pattern → keep severity but flag for re-evaluation
- `REVOKED` → downgrade to LOW with "revoked" badge
- `INERT` (well-formed but never valid) → INFO with "inert" badge
- `INDETERMINATE` → severity unchanged, add "probe failed" note
- `NOT_PROBED` → severity unchanged (default state)

## Why this is post-launch

v0.2 ships with static detection at 88-100% TP rates on tested
categories (per Day 1 antfooding measurement in
`docs/AUDIT_2026-05-21.md`). Liveness adds a second layer that requires
per-provider integration, careful privacy handling, and substantial UI
work. Right scope for v0.4 when the user base justifies the
per-provider integration investment.

## Why this is competitive moat material

The TP/FP table in `docs/AUDIT_2026-05-21.md` already shows Vigil
detecting things other tools miss (`AKIAJ5TEST*` style fixture keys,
`env_file` context). Liveness detection extends this from "detect more
accurately" to "tell me what to do about each finding." That's the
difference between a scanner and a triage tool. Triage tools command
higher price points and attach better to enterprise security
workflows.

## Implementation phases

- **v0.4**: AWS + Anthropic + GitHub PAT (the three most common in AI
  developer workflows). Opt-in CLI flag. Cached. CLI-only.
- **v0.5**: Add OpenAI, Stripe, Slack. Dashboard UI for opt-in and
  probe history.
- **v0.6**: Per-provider configurable cache TTL, scheduled re-probes,
  drift detection (key was `LIVE` last week, `REVOKED` today — useful
  security signal).
- **v1.0**: Liveness becomes default-on with explicit per-organization
  opt-in flow.

## Open questions for design phase

1. Should probes happen at alert-creation time (slow alerts, fewer
   probes) or background-deferred (fast alerts, more probes per real
   credential)?
2. How to handle credentials that match patterns but are
   provider-ambiguous (a 40-char hex string could be many things)?
3. Liability if a probe accidentally triggers a provider's anomaly
   detection on the credential's true owner.
4. Should we offer a "probe local first" mode that checks against the
   user's own `~/.aws/credentials`, `~/.anthropic_key`, etc. before
   hitting the provider? Cheaper, no network, no privacy issue, but
   only catches credentials the user themselves owns.

## Roadmap link

This is referenced from the v0.4 milestone in `docs/ROADMAP.md` when
that file exists (currently captured here standalone).
