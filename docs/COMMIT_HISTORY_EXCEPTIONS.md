# Commit history exceptions

Per `docs/BRANCHING.md`: new commits **must not** carry a
`Co-Authored-By: Claude` trailer. Per Q7 of the Phase 2 dispatch
(`docs/CC_DISPATCH_phase_3_kickoff.md`), the signed-commits enforcement
gate is deferred to Quality Gates Q3 (post-launch). When that gate
lands, the following pre-policy commits are grandfathered exceptions:

| SHA       | Date       | Subject                                           |
|-----------|------------|---------------------------------------------------|
| `8f07f9e` | (pre-policy) | (carries the trailer; identified by Wave-2 audit) |
| `770eef2` | (pre-policy) | (carries the trailer; identified by Wave-2 audit) |
| `7a8d712` | (pre-policy) | (carries the trailer; identified by Wave-2 audit) |

When signed-commits enforcement turns on:
- The branch-protection rule includes an allowlist for these three SHAs
  (or, equivalently, the policy applies only to commits after a marker
  SHA that lives in the protection config).
- No new exceptions are granted. Any future trailer is a hard CI fail.

Rationale for not rewriting history: rewriting + force-pushing three
mid-history commits would invalidate everyone's local clones, change
the SHAs of every subsequent commit, and break audit/issue references
that already cite SHA-stable identifiers (including
`docs/AUDIT_2026-05-21.md`).
