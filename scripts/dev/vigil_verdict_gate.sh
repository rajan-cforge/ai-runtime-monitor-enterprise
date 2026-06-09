#!/usr/bin/env bash
# vigil_verdict_gate.sh — pre-push merge gate for the vigil-notes judge/executor loop.
#
# Two protections (both bypass only with VIGIL_LOOP_OVERRIDE=1, for intentional WIP):
#   A. NO DIRECT PUSH TO main/master. Code reaches main via a GitHub PR merge
#      (gh pr merge runs server-side and does NOT trigger this local hook), never via a
#      local `git push origin main`. This closes the hole that let P2.3 bypass the loop.
#   B. A sprint feature branch (feat/v022-pX.Y*) may only be pushed once an APPROVE or
#      APPROVE-WITH-FIX verdict for that taskid exists in the local vigil-notes loop.
#
# Verdicts live OUTSIDE the repo (~/Documents/vigil-notes/), so this MUST be a local
# hook — GitHub CI can never see the verdict files.
#
# Install: make install-vigil-hook
# Bypass:  VIGIL_LOOP_OVERRIDE=1 git push ...   (WIP only; you will not PR it)
#
# pre-push receives on stdin:  <local ref> <local sha> <remote ref> <remote sha>
# Exit 0 = allow, exit 1 = block.

set -euo pipefail

LOOP_ROOT="${VIGIL_LOOP_ROOT:-$HOME/Documents/vigil-notes/v022}"

allow_override() { [ -n "${VIGIL_LOOP_OVERRIDE:-}" ]; }

# ---- Protection A: refuse direct pushes to main/master -----------------------------
# Inspect the remote refs being updated (from stdin). If main/master is among them and
# this is not a delete, block.
protected_push=""
if [ ! -t 0 ]; then
  while read -r _localref _localsha remoteref _remotesha; do
    case "$remoteref" in
      refs/heads/main|refs/heads/master) protected_push="$remoteref" ;;
    esac
  done
fi

if [ -n "$protected_push" ]; then
  if allow_override; then
    echo "vigil-gate: VIGIL_LOOP_OVERRIDE set — allowing direct push to $protected_push." >&2
    exit 0
  fi
  cat >&2 <<EOF

  ✗ vigil-gate BLOCKED a direct push to ${protected_push#refs/heads/}.

  In the vigil-notes loop, code reaches main only through a reviewed PR merge
  (gh pr merge --squash), never a local push to main. Push your feature branch and
  merge the PR after the judge returns APPROVE / APPROVE-WITH-FIX.

  Intentional exception (you will NOT open a PR for this): VIGIL_LOOP_OVERRIDE=1 git push ...

EOF
  exit 1
fi

# ---- Protection B: feature branch requires a verdict -------------------------------
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
token="$(printf '%s' "$branch" | grep -oiE 'p[0-9]+\.[0-9]+(-gate)?' | head -1 || true)"
if [ -z "$token" ]; then
  exit 0   # not a sprint feature branch — nothing to gate
fi
taskid="$(printf '%s' "$token" | tr '[:lower:]' '[:upper:]')"   # -> P2.3 / P2.2-GATE

if allow_override; then
  echo "vigil-gate: VIGIL_LOOP_OVERRIDE set — bypassing verdict gate for $taskid (WIP)." >&2
  exit 0
fi

shopt -s nocaseglob nullglob 2>/dev/null || true
found=""
for vf in "$LOOP_ROOT"/archive/"$taskid".a*/*"$taskid"*verdict.md \
          "$LOOP_ROOT"/inbox-executor/"$taskid".a*verdict.md; do
  [ -f "$vf" ] || continue
  if grep -qiE '^VERDICT:[[:space:]]*(APPROVE|APPROVE-WITH-FIX)\b' "$vf"; then
    found="$vf"; break
  fi
done

if [ -n "$found" ]; then
  echo "vigil-gate: OK — verdict for $taskid -> $found" >&2
  exit 0
fi

cat >&2 <<EOF

  ✗ vigil-gate BLOCKED this push.

  Branch '$branch' is a v0.2.2 sprint PR (taskid $taskid) but no
  APPROVE / APPROVE-WITH-FIX verdict was found in:
    $LOOP_ROOT/{archive,inbox-executor}/

  Run the loop first:
    S=$LOOP_ROOT/scripts/executor-loop.sh
    "\$S" submit $taskid <attempt> <result.md>
    "\$S" wait   $taskid <attempt>     # must return APPROVE or APPROVE-WITH-FIX

  WIP push you will NOT turn into a PR:  VIGIL_LOOP_OVERRIDE=1 git push ...

EOF
exit 1
