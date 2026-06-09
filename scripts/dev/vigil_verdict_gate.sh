#!/usr/bin/env bash
# vigil_verdict_gate.sh — pre-push merge gate for the vigil-notes judge/executor loop.
#
# Two protections (both bypass only with VIGIL_LOOP_OVERRIDE=1, for intentional WIP):
#   A. NO DIRECT PUSH TO main/master. Code reaches main via a GitHub PR merge
#      (gh pr merge runs server-side and does NOT trigger this local hook), never via a
#      local `git push origin main`. This closes the hole that let P2.3 bypass the loop.
#   B. A sprint feature ref (refs/heads/feat/v022-pX.Y*) may only be pushed once an
#      APPROVE or APPROVE-WITH-FIX verdict for that taskid exists in the local
#      vigil-notes loop. The gate inspects every ref BEING PUSHED (from stdin), not the
#      currently-checked-out branch — closes the bypass where a sprint ref is pushed
#      from a checkout of a different branch.
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

extract_taskid() {
  # extract_taskid <ref-or-branch>: prints uppercased taskid like P3.1 or P2.2-GATE,
  # or empty if no sprint pattern matches.
  local input="$1" token
  token="$(printf '%s' "$input" | grep -oiE 'p[0-9]+\.[0-9]+(-gate)?' | head -1 || true)"
  [ -z "$token" ] && return 0
  printf '%s' "$token" | tr '[:lower:]' '[:upper:]'
}

# ---- Collect every pushed remote ref from stdin (single pass) ----------------------
PUSHED_REFS=()
protected_push=""
if [ ! -t 0 ]; then
  while read -r _localref _localsha remoteref _remotesha; do
    PUSHED_REFS+=("$remoteref")
    case "$remoteref" in
      refs/heads/main|refs/heads/master) protected_push="$remoteref" ;;
    esac
  done
fi

# ---- Protection A: refuse direct pushes to main/master -----------------------------
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

# ---- Protection B: every sprint ref being pushed requires its own verdict ---------
# Collect taskids from pushed refs (primary). Fall back to the current branch
# only if no refs were on stdin (interactive smoke-test of the hook).
declare -a NEEDED_TASKIDS=()
if [ "${#PUSHED_REFS[@]}" -gt 0 ]; then
  for ref in "${PUSHED_REFS[@]}"; do
    refname="${ref#refs/heads/}"
    tid="$(extract_taskid "$refname")"
    [ -n "$tid" ] && NEEDED_TASKIDS+=("$tid")
  done
else
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
  tid="$(extract_taskid "$branch")"
  [ -n "$tid" ] && NEEDED_TASKIDS+=("$tid")
fi

# Deduplicate (Bash 3.2 compatible — no mapfile)
if [ "${#NEEDED_TASKIDS[@]}" -gt 0 ]; then
  _deduped=()
  while IFS= read -r _line; do
    [ -n "$_line" ] && _deduped+=("$_line")
  done < <(printf '%s\n' "${NEEDED_TASKIDS[@]}" | sort -u)
  NEEDED_TASKIDS=("${_deduped[@]}")
fi

if [ "${#NEEDED_TASKIDS[@]}" -eq 0 ]; then
  exit 0   # no sprint refs in this push — nothing to gate
fi

if allow_override; then
  echo "vigil-gate: VIGIL_LOOP_OVERRIDE set — bypassing verdict gate for ${NEEDED_TASKIDS[*]} (WIP)." >&2
  exit 0
fi

shopt -s nocaseglob nullglob 2>/dev/null || true

# For each pushed sprint taskid, require a matching APPROVE / APPROVE-WITH-FIX
# verdict. Match the verdict token against LINE 1 ONLY (the contract guarantees the
# first line is exactly "VERDICT: <TOKEN>") so a body line cannot spoof the verdict.
missing=()
for taskid in "${NEEDED_TASKIDS[@]}"; do
  found=""
  for vf in "$LOOP_ROOT"/archive/"$taskid".a*/*"$taskid"*verdict.md \
            "$LOOP_ROOT"/inbox-executor/"$taskid".a*verdict.md; do
    [ -f "$vf" ] || continue
    if head -n1 "$vf" | grep -qE '^VERDICT:[[:space:]]*(APPROVE|APPROVE-WITH-FIX)\b'; then
      found="$vf"; break
    fi
  done
  if [ -n "$found" ]; then
    echo "vigil-gate: OK — verdict for $taskid -> $found" >&2
  else
    missing+=("$taskid")
  fi
done

if [ "${#missing[@]}" -eq 0 ]; then
  exit 0
fi

{
  printf '\n  ✗ vigil-gate BLOCKED this push.\n\n'
  printf '  No APPROVE / APPROVE-WITH-FIX verdict found for sprint taskid(s):\n'
  for t in "${missing[@]}"; do printf '    - %s\n' "$t"; done
  printf '\n  Searched under:\n    %s/{archive,inbox-executor}/\n\n' "$LOOP_ROOT"
  printf '  Run the loop first:\n'
  printf '    S=%s/scripts/executor-loop.sh\n' "$LOOP_ROOT"
  printf '    "$S" submit <taskid> <attempt> <result.md>\n'
  printf '    "$S" wait   <taskid> <attempt>     # must return APPROVE or APPROVE-WITH-FIX\n\n'
  printf '  WIP push you will NOT turn into a PR:  VIGIL_LOOP_OVERRIDE=1 git push ...\n\n'
} >&2
exit 1
