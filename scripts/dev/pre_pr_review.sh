#!/usr/bin/env bash
# Pre-PR review: capture the local diff for the three reviewer agents
# (grader / architect / performance) to consume in local mode.
#
# Workflow:
#   1. The orchestrator (Claude Code) runs this script on a feature
#      branch that has commits ahead of origin/main.
#   2. The script creates a timestamped workspace under
#      ~/.vigil-pre-pr-review/<YYYYmmddTHHMMSS>/ with:
#        - diff.patch       full unified diff vs origin/main
#        - files.txt        list of paths touched by the diff
#        - meta.txt         branch name, base sha, head sha
#   3. The orchestrator then dispatches the three reviewer agents in
#      local mode, pointing each at the workspace.
#
# This script does NOT dispatch the agents itself — that happens in
# the orchestrator's conversational loop. See
# .claude/workflows/pre-pr-review.md for the full discipline.
#
# Exit codes:
#   0  workspace created, ready for reviewer dispatch
#   1  not a git repo, or no commits ahead of origin/main, or no diff
#   2  internal error (mkdir / git failed)

set -euo pipefail

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "ERROR: not inside a git repository" >&2
    exit 1
fi

base_ref="${BASE_REF:-origin/main}"

# Refresh the base ref quietly. Parse the remote and branch from
# `$base_ref` so an override like BASE_REF=origin/release/x actually
# fetches the right ref (the prior `git fetch origin main` was
# hard-coded and silently wrong when BASE_REF pointed elsewhere).
# We deliberately don't fail if the fetch can't reach the remote —
# the orchestrator may be working offline against a previously-
# fetched ref. The verify check below catches the truly-missing case.
case "$base_ref" in
    */*)
        remote="${base_ref%%/*}"
        remote_branch="${base_ref#*/}"
        git fetch "$remote" "$remote_branch" --quiet 2>/dev/null || true
        ;;
esac

if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
    echo "ERROR: base ref '$base_ref' not found locally; try 'git fetch ${remote:-origin} ${remote_branch:-main}'" >&2
    exit 1
fi

head_sha=$(git rev-parse HEAD)
base_sha=$(git merge-base "$base_ref" HEAD)
branch=$(git rev-parse --abbrev-ref HEAD)

# Capture both: committed range (HEAD vs base) AND working-tree state
# (staged + unstaged vs HEAD). The orchestrator may run the loop
# mid-implementation before any commit exists, so an empty committed
# range with non-empty working tree is a legitimate review target.
#
# Use cheap existence checks (`git diff --quiet ... && echo empty`)
# instead of capturing into shell variables — captured patches lose
# trailing newlines and `echo` mangles lines beginning with `-n` /
# `-e` / `--`. Writing `git diff` straight into the patch file is
# both faster and byte-faithful.
has_committed=1
has_working=1
if [ "$head_sha" = "$base_sha" ] || git diff --quiet "$base_sha"...HEAD; then
    has_committed=0
fi
if git diff --quiet HEAD; then
    has_working=0
fi

if [ "$has_committed" -eq 0 ] && [ "$has_working" -eq 0 ]; then
    echo "ERROR: no diff vs $base_ref — nothing committed and working tree clean" >&2
    exit 1
fi

timestamp=$(date -u +"%Y%m%dT%H%M%SZ")
workspace="${HOME}/.vigil-pre-pr-review/${timestamp}"

if ! mkdir -p "$workspace"; then
    echo "ERROR: failed to create workspace $workspace" >&2
    exit 2
fi

# Write the patch byte-faithfully (no echo round-trip).
patch_file="$workspace/diff.patch"
: > "$patch_file"
if [ "$has_committed" -eq 1 ]; then
    git diff "$base_sha"...HEAD >> "$patch_file"
fi
if [ "$has_working" -eq 1 ]; then
    if [ "$has_committed" -eq 1 ]; then
        printf '\n# --- working tree (uncommitted) ---\n' >> "$patch_file"
    fi
    git diff HEAD >> "$patch_file"
fi

# Union of paths touched in either committed range or working tree.
{
    git diff --name-only "$base_sha"...HEAD
    git diff --name-only HEAD
} | sort -u > "$workspace/files.txt"

cat > "$workspace/meta.txt" <<EOF
branch:    $branch
base_ref:  $base_ref
base_sha:  $base_sha
head_sha:  $head_sha
generated: $timestamp
EOF

echo "Ready for reviewer dispatch"
echo "Workspace: $workspace"
echo "Files touched: $(wc -l < "$workspace/files.txt" | tr -d ' ')"
