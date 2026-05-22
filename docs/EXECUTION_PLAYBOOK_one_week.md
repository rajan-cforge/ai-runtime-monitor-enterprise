# Execution Playbook: One-Week Multi-Agent Sprint

This is the day-by-day dispatch plan. Read it once, then execute. Your
role is orchestrator and reviewer. Claude Code subagents do the writing.

## Pre-flight (Day 0, before any code)

Block 4 hours today. Do not skip these.

```
[ ] 1. Verify Apple Developer Program enrollment for GoCloudForge Inc
       https://developer.apple.com/account → status = Active

[ ] 2. Generate Developer ID Application certificate in Apple portal
       Download .cer, install in Keychain, export as .p12 with password
       Store .p12 password in 1Password

[ ] 3. Generate Tauri signer keypair
       tauri signer generate -w ~/.tauri/airuntimemonitor.key
       Store private key in 1Password
       Commit public key to repo

[ ] 4. Register domain
       airuntimemonitor.com via Cloudflare or Namecheap
       Point A record to Vercel
       Verify DNS within 2 hours

[ ] 5. Apple notarytool credentials
       xcrun notarytool store-credentials AIRUNTIMEMON-NOTARY \
         --apple-id "$APPLE_ID" \
         --team-id "$TEAM_ID" \
         --password "$APP_SPECIFIC_PASSWORD"

[ ] 6. Stripe Payment Link for Pro tier ($29/mo)
       Create at dashboard.stripe.com
       Save URL to env STRIPE_PRO_LINK

[ ] 7. Run Track 0 prompt (multi-agent harness)
       Paste CC_PROMPT_00_multi_agent_harness.md into Claude Code
       Verify all 8 checklist items at the end pass
       Commit and push

[ ] 8. Open 4 terminal tabs with worktrees ready:
       git worktree add .worktrees/lane-A -b feature/lane-A-tauri
       git worktree add .worktrees/lane-B -b feature/lane-B-scanner
       git worktree add .worktrees/lane-D -b feature/lane-D-ui
       cd ../ && git clone ... airuntimemonitor-site  # Lane C is separate repo
```

If any of items 1-5 are blocked, the launch slips by however long that
takes. Surface those now, not on Day 4.

## Day 1: Launch Lanes B and C

Both lanes have zero overlap. Start them in parallel terminals.

### Terminal 1: Lane B (Extension Scanner)

```bash
cd .worktrees/lane-B
claude
```

Inside Claude Code:

```
You are the lead orchestrator. Read AGENTS.md, then read the prompt at
~/prompts/CC_PROMPT_01_extension_scanner.md.

Dispatch the extension-scanner-specialist to implement Lane B end-to-end
in this worktree. After each major unit (inventory, scorer, threat intel,
service, API), invoke the code-reviewer subagent against
.claude/rubrics/lane-B-scanner.md before committing.

For risk-rule R007 (AI-correlated installs) and any code that touches
subprocess execution, also invoke the security-reviewer subagent.

Update docs/SPRINT_ONE_WEEK.md after every task transition.

Begin.
```

Expected duration: 6 to 10 hours of agent wall-clock. You check in every
90 minutes to review what landed.

### Terminal 2: Lane C (Brand Site)

```bash
cd ~/code/airuntimemonitor-site
claude
```

```
You are the lead orchestrator for the brand site. Read the prompt at
~/prompts/CC_PROMPT_02_brand_site.md.

Dispatch brand-copywriter to scaffold Next.js 15 with brand tokens and
build the five pages. Every piece of copy must pass the brand-voice-check
skill at .claude/skills/brand-voice-check/SKILL.md.

After the scaffold is up, invoke code-reviewer against
.claude/rubrics/lane-C-site.md before pushing to Vercel.

Deploy preview to Vercel after each major commit. I will review the
preview URLs.

Begin.
```

Expected duration: 4 to 6 hours. Lighter than Lane B because copy is
fast and the design system is simple.

### Your Day 1 work (in between reviews)

- Apple Developer Program status confirmation
- Tauri signer key generation
- Domain DNS verification
- Write the HN/PH/LinkedIn launch copy (drafts only, ship Day 7)
- Email Naveen and Gou for "would you try the beta" intros

## Day 2: Launch Lane A, continue B and C

### Terminal 3: Lane A (Tauri Shell)

```bash
cd .worktrees/lane-A
claude
```

```
You are the lead orchestrator for Lane A. Read AGENTS.md, then read the
prompt at ~/prompts/CC_PROMPT_03_tauri_shell.md.

Dispatch tauri-rust-engineer to scaffold the Tauri v2 project under
desktop/, implement the menu bar tray, LaunchAgent supervisor, setup
wizard, and auto-updater.

The daemon contract is defined in claude_monitoring/monitor.py (Lane B
extends this with extension scanner endpoints — coordinate with Lane B
via docs/SPRINT_ONE_WEEK.md).

After implementation, invoke security-reviewer on cert_install.rs and
daemon.rs specifically.

Code signing and notarization happen on Day 5, not now. Just produce an
unsigned DMG that installs and runs.

Begin.
```

Expected duration: 8 to 12 hours of agent wall-clock across Days 2 and 3.

### Day 2 check-ins (every 2 hours)

- Review Lane B grader output. If any criterion failed, prompt the
  orchestrator to dispatch back to the specialist with the rubric
  feedback.
- Review Lane C Vercel previews on your phone. Approve or send back.
- Approve Lane A scaffold commits as they land.

## Day 3: Integration prep

By end of Day 3, you should have:
- Lane B: extension scanner code complete, 85%+ coverage, all rules tested
- Lane C: brand site deployed to Vercel staging, Lighthouse ≥95
- Lane A: Tauri scaffold runs locally, tray icon works, setup wizard
  flows end-to-end

If any lane is behind, slip its rubric requirements (not the rubric
itself, the scope). Better to ship Lane B with 6 of 9 risk rules than to
ship none. Update the rubric to match.

## Day 4: Launch Lane D

Lane D was blocked until Lane B's `/api/extensions` shipped. It should
have shipped by end of Day 2. Lane D starts here.

### Terminal 4: Lane D (Dashboard UI)

```bash
cd .worktrees/lane-D
claude
```

```
You are the lead orchestrator for Lane D. Read AGENTS.md and the prompt
at ~/prompts/CC_PROMPT_04_ui_polish.md.

Lane B's /api/extensions endpoint is now live on lane-B branch. Merge
lane-B into lane-D as your starting point.

Dispatch design-system-curator to implement the design tokens, then the
Overview, Extensions, and revamped Alerts tabs. Other tabs get a lighter
visual pass.

After each tab, invoke code-reviewer against .claude/rubrics/lane-D-ui.md.

Begin.
```

Expected duration: 8 to 12 hours.

### Day 4 your work

- Smoke-test Lane A built DMG on a clean macOS VM if you have one
- Draft the blog post: "I watched Claude Code install GlassWorm"
- Confirm Stripe Payment Link works end-to-end
- Final review of Lane C copy against brand voice rules

## Day 5: Integration and signing

This day is mostly your work, not agent work.

```bash
# Merge lanes to main
git checkout main
git merge feature/lane-B-scanner --no-ff -m "feat: extension scanner (Lane B)"
git merge feature/lane-A-tauri --no-ff -m "feat: Tauri desktop shell (Lane A)"
git merge feature/lane-D-ui --no-ff -m "feat: dashboard UI polish (Lane D)"

# Run full test suite
make test
make lint

# Build signed DMG
cd desktop
TAURI_SIGNING_PRIVATE_KEY=$(cat ~/.tauri/airuntimemonitor.key) \
TAURI_SIGNING_PRIVATE_KEY_PASSWORD=$(security find-generic-password ...) \
npm run tauri build

# Notarize
./scripts/notarize.sh src-tauri/target/release/bundle/dmg/*.dmg

# Verify
spctl --assess --type install --verbose src-tauri/target/release/bundle/dmg/*.dmg
# Expected: "accepted source=Notarized Developer ID"

# Tag and release
git tag v0.2.0
git push --tags
# GitHub Actions workflow publishes DMG + latest.json
```

If notarization fails, the failure email from Apple is detailed enough to
fix in one cycle. Budget 2 hours for back-and-forth.

## Day 6: Smoke test and pre-launch

```
[ ] Download DMG from GitHub Releases on a clean Mac
[ ] Install, open, complete setup wizard
[ ] Verify tray icon, dashboard launches in browser
[ ] Install a fixture malicious extension, confirm critical alert fires
[ ] Confirm auto-update prompt works (bump local version, point to release)
[ ] Brand site final pass: every link works, every CTA fires
[ ] Stripe checkout completes for a test card
[ ] Write final HN "Show HN" post (under 1500 chars title + body)
[ ] Write Product Hunt copy (tagline, description, gallery images)
[ ] Write LinkedIn launch post (3 paragraphs, GlassWorm as hook)
[ ] Email draft to your 12 design partners (personalized)
```

## Day 7: Launch

Sequence matters.

```
06:00 PT: Schedule Product Hunt launch for 12:01 AM PT the next day
07:00 PT: Submit Show HN post (highest engagement window)
08:00 PT: LinkedIn post
09:00 PT: r/netsec post
10:00 PT: r/cybersecurity post
11:00 PT: Email design partners
12:00 PT: Update GitHub README with launch announcement
14:00 PT: Monitor HN ranking, respond to top 10 comments
16:00 PT: Engage on LinkedIn replies
```

Set Calendly availability open for the rest of the week. Inbound calls
from interested seed funds will start within 24 hours if the launch
catches.

## Failure Modes and How to Recover

| Symptom                          | Likely cause                       | Fix                                         |
|----------------------------------|------------------------------------|---------------------------------------------|
| Notarization fails               | Entitlements missing or wrong      | Read Apple's email, fix entitlements.plist  |
| Tauri DMG won't install          | Wrong signing identity             | `security find-identity -v -p codesigning`  |
| Lane B coverage stuck at 70%     | Test fixtures don't exercise rules | Add more fixtures, not more tests           |
| Lane C Lighthouse fails on LCP   | Unoptimized hero image             | next/image with priority + WebP             |
| Dashboard UI flickers on tab     | React rerenders on poll            | useMemo on filtered lists, useDeferredValue |
| Grader keeps failing one criterion| Spec ambiguity                    | Refine rubric, not the implementation       |
| You burn out by Day 4            | Reviewing too often                | Two 2-hour blocks/day, not 20 interruptions |

## What Makes This Achievable

Three things, all enforced by the harness:

1. **Specialists never wait on each other.** Worktrees give every
   subagent its own filesystem view. Two specialists editing the same
   logical area at the same time never see each other's changes.

2. **Graders catch issues before you do.** You don't read every diff.
   You read graders' verdicts. A failing verdict tells you what to
   redirect, not what to debug.

3. **Hooks block the dumb mistakes.** No accidental `rm -rf`. No commit
   with failing tests. No `.env` checked in. No edits to secrets. The
   class of bugs that destroys a sprint cannot happen.

## What Will Slip

Be honest: at least one of these will slip. Pick now which one is
acceptable to slip.

- A full malicious-extension threat intel feed (vs. just the seeded IOCs)
- The Mac App Store submission (already planned for Q3)
- Light mode in the dashboard (defer to v0.3)
- Windows and Linux builds (defer until Mac has 500 weekly active)
- Custom analytics dashboard for Pro tier (use Stripe + Plausible alone)
- Enterprise fleet dashboard (already roadmapped post-launch)

Anything else slipping is a real problem. These six are fine.

## The Honest Calendar

- Best case: ship Day 7 evening with all 4 lanes
- Realistic: ship Day 8 morning with 3.5 lanes (Lane D partial)
- Worst case: ship Day 10 with Tauri unsigned (still distributable via Homebrew)

If you hit the worst case, ship anyway. A working product on Day 10 with
500 brew installs beats a perfect product on Day 21 with zero installs.
