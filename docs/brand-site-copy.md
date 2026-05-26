# Vigil Brand Site — Squarespace Content

This file contains the complete content and design intent for the Vigil v0.2 launch landing page at vigil.gocloudforge.com. Paste sections into Squarespace, pick a template that matches the design intent, and publish.

**Estimated build time:** 1-2 hours in the Squarespace editor.

**Tone:** Hybrid — security-product serious on the hero, developer-friendly on install and feature highlights. The goal is to make a senior developer feel "this is a real product I should try" and make a security buyer feel "this is something my CISO would take seriously."

---

## Design intent

### Template recommendations

Squarespace templates that fit the tone:

- **Bedford family** — clean, technical-product feel. Good for the hybrid tone.
- **Brine family** — flexible, modern. Works for both startup and enterprise vibes.
- **Five** — minimal, full-width, lets typography do the work. Strongest if you want the hero to dominate.

If asked to pick one: **Bedford** or **Brine**.

### Color palette

Dark mode forward (matches the dashboard's aesthetic):

- **Background:** near-black (#0d1117 or similar deep gray)
- **Primary text:** off-white (#e6edf3)
- **Accent (CTAs, highlights):** the dashboard's blue (#58a6ff)
- **Success/positive:** green (#3fb950) — used sparingly
- **Alert/critical:** red (#f85149) — used only when discussing threats

Alternatively, light-mode professional:

- **Background:** white or near-white
- **Primary text:** dark gray (#1a1a1a)
- **Accent:** a single bold color, probably the same blue
- **Subdued text:** medium gray (#666)

If asked to pick one: **dark mode forward** because it matches the dashboard product itself and signals "security-aware" to the target audience.

### Typography

- **Headings:** a clean sans-serif. Inter, Söhne, or whatever Squarespace's modern sans options are.
- **Body:** the same family for consistency.
- **Code/install snippets:** monospace. JetBrains Mono, IBM Plex Mono, or fallback to system monospace.

### Layout

One scrollable page. Sections from top to bottom:

1. Hero (above the fold)
2. The problem (one section, short)
3. What Vigil does (three feature highlights)
4. Install (the developer-friendly section)
5. For teams and enterprise (one line + contact)
6. Footer (links, contact, copyright)

No sticky header navigation needed; the page is short enough that scroll is fine.

---

## Section 1: Hero

**Headline (H1):**

Endpoint security for the AI developer.

**Subheadline:**

See what AI coding agents actually do on your machine. Detect credential exposure, supply chain risk, and adversarial behavior in real time.

**Primary CTA button:**

Install with pip

**Secondary CTA button:**

View on GitHub

(The primary CTA scrolls to the Install section. The secondary opens https://github.com/rajan-cforge/ai-runtime-monitor-enterprise in a new tab.)

**Hero visual:**

Either:
(a) A screenshot of the Vigil dashboard's Alerts tab showing the kind of detection it does. This is the most credible visual — "here's what you see when you run it."
(b) A simple animated terminal showing `pip install ai-runtime-monitor` → `ai-monitor --start` → dashboard URL output.
(c) A clean abstract graphic. Lowest credibility option; skip unless screenshots aren't ready.

Recommendation: **(a) the dashboard screenshot.** If you don't have a clean screenshot yet, take one tonight from your live dashboard with a few demonstrative alerts visible (any of the c654f242 session ones).

---

## Section 2: The problem

**Section header (H2):**

AI agents are writing code, accessing credentials, and calling APIs on your machine. Nobody's watching.

**Body paragraph:**

85% of developers use AI coding agents daily. 88% of organizations have reported AI-related security incidents. The agents install dependencies, read sensitive files, and make API calls — often overnight, often without supervision. Existing security tools weren't built for this. CrowdStrike watches for malware. Snyk watches your repository's dependencies. Nobody watches the AI agent that installs the dependencies, writes the code, and accesses production credentials at 3 AM while you sleep.

**(Optional callout block, smaller text below the paragraph):**

April 2026: a developer at a major SaaS company installed a Chrome extension from an AI vendor, granted it broad Google Workspace permissions, and within days the company's internal systems were compromised through OAuth trust chain pivot. No endpoint security product saw it coming.

---

## Section 3: What Vigil does

Three feature cards in a horizontal layout (responsive — stacks on mobile).

### Card 1

**Icon:** Eye, monitor, or similar visibility motif

**Heading:** Three-layer monitoring

**Body:** Captures every AI agent action through JSONL session tailing, system process monitoring, and optional HTTPS proxy interception. Works with Claude Code, Cursor, Copilot, ChatGPT Desktop, and 15+ other agents. Zero configuration required for the basic layer.

### Card 2

**Icon:** Shield, lock, or alert motif

**Heading:** Sensitive data detection

**Body:** Detects AWS keys, GitHub tokens, Anthropic API keys, and 20+ other credential patterns in AI session data. Severity-ranked alerts with drill-down to the exact conversation turn where exposure occurred. Plaintext auto-purged after 30 days; metadata retained for audit.

### Card 3

**Icon:** Package, chain, or supply chain motif

**Heading:** Supply chain intelligence

**Body:** Real-time CVE detection across 19 package managers via OSV.dev. Threat intel feeds from ThreatFox and URLhaus. Detects when AI agents install packages with known vulnerabilities or malicious behavior — before they execute.

---

## Section 4: Install

**Section header (H2):**

Install in 30 seconds

**Body intro:**

Free and open source. macOS today, Linux best-effort, Windows coming in v0.3.

**Code block 1 (pip):**

```bash
pip install ai-runtime-monitor
ai-monitor --setup
ai-monitor --start
```

**Code block 2 (Homebrew):**

```bash
brew tap rajan-cforge/vigil
brew install vigil
vigil --setup
vigil --start
```

**Caption under code blocks:**

Then open http://localhost:9081 in your browser. The setup wizard walks you through certificate trust (cryptographically constrained to AI domains only via X.509 NameConstraints), data directory creation, and dashboard token generation.

**Secondary CTA:**

Read the docs on GitHub →

(Link to the main repo's README)

---

## Section 5: For teams and enterprise

**Section header (H2):**

For teams and enterprises

**Body paragraph:**

Vigil's free tier runs on a single developer's machine. The Pro tier ($29/month) adds full HTTPS proxy capture and LaunchAgent auto-start. Enterprise tier adds fleet-scale monitoring with a control plane, RBAC, SSO, and SIEM integration. We're booking design partners now for the v1.0 fleet dashboard launching in Q4 2026.

**CTA button:**

Contact for enterprise →

(Mailto link to rajan@gocloudforge.com or a Squarespace form. If using a form, keep it minimal: name, company, email, "what AI agents do your developers use?" as a single open text field.)

---

## Section 6: Footer

Standard Squarespace footer with:

**Left column:**

- Vigil
- by GoCloudForge, Inc.
- © 2026

**Middle column:**

- GitHub (link)
- Documentation (link to main repo README)
- Security (mailto:security@gocloudforge.com)

**Right column:**

- Built in San Jose
- Apache 2.0 licensed

---

## SEO and metadata

**Page title:**

Vigil — Endpoint security for the AI developer

**Meta description:**

Real-time monitoring for AI coding agents. Detect credential exposure, supply chain risk, and adversarial behavior on your machine. Free and open source.

**Open Graph image:**

Use the dashboard screenshot from the hero, or create a 1200x630 graphic with the headline and a Vigil logo.

**Twitter/X card:**

Same as Open Graph.

---

## What I'd skip

The pitch deck has a lot of statistics ($18B cybersecurity funding, $4.63M shadow AI breach cost, etc.). They're valuable for investor conversations but read as filler on a landing page. The landing page's job is to convince a developer to install in 30 seconds, not to defend market opportunity.

The pitch deck's "Why now" timeline (Mar 31 Claude Code leak, Apr 7-10 RSAC, Apr 19 Vercel, etc.) is also better suited for sales conversations than landing page copy.

Keep both for the eventual /about page or /press page in v0.3.

---

## What to do tonight or over the weekend

1. Pick a Squarespace template (Bedford or Brine recommended)
2. Set the color palette (dark mode forward recommended)
3. Take a clean dashboard screenshot for the hero
4. Paste each section's content into Squarespace blocks
5. Configure DNS so vigil.gocloudforge.com resolves to the Squarespace site
6. Publish

Total time: 1-2 hours if you don't get into deep template customization.

After publish, share the URL and I'll do a quick review pass before launch announcement.
