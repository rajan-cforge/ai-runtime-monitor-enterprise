# Claude Code Sprint Prompt — Track C: Brand Site

## Mission

Build the public marketing site for AI Runtime Monitor. Five pages, dense and fast. Aesthetic: security tool, not consumer SaaS. Think Tailscale, Vanta, Wiz. Dark mode default.

## Repository

Create a new repo: `rajan-cforge/airuntimemonitor-site`

Local path: `/Users/rajan/code/airuntimemonitor-site`

## Stack

Same as NyayMitra Track A so the cognitive load stays low:

- Next.js 15 (App Router)
- React 19
- Tailwind v4
- TypeScript strict mode
- shadcn/ui components
- Lucide React icons
- MDX for blog posts and docs
- Plausible analytics (privacy-respecting, fits the brand)

## Pages

```
app/
  layout.tsx                  # root layout, nav, footer
  page.tsx                    # /          home
  features/page.tsx           # /features
  pricing/page.tsx            # /pricing
  download/page.tsx           # /download
  docs/page.tsx               # /docs       (links to GitHub docs initially)
  blog/page.tsx               # /blog       (MDX index)
  blog/[slug]/page.tsx        # /blog/:slug
```

## Domain and Hosting

Domain: `airuntimemonitor.com` (register via Cloudflare or Namecheap). Fallback if taken: `runtimemonitor.dev` or path on `gocloudforge.com/runtime-monitor`.

Hosting: Vercel. Connect GitHub repo, auto-deploy on `main`. Use Vercel's free tier until traction.

## Brand Tokens

```css
/* tailwind.config — extend theme */
colors: {
  bg: {
    base: '#0a0a0b',       /* near-black */
    elevated: '#111114',
    card: '#1a1a1f',
  },
  border: {
    subtle: '#27272f',
    strong: '#3a3a45',
  },
  text: {
    primary: '#f5f5f7',
    secondary: '#a1a1aa',
    tertiary: '#71717a',
  },
  accent: {
    DEFAULT: '#22d3ee',    /* cyan-400, primary CTA */
    hover: '#06b6d4',
  },
  severity: {
    critical: '#f43f5e',
    high: '#fb923c',
    medium: '#fbbf24',
    low: '#22d3ee',
  },
}
```

Typography: Inter for UI, JetBrains Mono for code blocks. Both from next/font/google.

## Hero Copy (above the fold)

```
Eyebrow:   ENDPOINT SECURITY FOR THE AI DEVELOPER

Headline:  See what Claude Code, Cursor, and Copilot
           actually do on your machine.

Subhead:   Real-time visibility into the network traffic, file
           access, package installs, and editor extensions of
           every AI coding tool running on your laptop.

CTAs:      [ Download for Mac (DMG) ]   [ brew install ]   [ View on GitHub ]

Demo:      45-second screen recording loop showing:
           - Claude Code installing a malicious npm package
           - Alert firing in the menu bar
           - Drill-down to the exact prompt that triggered it
```

Embed the demo as an MP4 with a poster image, autoplay muted on desktop, click-to-play on mobile.

## Features Section (home + /features)

Six feature cards in a 3x2 grid:

```
1. Network Visibility
   See every API call your AI tools make. mitmproxy under
   the hood, encrypted dashboard, zero egress.

2. Supply Chain Defense
   Catches malicious npm and pip packages the moment your AI
   agent installs them. Backed by OSV.dev, ThreatFox, URLhaus.

3. Editor Extension Scanner            [NEW]
   Inventories every VS Code, Cursor, JetBrains, and Xcode
   extension. Flags typosquats, hijacked publishers, and
   known-bad extensions from GHSA and OpenVSX advisories.

4. Sensitive Data Detection
   Catches AWS keys, GitHub tokens, JWTs, private keys, and
   12 other patterns in your AI sessions. Shows the exact turn
   where exposure occurred.

5. Cost Intelligence
   Token counting, burn rate, and the surprising finding that
   your most expensive sessions are your least productive.

6. Cross-Tool Timeline
   Claude Code, Cursor, Copilot, ChatGPT, Gemini, and
   Perplexity. Unified session view across every tool you use.
```

Each card: icon (Lucide), heading, two-sentence description. Hover state lifts the card 2px.

## Pricing (`/pricing`)

Three-column table:

```
┌──────────────────────┬──────────────────────┬──────────────────────┐
│  FREE                │  PRO                 │  ENTERPRISE          │
│  $0                  │  $29 / developer / mo│  Contact sales       │
│  Forever             │  Billed annually     │  Volume + custom     │
├──────────────────────┼──────────────────────┼──────────────────────┤
│  All monitoring      │  Everything in Free  │  Everything in Pro   │
│  Single machine      │  + SSL inspection    │  + Fleet dashboard   │
│  Open source         │  + Custom CA         │  + RBAC / SSO        │
│  Community support   │  + Encrypted DB      │  + SIEM forwarding   │
│                      │  + Dashboard auth    │  + Priority support  │
│                      │  + LaunchAgent       │  + SLA               │
│                      │  + Auto-update       │  + Dedicated CSM     │
├──────────────────────┼──────────────────────┼──────────────────────┤
│  [ Download ]        │  [ Start Trial ]     │  [ Book a Demo ]     │
└──────────────────────┴──────────────────────┴──────────────────────┘
```

Pro CTA links to Stripe Payment Link (placeholder URL `STRIPE_PRO_LINK` in env). Enterprise CTA opens a Calendly link or simple mailto.

## Download (`/download`)

Three install methods stacked:

```
1. DMG (recommended)
   Big download button. SHA-256 verification command.
   Signed and notarized by Apple.

2. Homebrew
   brew install gocloudforge/tap/ai-runtime-monitor
   (copy-to-clipboard button)

3. Python (developers)
   pip install ai-runtime-monitor
   ai-monitor

Coming soon: Windows .msi, Linux .AppImage
```

Pull the latest DMG URL from GitHub Releases via build-time fetch.

## Docs (`/docs`)

For v1.0, redirect to GitHub README and `/docs` folder. Add a banner: "Searchable docs coming soon."

For v1.1, render MDX from a `content/docs/` folder with a sidebar nav.

## Blog (`/blog`)

MDX-based. Three seed posts to write at launch:

```
1. "I watched Claude Code install malware in real-time"
   The Vercel breach analysis + your reproduction.

2. "What your AI coding tool actually sends to its API"
   The DLP findings + the 87% conversation-replay stat.

3. "GlassWorm and the rise of malicious editor extensions"
   The November 2025 OpenVSX campaign + how the scanner catches it.
```

Each post: MDX, hero image, 5-8 minute read, author byline (Rajan), social share buttons.

## SEO

- Open Graph tags on every page
- Structured data (Organization, SoftwareApplication)
- Sitemap.xml
- Robots.txt
- Meta descriptions hand-written per page

## Performance Targets

- Lighthouse Performance ≥95
- LCP <1.5s on 4G
- Bundle <100KB JS gzipped on home
- All images next/image optimized
- No client-side JS on /pricing, /download (use Server Components)

## Components Inventory

```
components/
  Nav.tsx
  Footer.tsx
  Hero.tsx
  FeatureGrid.tsx
  FeatureCard.tsx
  PricingTable.tsx
  CTAButton.tsx
  CodeBlock.tsx           # syntax-highlighted with copy button
  DemoVideo.tsx
  Logo.tsx
  StatsBar.tsx            # "X stars, Y installs, Z extensions scanned"
  TestimonialCard.tsx     # placeholder until you have quotes
```

## Verification Checklist

```bash
# 1. Type check
npm run typecheck

# 2. Lint
npm run lint

# 3. Build
npm run build

# 4. Lighthouse (CI)
npx @lhci/cli@latest autorun --collect.url=http://localhost:3000 --collect.url=http://localhost:3000/pricing

# 5. Visual check at 375px, 768px, 1440px viewports

# 6. Confirm all CTAs lead to working destinations:
#    - DMG button → GitHub Releases latest .dmg
#    - brew copy button → clipboard contains correct command
#    - Stripe link → Stripe payment page loads
#    - GitHub button → github.com/rajan-cforge/ai-runtime-monitor

# 7. OG card render check via https://opengraph.xyz
```

## Stop and Ask If

- Domain registration is uncertain (which name to register)
- Stripe Payment Links are not set up yet (use placeholder env var)
- Demo video does not exist (use a static screenshot as placeholder)

## First Commit

```
chore: initial Next.js 15 + Tailwind v4 scaffold

- App Router with five pages
- Brand tokens in tailwind config
- shadcn/ui components installed
- Plausible analytics wired
- Hero, FeatureGrid, PricingTable, CTAButton components
- Lighthouse passing 95+ on all routes
```
