# Claude Code Sprint Prompt — Track D: Dashboard UI Polish

## Mission

Transform the existing dashboard from "functional internal tool" into "enterprise security product." Adopt a proper design system, add the new Extensions tab from Track B, redesign the Alerts experience, add empty states, dark mode default. Aesthetic reference: Linear, Vanta, Wiz — dense, calm, severity-graded.

## Prerequisites

- Track B must have shipped `/api/extensions` endpoint
- Dashboard codebase familiarity: read `claude_monitoring/dashboard/` before starting

## Branch

```
git checkout -b feature/dashboard-polish-v2
```

## Stack Decision

If the current dashboard is plain `dashboard.html` with vanilla JS, do a controlled migration to React + Vite inside the existing FastAPI serving path. If it is already React, just upgrade.

```
claude_monitoring/dashboard/
  app/                          # NEW React app
    src/
      main.tsx
      App.tsx
      components/
        Layout.tsx
        Sidebar.tsx
        TopBar.tsx
        KpiCard.tsx
        SeverityBadge.tsx
        AlertCard.tsx
        EmptyState.tsx
        DataTable.tsx
        SessionRow.tsx
        ExtensionRow.tsx
        Filter.tsx
        CodeBlock.tsx
      tabs/
        Overview.tsx
        Sessions.tsx
        ApiTraffic.tsx
        Alerts.tsx
        SupplyChain.tsx
        Extensions.tsx          # NEW from Track B
        Inventory.tsx
        Settings.tsx
      api/
        client.ts               # typed fetch wrappers
      hooks/
        useStream.ts            # SSE for live alerts
        usePolling.ts
      types/
        index.ts                # generated from OpenAPI
      styles/
        globals.css
        tokens.css
    package.json
    vite.config.ts
    tailwind.config.ts
    tsconfig.json
```

FastAPI serves `dashboard/app/dist/` at `/` with a fallback to `index.html` for client-side routing.

## Design Tokens (`styles/tokens.css`)

```css
:root {
  --bg-base: #0a0a0b;
  --bg-elevated: #111114;
  --bg-card: #1a1a1f;
  --bg-hover: #22222a;

  --border-subtle: #27272f;
  --border-strong: #3a3a45;

  --text-primary: #f5f5f7;
  --text-secondary: #a1a1aa;
  --text-tertiary: #71717a;
  --text-disabled: #52525b;

  --accent: #22d3ee;
  --accent-hover: #06b6d4;
  --accent-muted: rgba(34, 211, 238, 0.1);

  --severity-critical: #f43f5e;
  --severity-high: #fb923c;
  --severity-medium: #fbbf24;
  --severity-low: #22d3ee;
  --severity-info: #71717a;

  --severity-critical-bg: rgba(244, 63, 94, 0.08);
  --severity-high-bg: rgba(251, 146, 60, 0.08);
  --severity-medium-bg: rgba(251, 191, 36, 0.08);
  --severity-low-bg: rgba(34, 211, 238, 0.08);

  --font-ui: 'Inter', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', 'SF Mono', monospace;

  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;
  --radius-xl: 12px;

  --shadow-card: 0 1px 0 rgba(255,255,255,0.03), 0 0 0 1px var(--border-subtle);
  --shadow-elevated: 0 4px 12px rgba(0,0,0,0.4), 0 0 0 1px var(--border-subtle);
}
```

Light mode toggle is a stretch goal. Default is dark. Do not waste cycles on light mode polish in this sprint.

## Layout

```
┌──────────────────────────────────────────────────────────────────┐
│  ai-runtime-monitor  |  rajan@gocloudforge   ●Live   ⚙          │  TopBar (56px)
├─────────┬────────────────────────────────────────────────────────┤
│         │                                                         │
│ ▣ Over  │   <tab content>                                         │
│ ⊞ Sess  │                                                         │
│ ⇄ API   │                                                         │  Sidebar (240px)
│ ⚠ Alerts│                                                         │  + main content
│ ⛁ Supp  │                                                         │
│ ⊕ Exts  │                                                         │
│ ⊟ Inv   │                                                         │
│ ⚙ Set   │                                                         │
│         │                                                         │
└─────────┴────────────────────────────────────────────────────────┘
```

Sidebar item shows a small severity-colored dot if that tab has unresolved critical or high findings.

## Tab: Overview (new home page)

KPI strip across the top, then three panels.

```
┌───────────────┬───────────────┬───────────────┬───────────────┐
│ ACTIVE        │ ALERTS        │ EXTENSIONS    │ SESSIONS      │
│ AGENTS        │ (24h)         │ AT RISK       │ (today)       │
│               │               │               │               │
│ 4             │ 7 ⚠           │ 3 / 47        │ 42            │
│ ↑ 2 vs yest   │ ↓ 1 vs yest   │ ↑ 1 vs week   │ ↑ 12 vs yest  │
└───────────────┴───────────────┴───────────────┴───────────────┘

┌─────────────────────────────────┬────────────────────────────┐
│ Recent Critical Alerts          │ Tools Detected             │
│ (last 24 hours)                 │                            │
│                                 │ ● Claude Code   12 sess    │
│ ⚠ GlassWorm extension detected  │ ● Cursor         3 sess    │
│   in Cursor — 4 min ago         │ ● Copilot        1 sess    │
│                                 │ ● ChatGPT App    2 sess    │
│ ⚠ AWS key exposed in Claude     │ ● Ollama         5 sess    │
│   Code session — 1h ago         │ ● Claude Desktop 8 sess    │
│                                 │                            │
│ View all →                      │ Manage →                   │
└─────────────────────────────────┴────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│ Activity Timeline (last 6 hours)                               │
│                                                                │
│ [stacked area chart: events by severity over time]             │
└────────────────────────────────────────────────────────────────┘
```

KPI delta arrows use severity color when the trend is bad. No exclamation marks. No emojis in production UI.

## Tab: Alerts (overhaul)

Cards, not a flat table. Group by session, severity-graded left border.

```
┌────────────────────────────────────────────────────────────────┐
│ ◤  CRITICAL                                  4 min ago         │
│    GlassWorm extension detected in Cursor                      │
│                                                                │
│    Cursor installed evil-publisher.malicious-extension v1.0.2  │
│    at 14:32 during session abc123. Extension matches known     │
│    IOC from OpenVSX advisory OpenVSX-2025-002.                 │
│                                                                │
│    [View Extension] [View Session] [Dismiss]                   │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│ ◤  HIGH                                      1 hour ago        │
│    AWS access key exposed in Claude Code session               │
│    ...                                                         │
└────────────────────────────────────────────────────────────────┘
```

Left border is 3px solid in the severity color. Card body is `--bg-card` with `--border-subtle` border. Hover lifts via `--shadow-elevated`.

Filters in the top right: Severity (multi-select), Tool (multi-select), Status (Open/Dismissed), Time range. Persist filter state in URL params.

Dismiss writes to DB and is reversible from the Dismissed view.

## Tab: Extensions (new, from Track B)

```
┌────────────────────────────────────────────────────────────────┐
│  Editor    Extension                Publisher       Risk   Age │
│  ──────────────────────────────────────────────────────────── │
│  Cursor    evil.malicious-ext       evil           ●CRIT   2d │
│  VS Code   pretti3r.prettier        pretti3r       ●HIGH   7d │
│  VS Code   ms-python.python         microsoft      ●LOW    8m │
│  Cursor    eamodio.gitlens          eamodio        ●INFO   3m │
│  JetBrains com.intellij.python      JetBrains      ●INFO   5m │
│  ...                                                           │
└────────────────────────────────────────────────────────────────┘

[ Rescan ] [ Refresh threat intel ]  47 extensions across 4 editors
```

Click row → drawer with full manifest, findings, marketplace link, "show in Finder" button.

Top of the tab: thin banner if any critical findings exist:

```
⚠ 1 critical extension finding. View →
```

## Tab: Sessions (denser)

Existing tab. Lighten the visual weight. Replace any banded row coloring with subtle borders. Switch agent badges to use the severity tokens but in muted variants:

- Claude Code → cyan-400 outline badge
- Cursor → purple-400
- Copilot → emerald-400
- ChatGPT → orange-400
- OpenClaw → blue-400

Strip the Telegram metadata wrapper from OpenClaw session display (this is a known issue from the prior sprint — confirm it is fixed).

## Tab: API Traffic

Columns: Time, Tool, Method, Host, Path, Status, Tokens, Cost. Click row → JSON drawer with copy-to-clipboard and "open in new tab" buttons.

Add a quick filter chip row at the top: "Errors only", "POST only", "Last 1h", "Anthropic only", "OpenAI only".

## Tab: Settings

Tabs within: General, Daemon, Proxy, Certificates, Fleet (greyed out if Free tier), Notifications.

Daemon section shows:
- LaunchAgent install status
- Last restart time
- Buttons: Restart, Reinstall, Uninstall

Certificates section:
- Custom CA fingerprint
- Trust status (System keychain, Login keychain)
- Buttons: Reinstall cert, Rotate cert

## Empty States

Every tab gets a teaching empty state when there is no data:

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│                       ⊕                                        │
│                                                                │
│           No editor extensions detected yet                    │
│                                                                │
│   We did not find VS Code, Cursor, JetBrains, or Xcode         │
│   extensions on this machine. If you have these editors        │
│   installed, click Rescan to try again.                        │
│                                                                │
│                  [ Rescan extensions ]                         │
│                                                                │
│                  Read the docs →                               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

Component: `<EmptyState icon={IconComponent} title="" body="" cta={{label, onClick}} />`.

## Components

### `<SeverityBadge severity="critical|high|medium|low|info" variant="solid|outline|muted">`

Solid variant for highest emphasis, muted for tables, outline for status chips. All use the token colors.

### `<DataTable>`

Built on TanStack Table. Sticky header, virtualized rows above 200, sortable columns, column visibility toggle, CSV export.

### `<KpiCard title delta trend status>`

Status drives the accent color of the delta arrow.

### `<CodeBlock language code copyable>`

Syntax highlighted via Shiki (build-time tokenization, no runtime cost). Copy button in top-right.

## API Client (`api/client.ts`)

Typed wrapper around fetch:

```typescript
import type { components } from '../types/openapi'

type Extension = components['schemas']['Extension']
type Alert = components['schemas']['Alert']

export const api = {
  extensions: {
    list: () => request<Extension[]>('GET', '/api/extensions'),
    get: (id: string) => request<Extension>('GET', `/api/extensions/${id}`),
    rescan: () => request<void>('POST', '/api/extensions/scan'),
    dismissFinding: (extId: string, ruleId: string) =>
      request<void>('POST', `/api/extensions/${extId}/dismiss-finding/${ruleId}`),
  },
  alerts: {
    list: (filters: AlertFilters) => request<Alert[]>('GET', '/api/alerts', filters),
    stream: () => new EventSource('/api/alerts/stream'),
    dismiss: (id: string) => request<void>('POST', `/api/alerts/${id}/dismiss`),
  },
  sessions: { ... },
  status: { ... },
  settings: { ... },
}
```

Generate types from the FastAPI OpenAPI spec via `openapi-typescript`.

## Live Updates

Use SSE for the Alerts stream and tray-icon-equivalent header indicator. Wrap in a `useStream<Alert>('/api/alerts/stream')` hook with reconnect-with-backoff.

## Verification Checklist

```bash
# 1. Type check
cd claude_monitoring/dashboard/app && npm run typecheck

# 2. Build
npm run build
# Bundle size < 300KB gzipped

# 3. Lighthouse against the running daemon's dashboard
npx lighthouse http://localhost:9081 --view --preset=desktop

# 4. Visual regression
# Take screenshots of every tab in both states (empty + populated)
# Compare against baseline screenshots in tests/dashboard/visuals/

# 5. Full smoke
pytest tests/ -v 2>&1 | tail -30
# All API tests still passing, no regression

# 6. Manual click-through every tab
# Confirm no console errors, no broken images, no missing tokens
```

## Out of Scope (defer)

- Light mode
- Mobile responsive (dashboard is desktop-only)
- i18n
- User-customizable dashboards

## Commit

```
feat(dashboard): full UI overhaul with design tokens, Extensions tab, alert cards

- React 19 + Vite + Tailwind v4 inside existing FastAPI serving path
- Design tokens for severity, surfaces, typography
- New Overview, Extensions, and redesigned Alerts tabs
- TanStack Table for dense data views
- SSE-driven live alerts with backoff reconnect
- EmptyState component used across every tab
- Lighthouse 95+ on the running dashboard
```
