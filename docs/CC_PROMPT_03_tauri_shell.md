# Claude Code Sprint Prompt — Track A: Tauri Desktop Shell

## Mission

Wrap AI Runtime Monitor as a real macOS application. Menu bar icon, native notifications, one-click setup wizard, auto-update, signed and notarized DMG. Python daemon stays as the backend, managed by LaunchAgent. Tauri shell is thin and supervisory.

## Branch

```
git checkout -b feature/tauri-desktop-shell
```

## Repository Layout

Add a new `desktop/` directory to the existing repo:

```
ai-runtime-monitor/
  claude_monitoring/      # existing Python backend
  desktop/                # NEW Tauri shell
    src-tauri/
      Cargo.toml
      tauri.conf.json
      build.rs
      icons/
        icon.icns
        icon.ico
        icon.png
        tray-active.png   # 22x22, green dot
        tray-inactive.png # 22x22, gray
        tray-alert.png    # 22x22, red dot
      src/
        main.rs
        menu.rs
        daemon.rs
        updater.rs
        commands.rs
        paths.rs
        notifications.rs
        cert_install.rs
    src/
      main.tsx
      App.tsx
      SetupWizard.tsx
      StatusPanel.tsx
      vite-env.d.ts
    package.json
    vite.config.ts
    index.html
    tsconfig.json
```

## Setup

```bash
cd /Users/rajan/code/ai-runtime-monitor
npm create tauri-app@latest desktop -- --template react-ts
cd desktop
cargo add tauri-plugin-shell
cargo add tauri-plugin-updater
cargo add tauri-plugin-notification
cargo add tauri-plugin-autostart
cargo add tauri-plugin-fs
```

Bump Tauri to v2 (stable). Use React 19 + Tailwind v4 inside the webview to match your other projects.

## Architecture

```
        ┌──────────────────────────┐
        │  Menu Bar Tray Icon       │ ← Tauri
        │  click → dropdown menu    │
        └──────────┬───────────────┘
                   │ ipc
        ┌──────────▼───────────────┐
        │  Tauri Rust Backend       │
        │  - Supervises LaunchAgent │
        │  - Polls daemon health    │
        │  - Forwards alerts        │
        │  - Manages auto-update    │
        └──────────┬───────────────┘
                   │ http://127.0.0.1:9081/api/...
        ┌──────────▼───────────────┐
        │  Python Daemon            │ ← Existing
        │  - LaunchAgent service    │
        │  - mitmproxy on 9080      │
        │  - Dashboard on 9081      │
        └──────────────────────────┘

        ┌──────────────────────────┐
        │  Default Browser          │ ← User-facing dashboard
        │  http://localhost:9081    │   stays browser-based
        └──────────────────────────┘
```

The Tauri main window is only used for the first-run setup wizard. After setup completes, the app lives in the menu bar. The dashboard opens in the user's default browser via `tauri-plugin-shell::open`.

## Menu Bar (`menu.rs`)

```rust
// Dropdown content when user clicks the tray icon
//
//  ┌────────────────────────────────────┐
//  │ AI Runtime Monitor      ● Active  │
//  │ ─────────────────────────────────  │
//  │ Open Dashboard              ⌘D    │
//  │ ─────────────────────────────────  │
//  │ Claude Code           ● 3 active   │
//  │ Cursor                ● 1 active   │
//  │ ChatGPT App           ● 0          │
//  │ ─────────────────────────────────  │
//  │ ⚠  7 critical alerts               │
//  │ Last scan: 4 min ago               │
//  │ ─────────────────────────────────  │
//  │ Pause Monitoring                   │
//  │ Settings...                ⌘,     │
//  │ Check for Updates                  │
//  │ ─────────────────────────────────  │
//  │ Quit                       ⌘Q     │
//  └────────────────────────────────────┘
```

Tray icon states (drive from `daemon.rs::get_status()`):

- `tray-active.png` (green) — daemon healthy, no critical alerts
- `tray-alert.png` (red) — one or more critical findings
- `tray-inactive.png` (gray) — daemon stopped or unreachable

Refresh tray state every 5 seconds.

## Daemon Supervisor (`daemon.rs`)

```rust
pub struct DaemonStatus {
    pub running: bool,
    pub proxy_running: bool,
    pub dashboard_reachable: bool,
    pub active_sessions: u32,
    pub critical_alerts: u32,
    pub last_scan_ago_seconds: u32,
}

pub async fn get_status() -> Result<DaemonStatus, DaemonError> {
    // GET http://127.0.0.1:9081/api/status
    // Timeout: 2s
}

pub fn install_launch_agent() -> Result<(), DaemonError> {
    // Copy plist to ~/Library/LaunchAgents/com.gocloudforge.ai-runtime-monitor.plist
    // launchctl load -w <plist>
}

pub fn uninstall_launch_agent() -> Result<(), DaemonError> {
    // launchctl unload <plist>
    // Remove plist
}

pub fn restart_daemon() -> Result<(), DaemonError> {
    // launchctl kickstart -k gui/<uid>/com.gocloudforge.ai-runtime-monitor
}

pub fn is_launch_agent_installed() -> bool {
    // Check plist existence and launchctl print state
}
```

LaunchAgent plist template lives at `desktop/src-tauri/resources/launchagent.plist.template`. Tauri renders it with the user's home path at install time.

## Tauri Commands (`commands.rs`)

Expose to the webview for the setup wizard:

```rust
#[tauri::command]
async fn get_daemon_status() -> Result<DaemonStatus, String> { ... }

#[tauri::command]
async fn install_certificate() -> Result<(), String> {
    // Run: security add-trusted-cert -d -r trustRoot
    //      -k /Library/Keychains/System.keychain <cert_path>
    // Requires sudo via osascript prompt
}

#[tauri::command]
async fn enable_system_proxy() -> Result<(), String> { ... }

#[tauri::command]
async fn disable_system_proxy() -> Result<(), String> { ... }

#[tauri::command]
async fn open_dashboard() -> Result<(), String> {
    // tauri-plugin-shell::open("http://localhost:9081")
}

#[tauri::command]
async fn complete_setup() -> Result<(), String> {
    // Write ~/Library/Application Support/AI Runtime Monitor/.setup_complete
    // Close main window, leave only tray
}

#[tauri::command]
async fn install_browser_extension() -> Result<(), String> {
    // Open Chrome with the unpacked extension folder
    // chrome --load-extension=<path>
}
```

## Setup Wizard (`src/SetupWizard.tsx`)

Five-step wizard in the Tauri main window:

```
Step 1: Welcome
  - Logo, product description, what it monitors
  - [Get Started] → Step 2

Step 2: Install Certificate
  - "AI Runtime Monitor needs to install a monitoring
     certificate so it can inspect AI tool traffic."
  - [Install Certificate]
    → invokes install_certificate command
    → osascript prompts for sudo
  - On success: green check, [Next]

Step 3: Enable Desktop App Monitoring
  - Toggle: Enable system proxy
  - "This lets us monitor desktop apps like ChatGPT and
     Claude Desktop in addition to CLI tools."
  - [Next]

Step 4: Install Browser Extension (optional)
  - "Adds visibility into Claude.ai, ChatGPT web,
     Gemini, and Perplexity sessions."
  - [Install] opens Chrome extensions page with unpacked
    extension already loaded
  - [Skip] continues without

Step 5: Done
  - "AI Runtime Monitor is running in your menu bar."
  - Shows the tray icon location with an arrow
  - [Open Dashboard] → invokes open_dashboard
  - Closes main window, app lives in tray
```

Use shadcn/ui for the wizard chrome. Each step has a progress bar at the top.

## Auto-Update (`updater.rs`)

Use `tauri-plugin-updater` with a GitHub Releases endpoint:

```json
// tauri.conf.json fragment
"updater": {
  "active": true,
  "endpoints": [
    "https://github.com/rajan-cforge/ai-runtime-monitor/releases/latest/download/latest.json"
  ],
  "dialog": true,
  "pubkey": "<base64-pubkey-from-tauri-signer>"
}
```

Generate signing keys with `tauri signer generate`. Store private key in 1Password, public key in repo. CI signs the DMG and writes `latest.json` to the GitHub release on every tag.

Check for updates on launch + every 24 hours via a Rust task.

## Notifications (`notifications.rs`)

```rust
pub async fn fire_critical(title: &str, body: &str, url: Option<&str>) {
    // Use tauri-plugin-notification, fall back to osascript:
    // osascript -e 'display notification "..." with title "..." sound name "Submarine"'
    // Clicking notification opens dashboard URL if provided
}
```

Subscribe to the daemon's SSE endpoint at `/api/alerts/stream` and fire native notifications on critical findings.

## DMG Packaging

`tauri.conf.json` fragment:

```json
"bundle": {
  "active": true,
  "targets": ["dmg", "app"],
  "identifier": "com.gocloudforge.ai-runtime-monitor",
  "icon": ["icons/icon.icns", "icons/icon.png"],
  "macOS": {
    "frameworks": [],
    "minimumSystemVersion": "12.0",
    "signingIdentity": "Developer ID Application: GoCloudForge Inc (TEAMID)",
    "providerShortName": "GoCloudForge",
    "entitlements": "entitlements.plist",
    "exceptionDomain": "localhost",
    "dmg": {
      "background": "dmg-background.png",
      "windowSize": { "width": 600, "height": 400 },
      "appPosition": { "x": 175, "y": 190 },
      "applicationFolderPosition": { "x": 425, "y": 190 }
    }
  }
}
```

`entitlements.plist`:

```xml
<key>com.apple.security.network.client</key><true/>
<key>com.apple.security.network.server</key><true/>
<key>com.apple.security.files.user-selected.read-write</key><true/>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
```

## Notarization Script

`desktop/scripts/notarize.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

DMG="$1"
BUNDLE_ID="com.gocloudforge.ai-runtime-monitor"

xcrun notarytool submit "$DMG" \
  --apple-id "$APPLE_ID" \
  --team-id "$TEAM_ID" \
  --password "$APP_SPECIFIC_PASSWORD" \
  --wait

xcrun stapler staple "$DMG"
spctl --assess --type install --verbose "$DMG"
```

Credentials live in env vars or a GitHub Actions secret bundle.

## GitHub Actions Release Workflow

`.github/workflows/release.yml`:

```yaml
on:
  push:
    tags: ['v*']

jobs:
  build-dmg:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - uses: dtolnay/rust-toolchain@stable
      - name: Install Apple cert
        env:
          MACOS_CERTIFICATE_BASE64: ${{ secrets.MACOS_CERTIFICATE_BASE64 }}
          MACOS_CERTIFICATE_PWD: ${{ secrets.MACOS_CERTIFICATE_PWD }}
        run: ./scripts/import-cert.sh
      - run: npm ci
        working-directory: desktop
      - run: npm run tauri build
        working-directory: desktop
        env:
          TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}
          TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}
      - name: Notarize
        env:
          APPLE_ID: ${{ secrets.APPLE_ID }}
          TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
          APP_SPECIFIC_PASSWORD: ${{ secrets.APPLE_APP_PASSWORD }}
        run: ./desktop/scripts/notarize.sh desktop/src-tauri/target/release/bundle/dmg/*.dmg
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            desktop/src-tauri/target/release/bundle/dmg/*.dmg
            desktop/src-tauri/target/release/bundle/macos/*.app.tar.gz
            desktop/src-tauri/target/release/bundle/macos/*.app.tar.gz.sig
            latest.json
```

## Verification Checklist

```bash
# 1. Dev build runs
cd desktop && npm run tauri dev
# → Tauri window opens with setup wizard

# 2. Production build
npm run tauri build
# → DMG at src-tauri/target/release/bundle/dmg/*.dmg

# 3. Install and run from DMG
open src-tauri/target/release/bundle/dmg/*.dmg
# Drag to Applications, double-click
# → Setup wizard runs
# → Tray icon appears
# → Dashboard opens in browser

# 4. Tray states
# - Kill the LaunchAgent → tray turns gray within 5s
# - Restart it → tray turns green
# - Trigger a critical alert → tray turns red

# 5. Auto-update
# Tag v0.2.0, push, wait for CI
# Bump local app to v0.1.9 manually
# Launch → update prompt appears

# 6. Notarization passes
spctl --assess --type install --verbose AI-Runtime-Monitor.dmg
# Expected: "accepted source=Notarized Developer ID"

# 7. Clean uninstall
# Quit from menu → tray gone
# Settings → Uninstall → LaunchAgent removed, no leftover processes
```

## Stop and Ask If

- Apple Developer Program enrollment is not complete (status check: https://developer.apple.com/account)
- Signing certificates are not yet generated in Apple's portal
- Tauri signer keypair has not been generated
