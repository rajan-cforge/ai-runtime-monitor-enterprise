# AI Runtime Monitor — Browser Extension

Chrome extension for monitoring AI chat sessions (Claude, ChatGPT, Gemini).

## Features

- Captures user prompts and assistant responses from AI chat pages
- Sends captured data to the local AI Runtime Monitor (localhost:9081)
- All data stays on your machine — no external network calls
- Read-only DOM observation — does not modify pages

## Installation (Development)

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked" and select this directory
4. Navigate to any supported AI chat page

## Supported Sites

- claude.ai
- chatgpt.com / chat.openai.com
- gemini.google.com

## Privacy

- All captured data is sent only to localhost:9081
- No external network calls, no telemetry, no analytics
- Extension does not modify page content
- Text is truncated to 5000 characters
