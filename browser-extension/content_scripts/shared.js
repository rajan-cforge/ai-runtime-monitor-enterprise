// Copyright 2026 GoCloudForge, Inc. All rights reserved.
// Proprietary and confidential.
// AI Runtime Monitor — Content Script (shared)
// SECURITY: Read-only DOM observation. No page modification. No external network calls.

const MAX_TEXT_LENGTH = 5000;
let lastEventTime = 0;
const MIN_EVENT_INTERVAL_MS = 2000; // 2 seconds between events

// Content dedup: track captured hashes per conversation+type
// Survives within page session, resets on full page reload (which is correct)
const _capturedHashes = new Map(); // key: "convId_type_hash" → timestamp
const DEDUP_WINDOW_MS = 86400000; // 24 hours

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h) + str.charCodeAt(i);
    h |= 0;
  }
  return h.toString(36);
}

function truncateText(text) {
  if (!text) return '';
  return text.length > MAX_TEXT_LENGTH ? text.substring(0, MAX_TEXT_LENGTH) : text;
}

function getService() {
  const host = window.location.hostname;
  if (host.includes('claude.ai')) return 'Claude Web';
  if (host.includes('chatgpt.com') || host.includes('chat.openai.com')) return 'ChatGPT';
  if (host.includes('gemini.google.com')) return 'Gemini';
  if (host.includes('perplexity.ai')) return 'Perplexity';
  return 'Unknown';
}

function getConversationId() {
  const path = window.location.pathname;
  const service = getService();
  if (service === 'ChatGPT' && path.includes('/c/')) {
    return path.split('/c/')[1]?.split('/')[0]?.split('?')[0] || null;
  }
  if (service === 'Gemini' && path.includes('/app/')) {
    return path.split('/app/')[1]?.split('/')[0]?.split('?')[0] || null;
  }
  if (service === 'Claude Web' && path.includes('/chat/')) {
    return path.split('/chat/')[1]?.split('/')[0]?.split('?')[0] || null;
  }
  return null;
}

function sendCaptureEvent(type, text) {
  const now = Date.now();
  if (now - lastEventTime < MIN_EVENT_INTERVAL_MS) return;
  if (!text || text.length < 10) return;

  // Content-based dedup: hash first 200 chars, keyed by conversation+type
  const convId = getConversationId() || 'unknown';
  const hash = simpleHash(text.substring(0, 200));
  const dedupKey = convId + '_' + type + '_' + hash;

  const lastSeen = _capturedHashes.get(dedupKey);
  if (lastSeen && (now - lastSeen) < DEDUP_WINDOW_MS) return; // Same content within 1 hour
  _capturedHashes.set(dedupKey, now);

  // Cleanup old entries periodically
  if (_capturedHashes.size > 200) {
    for (const [k, v] of _capturedHashes) {
      if (now - v > DEDUP_WINDOW_MS) _capturedHashes.delete(k);
    }
  }

  lastEventTime = now;

  const event = {
    service: getService(),
    url: window.location.href,
    timestamp: new Date().toISOString(),
    type: type,
    text: truncateText(text),
    conversation_id: convId !== 'unknown' ? convId : null,
    title: document.title
  };

  try {
    chrome.runtime.sendMessage(event);
  } catch (e) {
    // Extension context invalidated — page was reloaded
  }
}

// ─── Section 6: extension heartbeat ────────────────────────────
// Every 60 seconds the content script reports selector match counts to the
// monitor. The monitor's dashboard surfaces a yellow warning banner when:
//   - A heartbeat hasn't arrived in 5+ minutes (extension crashed/blocked), or
//   - Selector match counts drop to 0 (Anthropic/OpenAI/Google shipped a DOM
//     change and our scrapers stopped matching).
// Site-specific scripts override window.AIMon.getSelectorCounts() to plug
// in their own selector lists. Default returns zeros so unconfigured pages
// still send a heartbeat (so we can tell the extension is alive).
let _capturesSent = 0;
let _lastSelectorFailureReported = 0;
// Per-type captures since the last heartbeat. Lets us report meaningful
// counts for event-driven user-prompt capture sites (ChatGPT, Gemini)
// where the DOM has no scrapeable user input — the input clears on
// submit, so the only signal is the Enter/send-button event that fires
// once per prompt. Reset to zero on every heartbeat.
let _captureWindow = { user_prompt: 0, assistant_response: 0 };

function _defaultSelectorCounts() {
  return { user: 0, assistant: 0 };
}

async function sendHeartbeat(extra) {
  const counts = (window.AIMon && window.AIMon.getSelectorCounts)
    ? window.AIMon.getSelectorCounts()
    : _defaultSelectorCounts();
  // Take the higher of (DOM matches right now) and (capture events
  // flowed through us since the last heartbeat). Either signal is
  // sufficient evidence the site is actively monitored:
  //   - DOM-scraping sites (claude.ai) report DOM counts — historical
  //     prompts/responses still on the page.
  //   - Event-driven sites (ChatGPT, Gemini) report the count of
  //     prompts the user typed in the last 60s — DOM count is always 0.
  // Using max() means selector_failure only trips when BOTH sources
  // are silent, which is the correct condition for "extension is
  // alive but not seeing any AI activity".
  const userMatches = Math.max(counts.user || 0, _captureWindow.user_prompt);
  const assistantMatches = Math.max(counts.assistant || 0, _captureWindow.assistant_response);
  const failure = (userMatches === 0 && assistantMatches === 0);
  // Reset the per-heartbeat capture window
  _captureWindow = { user_prompt: 0, assistant_response: 0 };
  const body = Object.assign({
    hostname: window.location.hostname,
    user_matches: userMatches,
    assistant_matches: assistantMatches,
    captures_sent: _capturesSent,
    selector_failure: failure,
    timestamp: new Date().toISOString(),
  }, extra || {});
  try {
    await fetch('http://127.0.0.1:9081/api/browser/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) {
    // Monitor not running — silently drop. Extension keeps trying every 60s.
  }
}

// Wrap sendCaptureEvent to count successful sends for the heartbeat
const _origSendCaptureEvent = sendCaptureEvent;
function sendCaptureEventTracked(type, text) {
  _origSendCaptureEvent(type, text);
  _capturesSent += 1;
  if (type === 'user_prompt') _captureWindow.user_prompt += 1;
  else if (type === 'assistant_response') _captureWindow.assistant_response += 1;
}

// Export for site-specific scripts
if (typeof window !== 'undefined') {
  window.AIMon = {
    sendCaptureEvent: sendCaptureEventTracked,
    sendHeartbeat,
    truncateText,
    getService,
    getConversationId,
    getSelectorCounts: _defaultSelectorCounts,
  };

  // Start the heartbeat loop. First beat fires after 5 seconds so the
  // selector self-test (Section 6d) can populate its findElements counts
  // before we ask for them.
  setTimeout(function() {
    sendHeartbeat();
    setInterval(sendHeartbeat, 60000);
  }, 5000);
}
