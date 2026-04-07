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
const DEDUP_WINDOW_MS = 3600000; // 1 hour

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

// Export for site-specific scripts
if (typeof window !== 'undefined') {
  window.AIMon = { sendCaptureEvent, truncateText, getService, getConversationId };
}
