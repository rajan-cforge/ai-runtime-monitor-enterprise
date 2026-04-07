// AI Runtime Monitor — Content Script (shared)
// SECURITY: Read-only DOM observation. No page modification. No external network calls.
// All captured text truncated to 5000 chars. Rate limited to 1 event/sec.

const MAX_TEXT_LENGTH = 5000;
let lastEventTime = 0;
const MIN_EVENT_INTERVAL_MS = 1000;
let _lastContentHash = '';

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
  // Content-based dedup: skip if same text captured recently
  const hash = simpleHash((text || '').substring(0, 200));
  if (hash === _lastContentHash) return;
  _lastContentHash = hash;
  lastEventTime = now;

  const event = {
    service: getService(),
    url: window.location.href,
    timestamp: new Date().toISOString(),
    type: type,  // 'user_prompt' or 'assistant_response'
    text: truncateText(text),
    conversation_id: getConversationId(),
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
