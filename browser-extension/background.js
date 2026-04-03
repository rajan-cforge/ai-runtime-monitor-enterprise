// AI Runtime Monitor — Background Service Worker
// SECURITY: Only sends to 127.0.0.1:9081. No external network calls.

const MONITOR_URL = 'http://127.0.0.1:9081/api/browser/ingest';
const BATCH_INTERVAL_MS = 5000;
const MAX_BATCH_SIZE = 100;
const MAX_OFFLINE_QUEUE = 1000;

let eventBuffer = [];

// Receive events from content scripts
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message && message.service && message.type) {
    eventBuffer.push(message);
    // Update badge count
    chrome.action.setBadgeText({ text: String(eventBuffer.length) });
    chrome.action.setBadgeBackgroundColor({ color: '#238636' });
  }
});

// Batch send events
setInterval(async function() {
  if (eventBuffer.length === 0) return;

  const batch = eventBuffer.splice(0, MAX_BATCH_SIZE);

  try {
    const response = await fetch(MONITOR_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events: batch })
    });

    if (response.ok) {
      chrome.action.setBadgeText({ text: '' });
      // Store success count
      const data = await response.json();
      const stored = await chrome.storage.local.get('todayCount');
      const today = new Date().toDateString();
      const count = (stored.todayCount?.date === today) ? stored.todayCount.count + (data.stored || 0) : (data.stored || 0);
      await chrome.storage.local.set({ todayCount: { date: today, count: count } });
    } else {
      // Put events back
      eventBuffer.unshift(...batch);
      trimBuffer();
    }
  } catch (e) {
    // Monitor offline — queue events
    eventBuffer.unshift(...batch);
    trimBuffer();
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
  }
}, BATCH_INTERVAL_MS);

function trimBuffer() {
  if (eventBuffer.length > MAX_OFFLINE_QUEUE) {
    eventBuffer = eventBuffer.slice(-MAX_OFFLINE_QUEUE);
  }
}
