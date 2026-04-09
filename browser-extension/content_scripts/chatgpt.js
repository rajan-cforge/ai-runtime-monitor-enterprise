// Copyright 2026 GoCloudForge, Inc. All rights reserved.
// Proprietary and confidential.
(function() {
  // ChatGPT changes DOM frequently — use multiple fallback selectors
  const ASSISTANT_SELECTORS = [
    '[data-message-author-role="assistant"] .markdown',
    '[data-message-author-role="assistant"]',
    'article [data-message-author-role="assistant"]',
    '.agent-turn .markdown',
    '.markdown.prose',
  ];
  const INPUT_SELECTORS = [
    '#prompt-textarea',
    'div[contenteditable="true"][id="prompt-textarea"]',
    '#prompt-textarea p',
    'textarea[data-id="root"]',
  ];

  let observedMessages = new WeakSet();
  let lastAssistantCount = 0;

  function extractText(el) {
    return el ? el.textContent?.trim() || '' : '';
  }

  function findAssistantMessages() {
    for (const sel of ASSISTANT_SELECTORS) {
      const els = document.querySelectorAll(sel);
      if (els.length > 0) return Array.from(els);
    }
    return [];
  }

  function findInput() {
    for (const sel of INPUT_SELECTORS) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  // Poll-based approach: check for new assistant messages every 3 seconds
  // This is more reliable than MutationObserver for ChatGPT's streaming DOM
  function pollForNewMessages() {
    const messages = findAssistantMessages();
    if (messages.length > lastAssistantCount) {
      // New messages appeared — capture the latest ones
      const newMsgs = messages.slice(lastAssistantCount);
      for (const el of newMsgs) {
        if (!observedMessages.has(el)) {
          observedMessages.add(el);
          const text = extractText(el);
          if (text.length > 10) {
            window.AIMon?.sendCaptureEvent('assistant_response', text);
          }
        }
      }
      lastAssistantCount = messages.length;
    }
  }

  // Also keep MutationObserver as a backup for immediate detection
  const observer = new MutationObserver(function() {
    // Debounce: wait 2 seconds after last mutation for streaming to finish
    clearTimeout(observer._timeout);
    observer._timeout = setTimeout(pollForNewMessages, 2000);
  });

  function start() {
    const target = document.querySelector('main') || document.body;
    observer.observe(target, { childList: true, subtree: true });
    setInterval(pollForNewMessages, 5000);

    // Self-test: log which selectors match
    for (const sel of ASSISTANT_SELECTORS) {
      try {
        const count = document.querySelectorAll(sel).length;
        if (count > 0) console.log('[AI-Monitor] ChatGPT selector match:', sel, '→', count);
      } catch(e) {}
    }

    // Capture last 3 assistant messages on load for context
    const msgs = findAssistantMessages();
    msgs.slice(-3).forEach(function(el) {
      const text = extractText(el);
      if (text.length > 10) window.AIMon?.sendCaptureEvent('assistant_response', text);
    });
    lastAssistantCount = msgs.length;
    console.log('[AI-Monitor] chatgpt.com: found', msgs.length, 'assistant messages');
  }

  // Capture user prompt on Enter
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      const input = findInput();
      if (input) {
        const text = extractText(input);
        if (text.length > 0) {
          window.AIMon?.sendCaptureEvent('user_prompt', text);
        }
      }
    }
  }, true);

  // Also capture on click of the send button
  document.addEventListener('click', function(e) {
    const btn = e.target.closest('button[data-testid="send-button"], button[aria-label="Send prompt"]');
    if (btn) {
      const input = findInput();
      if (input) {
        const text = extractText(input);
        if (text.length > 0) {
          window.AIMon?.sendCaptureEvent('user_prompt', text);
        }
      }
    }
  }, true);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    // Delay start to let ChatGPT SPA render
    setTimeout(start, 2000);
  }
})();
