// Copyright 2026 GoCloudForge, Inc. All rights reserved.
// Proprietary and confidential.
// Gemini content capture
(function() {
  const ASSISTANT_SELECTORS = [
    'message-content',
    '.model-response-text',
    '[data-message-id] .markdown',
  ];
  const INPUT_SELECTORS = [
    'rich-textarea',
    '.ql-editor',
    'textarea',
  ];

  let _lastAssistantCount = 0;

  function findElements(selectors) {
    for (const sel of selectors) {
      try {
        const els = document.querySelectorAll(sel);
        if (els.length > 0) return Array.from(els);
      } catch(e) {}
    }
    return [];
  }

  function extractText(el) {
    return el ? el.textContent?.trim() || '' : '';
  }

  function captureNewMessages() {
    if (!window.AIMon) return;
    const msgs = findElements(ASSISTANT_SELECTORS);
    msgs.slice(_lastAssistantCount).forEach(function(el) {
      const text = extractText(el);
      if (text.length > 10) window.AIMon.sendCaptureEvent('assistant_response', text);
    });
    _lastAssistantCount = msgs.length;
  }

  // Section 6c: re-poll 5s later to catch the final streaming chunk.
  let _debounceTimer = null;
  const observer = new MutationObserver(function() {
    clearTimeout(_debounceTimer);
    _debounceTimer = setTimeout(function() {
      captureNewMessages();
      setTimeout(captureNewMessages, 5000);
    }, 2000);
  });

  function start() {
    const target = document.querySelector('main') || document.body;
    observer.observe(target, { childList: true, subtree: true });
    setInterval(captureNewMessages, 10000);

    // Section 6: heartbeat selector counts.
    if (window.AIMon) {
      window.AIMon.getSelectorCounts = function() {
        return { user: 0, assistant: findElements(ASSISTANT_SELECTORS).length };
      };
    }

    // Capture last 3 assistant messages on load
    const msgs = findElements(ASSISTANT_SELECTORS);
    msgs.slice(-3).forEach(function(el) {
      const text = extractText(el);
      if (text.length > 10) window.AIMon?.sendCaptureEvent('assistant_response', text);
    });
    _lastAssistantCount = msgs.length;
    console.log('[AI-Monitor] gemini: found', msgs.length, 'assistant messages');
  }

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      const input = document.querySelector(INPUT_SELECTORS.join(', '));
      if (input) {
        const text = extractText(input);
        if (text.length > 0) window.AIMon?.sendCaptureEvent('user_prompt', text);
      }
    }
  }, true);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { setTimeout(start, 3000); });
  } else {
    setTimeout(start, 3000);
  }
})();
