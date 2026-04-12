// Copyright 2026 GoCloudForge, Inc. All rights reserved.
// Proprietary and confidential.
// Claude.ai content capture — verified selectors Apr 2026
(function() {
  // Multiple selector strategies — claude.ai changes DOM frequently
  const USER_SELECTORS = [
    '[data-testid="user-message"]',
    '.font-user-message',
    '[data-testid*="user"]',
  ];
  const ASSISTANT_SELECTORS = [
    '[data-is-streaming="false"]',
    '[data-is-streaming]',
    '[data-testid="assistant-message"]',
    '.font-claude-message',
  ];

  let _lastUserCount = 0;
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

  function captureNewMessages() {
    if (!window.AIMon) return;
    const users = findElements(USER_SELECTORS);
    const assistants = findElements(ASSISTANT_SELECTORS);

    // Only capture NEW messages beyond what we've already seen
    users.slice(_lastUserCount).forEach(function(el) {
      const text = el.textContent?.trim() || '';
      if (text.length > 10) {
        window.AIMon.sendCaptureEvent('user_prompt', text);
      }
    });
    _lastUserCount = users.length;

    assistants.slice(_lastAssistantCount).forEach(function(el) {
      // Skip still-streaming messages
      if (el.getAttribute && el.getAttribute('data-is-streaming') === 'true') return;
      const text = el.textContent?.trim() || '';
      if (text.length > 10) {
        window.AIMon.sendCaptureEvent('assistant_response', text);
      }
    });
    _lastAssistantCount = assistants.length;
  }

  // MutationObserver with debounce for streaming completion.
  // Section 6c: schedule a SECOND capture 5s after the debounce fires to
  // catch the final streaming chunk that arrives after Claude flips
  // data-is-streaming="false".
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

    // Section 6: expose selector counts to shared.js so the heartbeat can
    // report them. We override window.AIMon.getSelectorCounts after shared.js
    // has set its default — same window object, runs in document order.
    if (window.AIMon) {
      window.AIMon.getSelectorCounts = function() {
        return {
          user: findElements(USER_SELECTORS).length,
          assistant: findElements(ASSISTANT_SELECTORS).length,
        };
      };
    }

    // Section 6d: selector self-test 5s after start. If we found 0 user AND
    // 0 assistant elements, the next heartbeat will report selector_failure.
    setTimeout(function() {
      const u = findElements(USER_SELECTORS).length;
      const a = findElements(ASSISTANT_SELECTORS).length;
      if (u === 0 && a === 0) {
        console.error('[AI-Monitor] claude.ai SELECTORS BROKEN — 0 matches for both user and assistant');
      } else {
        console.log('[AI-Monitor] claude.ai self-test:', u, 'user,', a, 'assistant');
      }
    }, 5000);

    // Capture last 3 user + assistant messages for context on page load
    const users = findElements(USER_SELECTORS);
    const assistants = findElements(ASSISTANT_SELECTORS);

    users.slice(-3).forEach(function(el) {
      const text = el.textContent?.trim() || '';
      if (text.length > 10) window.AIMon?.sendCaptureEvent('user_prompt', text);
    });
    assistants.slice(-3).forEach(function(el) {
      if (el.getAttribute?.('data-is-streaming') === 'true') return;
      const text = el.textContent?.trim() || '';
      if (text.length > 10) window.AIMon?.sendCaptureEvent('assistant_response', text);
    });

    // Set counts AFTER initial capture — future captures are incremental
    _lastUserCount = users.length;
    _lastAssistantCount = assistants.length;
    console.log('[AI-Monitor] claude.ai: captured last 3 of', users.length, 'user +', assistants.length, 'assistant msgs');
  }

  // Capture on Enter key with slight delay for DOM update
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      setTimeout(captureNewMessages, 500);
    }
  }, true);

  // Delay start for SPA rendering
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { setTimeout(start, 3000); });
  } else {
    setTimeout(start, 3000);
  }
})();
