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

  // MutationObserver with debounce for streaming completion
  let _debounceTimer = null;
  const observer = new MutationObserver(function() {
    clearTimeout(_debounceTimer);
    _debounceTimer = setTimeout(captureNewMessages, 2000);
  });

  function start() {
    const target = document.querySelector('main') || document.body;
    observer.observe(target, { childList: true, subtree: true });
    // Poll as fallback every 10 seconds
    setInterval(captureNewMessages, 10000);
    // Initialize — don't capture existing history
    _lastUserCount = findElements(USER_SELECTORS).length;
    _lastAssistantCount = findElements(ASSISTANT_SELECTORS).length;
    console.log('[AI-Monitor] claude.ai: found', _lastUserCount, 'user +', _lastAssistantCount, 'assistant msgs');
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
