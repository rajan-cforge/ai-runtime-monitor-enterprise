// Claude.ai specific selectors and observers
(function() {
  const SELECTORS = {
    userMessage: '[data-testid="user-message"], .font-user-message',
    assistantMessage: '[data-testid="assistant-message"], .font-claude-message',
    inputArea: '[contenteditable="true"], textarea',
    messageContainer: 'main, [role="main"], .conversation-container'
  };

  let observedMessages = new WeakSet();

  function extractText(el) {
    return el ? el.textContent?.trim() || '' : '';
  }

  function scanExistingMessages() {
    document.querySelectorAll(SELECTORS.assistantMessage).forEach(function(el) {
      if (!observedMessages.has(el)) {
        observedMessages.add(el);
        const text = extractText(el);
        if (text.length > 10) {
          window.AIMon.sendCaptureEvent('assistant_response', text);
        }
      }
    });
  }

  // Watch for new messages via MutationObserver
  const observer = new MutationObserver(function(mutations) {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        // Check if added node is or contains a message
        const assistants = node.matches?.(SELECTORS.assistantMessage)
          ? [node]
          : Array.from(node.querySelectorAll?.(SELECTORS.assistantMessage) || []);

        assistants.forEach(function(el) {
          if (!observedMessages.has(el)) {
            observedMessages.add(el);
            // Delay to let streaming finish
            setTimeout(function() {
              const text = extractText(el);
              if (text.length > 10) {
                window.AIMon.sendCaptureEvent('assistant_response', text);
              }
            }, 2000);
          }
        });
      }
    }
  });

  // Start observing
  function startObserving() {
    const target = document.querySelector(SELECTORS.messageContainer) || document.body;
    observer.observe(target, { childList: true, subtree: true });
    scanExistingMessages();
  }

  // Handle submit (user prompt capture)
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      const input = document.querySelector(SELECTORS.inputArea);
      if (input) {
        const text = extractText(input);
        if (text.length > 0) {
          window.AIMon.sendCaptureEvent('user_prompt', text);
        }
      }
    }
  }, true);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startObserving);
  } else {
    startObserving();
  }
})();
