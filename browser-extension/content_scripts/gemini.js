(function() {
  const SELECTORS = {
    assistantMessage: 'message-content, .model-response-text',
    inputArea: 'rich-textarea, .ql-editor, textarea',
    messageContainer: 'main, .conversation-container'
  };

  let observedMessages = new WeakSet();

  function extractText(el) {
    return el ? el.textContent?.trim() || '' : '';
  }

  const observer = new MutationObserver(function(mutations) {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;
        const msgs = node.matches?.(SELECTORS.assistantMessage)
          ? [node]
          : Array.from(node.querySelectorAll?.(SELECTORS.assistantMessage) || []);
        msgs.forEach(function(el) {
          if (!observedMessages.has(el)) {
            observedMessages.add(el);
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

  function start() {
    const target = document.querySelector(SELECTORS.messageContainer) || document.body;
    observer.observe(target, { childList: true, subtree: true });
  }

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
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
