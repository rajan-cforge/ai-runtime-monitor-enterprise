// Check monitor status
async function checkStatus() {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  try {
    const r = await fetch('http://127.0.0.1:9081/api/stats', { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      dot.className = 'dot online';
      text.textContent = 'Connected to monitor';
    } else {
      dot.className = 'dot offline';
      text.textContent = 'Monitor error';
    }
  } catch (e) {
    dot.className = 'dot offline';
    text.textContent = 'Monitor not running';
  }
}

// Load counts
async function loadCounts() {
  const stored = await chrome.storage.local.get('todayCount');
  const today = new Date().toDateString();
  const count = (stored.todayCount?.date === today) ? stored.todayCount.count : 0;
  document.getElementById('today-count').textContent = count;
}

checkStatus();
loadCounts();
