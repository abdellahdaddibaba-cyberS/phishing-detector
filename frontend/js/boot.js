// ============================================================
// BOOT
// Entry point — runs once when the page loads
// ============================================================

// Initial render
render();

// Load scan history from the backend
loadHistory();

// Check backend health and update the sidebar status dot
(async () => {
  try {
    const r    = await fetch(`${API_BASE}/health`);
    const data = await r.json();
    const dot  = document.querySelector('.status-dot');
    const txt  = document.querySelector('.status-text');
    if (dot && txt) {
      if (data.status === 'ok') {
        dot.style.background = 'var(--safe)';
        txt.textContent = data.mongodb ? 'API + DB Online' : 'API Online (no DB)';
      } else {
        dot.style.background = 'var(--warn)';
        txt.textContent = 'API Degraded';
      }
    }
  } catch {
    const dot = document.querySelector('.status-dot');
    const txt = document.querySelector('.status-text');
    if (dot && txt) {
      dot.style.background = 'var(--danger)';
      txt.textContent = 'Backend Offline';
    }
  }
})();
