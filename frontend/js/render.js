// ============================================================
// RENDER ENGINE
// Core rendering: app shell, sidebar, topbar, page router
// ============================================================

function render() {
  const app = document.getElementById('app');
  app.innerHTML = `
    <div class="app">
      ${renderSidebar()}
      <div class="main">
        ${renderTopbar()}
        <div class="content">${renderPage()}</div>
      </div>
    </div>
  `;
  attachListeners();
}

function renderSidebar() {
  const navItems = [
    { id:'dashboard', icon:'📊', label:'Dashboard' },
    { id:'scan', icon:'🔍', label:'New Scan' },
    { id:'history', icon:'📋', label:'History' },
    { id:'settings', icon:'⚙️', label:'Settings' },
  ];
  return `
  <nav class="sidebar">
    <div class="sidebar-logo">
      <div class="logo-icon">🛡️</div>
      <div>
        <div class="logo-name">PhishGuard</div>
        <div class="logo-version">v1.0 · MDP Project</div>
      </div>
    </div>
    <div class="nav-section">Navigation</div>
    <div class="nav">
      ${navItems.map(n=>`
        <div class="nav-item ${state.page===n.id?'active':''}" data-nav="${n.id}">
          <span class="nav-icon">${n.icon}</span> ${n.label}
        </div>`).join('')}
    </div>
    <div class="sidebar-footer">
      <span class="status-dot"></span>
      <span class="status-text">System Online</span>
    </div>
  </nav>`;
}

function renderTopbar() {
  const titles = {
    dashboard: 'Dashboard',
    scan:      'New Scan',
    history:   'Scan History',
    results:   'Analysis Results',
    settings:  'Settings',
  };
  return `
  <div class="topbar">
    <div class="topbar-title">PHISHGUARD / ${(titles[state.page]||'').toUpperCase()}</div>
    <div class="topbar-right">
      <span style="font-size:11px;font-family:var(--mono);color:var(--text3);">Scans: ${state.scans.length}</span>
      <div class="avatar">AD</div>
    </div>
  </div>`;
}

function renderPage() {
  if (state.page === 'dashboard') return renderDashboard();
  if (state.page === 'scan')      return renderScan();
  if (state.page === 'results')   return renderResults();
  if (state.page === 'history')   return renderHistory();
  if (state.page === 'settings')  return renderSettings();
  return '';
}
