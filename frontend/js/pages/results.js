// ============================================================
// PAGE: RESULTS
// Displays score gauge, detection breakdown, and explanation
// ============================================================
function renderResults() {
  const r = state.currentResult;
  if(!r) { navigate('scan'); return ''; }
  const level = r.riskLevel;
  const color = level==='safe'?'var(--safe)':level==='suspicious'?'var(--warn)':'var(--danger)';
  const icon = level==='safe'?'✅':level==='suspicious'?'⚠️':'🎣';

  // SVG gauge
  const radius = 54; const cx=70; const cy=70;
  const circumference = Math.PI * radius;
  const pct = r.score/100;
  const dashoffset = circumference * (1 - pct);

  return `
  <div class="page" style="max-width:740px;margin:0 auto;">
    <div class="risk-banner ${level}">
      <div style="text-align:center;padding:0 10px;">
        <div class="risk-score">${r.score}</div>
        <div style="font-size:11px;font-family:var(--mono);color:${color};opacity:0.7;">/ 100</div>
      </div>
      <div style="flex:1;">
        <div class="risk-label" style="color:${color};">${icon} ${level}</div>
        <div class="risk-desc">Phishing Risk Score</div>
        <div style="margin-top:12px;">
          <div class="score-bar-wrap" style="height:6px;border-radius:3px;">
            <div class="score-bar-fill" style="width:${r.score}%;background:${color};"></div>
          </div>
        </div>
      </div>
      <div class="gauge-wrap">
        <svg width="140" height="80" viewBox="0 0 140 80">
          <path d="M 16,70 A ${radius},${radius} 0 0 1 124,70" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10" stroke-linecap="round"/>
          <path d="M 16,70 A ${radius},${radius} 0 0 1 124,70" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round"
            stroke-dasharray="${circumference}" stroke-dashoffset="${dashoffset}" style="transition:stroke-dashoffset 1s ease;"/>
          <text x="70" y="65" text-anchor="middle" font-size="18" font-family="Space Mono,monospace" font-weight="700" fill="${color}">${r.score}</text>
        </svg>
      </div>
    </div>

    <!-- Detection Breakdown -->
    <div class="card" style="margin-bottom:16px;padding:8px 0;">
      <div style="padding:0 18px 10px;"><div class="section-title">Detection <span>Breakdown</span></div></div>

      <!-- Linguistic -->
      <div class="collapse-header" onclick="toggleCollapse('linguistic')">
        <div style="display:flex;align-items:center;gap:10px;">
          <span>📝</span>
          <span style="font-size:14px;font-weight:500;">Linguistic Indicators</span>
          <span class="badge ${r.linguisticFlags.length?'suspicious':'safe'}">${r.linguisticFlags.length}</span>
        </div>
        <span style="color:var(--text3)">${state.collapseState.linguistic?'▲':'▼'}</span>
      </div>
      ${state.collapseState.linguistic?`
      <div class="collapse-body">
        ${r.linguisticFlags.length
          ? r.linguisticFlags.map(f=>`<span class="flag-pill">"${f}"</span>`).join('')
          : '<div class="empty-flag">No linguistic indicators detected.</div>'}
      </div>`:''}
      <hr style="border:none;border-top:1px solid var(--border);margin:0 18px;">

      <!-- URL -->
      <div class="collapse-header" onclick="toggleCollapse('url')">
        <div style="display:flex;align-items:center;gap:10px;">
          <span>🔗</span>
          <span style="font-size:14px;font-weight:500;">URL Anomalies</span>
          <span class="badge ${r.urlFlags.length?'suspicious':'safe'}">${r.urlFlags.length}</span>
        </div>
        <span style="color:var(--text3)">${state.collapseState.url?'▲':'▼'}</span>
      </div>
      ${state.collapseState.url?`
      <div class="collapse-body">
        ${r.urlFlags.length
          ? r.urlFlags.map(f=>`<span class="flag-pill url">${f}</span>`).join('')
          : '<div class="empty-flag">No URL anomalies detected.</div>'}
      </div>`:''}
    </div>

    <!-- Explanation -->
    <div class="explain-box">
      <div class="explain-title">💡 Why this was flagged</div>
      <div class="explain-text">${r.explanation}</div>
    </div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <button class="btn btn-primary" onclick="navigate('scan')">🔍 Scan Another</button>
      <button class="btn btn-secondary" onclick="saveToHistory()">💾 Save to History</button>
      <button class="btn btn-ghost" onclick="navigate('history')">📋 View History</button>
    </div>
  </div>`;
}
