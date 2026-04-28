// ============================================================
// PAGE: DASHBOARD
// Shows stats, risk distribution chart, and recent scans table
// ============================================================
function renderDashboard() {
  const total = state.scans.length;
  const phishing = state.scans.filter(s=>s.result.riskLevel==='phishing').length;
  const suspicious = state.scans.filter(s=>s.result.riskLevel==='suspicious').length;
  const safe = state.scans.filter(s=>s.result.riskLevel==='safe').length;
  const recent = [...state.scans].sort((a,b)=>b.id-a.id).slice(0,5);
  const safePct = Math.round(safe/total*100);
  const suspPct = Math.round(suspicious/total*100);
  const fishPct = Math.round(phishing/total*100);

  return `
  <div class="page">
    <div class="metric-grid">
      <div class="metric-card blue">
        <div class="metric-label">Total Scans</div>
        <div class="metric-value">${total}</div>
        <div class="metric-icon">🔬</div>
      </div>
      <div class="metric-card red">
        <div class="metric-label">Phishing</div>
        <div class="metric-value">${phishing}</div>
        <div class="metric-icon">🎣</div>
      </div>
      <div class="metric-card amber">
        <div class="metric-label">Suspicious</div>
        <div class="metric-value">${suspicious}</div>
        <div class="metric-icon">⚠️</div>
      </div>
      <div class="metric-card green">
        <div class="metric-label">Safe</div>
        <div class="metric-value">${safe}</div>
        <div class="metric-icon">✅</div>
      </div>
    </div>

    <div class="two-col">
      <div class="card">
        <div class="section-header">
          <div class="section-title">Risk <span>Distribution</span></div>
        </div>
        <div class="bar-chart">
          <div class="bar-row">
            <div class="bar-name">Safe</div>
            <div class="bar-track"><div class="bar-fill" style="width:${safePct}%;background:var(--safe);"></div></div>
            <div class="bar-pct">${safePct}%</div>
          </div>
          <div class="bar-row">
            <div class="bar-name">Suspicious</div>
            <div class="bar-track"><div class="bar-fill" style="width:${suspPct}%;background:var(--warn);"></div></div>
            <div class="bar-pct">${suspPct}%</div>
          </div>
          <div class="bar-row">
            <div class="bar-name">Phishing</div>
            <div class="bar-track"><div class="bar-fill" style="width:${fishPct}%;background:var(--danger);"></div></div>
            <div class="bar-pct">${fishPct}%</div>
          </div>
        </div>
        <hr class="divider">
        <div style="display:flex;gap:18px;font-size:12px;font-family:var(--mono);">
          <span style="color:var(--safe)">● Safe: ${safe}</span>
          <span style="color:var(--warn)">● Suspicious: ${suspicious}</span>
          <span style="color:var(--danger)">● Phishing: ${phishing}</span>
        </div>
      </div>

      <div class="card">
        <div class="section-header">
          <div class="section-title">Score <span>Breakdown</span></div>
        </div>
        <div style="display:flex;flex-direction:column;gap:10px;">
          ${state.scans.slice(0,6).map(s=>`
          <div>
            <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
              <span style="font-size:11px;color:var(--text2);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${s.preview.substring(0,40)}…</span>
              <span style="font-size:11px;font-family:var(--mono);color:${scoreColor(s.result.score)}">${s.result.score}</span>
            </div>
            <div class="score-bar-wrap"><div class="score-bar-fill" style="width:${s.result.score}%;background:${scoreColor(s.result.score)};"></div></div>
          </div>`).join('')}
        </div>
      </div>
    </div>

    <div style="margin-top:18px;" class="card">
      <div class="section-header">
        <div class="section-title">Recent <span>Scans</span></div>
        <button class="btn btn-ghost" style="font-size:12px;padding:6px 12px;" onclick="navigate('history')">View all →</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Date</th><th>Message Preview</th><th>Risk Level</th><th>Score</th><th></th></tr></thead>
          <tbody>
            ${recent.map(s=>`
            <tr>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);">${formatDate(s.date)}</td>
              <td><div class="preview-text">${s.preview}</div></td>
              <td><span class="badge ${s.result.riskLevel}">${s.result.riskLevel.toUpperCase()}</span></td>
              <td><span style="font-family:var(--mono);font-size:13px;color:${scoreColor(s.result.score)};font-weight:700;">${s.result.score}</span></td>
              <td><button class="btn btn-ghost" style="font-size:11px;padding:5px 10px;" onclick="viewResult('${s.id}')">View</button></td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>`;
}
