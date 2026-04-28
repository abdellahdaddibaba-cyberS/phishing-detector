// ============================================================
// PAGE: HISTORY
// Shows paginated scan history with search and filter
// ============================================================
function renderHistory() {
  let filtered = state.scans.filter(s => {
    const matchFilter = state.historyFilter==='all' || s.result.riskLevel===state.historyFilter;
    const matchSearch = s.preview.toLowerCase().includes(state.historySearch.toLowerCase());
    return matchFilter && matchSearch;
  });
  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total/ITEMS_PER_PAGE));
  const pg = Math.min(state.historyPage, totalPages);
  const paged = filtered.slice((pg-1)*ITEMS_PER_PAGE, pg*ITEMS_PER_PAGE);
  const filters = ['all','safe','suspicious','phishing'];

  return `
  <div class="page">
    <div class="history-controls">
      <div class="search-input-wrap">
        <span class="search-icon">🔍</span>
        <input type="text" id="history-search" placeholder="Search scans…" value="${state.historySearch}">
      </div>
      <div class="filter-pills">
        ${filters.map(f=>`<div class="filter-pill ${state.historyFilter===f?'active':''}" data-filter="${f}">${f.charAt(0).toUpperCase()+f.slice(1)}</div>`).join('')}
      </div>
    </div>

    <div class="card">
      <div class="section-header">
        <div class="section-title">Scan <span>Log</span> <span style="color:var(--text3)">(${total})</span></div>
      </div>
      ${paged.length===0 ? `
        <div class="empty-state">
          <div class="empty-icon">📭</div>
          <div class="empty-msg">No scans found for your search or filter.</div>
        </div>` : `
      <div class="table-wrap">
        <table>
          <thead><tr><th>Date</th><th>Preview</th><th>Risk Level</th><th>Score</th><th>Action</th></tr></thead>
          <tbody>
            ${paged.map(s=>`
            <tr>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap;">${formatDate(s.date)}</td>
              <td>
                <div class="preview-text">${s.preview}</div>
                <div class="score-bar-wrap" style="margin-top:6px;max-width:200px;"><div class="score-bar-fill" style="width:${s.result.score}%;background:${scoreColor(s.result.score)};"></div></div>
              </td>
              <td><span class="badge ${s.result.riskLevel}">${s.result.riskLevel.toUpperCase()}</span></td>
              <td><span style="font-family:var(--mono);font-size:14px;font-weight:700;color:${scoreColor(s.result.score)};">${s.result.score}</span></td>
              <td><button class="btn btn-ghost" style="font-size:11px;padding:5px 10px;" onclick="viewResult('${s.id}')">View →</button></td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
      <div class="pagination">
        <span class="page-info">Page ${pg} of ${totalPages}</span>
        <button class="page-btn" onclick="changePage(${pg-1})" ${pg<=1?'disabled':''}>← Prev</button>
        <button class="page-btn" onclick="changePage(${pg+1})" ${pg>=totalPages?'disabled':''}>Next →</button>
      </div>`}
    </div>
  </div>`;
}
