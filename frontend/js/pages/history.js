// ============================================================
// PAGE: HISTORY
// Shows paginated scan history with search, filter, and delete
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
    <!-- CONFIRMATION MODAL -->
    ${state.confirmModal ? `
    <div style="position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:9000;display:flex;align-items:center;justify-content:center;">
      <div style="background:var(--surface);border:1px solid var(--border2);border-radius:14px;padding:28px 32px;max-width:380px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.25);">
        <div style="font-size:24px;margin-bottom:10px;">${state.confirmModal.icon}</div>
        <div style="font-size:16px;font-weight:600;color:var(--text);margin-bottom:8px;">${state.confirmModal.title}</div>
        <div style="font-size:13px;color:var(--text2);margin-bottom:22px;line-height:1.6;">${state.confirmModal.message}</div>
        <div style="display:flex;gap:10px;justify-content:flex-end;">
          <button class="btn btn-ghost" onclick="closeConfirmModal()">Cancel</button>
          <button class="btn btn-danger" onclick="${state.confirmModal.action}">
            🗑 ${state.confirmModal.confirmLabel}
          </button>
        </div>
      </div>
    </div>` : ''}

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
        <div style="display:flex;gap:8px;">
          ${state.selectedScans && state.selectedScans.size > 0 ? `
          <button class="btn btn-danger" style="font-size:12px;padding:6px 12px;" onclick="confirmDeleteSelected()">
            🗑 Delete Selected (${state.selectedScans.size})
          </button>` : ''}
          <button class="btn btn-danger" style="font-size:12px;padding:6px 12px;" onclick="confirmDeleteAll()" ${total===0?'disabled':''}>
            🗑 Delete All
          </button>
        </div>
      </div>
      ${paged.length===0 ? `
        <div class="empty-state">
          <div class="empty-icon">📭</div>
          <div class="empty-msg">No scans found for your search or filter.</div>
        </div>` : `
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th style="width:36px;"><input type="checkbox" id="select-all-cb" onchange="toggleSelectAll(this.checked)" style="cursor:pointer;accent-color:var(--accent);"></th>
            <th>Date</th><th>Preview</th><th>Risk Level</th><th>Score</th><th>Action</th>
          </tr></thead>
          <tbody>
            ${paged.map(s=>`
            <tr>
              <td>
                <input type="checkbox" class="scan-cb" data-id="${s.id}"
                  onchange="toggleSelectScan('${s.id}', this.checked)"
                  ${state.selectedScans && state.selectedScans.has(s.id) ? 'checked' : ''}
                  style="cursor:pointer;accent-color:var(--accent);">
              </td>
              <td style="font-family:var(--mono);font-size:11px;color:var(--text3);white-space:nowrap;">${formatDate(s.date)}</td>
              <td>
                <div class="preview-text">${s.preview}</div>
                <div class="score-bar-wrap" style="margin-top:6px;max-width:200px;"><div class="score-bar-fill" style="width:${s.result.score}%;background:${scoreColor(s.result.score)};"></div></div>
              </td>
              <td><span class="badge ${s.result.riskLevel}">${s.result.riskLevel.toUpperCase()}</span></td>
              <td><span style="font-family:var(--mono);font-size:14px;font-weight:700;color:${scoreColor(s.result.score)};">${s.result.score}</span></td>
              <td style="display:flex;gap:6px;align-items:center;">
                <button class="btn btn-ghost" style="font-size:11px;padding:5px 10px;" onclick="viewResult('${s.id}')">View →</button>
                <button class="btn btn-danger" style="font-size:11px;padding:5px 9px;" onclick="confirmDeleteOne('${s.id}')">🗑</button>
              </td>
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
