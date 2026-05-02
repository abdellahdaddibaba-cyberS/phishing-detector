// ============================================================
// ACTIONS
// All user interactions: navigation, scanning, file picking,
// history loading, settings saving, and event listeners
// ============================================================
function attachListeners() {
  // Nav
  document.querySelectorAll('[data-nav]').forEach(el=>{
    el.addEventListener('click', ()=>navigate(el.dataset.nav));
  });
  // Tabs
  document.querySelectorAll('[data-tab]').forEach(el=>{
    el.addEventListener('click', ()=>{ state.scanTab=el.dataset.tab; render(); });
  });
  // Filters
  document.querySelectorAll('[data-filter]').forEach(el=>{
    el.addEventListener('click', ()=>{ state.historyFilter=el.dataset.filter; state.historyPage=1; render(); });
  });
  // History search
  const hs = document.getElementById('history-search');
  if(hs) hs.addEventListener('input', e=>{
    const val = e.target.value;
    const selStart = e.target.selectionStart;
    const selEnd   = e.target.selectionEnd;
    state.historySearch = val;
    state.historyPage = 1;
    render();
    const newHs = document.getElementById('history-search');
    if(newHs){ newHs.focus(); newHs.setSelectionRange(selStart, selEnd); }
  });
  // Full email textarea
  const se = document.getElementById('scan-email');
  if(se) {
    se.addEventListener('input', e=>{ state.scanEmail=e.target.value; document.getElementById('email-char-count').textContent=e.target.value.length+' characters'; });
  }
  // Scan text
  const st = document.getElementById('scan-text');
  if(st) {
    st.addEventListener('input', e=>{ state.scanText=e.target.value; document.getElementById('char-count').textContent=e.target.value.length+' characters'; });
  }
  // Scan URL
  const su = document.getElementById('scan-url');
  if(su) su.addEventListener('change', e=>state.scanUrl=e.target.value);
  // Sliders
  ['ling','url'].forEach(k=>{
    const el = document.getElementById('sl-'+k);
    if(el) el.addEventListener('input', e=>{
      const map={ling:'lingWeight',url:'urlWeight'};
      state.settings[map[k]] = +e.target.value;
      document.getElementById('sv-'+k).textContent='+'+e.target.value;
      document.getElementById('total-weight').textContent = state.settings.lingWeight+state.settings.urlWeight;
    });
  });
  // Thresholds
  ['susp','fish'].forEach(k=>{
    const el = document.getElementById('thresh-'+k);
    if(el) el.addEventListener('input', e=>{
      state.settings[k==='susp'?'suspThresh':'fishThresh'] = +e.target.value;
      validateThresh();
    });
  });
}

function navigate(page) {
  state.page=page;
  render();
  window.scrollTo(0,0);
  if (page === 'history' && !state.historyLoaded) {
    loadHistory();
  }
}
function viewResult(id) {
  const scan = state.scans.find(s=>s.id===id);
  if(scan){ state.currentResult=scan.result; state.page='results'; render(); window.scrollTo(0,0); }
}
function changePage(p) { state.historyPage=p; render(); }
function toggleCollapse(k) { state.collapseState[k]=!state.collapseState[k]; render(); }
function applyTheme() {
  if (state.settings.darkMode) {
    document.body.classList.add('dark-mode');
  } else {
    document.body.classList.remove('dark-mode');
  }
}
function toggleDark() {
  state.settings.darkMode = !state.settings.darkMode;
  applyTheme();
  render();
}

function openEmlPicker() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.eml,.msg';
  input.onchange = e => {
    const file = e.target.files[0];
    if (file) {
      state.emlFile = file;
      state.emlFileName = file.name;
      state.scanEmail = '';
      render();
    }
  };
  input.click();
}

async function startScan() {
  if (state.scanning) return;

  const textVal = state.scanText.trim();
  const urlVal  = state.scanUrl.trim();
  if (state.scanTab === 'email' && !state.scanEmail.trim() && !state.emlFile) { showToast('Please upload a .eml file or paste email content', 'error'); return; }
  if (state.scanTab === 'text' && !textVal) { showToast('Please enter message content', 'error'); return; }
  if (state.scanTab === 'url'  && !urlVal)  { showToast('Please enter a URL', 'error'); return; }

  state.scanning = true;
  state.scanningStatus = 'Analyzing...';
  state.apiError = null;
  render();

  try {
    const formData = new FormData();

    if (state.scanTab === 'email') {
      // EML file upload → use dedicated endpoint
      if (state.emlFile) {
        const emlForm = new FormData();
        emlForm.append('eml_file', state.emlFile);
        const resp = await fetch(`${API_BASE}/analyze-eml`, { method: 'POST', body: emlForm });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({ error: 'Server error ' + resp.status }));
          throw new Error(err.error || 'Server error ' + resp.status);
        }
        const data = await resp.json();
        const linguistic = data.details?.linguistic || {};
        const urls       = data.details?.urls       || {};
        const linguisticFlags = (linguistic.found || []).map(f => f.word || f.keyword || f).filter(Boolean);
        const urlFlags = (urls.suspicious_urls || []).map(u => {
          const reasons = u.reasons || [];
          return `${reasons.length ? reasons.join(', ') : 'Suspicious URL'}: ${u.url}`;
        });
        const explanationText = Array.isArray(data.explanation) ? data.explanation.join(' ') : (data.explanation || '');
        state.currentResult = {
          score: data.score, riskLevel: (data.risk_level || 'safe').toLowerCase(),
          linguisticFlags, urlFlags, attachmentFlags: [], explanation: explanationText,
        };
        state.scans.unshift({
          id: data.analyzed_at || Date.now().toString(),
          date: (data.analyzed_at || new Date().toISOString()).split('T')[0],
          preview: data.email_preview || state.emlFileName,
          result: state.currentResult,
        });
        state.page = 'results';
        state.scanEmail = ''; state.emlFile = null; state.emlFileName = '';
        state.scanning = false;
        render(); return;
      }
      // Paste fallback
      formData.append('email_text', state.scanEmail.trim());
    } else if (state.scanTab === 'text') {
      formData.append('email_text', textVal);
    } else if (state.scanTab === 'url') {
      formData.append('email_text', urlVal);
    }

    const resp = await fetch(`${API_BASE}/analyze-email`, {
      method: 'POST',
      body: formData,
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: 'Server error ' + resp.status }));
      throw new Error(err.error || 'Server error ' + resp.status);
    }

    const data = await resp.json();

    const linguistic = data.details?.linguistic || {};
    const urls       = data.details?.urls       || {};

    const linguisticFlags = (linguistic.found || []).map(f => f.word || f.keyword || f).filter(Boolean);
    const urlFlags = (urls.suspicious_urls || []).map(u => {
      const reasons = u.reasons || [];
      return `${reasons.length ? reasons.join(', ') : 'Suspicious URL'}: ${u.url}`;
    });

    const explanationText = Array.isArray(data.explanation)
      ? data.explanation.join(' ')
      : (data.explanation || 'No explanation provided.');

    const mapped = {
      score:           data.score,
      riskLevel:       (data.risk_level || 'Safe').toLowerCase(),
      linguisticFlags,
      urlFlags,
      attachmentFlags: [],
      explanation:     explanationText,
    };

    state.currentResult = mapped;

    state.scans.unshift({
      id:      data.analyzed_at || Date.now().toString(),
      date:    (data.analyzed_at || new Date().toISOString()).split('T')[0],
      preview: data.email_preview || textVal.substring(0, 120) || 'Scan result',
      result:  mapped,
    });

    state.page = 'results';
    state.scanText  = '';
    state.scanUrl   = '';
    state.scanEmail = '';
    state.emlFile   = null;
    state.emlFileName = '';
    render();

  } catch (err) {
    state.apiError = err.message;
    showToast('Error: ' + err.message, 'error');
    render();
  } finally {
    state.scanning = false;
    state.scanningStatus = '';
  }
}

async function loadHistory() {
  try {
    const resp = await fetch(`${API_BASE}/history`);
    if (!resp.ok) return;
    const data = await resp.json();

    const mapped = (Array.isArray(data) ? data : []).map((doc, i) => {
      const linguistic = doc.details?.linguistic || {};
      const urls       = doc.details?.urls       || {};

      const linguisticFlags = (linguistic.found || []).map(f => f.word || f.keyword || f).filter(Boolean);
      const urlFlags = (urls.suspicious_urls || []).map(u => {
        const reasons = u.reasons || [];
        return `${reasons.length ? reasons.join(', ') : 'Suspicious URL'}: ${u.url}`;
      });
      const explanationText = Array.isArray(doc.explanation)
        ? doc.explanation.join(' ')
        : (doc.explanation || '');

      return {
        id:      doc.analyzed_at || String(i),
        date:    (doc.analyzed_at || new Date().toISOString()).split('T')[0],
        preview: doc.email_preview || 'Scan result',
        result: {
          score:           doc.score,
          riskLevel:       (doc.risk_level || 'safe').toLowerCase(),
          linguisticFlags,
          urlFlags,
          attachmentFlags: [],
          explanation:     explanationText,
        },
      };
    });

    const existingIds = new Set(state.scans.map(s => s.id));
    const newFromServer = mapped.filter(s => !existingIds.has(s.id));
    state.scans = [...state.scans, ...newFromServer];
    state.historyLoaded = true;
    render();
  } catch (e) {
    state.historyLoaded = true;
    render();
  }
}

function saveToHistory() {
  showToast('Already saved to server database ✓', 'success');
}

function validateThresh() {
  const err = document.getElementById('thresh-error');
  if(!err) return;
  err.style.display = state.settings.suspThresh >= state.settings.fishThresh ? 'block' : 'none';
}

function saveSettings() {
  const ts = state.settings.suspThresh;
  const tf = state.settings.fishThresh;
  if(ts >= tf) { showToast('Fix threshold values first', 'error'); return; }
  showToast('Settings saved ✓', 'success');
}

// ── Selection ──
function toggleSelectScan(id, checked) {
  if (!state.selectedScans) state.selectedScans = new Set();
  if (checked) state.selectedScans.add(id);
  else state.selectedScans.delete(id);
  render();
}
function toggleSelectAll(checked) {
  if (!state.selectedScans) state.selectedScans = new Set();
  if (checked) {
    state.scans.forEach(s => state.selectedScans.add(s.id));
  } else {
    state.selectedScans.clear();
  }
  render();
}

// ── Confirm Modal ──
function closeConfirmModal() {
  state.confirmModal = null;
  render();
}
function confirmDeleteAll() {
  state.confirmModal = {
    icon: '🗑️',
    title: 'Delete All Scans',
    message: 'This will permanently remove ALL scan history from the database. This action cannot be undone.',
    confirmLabel: 'Yes, Delete All',
    action: 'executeDeleteAll()'
  };
  render();
}
function confirmDeleteSelected() {
  const count = state.selectedScans ? state.selectedScans.size : 0;
  state.confirmModal = {
    icon: '🗑️',
    title: `Delete ${count} Selected Scan${count !== 1 ? 's' : ''}`,
    message: `This will permanently remove the ${count} selected scan${count !== 1 ? 's' : ''} from the database.`,
    confirmLabel: `Delete ${count} Selected`,
    action: 'executeDeleteSelected()'
  };
  render();
}
function confirmDeleteOne(id) {
  state.confirmModal = {
    icon: '🗑️',
    title: 'Delete This Scan',
    message: 'This will permanently remove this scan from the database.',
    confirmLabel: 'Delete',
    action: `executeDeleteOne('${id}')`
  };
  render();
}

// ── Execute Deletes ──
async function executeDeleteAll() {
  state.confirmModal = null;
  try {
    const resp = await fetch(`${API_BASE}/history/clear`, { method: 'DELETE' });
    if (resp.ok) {
      state.scans = [];
      state.selectedScans = new Set();
      state.historyLoaded = false;
      showToast('All scans deleted ✓', 'success');
    } else {
      showToast('Failed to delete from server', 'error');
    }
  } catch (e) {
    state.scans = [];
    state.selectedScans = new Set();
    showToast('Cleared locally (server offline)', 'success');
  }
  render();
}
async function executeDeleteSelected() {
  state.confirmModal = null;
  const ids = state.selectedScans ? [...state.selectedScans] : [];
  let serverFailed = false;
  for (const id of ids) {
    try {
      await fetch(`${API_BASE}/history/${encodeURIComponent(id)}`, { method: 'DELETE' });
    } catch (e) { serverFailed = true; }
  }
  state.scans = state.scans.filter(s => !ids.includes(s.id));
  state.selectedScans = new Set();
  showToast(serverFailed ? 'Removed locally (server offline)' : `${ids.length} scan${ids.length!==1?'s':''} deleted ✓`, serverFailed ? 'error' : 'success');
  render();
}
async function executeDeleteOne(id) {
  state.confirmModal = null;
  try {
    await fetch(`${API_BASE}/history/${encodeURIComponent(id)}`, { method: 'DELETE' });
  } catch (e) {}
  state.scans = state.scans.filter(s => s.id !== id);
  if (state.selectedScans) state.selectedScans.delete(id);
  showToast('Scan deleted ✓', 'success');
  render();
}
