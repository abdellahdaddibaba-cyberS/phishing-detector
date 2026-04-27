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
  if(hs) hs.addEventListener('input', e=>{ state.historySearch=e.target.value; state.historyPage=1; render(); });
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
  ['ling','url','attach'].forEach(k=>{
    const el = document.getElementById('sl-'+k);
    if(el) el.addEventListener('input', e=>{
      const map={ling:'lingWeight',url:'urlWeight',attach:'attachWeight'};
      state.settings[map[k]] = +e.target.value;
      document.getElementById('sv-'+k).textContent='+'+e.target.value;
      document.getElementById('total-weight').textContent = state.settings.lingWeight+state.settings.urlWeight+state.settings.attachWeight;
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
function toggleDark() { state.settings.darkMode=!state.settings.darkMode; render(); }

function openEmlPicker() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.eml,.msg';
  input.onchange = e => {
    const file = e.target.files[0];
    if (file) {
      state.emlFile = file;
      state.emlFileName = file.name;
      // clear paste text when file chosen
      state.scanEmail = '';
      render();
    }
  };
  input.click();
}

function openFilePicker() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.exe,.js,.docm,.pdf,.zip,.bat,.vbs,.doc,.docx,.xls,.xlsx,.txt,.eml';
  input.onchange = e => {
    const file = e.target.files[0];
    if (file) {
      state.scanFile = file;
      state.scanAttachName = file.name;
      render();
    }
  };
  input.click();
}

async function startScan() {
  if (state.scanning) return;

  // Validate inputs
  const textVal = state.scanText.trim();
  const urlVal  = state.scanUrl.trim();
  if (state.scanTab === 'email' && !state.scanEmail.trim() && !state.emlFile) { showToast('Please upload a .eml file or paste email content', 'error'); return; }
  if (state.scanTab === 'text' && !textVal) { showToast('Please enter message content', 'error'); return; }
  if (state.scanTab === 'url'  && !urlVal)  { showToast('Please enter a URL', 'error'); return; }
  if (state.scanTab === 'attach' && !state.scanFile) { showToast('Please select a file', 'error'); return; }

  state.scanning = true;
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
        const attach     = data.details?.attachments|| {};
        const linguisticFlags = (linguistic.found || []).map(f => f.word || f.keyword || f).filter(Boolean);
        const urlFlags = (urls.suspicious_urls || []).map(u => {
          const reasons = u.reasons || [];
          return `${reasons.length ? reasons.join(', ') : 'Suspicious URL'}: ${u.url}`;
        });
        const attachmentFlags = (attach.risky_attachments || []).map(a => a.reason ? `${a.reason}: ${a.file}` : a.file);
        const explanationText = Array.isArray(data.explanation) ? data.explanation.join(' ') : (data.explanation || '');
        state.currentResult = {
          score: data.score, riskLevel: (data.risk_level || 'safe').toLowerCase(),
          linguisticFlags, urlFlags, attachmentFlags, explanation: explanationText,
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
      // Paste fallback → use regular endpoint
      formData.append('email_text', state.scanEmail.trim());
    } else if (state.scanTab === 'text') {
      formData.append('email_text', textVal);
    } else if (state.scanTab === 'url') {
      formData.append('email_text', urlVal);
    } else if (state.scanTab === 'attach') {
      if (state.scanFile) formData.append('file', state.scanFile);
      if (textVal) formData.append('email_text', textVal);
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

    // Map backend response → frontend result shape
    const linguistic = data.details?.linguistic || {};
    const urls       = data.details?.urls       || {};
    const attach     = data.details?.attachments|| {};

    // Build linguistic flags from found keywords
    const linguisticFlags = (linguistic.found || []).map(f => f.word || f.keyword || f).filter(Boolean);

    // Build URL flags from suspicious_urls
    const urlFlags = (urls.suspicious_urls || []).map(u => {
      const reasons = u.reasons || [];
      const label   = reasons.length ? reasons.join(', ') : 'Suspicious URL';
      return `${label}: ${u.url}`;
    });

    // Build attachment flags
    const attachmentFlags = (attach.risky_attachments || []).map(a => {
      return a.reason ? `${a.reason}: ${a.file}` : a.file;
    });

    // explanation comes as array from backend
    const explanationText = Array.isArray(data.explanation)
      ? data.explanation.join(' ')
      : (data.explanation || 'No explanation provided.');

    const mapped = {
      score:           data.score,
      riskLevel:       (data.risk_level || 'Safe').toLowerCase(),
      linguisticFlags,
      urlFlags,
      attachmentFlags,
      explanation:     explanationText,
    };

    state.currentResult = mapped;

    // Add to local scans list for dashboard/history UI
    const newScan = {
      id:      data.analyzed_at || Date.now().toString(),
      date:    (data.analyzed_at || new Date().toISOString()).split('T')[0],
      preview: data.email_preview || textVal.substring(0, 120) || state.scanAttachName || 'Scan result',
      result:  mapped,
    };
    state.scans.unshift(newScan);

    state.page = 'results';
    // Reset inputs
    state.scanText      = '';
    state.scanUrl       = '';
    state.scanEmail     = '';
    state.emlFile       = null;
    state.emlFileName   = '';
    state.scanAttachName= '';
    state.scanFile      = null;
    render();

  } catch (err) {
    state.apiError = err.message;
    showToast('Error: ' + err.message, 'error');
    render();
  } finally {
    state.scanning = false;
  }
}

async function loadHistory() {
  try {
    const resp = await fetch(`${API_BASE}/history`);
    if (!resp.ok) return;
    const data = await resp.json();

    // Map backend history records → frontend scan shape
    const mapped = (Array.isArray(data) ? data : []).map((doc, i) => {
      const linguistic = doc.details?.linguistic || {};
      const urls       = doc.details?.urls       || {};
      const attach     = doc.details?.attachments|| {};

      const linguisticFlags = (linguistic.found || []).map(f => f.word || f.keyword || f).filter(Boolean);
      const urlFlags = (urls.suspicious_urls || []).map(u => {
        const reasons = u.reasons || [];
        return `${reasons.length ? reasons.join(', ') : 'Suspicious URL'}: ${u.url}`;
      });
      const attachmentFlags = (attach.risky_attachments || []).map(a =>
        a.reason ? `${a.reason}: ${a.file}` : a.file
      );
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
          attachmentFlags,
          explanation:     explanationText,
        },
      };
    });

    // Merge: keep local scans (new ones from this session) + server history, dedup by id
    const existingIds = new Set(state.scans.map(s => s.id));
    const newFromServer = mapped.filter(s => !existingIds.has(s.id));
    state.scans = [...state.scans, ...newFromServer];
    state.historyLoaded = true;
    render();
  } catch (e) {
    // Server not reachable — keep local scans only
    state.historyLoaded = true;
    render();
  }
}

function saveToHistory() {
  // Results are auto-saved to MongoDB by the backend on every scan.
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
