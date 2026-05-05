// ============================================================
// PAGE: NEW SCAN
// Tabs: Full Email (.eml upload + paste) | Message Text | URL
// ============================================================
function renderScan() {
  const tabs = [
    { id:'email', label:'📧 Full Email' },
    { id:'text',  label:'📝 Message Text' },
    { id:'url',   label:'🔗 URL' },
  ];
  return `
  <div class="page" style="max-width:680px;margin:0 auto;">
    <div class="card">
      <div style="margin-bottom:20px;">
        <h2 style="font-size:18px;font-weight:600;margin-bottom:4px;">Analyze Message</h2>
        <p style="font-size:13px;color:var(--text3);">Submit a full email or individual content to scan for phishing indicators across linguistic and URL vectors.</p>
      </div>
      <div class="tabs">
        ${tabs.map(t=>`<div class="tab ${state.scanTab===t.id?'active':''}" data-tab="${t.id}">${t.label}</div>`).join('')}
      </div>

      ${state.scanTab==='email'?`
        <!-- EML UPLOAD SECTION -->
        <div style="margin-bottom:18px;">
          <div style="font-size:12px;font-family:var(--mono);color:var(--text3);letter-spacing:0.05em;margin-bottom:10px;">OPTION 1 — UPLOAD .EML FILE <span style="color:var(--accent);">(Recommended)</span></div>
          <div class="dropzone ${state.emlFileName?'active':''}" onclick="openEmlPicker()" style="padding:24px 20px;">
            <div class="dropzone-icon">${state.emlFileName?'📧':'📂'}</div>
            ${state.emlFileName
              ? `<div style="font-size:14px;font-weight:500;color:var(--accent);">${state.emlFileName}</div>
                 <div style="font-size:12px;color:var(--text3);margin-top:4px;">Click to change file</div>`
              : `<div style="font-size:14px;font-weight:500;">Click to upload .eml file</div>
                 <div style="font-size:12px;color:var(--text3);margin-top:6px;">Download from Gmail: ⋮ menu → <strong>Download message</strong></div>`}
          </div>
          ${state.emlFileName ? `
          <div style="background:rgba(0,212,170,0.06);border:1px solid rgba(0,212,170,0.15);border-radius:8px;padding:12px 14px;margin-top:10px;">
            <div style="font-size:11px;font-family:var(--mono);color:var(--accent);margin-bottom:6px;">⚡ WILL AUTO-EXTRACT FROM .EML</div>
            <div style="font-size:12px;color:var(--text2);line-height:1.7;">✓ Full email body text<br>✓ All URLs (checked via VirusTotal)</div>
          </div>` : ''}
        </div>

        <!-- DIVIDER -->
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;">
          <hr style="flex:1;border:none;border-top:1px solid var(--border);">
          <span style="font-size:11px;font-family:var(--mono);color:var(--text3);">OR</span>
          <hr style="flex:1;border:none;border-top:1px solid var(--border);">
        </div>

        <!-- PASTE SECTION -->
        <div class="form-group">
          <div style="font-size:12px;font-family:var(--mono);color:var(--text3);letter-spacing:0.05em;margin-bottom:8px;">OPTION 2 — PASTE RAW EMAIL TEXT</div>
          <textarea id="scan-email" rows="8" placeholder="Paste the full email content here (Ctrl+A in Gmail → Ctrl+C → paste here)" style="resize:vertical;font-family:var(--mono);font-size:12px;">${state.scanEmail}</textarea>
          <div class="char-count" id="email-char-count">${state.scanEmail.length} characters</div>
        </div>
      `:""}
      ${state.scanTab==='text'?`
        <div class="form-group">
          <label>Message Content</label>
          <textarea id="scan-text" rows="7" placeholder="Paste the suspicious email or message content here..." style="resize:vertical;">${state.scanText}</textarea>
          <div class="char-count" id="char-count">${state.scanText.length} characters</div>
        </div>
      `:''}
      ${state.scanTab==='url'?`
        <div class="form-group">
          <label>Suspicious URL</label>
          <input type="text" id="scan-url" placeholder="https://example.com/login?token=..." value="${state.scanUrl}">
        </div>
      `:''}

      ${state.apiError ? `
      <div style="background:rgba(248,113,113,0.1);border:1px solid rgba(248,113,113,0.3);border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:13px;color:var(--danger);">
        ⚠️ <strong>API Error:</strong> ${state.apiError}<br>
        <span style="font-size:11px;color:var(--text3);">Make sure the Flask backend is running on port 5000 (<code>python app.py</code>)</span>
      </div>` : ''}
      <button class="btn btn-primary btn-lg" id="analyze-btn" onclick="startScan()" ${state.scanning?'disabled':''}>
        ${state.scanning ? `<span class="spinner"></span> ${state.scanningStatus || 'Analyzing...'}` : '🔍 Analyze'}
      </button>
      ${state.scanning ? `<div style="font-size:11px;color:var(--text3);margin-top:8px;font-family:var(--mono);">⏳ Querying VirusTotal API — this may take 15–20 seconds...</div>` : ''}
    </div>

    <div class="card" style="margin-top:16px;background:var(--surface2);">
      <div class="section-title" style="margin-bottom:12px;">Scoring <span>Reference</span></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:12px;font-family:var(--mono);">
        <div style="padding:10px;background:var(--surface3);border-radius:8px;">
          <div style="color:var(--text3);margin-bottom:4px;">Keywords</div>
          <div style="color:var(--warn);font-weight:700;">+${state.settings.lingWeight} pts</div>
        </div>
        <div style="padding:10px;background:var(--surface3);border-radius:8px;">
          <div style="color:var(--text3);margin-bottom:4px;">Malicious URL</div>
          <div style="color:var(--warn);font-weight:700;">+${state.settings.urlWeight} pts</div>
        </div>
      </div>
      <div style="margin-top:12px;display:flex;gap:16px;font-size:11px;font-family:var(--mono);">
        <span style="color:var(--safe)">✓ 0–${state.settings.suspThresh} Safe</span>
        <span style="color:var(--warn)">⚠ ${state.settings.suspThresh}–${state.settings.fishThresh} Suspicious</span>
        <span style="color:var(--danger)">✗ ${state.settings.fishThresh}–100 Phishing</span>
      </div>
    </div>
  </div>`;
}
