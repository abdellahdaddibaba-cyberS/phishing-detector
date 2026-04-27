// ============================================================
// PAGE: SETTINGS
// Scoring weights, detection thresholds, appearance options
// ============================================================
function renderSettings() {
  const s = state.settings;
  return `
  <div class="page" style="max-width:640px;">
    <div class="card">
      <div class="settings-title">⚖️ Scoring Weights</div>
      <div class="slider-row">
        <div class="slider-label">Linguistic keywords</div>
        <input type="range" min="0" max="50" value="${s.lingWeight}" id="sl-ling">
        <div class="slider-val" id="sv-ling">+${s.lingWeight}</div>
      </div>
      <div class="slider-row">
        <div class="slider-label">Malicious URL</div>
        <input type="range" min="0" max="60" value="${s.urlWeight}" id="sl-url">
        <div class="slider-val" id="sv-url">+${s.urlWeight}</div>
      </div>
      <div class="slider-row">
        <div class="slider-label">Dangerous attachment</div>
        <input type="range" min="0" max="70" value="${s.attachWeight}" id="sl-attach">
        <div class="slider-val" id="sv-attach">+${s.attachWeight}</div>
      </div>
      <div style="font-size:12px;font-family:var(--mono);color:var(--text3);margin-top:4px;">
        Total weight: <span id="total-weight" style="color:var(--accent);">${s.lingWeight+s.urlWeight+s.attachWeight}</span>
      </div>
    </div>

    <div class="card" style="margin-top:16px;">
      <div class="settings-title">🎯 Detection Thresholds</div>
      <div class="two-col">
        <div class="form-group">
          <label>Suspicious Threshold</label>
          <input type="number" id="thresh-susp" value="${s.suspThresh}" min="1" max="99">
        </div>
        <div class="form-group">
          <label>Phishing Threshold</label>
          <input type="number" id="thresh-fish" value="${s.fishThresh}" min="2" max="100">
        </div>
      </div>
      <div id="thresh-error" style="font-size:12px;color:var(--danger);margin-top:-8px;display:none;">⚠ Suspicious threshold must be less than phishing threshold.</div>
    </div>

    <div class="card" style="margin-top:16px;">
      <div class="settings-title">🎨 Appearance</div>
      <div class="toggle-row">
        <div class="toggle-label">Dark Mode</div>
        <div class="toggle ${s.darkMode?'on':''}" id="toggle-dark" onclick="toggleDark()">
          <div class="toggle-thumb"></div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top:16px;">
      <div class="settings-title">ℹ️ About</div>
      <div class="about-card">
        <strong>PhishGuard v1.0</strong> — Phishing Attack Detection System<br>
        <br>
        A frontend interface for the MDP Project. Analyzes messages for phishing indicators across three vectors: <strong>linguistic patterns</strong> (urgency, fear, authority), <strong>URL anomalies</strong> (domain spoofing, IP-based links), and <strong>attachment risks</strong> (macro-enabled documents, executable files).<br>
        <br>
        Backend: Flask API · Storage: MongoDB · NLP: spaCy · URL Checks: VirusTotal API
      </div>
    </div>

    <div style="margin-top:18px;display:flex;gap:10px;">
      <button class="btn btn-primary" onclick="saveSettings()">💾 Save Settings</button>
      <button class="btn btn-ghost" onclick="render()">↺ Reset</button>
    </div>
  </div>`;
}
