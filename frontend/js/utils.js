// ============================================================
// UTILITIES
// Small helper functions used across all pages
// ============================================================

function scoreColor(score) {
  if (score <= 30) return 'var(--safe)';
  if (score <= 70) return 'var(--warn)';
  return 'var(--danger)';
}

function riskLevel(score) {
  if (score <= 30) return 'safe';
  if (score <= 70) return 'suspicious';
  return 'phishing';
}

function formatDate(d) {
  return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  document.getElementById('toast-msg').textContent = msg;
  t.className = 'toast show ' + (type === 'success' ? 'success' : '');
  setTimeout(() => { t.className = 'toast'; }, 2600);
}

// Maps a raw backend API response to the frontend result shape
function mapApiResponse(data) {
  const linguistic = data.details?.linguistic || {};
  const urls       = data.details?.urls       || {};

  const linguisticFlags = (linguistic.found || [])
    .map(f => f.word || f.keyword || f).filter(Boolean);

  const urlFlags = (urls.suspicious_urls || []).map(u => {
    const reasons = u.reasons || [];
    return `${reasons.length ? reasons.join(', ') : 'Suspicious URL'}: ${u.url}`;
  });

  const explanationText = Array.isArray(data.explanation)
    ? data.explanation.join(' ')
    : (data.explanation || 'No explanation provided.');

  return {
    score:           data.score,
    riskLevel:       (data.risk_level || 'safe').toLowerCase(),
    linguisticFlags,
    urlFlags,
    explanation:     explanationText,
  };
}
