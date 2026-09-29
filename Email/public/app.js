(() => {
  const $ = (id) => document.getElementById(id);

  const state = {
    status: null,
    emails: [],
    selectedId: null,
    pin: sessionStorage.getItem('em_pin') || '',
    ws: null,
    wsState: 'connecting',
    reconnectTimer: null,
    pollTimer: null,
    bannerTimer: null,
    newIds: new Set(),
    settingsLoaded: false,
  };

  const esc = (s) =>
    String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

  const fmtBytes = (n) => {
    if (!Number.isFinite(n) || n <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log2(n) / 10));
    const v = n / 2 ** (i * 10);
    return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  };

  const fmtDate = (iso) => {
    if (!iso) return '-';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '-' : d.toLocaleString();
  };

  const fmtRelative = (iso) => {
    if (!iso) return '';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    const diff = Math.max(0, Date.now() - d.getTime());
    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // ---------- Safety status ----------

  const SAFETY_LABELS = {
    safe: '\u{1F7E2} SAFE',
    dangerous: '\u{1F534} DANGEROUS',
    unknown: '\u26AA UNKNOWN',
  };

  function safetyInfo(email) {
    const raw = (email && email.safety) || {};
    const status = Object.prototype.hasOwnProperty.call(SAFETY_LABELS, raw.status) ? raw.status : 'unknown';
    const reasons = Array.isArray(raw.reasons) ? raw.reasons.join(' ') : '';
    return {
      status,
      label: typeof raw.label === 'string' && raw.label ? raw.label : SAFETY_LABELS[status],
      reasons,
    };
  }

  function safetyBadgeHtml(email) {
    const s = safetyInfo(email);
    return `<span class="safety-badge" data-status="${esc(s.status)}"${
      s.reasons ? ` title="${esc(s.reasons)}"` : ''
    }>${esc(s.label)}</span>`;
  }

  // ---------- API ----------

  async function api(path, { method = 'GET', body } = {}) {
    let res;
    try {
      res = await fetch(path, {
        method,
        headers: { 'Content-Type': 'application/json', ...(state.pin ? { 'x-pin': state.pin } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new Error('Server/API error: cannot reach the server.');
    }
    let data = null;
    try {
      data = await res.json();
    } catch {
      /* empty body */
    }
    if (res.status === 401 && data && data.code === 'pin_required') {
      openPin();
      throw new Error('Dashboard PIN required.');
    }
    if (!res.ok) {
      const err = new Error((data && data.error) || `Server/API error: HTTP ${res.status}`);
      err.code = data && data.code;
      throw err;
    }
    return data;
  }

  // ---------- Banner / toast ----------

  function showBanner(text, kind = 'error') {
    const banner = $('banner');
    banner.dataset.kind = kind;
    $('bannerText').textContent = text;
    banner.hidden = false;
    clearTimeout(state.bannerTimer);
    if (kind !== 'error') {
      state.bannerTimer = setTimeout(() => {
        banner.hidden = true;
      }, 7000);
    }
  }

  function hideBanner() {
    clearTimeout(state.bannerTimer);
    $('banner').hidden = true;
  }

  let toastTimer = null;
  function showToast(text) {
    const toast = $('toast');
    toast.textContent = text;
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.hidden = true;
    }, 4000);
  }

  // ---------- Status ----------

  function applyStatus(st) {
    if (!st) return;
    state.status = st;
    renderStatus();
  }

  function renderStatus() {
    const st = state.status;
    if (!st) return;
    const active = st.monitoring === 'active';
    const pill = $('statusPill');
    pill.dataset.state = active ? 'active' : 'inactive';
    pill.textContent = active ? 'ACTIVE' : 'INACTIVE';
    $('statusMessage').textContent = st.message || '';
    $('totalEmails').textContent = String(st.totalEmails ?? 0);
    $('lastEmailAt').textContent = st.lastEmailAt ? `Last email: ${fmtRelative(st.lastEmailAt)}` : 'No emails yet';

    const box = $('mailboxAddress');
    if (st.mailbox && st.mailbox.address) {
      box.textContent = st.mailbox.address;
      $('mailboxHost').textContent = `${st.mailbox.host}${st.mailbox.source ? ` - via ${st.mailbox.source === 'env' ? '.env' : 'saved settings'}` : ''}`;
    } else {
      box.textContent = 'Not configured';
      $('mailboxHost').textContent = 'Open Settings to configure a mailbox.';
    }

    $('startBtn').disabled = ['active', 'connecting', 'reconnecting'].includes(st.state);
    $('stopBtn').disabled = st.state === 'stopped';

    if (st.code === 'not_configured' && !state.settingsLoaded) {
      state.settingsLoaded = true;
      openSettings();
    }
  }

  // ---------- Email list ----------

  function mergeEmails(list) {
    const map = new Map(state.emails.map((e) => [e.id, e]));
    for (const e of list) {
      if (!e || !e.id) continue;
      map.set(e.id, e);
    }
    state.emails = [...map.values()].sort((a, b) => new Date(b.receivedAt || b.date) - new Date(a.receivedAt || a.date));
  }

  function fromLabel(e) {
    const name = (e.from && e.from.name) || '';
    const addr = (e.from && e.from.address) || '';
    if (name && addr) return `${name} <${addr}>`;
    return name || addr || '(unknown sender)';
  }

  function renderList() {
    const list = $('emailList');
    const empty = $('listEmpty');
    empty.hidden = state.emails.length > 0;
    $('emailCount').textContent = state.emails.length ? `${state.emails.length} shown` : '';

    list.innerHTML = state.emails
      .map((e) => {
        const chips = [safetyBadgeHtml(e)];
        if (e.attachments && e.attachments.length) {
          chips.push(`<span class="chip">${e.attachments.length} attachment${e.attachments.length > 1 ? 's' : ''}</span>`);
        }
        if (e.links && e.links.length) {
          chips.push(`<span class="chip">${e.links.length} link${e.links.length > 1 ? 's' : ''}</span>`);
        }
        const selected = e.id === state.selectedId ? ' selected' : '';
        const fresh = state.newIds.has(e.id) ? ' new' : '';
        return `<button type="button" class="email-item${selected}${fresh}" data-id="${esc(e.id)}">
          <span class="email-item-top">
            <span class="email-from">${esc(fromLabel(e))}</span>
            <span class="email-date">${esc(fmtRelative(e.receivedAt || e.date))}</span>
          </span>
          <span class="email-subject">${esc(e.subject || '(no subject)')}</span>
          ${e.preview ? `<span class="email-preview">${esc(e.preview)}</span>` : ''}
          ${chips.length ? `<span class="chips">${chips.join('')}</span>` : ''}
        </button>`;
      })
      .join('');
  }

  // ---------- Detail ----------

  async function openEmail(id) {
    state.selectedId = id;
    renderList();
    $('detailEmpty').hidden = true;
    const content = $('detailContent');
    content.hidden = false;
    content.innerHTML = '<div class="detail-inner"><p class="muted">Loading email details...</p></div>';
    try {
      const email = await api(`/api/emails/${encodeURIComponent(id)}`);
      renderDetail(email);
    } catch (err) {
      content.innerHTML = `<div class="detail-inner"><p class="muted">${esc(err.message)}</p></div>`;
    }
  }

  function renderDetail(email) {
    const content = $('detailContent');
    const toList = (email.to || []).map((a) => a.address).filter(Boolean).join(', ');
    const ccList = (email.cc || []).map((a) => a.address).filter(Boolean).join(', ');

    const hasText = Boolean(email.text && email.text.trim());
    const hasHtml = Boolean(email.html && email.html.trim());

    let bodyHtml;
    if (hasText || hasHtml) {
      bodyHtml = `
        <div class="section">
          <h4>Message body</h4>
          ${hasText && hasHtml ? `<div class="toggle-row"><button type="button" class="btn" id="bodyToggle">Show rendered HTML</button></div>` : ''}
          ${hasText ? `<pre class="body-text" id="bodyText">${esc(email.text)}</pre>` : ''}
          ${hasHtml ? `<iframe class="body-frame" id="bodyFrame" sandbox="" title="HTML body preview" ${hasText ? 'hidden' : ''}></iframe>` : ''}
        </div>`;
    } else {
      bodyHtml = `<div class="section"><h4>Message body</h4><p class="muted">This email has no readable message body.</p></div>`;
    }

    const attachments = email.attachments || [];
    const attHtml = `
      <div class="section">
        <h4>Attachments (${attachments.length})</h4>
        ${
          attachments.length
            ? `<table class="attachments">
                <thead><tr><th>File name</th><th>Type</th><th>Size</th></tr></thead>
                <tbody>${attachments
                  .map(
                    (a) =>
                      `<tr><td>${esc(a.filename)}</td><td>${esc(a.contentType || '-')}</td><td>${esc(fmtBytes(a.size))}</td></tr>`,
                  )
                  .join('')}</tbody>
              </table>
              <p class="note">Attachment contents are never opened or executed by this system.</p>`
            : '<p class="muted">No attachments.</p>'
        }
      </div>`;

    const links = email.links || [];
    const linksHtml = `
      <div class="section">
        <h4>Links / URLs (${links.length})</h4>
        ${
          links.length
            ? `<ul class="links-list">${links
                .map(
                  (u) =>
                    `<li><a href="${esc(u)}" target="_blank" rel="noopener noreferrer nofollow">${esc(u)}</a></li>`,
                )
                .join('')}</ul>`
            : '<p class="muted">No links found in this email.</p>'
        }
      </div>`;

    content.innerHTML = `
      <div class="detail-inner">
        <h3 class="detail-subject">${esc(email.subject || '(no subject)')}</h3>
        <div class="meta-grid">
          <span class="label">From</span><span class="value">${esc(fromLabel(email))}</span>
          <span class="label">Receiver</span><span class="value">${esc(email.receiver || toList || '-')}</span>
          ${ccList ? `<span class="label">Cc</span><span class="value">${esc(ccList)}</span>` : ''}
          <span class="label">Date</span><span class="value">${esc(fmtDate(email.date))}</span>
          <span class="label">Received</span><span class="value">${esc(fmtDate(email.receivedAt))}</span>
          <span class="label">Size</span><span class="value">${esc(fmtBytes(email.size))}</span>
          ${email.messageId ? `<span class="label">Message-ID</span><span class="value">${esc(email.messageId)}</span>` : ''}
          <span class="label">Safety Status</span><span class="value">${safetyBadgeHtml(email)}</span>
        </div>
        ${bodyHtml}
        ${attHtml}
        ${linksHtml}
      </div>`;

    if (hasHtml) {
      const frame = $('bodyFrame');
      if (frame) frame.srcdoc = email.html;
    }
    const toggle = $('bodyToggle');
    if (toggle) {
      toggle.addEventListener('click', () => {
        const text = $('bodyText');
        const frame = $('bodyFrame');
        const showingHtml = !frame.hidden;
        frame.hidden = showingHtml;
        if (text) text.hidden = !showingHtml;
        toggle.textContent = showingHtml ? 'Show rendered HTML' : 'Show plain text';
      });
    }
  }

  // ---------- WebSocket ----------

  function setConn(mode) {
    state.wsState = mode;
    const badge = $('connBadge');
    badge.dataset.state = mode;
    $('connText').textContent = mode === 'live' ? 'Live' : mode === 'reconnecting' ? 'Reconnecting' : mode === 'offline' ? 'Offline' : 'Connecting';
  }

  function connectWS() {
    if (state.ws && (state.ws.readyState === WebSocket.OPEN || state.ws.readyState === WebSocket.CONNECTING)) return;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}/ws${state.pin ? `?pin=${encodeURIComponent(state.pin)}` : ''}`;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch {
      setConn('reconnecting');
      scheduleReconnect();
      startPolling();
      return;
    }
    state.ws = ws;

    ws.onopen = () => {
      setConn('live');
      stopPolling();
      clearTimeout(state.reconnectTimer);
    };
    ws.onmessage = (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (msg.type === 'status') applyStatus(msg.data);
      else if (msg.type === 'email:new') addEmail(msg.data);
      else if (msg.type === 'emails:initial') {
        mergeEmails(msg.data || []);
        renderList();
      }
    };
    ws.onclose = (ev) => {
      if (state.ws !== ws) return;
      state.ws = null;
      if (ev.code === 4401) {
        setConn('offline');
        openPin();
        return;
      }
      setConn('reconnecting');
      scheduleReconnect();
      startPolling();
    };
    ws.onerror = () => {
      /* onclose follows */
    };
  }

  function scheduleReconnect() {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = setTimeout(connectWS, 3000);
  }

  function startPolling() {
    if (state.pollTimer) return;
    state.pollTimer = setInterval(async () => {
      try {
        const st = await api('/api/status');
        applyStatus(st);
        const list = await api('/api/emails?limit=50');
        mergeEmails(list.emails || []);
        renderList();
      } catch {
        /* keep trying silently; banner comes from explicit actions */
      }
    }, 10000);
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function addEmail(summary) {
    if (!summary || !summary.id) return;
    const exists = state.emails.some((e) => e.id === summary.id);
    state.newIds.add(summary.id);
    mergeEmails([summary]);
    renderList();
    if (!exists && state.status) {
      state.status.totalEmails = (state.status.totalEmails || 0) + 1;
      renderStatus();
      showToast(`New email from ${fromLabel(summary)}`);
    }
  }

  // ---------- Actions ----------

  async function startMonitoring() {
    try {
      $('startBtn').disabled = true;
      const resp = await api('/api/monitor/start', { method: 'POST' });
      applyStatus(resp.status);
      if (resp.status && resp.status.code !== 'ok' && resp.status.code !== 'connecting') {
        showBanner(resp.status.message, 'error');
      } else if (resp.status && resp.status.code === 'ok') {
        showBanner('Monitoring started.', 'success');
      }
    } catch (err) {
      showBanner(err.message, 'error');
    } finally {
      renderStatus();
    }
  }

  async function stopMonitoring() {
    try {
      const resp = await api('/api/monitor/stop', { method: 'POST' });
      applyStatus(resp.status);
      showBanner('Monitoring stopped.', 'info');
    } catch (err) {
      showBanner(err.message, 'error');
    }
  }

  async function checkNewMail() {
    try {
      $('refreshBtn').disabled = true;
      const resp = await api('/api/monitor/refresh', { method: 'POST' });
      applyStatus(resp.status);
      showToast(resp.message || 'No new emails.');
      const list = await api('/api/emails?limit=50');
      mergeEmails(list.emails || []);
      renderList();
    } catch (err) {
      showBanner(err.message, 'error');
    } finally {
      $('refreshBtn').disabled = false;
    }
  }

  // ---------- Settings dialog ----------

  async function openSettings() {
    const dlg = $('settingsDialog');
    try {
      const s = await api('/api/settings');
      $('setHost').value = s.host || '';
      $('setPort').value = s.port || 993;
      $('setSecure').checked = s.secure !== false;
      $('setUser').value = s.user || '';
      $('setMonitored').value = s.monitored || '';
      $('setPass').value = '';
      $('settingsSource').textContent = s.configured
        ? `Currently active: ${s.source === 'env' ? 'credentials from .env file' : 'saved settings'}. Password: ${s.hasPassword ? 'set (hidden)' : 'missing'}.`
        : 'No mailbox configured yet. Enter your IMAP account below.';
    } catch (err) {
      showBanner(err.message, 'error');
    }
    if (!dlg.open) dlg.showModal();
  }

  async function saveSettings(ev) {
    ev.preventDefault();
    const payload = {
      host: $('setHost').value.trim(),
      port: parseInt($('setPort').value, 10),
      secure: $('setSecure').checked,
      user: $('setUser').value.trim(),
      monitored: $('setMonitored').value.trim() || undefined,
    };
    const pass = $('setPass').value;
    if (pass) payload.pass = pass;
    try {
      $('settingsSave').disabled = true;
      const resp = await api('/api/settings', { method: 'POST', body: payload });
      $('settingsDialog').close();
      showBanner(resp.message || 'Settings saved.', 'success');
      setTimeout(async () => {
        try {
          applyStatus(await api('/api/status'));
        } catch {
          /* ignore */
        }
      }, 400);
    } catch (err) {
      showBanner(err.message, 'error');
    } finally {
      $('settingsSave').disabled = false;
    }
  }

  // ---------- PIN dialog ----------

  function openPin() {
    const dlg = $('pinDialog');
    if (dlg.open) return;
    $('pinInput').value = '';
    dlg.showModal();
  }

  async function submitPin(ev) {
    ev.preventDefault();
    state.pin = $('pinInput').value;
    sessionStorage.setItem('em_pin', state.pin);
    $('pinDialog').close();
    if (state.ws) {
      state.ws.onclose = null;
      state.ws.close();
      state.ws = null;
    }
    connectWS();
    try {
      await loadAll();
    } catch {
      openPin();
    }
  }

  // ---------- Boot ----------

  async function loadAll() {
    const [st, list] = await Promise.all([api('/api/status'), api('/api/emails?limit=50')]);
    applyStatus(st);
    mergeEmails(list.emails || []);
    renderList();
  }

  function bind() {
    $('settingsBtn').addEventListener('click', openSettings);
    $('settingsCancel').addEventListener('click', () => $('settingsDialog').close());
    $('settingsForm').addEventListener('submit', saveSettings);
    $('pinForm').addEventListener('submit', submitPin);
    $('startBtn').addEventListener('click', startMonitoring);
    $('stopBtn').addEventListener('click', stopMonitoring);
    $('refreshBtn').addEventListener('click', checkNewMail);
    $('bannerClose').addEventListener('click', hideBanner);
    $('emailList').addEventListener('click', (ev) => {
      const item = ev.target.closest('.email-item');
      if (!item) return;
      state.newIds.delete(item.dataset.id);
      openEmail(item.dataset.id);
    });
  }

  async function init() {
    bind();
    setConn('connecting');
    try {
      await loadAll();
    } catch {
      /* pin dialog / banner already handled */
    }
    connectWS();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
