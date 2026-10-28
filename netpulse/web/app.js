'use strict';
/* netpulse dashboard — vanilla JS, no build step. Globe via bundled globe.gl (three.js inside);
   automatic 2D canvas fallback when WebGL is unavailable (or with ?map=2d). */

// One red for danger (malware is told apart by weight, not hue), one yellow, warm greys.
const COLORS = { malware: '#e5484d', tracker: '#e5484d', suspicious: '#e3b341', normal: '#7d8590', local: '#4a4a4a' };
const ORIGIN_COLOR = '#e6e3dc';
const RANK = { malware: 4, tracker: 3, suspicious: 2, normal: 1, local: 0 };
// Arcs to the same country fan out slightly by category instead of overlapping.
const OFFSET = { malware: [0, 2.6], tracker: [1.6, 1.6], suspicious: [-1.6, -1.6], normal: [0, 0], local: [0, 0] };
const ARC_LINGER_MS = 60000; // keep an arc this long after its socket closes
const HISTORY_MAX = 4000;
const RENDER_DELAY_MS = 250;

const state = {
  origin: { lat: 20, lon: 0, label: 'You' },
  open: new Map(), // id -> connection currently open
  history: new Map(), // id -> connection incl. closed ones (closedAt), for arcs + detail
  procs: new Map(), // app -> ProcessAgg
  blockedDomains: new Set(), // domains netpulse has blocked (hosts file), from /api/blocks
  stats: null,
  paused: false,
  selected: null, // app key shown in the detail view
  showAll: false,
  fresh: new Set(), // apps that just became culprits (row flash)
  explanations: new Map(), // tracker domain -> one sentence (optional LLM explainer)
  view: 'caught', // 'caught' | 'timeline'
  appHistory: new Map(), // app -> {endpoints, findings} from /api/history
  lastVisit: 0, // seconds; previous visit, for "while you were away"
  awayChecked: false,
  countryNames: new Map(),
};

const $ = (id) => document.getElementById(id);
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
// Hostnames come from DNS (attacker-controllable) — everything rendered as HTML goes through esc().
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const SEVERITY = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
// Trusted apps leave the Caught list — unless they touched known malware, which trust never hides.
const isCulprit = (p) => !!p && (!p.trusted || p.malware_count > 0)
  && (p.tracker_count > 0 || p.suspicious_count > 0 || p.alert_count > 0 || p.malware_count > 0)
  && SEVERITY[p.severity || 'info'] >= SEVERITY[state.stats?.min_severity || 'low'];
const hostOf = (c) => c.remote_host || c.raddr;
const countryName = (code) => state.countryNames.get(code) || code || 'Unknown';

function hexA(hex, alpha) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
}

// ---------------------------------------------------------------- toast

let toastTimer = null;
function toast(msg, ms = 3200) {
  const el = $('toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, ms);
}

// ---------------------------------------------------------------- live feed

let wasConnected = false;
let lostAt = 0;
function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
  ws.onopen = () => {
    // The server replays a full snapshot on every (re)connect, so culprits update in place.
    state.open.clear();
    state.history.clear();
    state.procs.clear();
    lastPanelHtml = '';
    setConnState('live', 'live');
    if (lostAt) toast('Reconnected — back to live.');
    lostAt = 0;
    wasConnected = true;
  };
  ws.onmessage = (e) => {
    try { handle(JSON.parse(e.data)); } catch (err) { console.error('bad event', err); }
  };
  ws.onclose = () => {
    setConnState('disconnected — retrying…', 'down');
    if (wasConnected && !lostAt) {
      lostAt = Date.now();
      toast('Lost connection to netpulse — is `netpulse watch` still running? Retrying…', 6000);
    }
    setTimeout(connect, 2000);
  };
}

function setConnState(text, cls) {
  const el = $('conn-state');
  el.textContent = text;
  el.className = `conn-state ${cls}`;
}

function handle(ev) {
  switch (ev.type) {
    case 'origin':
      state.origin = ev.origin;
      map.setOrigin(ev.origin);
      scheduleRender({ map: true });
      break;
    case 'connection_new':
    case 'connection_update':
      upsert(ev.connection);
      break;
    case 'connection_closed':
      closeConnection(ev.id, ev.closed_at);
      break;
    case 'process_update':
      updateProcess(ev.process);
      break;
    case 'stats':
      updateStats(ev.stats);
      break;
    case 'reset':
      onReset(ev.target);
      break;
  }
}

// ---------------------------------------------------------------- per-area reset

const RESET_CONFIRM = {
  caught: 'Clear the Caught list?\n\nnetpulse forgets which apps it caught, including from saved history. '
    + 'Apps that are still connecting will reappear. Your timeline, trust list and blocks are kept.',
  timeline: 'Clear the timeline?\n\nAll saved findings are deleted. Caught, your trust list and blocks are kept.',
  trust: 'Clear the trust list?\n\nEvery app and domain you trusted will be called out again.',
};
const RESET_DONE = {
  caught: 'Caught list cleared.',
  timeline: 'Timeline cleared.',
  report: 'New report period started. The report now counts activity from this moment.',
  map: 'Map cleared.',
  trust: 'Trust list cleared.',
};

async function resetArea(target) {
  if (RESET_CONFIRM[target] && !confirm(RESET_CONFIRM[target])) return;
  try {
    await postJson('/api/reset', { target });
    onReset(target);
    toast(RESET_DONE[target]);
  } catch (err) {
    toast(`Couldn't clear: ${err.message}`, 6000);
  }
}

function onReset(target) {
  if (target === 'caught') {
    state.procs.clear();
    state.fresh.clear();
    lastPanelHtml = '';
    if (state.selected) closeDetail();
    scheduleRender({ panel: true, map: true });
  } else if (target === 'map') {
    for (const [id, c] of state.history) if (c.closedAt) state.history.delete(id);
    scheduleRender({ map: true });
  } else if (target === 'timeline') {
    lastTimelineHtml = '';
    $('away-badge').hidden = true;
    if (state.view === 'timeline') loadTimeline();
  } else if (target === 'trust') {
    lastPanelHtml = '';
    scheduleRender({ panel: true });
  }
}

function upsert(c) {
  const prev = state.history.get(c.id);
  c.closedAt = null;
  state.open.set(c.id, c);
  state.history.set(c.id, c);
  const escalated = c.lat != null && RANK[c.category] >= RANK.suspicious
    && (!prev || prev.category !== c.category);
  if (escalated) map.ping(c);
  trimHistory();
  scheduleRender({ map: true, panel: state.selected === c.app });
}

function closeConnection(id, closedAt) {
  // closed_at (seconds) is only set when the server replays history to a freshly loaded page.
  const c = state.history.get(id);
  if (c) c.closedAt = closedAt ? closedAt * 1000 : Date.now();
  state.open.delete(id);
  scheduleRender({ map: true, panel: !!c && state.selected === c.app });
}

function trimHistory() {
  if (state.history.size <= HISTORY_MAX) return;
  for (const [id, c] of state.history) {
    if (c.closedAt) state.history.delete(id);
    if (state.history.size <= HISTORY_MAX * 0.9) break;
  }
}

function updateProcess(p) {
  if (!isCulprit(state.procs.get(p.app)) && isCulprit(p)) state.fresh.add(p.app);
  state.procs.set(p.app, p);
  scheduleRender({ panel: true, map: true });  // a culprit's flagged lines stay on the map
}

function updateStats(s) {
  const prev = state.stats;
  state.stats = s;
  setPill('pill-apps', s.apps);
  setPill('pill-trackers', s.trackers, prev && s.trackers > prev.trackers);
  setPill('pill-countries', s.countries);
  setPill('pill-suspicious', s.suspicious, prev && s.suspicious > prev.suspicious);
  setPill('pill-malware', s.malware || 0, prev && s.malware > (prev.malware || 0));
  $('pill-malware').hidden = !s.malware;
  renderMalwareAlert(s.unattributed_malware || []);
  state.paused = !!s.paused;
  document.body.classList.toggle('paused', state.paused);
  $('btn-pause').textContent = state.paused ? 'Resume' : 'Pause';
  $('map-paused').hidden = !state.paused;
  $('tab-timeline').hidden = !s.history;
  renderAlertsButton(s.alerts || 'off');
  if (s.history && !state.awayChecked) checkAway();
  const trustKey = JSON.stringify(s.trust || {});
  if (prev && (prev.min_severity !== s.min_severity || JSON.stringify(prev.trust || {}) !== trustKey)) {
    lastPanelHtml = '';
    scheduleRender({ panel: true });
    if (state.view === 'timeline') loadTimeline();
  }
  renderUnattributed(s.unattributed || []);
}

function setPill(id, value, bump) {
  const el = $(id);
  el.querySelector('dd').textContent = value;
  if (bump) {
    el.classList.remove('bump');
    void el.offsetWidth; // restart the animation
    el.classList.add('bump');
  }
}

// ---------------------------------------------------------------- render scheduling

const pending = { map: false, panel: false };
let renderTimer = null;
function scheduleRender(parts) {
  pending.map ||= !!parts.map;
  pending.panel ||= !!parts.panel;
  if (renderTimer) return;
  renderTimer = setTimeout(() => {
    renderTimer = null;
    if (pending.map) updateMap();
    if (pending.panel) renderPanel();
    pending.map = pending.panel = false;
  }, RENDER_DELAY_MS);
}

// ---------------------------------------------------------------- Caught panel

function renderPanel() {
  if (state.selected) { renderDetail(); return; }
  const list = [...state.procs.values()]
    .filter((p) => state.showAll || isCulprit(p))
    .sort((a, b) => b.nosiness - a.nosiness || a.name.localeCompare(b.name));
  const html = list.length
    ? list.map(culpritRow).join('')
    : `<div class="empty">Nothing caught yet.<br>Use your laptop normally — browse, open apps —
       and anything tracking you or phoning home shows up here.</div>`;
  // Only touch the DOM when something changed, so a click never lands on a row mid-replacement.
  if (html !== lastPanelHtml) {
    $('caught-list').innerHTML = html;
    lastPanelHtml = html;
    renderTrusted();
  }
  state.fresh.clear();
}
let lastPanelHtml = '';

const PROCESS_ALERTS = new Set(['masquerading', 'silent_tool_online', 'dual_use_tool_online', 'risky_location', 'bad_signature']);

function worstAlert(p) {
  return p.flags.filter((f) => PROCESS_ALERTS.has(f.id))
    .sort((a, b) => SEVERITY[b.severity] - SEVERITY[a.severity])[0];
}

function culpritRow(p) {
  const alert = worstAlert(p);
  const hot = p.malware_count || p.tracker_count || (alert && SEVERITY[alert.severity] >= SEVERITY.critical);
  const blockedApps = (state.stats && state.stats.blocks && state.stats.blocks.apps) || [];
  const blockedChip = blockedApps.includes(p.name) ? '<span class="chip blocked">blocked</span>' : '';
  const malwareChip = p.malware_count
    ? `<span class="chip malware">MALWARE${p.malware_count > 1 ? ` ×${p.malware_count}` : ''}</span>` : '';
  const kind = hot ? '' : isCulprit(p) ? 'mild' : 'clean';
  const alertChip = alert && SEVERITY[alert.severity] >= SEVERITY.high
    ? `<span class="chip ${alert.severity === 'critical' ? 'tracker' : 'suspicious'}">${esc(alert.title)}</span>` : '';
  const fresh = state.fresh.has(p.app) ? 'fresh' : '';
  const sigChip = p.info && (p.info.signature === 'unsigned' || p.info.signature === 'invalid')
    ? `<span class="chip suspicious">${p.info.signature === 'unsigned' ? 'unsigned' : 'bad signature'}</span>` : '';
  const chips = p.top_trackers.length || sigChip || alertChip || malwareChip || blockedChip
    ? `<div class="chips">${blockedChip}${malwareChip}${alertChip}${sigChip}${p.top_trackers.slice(0, 4).map((d) => `<span class="chip tracker">${esc(d)}</span>`).join('')}</div>`
    : '';
  const block = isCulprit(p) ? `<div class="c-actions">
      <button type="button" class="block" data-block="${esc(p.app)}">Block</button>
      ${p.trusted ? '' : `<button type="button" class="trust" data-trust-app="${esc(p.app)}" title="Mark as expected: hide it from Caught">Trust</button>`}
    </div>` : '';
  return `<div class="culprit ${kind} ${fresh}" data-app="${esc(p.app)}">
    <div class="sev-bar"></div>
    <div class="c-body">
      ${p.last_seen && Date.now() / 1000 - p.last_seen > 120 ? `<div class="c-ago">last active ${ago(p.last_seen)}</div>` : ''}
      <div class="c-top"><span class="c-name" title="${esc(p.exe || p.name)}">${esc(p.name)}</span>
        <span class="c-score" title="nosiness">${Math.round(p.nosiness)}</span></div>
      <div class="meter"><i style="width:${Math.max(3, Math.min(100, p.nosiness))}%"></i></div>
      <div class="verdict">${esc(p.verdict_text)}</div>
      ${chips}
    </div>
    ${block}
  </div>`;
}

function renderMalwareAlert(hits) {
  const el = $('malware-alert');
  el.hidden = !hits.length;
  if (!hits.length) return;
  el.innerHTML = `<b>Known malware domain looked up on this computer</b>
    <div>${hits.map((h) => `<div class="mono">${esc(h)}</div>`).join('')}</div>
    <div class="k">No open connection explains it yet — whatever looked it up may connect later, or already did too
      quickly to see. A full antivirus scan is worth running.</div>`;
}

function renderUnattributed(domains) {
  const el = $('unattributed');
  el.hidden = !domains.length;
  if (!domains.length) return;
  el.innerHTML = `Also looked up on this machine (app unknown):
    <div class="chips">${domains.map((d) => `<span class="chip tracker">${esc(d)}</span>`).join('')}</div>`;
}

function renderDetail() {
  const p = state.procs.get(state.selected);
  if (!p) { closeDetail(); return; }
  const conns = [...state.history.values()].filter((c) => c.app === state.selected);

  // One row per endpoint (host, port, category), not per socket.
  const rows = new Map();
  for (const c of conns) {
    const key = `${hostOf(c)}|${c.rport}|${c.category}`;
    // What "trust" on this row would cover: the tracker/malware rule if there is one, else the host.
    const isIp = (c.threat_indicator || '').match(/^[\d.:]+$/);
    const rule = c.tracker_rule || (!isIp && c.threat_indicator) || c.remote_host;
    const r = rows.get(key) || { host: hostOf(c), ip: c.raddr, port: c.rport, category: c.category, country: c.country, rule, n: 0, open: 0 };
    r.n += 1;
    if (!c.closedAt) r.open += 1;
    rows.set(key, r);
  }
  const sorted = [...rows.values()].sort((a, b) => RANK[b.category] - RANK[a.category] || b.open - a.open || b.n - a.n
    || a.host.localeCompare(b.host));

  const flags = new Map();
  for (const f of p.flags) flags.set(f.title, f);
  for (const c of conns) for (const f of c.flags) if (f.severity !== 'info') flags.set(f.title, f);

  const html = `
    <h3>${esc(p.name)}</h3>
    <div class="exe">${esc(p.exe || 'path unavailable')}${p.pid ? ` · pid ${p.pid}` : ''}</div>
    <div class="verdict">${esc(p.verdict_text)}</div>
    ${p.malware.length ? `<div class="section malware-title">Known malware</div>
      ${p.malware.map((m) => `<div class="flag critical malware">${esc(m)}</div>`).join('')}` : ''}
    ${aboutApp(p)}
    <div class="chips">
      <span class="chip">nosiness ${Math.round(p.nosiness)}</span>
      <span class="chip">${plural(p.distinct_remotes, 'remote')}</span>
      <span class="chip">${plural(p.distinct_countries, 'country').replace('countrys', 'countries')}</span>
    </div>
    ${p.top_trackers.length ? `<div class="section">Trackers</div>
      <div class="chips">${p.top_trackers.map((d) => `<span class="chip tracker">${esc(d)}</span>`).join('')}</div>` : ''}
    ${p.top_trackers.some((d) => state.explanations.has(d)) ? `<div class="explain-list">
      ${p.top_trackers.filter((d) => state.explanations.has(d)).map((d) => `<div><span class="mono">${esc(d)}</span><br>${esc(state.explanations.get(d))}</div>`).join('')}
    </div>` : ''}
    ${flags.size ? `<div class="section">Findings</div>
      ${[...flags.values()].slice(0, 8).map((f) => `<div class="flag ${esc(f.severity)}"><b>${esc(f.title)}</b><br>${esc(f.detail)}</div>`).join('')}` : ''}
    ${historySection(p.app, new Set(rows.keys()))}
    <div class="section">Connections this session (${sorted.length})</div>
    <div class="conn-list">
      ${sorted.slice(0, 150).map((r) => `<div class="conn ${r.open ? '' : 'closed'}">
        <span class="host" title="${esc(r.ip)}">${esc(r.host)}:${r.port}</span>
        <span class="meta">${esc(r.country || '—')}${r.n > 1 ? ` ×${r.n}` : ''}</span>
        <span class="chip ${esc(r.category)}">${esc(r.category)}</span>
        ${RANK[r.category] >= RANK.suspicious && r.rule
          ? `<button type="button" class="trust-link" data-trust-domain="${esc(r.rule)}" data-category="${esc(r.category)}" title="Trust ${esc(r.rule)} and its subdomains">trust</button>`
          : '<span></span>'}
      </div>`).join('')}
    </div>`;
  // The Block button lives outside the re-rendered area so it's never swapped out under a click.
  const block = $('btn-detail-block');
  block.hidden = !isCulprit(p);
  block.textContent = `Block ${p.name}`;
  $('btn-detail-trust').textContent = p.trusted ? 'Untrust app' : 'Trust app';
  const explain = $('btn-explain');
  explain.hidden = !(state.stats?.llm && p.top_trackers.some((d) => !state.explanations.has(d)));
  if (html !== lastDetailHtml) {
    $('detail').innerHTML = html;
    lastDetailHtml = html;
  }
}
let lastDetailHtml = '';

function ago(seconds) {
  const s = Math.max(0, Date.now() / 1000 - seconds);
  if (s < 90) return 'just now';
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

const SIGNATURE = {
  valid: (i) => `<span class="sig ok">${esc(i.signer || 'Signed')}</span> <span class="k">verified</span>`,
  unsigned: () => '<span class="sig warn">Unsigned</span> <span class="k">no verified publisher</span>',
  invalid: (i) => `<span class="sig bad">Signature invalid or untrusted</span>${i.signer ? ` <span class="k">claims ${esc(i.signer)}</span>` : ''}`,
  unknown: () => '<span class="k">Publisher unknown</span>',
  checking: () => '<span class="k">checking signature…</span>',
};

function aboutApp(p) {
  const i = p.info;
  if (!i) return '<div class="section">About this app</div><div class="about k">Looking up publisher and launch details…</div>';
  const parent = i.parent_name ? `${esc(i.parent_name)} <span class="k">pid ${i.parent_pid}</span>`
    : i.parent_pid ? `<span class="k">pid ${i.parent_pid} (no longer running)</span>` : '<span class="k">unknown</span>';
  const started = i.started ? `${ago(i.started)} <span class="k">${esc(new Date(i.started * 1000).toLocaleString())}</span>` : '<span class="k">unknown</span>';
  return `<div class="section">About this app</div>
    <dl class="about">
      <dt>Publisher</dt><dd>${SIGNATURE[i.signature](i)}</dd>
      <dt>Started</dt><dd>${started}</dd>
      <dt>Started by</dt><dd>${parent}</dd>
      ${i.user ? `<dt>User</dt><dd>${esc(i.user)}</dd>` : ''}
      <dt>Command</dt><dd>${i.cmdline ? `<code>${esc(i.cmdline)}</code>` : '<span class="k">not available (run as admin to see protected processes)</span>'}</dd>
    </dl>`;
}

function openDetail(app) {
  state.selected = app;
  $('caught-view').hidden = true;
  $('timeline-view').hidden = true;
  $('detail-view').hidden = false;
  $('btn-back').textContent = state.view === 'timeline' ? 'Back to Timeline' : 'Back to Caught';
  $('btn-clear-panel').hidden = true;
  $('panel').scrollTop = 0;
  renderDetail();
  loadAppHistory(app);
}

function closeDetail() {
  state.selected = null;
  $('detail-view').hidden = true;
  lastDetailHtml = '';
  setView(state.view);
}

// ---------------------------------------------------------------- history & timeline

function storageGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function storageSet(key, value) {
  try { localStorage.setItem(key, value); } catch { /* private window / blocked storage: fine */ }
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

function setView(view) {
  state.view = view;
  $('tab-caught').classList.toggle('active', view === 'caught');
  $('tab-timeline').classList.toggle('active', view === 'timeline');
  if (state.selected) return; // stay in the detail view; the tab applies when going back
  const clear = $('btn-clear-panel');
  clear.hidden = false;
  clear.textContent = view === 'timeline' ? 'Clear timeline' : 'Clear list';
  clear.title = view === 'timeline' ? 'Delete saved findings' : 'Forget the apps caught so far';
  $('caught-view').hidden = view !== 'caught';
  $('timeline-view').hidden = view !== 'timeline';
  if (view === 'timeline') {
    $('away-badge').hidden = true;
    loadTimeline();
  } else {
    renderPanel();
  }
}

async function checkAway() {
  // "While you were away": count events since the previous visit, then remember this visit.
  state.awayChecked = true;
  state.lastVisit = parseFloat(storageGet('netpulse.lastVisit') || '0');
  storageSet('netpulse.lastVisit', String(Date.now() / 1000));
  if (!state.lastVisit) return;
  try {
    const { events } = await fetchJson(`/api/timeline?since=${state.lastVisit}`);
    if (events.length && state.view !== 'timeline') {
      $('away-badge').textContent = `${events.length} new`;
      $('away-badge').hidden = false;
      toast(`While you were away: ${plural(events.length, 'new finding')} — see the Timeline tab.`, 5000);
    }
  } catch { /* history endpoint unavailable: no badge */ }
}

let lastTimelineHtml = '';
async function loadTimeline() {
  let events;
  try {
    ({ events } = await fetchJson(`/api/timeline?all=${$('timeline-all').checked}`));
  } catch (err) {
    $('timeline-list').innerHTML = `<div class="empty">Couldn't load the timeline (${esc(err.message)}).</div>`;
    return;
  }
  // Trusted apps and domains stay out of the timeline (known malware always shows).
  const trustedApps = new Set(((state.stats && state.stats.trust) || {}).apps || []);
  const visible = events.filter((e) => e.kind === 'known_malware' || (!trustedApps.has(e.app) && !trustCovers(e.key)));
  const hidden = events.length - visible.length;
  const note = hidden ? `<div class="k" style="font-size:12px;margin-top:6px">${plural(hidden, 'finding')} about trusted apps or domains hidden.</div>` : '';
  const html = (visible.length ? timelineHtml(visible)
    : '<div class="empty">Nothing recorded yet.<br>Findings appear here the first time each app does something worth knowing — and stay after restarts.</div>') + note;
  if (html !== lastTimelineHtml) {
    $('timeline-list').innerHTML = html;
    lastTimelineHtml = html;
  }
}

function timelineHtml(events) {
  let day = '';
  const out = [];
  for (const e of events) {
    const d = new Date(e.first_seen * 1000);
    const label = d.toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' });
    if (label !== day) {
      day = label;
      out.push(`<div class="tl-day">${esc(label)}</div>`);
    }
    const isNew = state.lastVisit && e.first_seen > state.lastVisit;
    const again = e.hits > 1 ? ` · seen ${e.hits}×, last ${ago(e.last_seen)}` : '';
    out.push(`<div class="tl-row ${isNew ? 'new' : ''}" title="${esc(e.detail || '')}">
      <span class="t">${d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</span>
      <span class="sev ${esc(e.severity)}"></span>
      <span><span class="app" data-app="${esc(e.app)}">${esc(e.name || '?')}</span> — ${esc(e.title)}
        <span class="seen">${esc(again)}</span></span>
    </div>`);
  }
  return out.join('');
}

async function loadAppHistory(app) {
  try {
    const data = await fetchJson(`/api/history?app=${encodeURIComponent(app)}`);
    if (!data.enabled) return;
    state.appHistory.set(app, data);
    if (state.selected === app) renderDetail();
  } catch { /* detail view still shows live data */ }
}

function historySection(app, liveKeys) {
  const h = state.appHistory.get(app);
  if (!h) return '';
  const earlier = h.endpoints.filter((r) => !liveKeys.has(`${r.host || r.ip}|${r.port}|${r.category}`)).slice(0, 60);
  const earlierRows = earlier.map((r) => `<div class="conn closed">
      <span class="host" title="${esc(r.ip)}">${esc(r.host || r.ip)}:${r.port}</span>
      <span class="meta">${esc(r.country || '—')} · ${esc(ago(r.last_seen))}</span>
      <span class="chip ${esc(r.category)}">${esc(r.category)}</span>
      <span></span>
    </div>`).join('');
  const findings = h.findings.slice(0, 40).map((f) => `<div class="tl-row">
      <span class="t">${esc(new Date(f.first_seen * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }))}</span>
      <span class="sev ${esc(f.severity)}"></span>
      <span>${esc(f.title)}${f.hits > 1 ? ` <span class="seen">· seen ${f.hits}×</span>` : ''}</span>
    </div>`).join('');
  return `${findings ? `<div class="section">History</div><div class="timeline-list">${findings}</div>` : ''}
    ${earlierRows ? `<div class="section">Earlier connections (${earlier.length})</div><div class="conn-list">${earlierRows}</div>` : ''}`;
}

// ---------------------------------------------------------------- desktop alerts

const ALERT_LEVELS = ['all', 'critical', 'off'];
const ALERT_LABELS = { all: 'Alerts: all', critical: 'Alerts: critical', off: 'Alerts: off' };

function renderAlertsButton(level) {
  const b = $('btn-alerts');
  b.textContent = ALERT_LABELS[level] || ALERT_LABELS.off;
  b.dataset.level = level;
}

async function cycleAlerts() {
  const current = $('btn-alerts').dataset.level || 'all';
  const next = ALERT_LEVELS[(ALERT_LEVELS.indexOf(current) + 1) % ALERT_LEVELS.length];
  try {
    const res = await fetch('/api/alerts', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ level: next }),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    renderAlertsButton(next);
    toast({ all: 'Desktop alerts: new apps, new trackers, beacons and anything critical.',
            critical: 'Desktop alerts: critical only (malware, fake system files…).',
            off: 'Desktop alerts off.' }[next]);
  } catch (err) {
    toast(`Couldn't change alerts: ${err.message}`);
  }
}

// ---------------------------------------------------------------- trust list

function trustedDomains() {
  return (state.stats && state.stats.trust && state.stats.trust.domains) || [];
}

function trustCovers(host) {
  if (!host) return false;
  const labels = String(host).toLowerCase().split('.');
  const domains = new Set(trustedDomains());
  return labels.some((_, i) => domains.has(labels.slice(i).join('.')));
}

async function setTrust(kind, value, name, on) {
  try {
    const res = await fetch(on ? '/api/trust' : '/api/untrust', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, value, name }),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
    toast(on ? `Trusted ${name}. It won't be called out any more (known malware still will).` : `${name} is no longer trusted.`);
    lastPanelHtml = '';
  } catch (err) {
    toast(`Couldn't update the trust list: ${err.message}`);
  }
}

function trustApp(app) {
  const p = state.procs.get(app);
  if (p) setTrust('app', app, p.name, !p.trusted);
}

function trustDomain(domain, category) {
  if (category === 'malware' && !confirm(`${domain} is on a known-malware list. Only trust it if you're sure it's a false positive. Trust it anyway?`)) return;
  setTrust('domain', domain, domain, true);
}

function renderTrusted() {
  const apps = [...state.procs.values()].filter((p) => p.trusted);
  const domains = trustedDomains();
  const total = apps.length + domains.length;
  $('trusted-box').hidden = !total;
  $('trusted-count').textContent = total;
  $('trusted-list').innerHTML = apps.map((p) => `<div class="trusted-row">
      <span class="v" title="${esc(p.app)}"><span class="kind">app</span>${esc(p.name)}</span>
      <button type="button" data-untrust-kind="app" data-untrust="${esc(p.app)}" data-name="${esc(p.name)}">Untrust</button>
    </div>`).concat(domains.map((d) => `<div class="trusted-row">
      <span class="v"><span class="kind">domain</span>${esc(d)}</span>
      <button type="button" data-untrust-kind="domain" data-untrust="${esc(d)}" data-name="${esc(d)}">Untrust</button>
    </div>`)).join('');
}

// ---------------------------------------------------------------- optional LLM explainer

async function explainTrackers() {
  const p = state.procs.get(state.selected);
  if (!p) return;
  const button = $('btn-explain');
  button.disabled = true;
  button.textContent = 'Asking…';
  try {
    const res = await fetch('/api/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains: p.top_trackers }),
    });
    if (!res.ok) throw new Error(`${res.status}`);
    const { explanations } = await res.json();
    for (const [domain, sentence] of Object.entries(explanations)) state.explanations.set(domain, sentence);
    if (!Object.keys(explanations).length) toast('No explanation available right now — the verdict above still stands.');
  } catch {
    toast('Explainer unavailable — the verdict above still stands.');
  } finally {
    button.disabled = false;
    button.textContent = 'What are these?';
    renderDetail();
  }
}

// ---------------------------------------------------------------- block / export modal

const modal = { apps: [], format: 'hosts', text: '', filename: 'netpulse-hosts.txt', seq: 0 };

function openBlock(app) {
  // app = one culprit's key, or null for "Export blocklist" (everything caught).
  const p = app ? state.procs.get(app) : null;
  modal.apps = app ? [app] : [];
  modal.format = 'hosts';
  $('modal-title').textContent = p ? `Block ${p.name}` : 'Export blocklist — everything caught';
  const ua = navigator.userAgent;
  for (const tab of document.querySelectorAll('.tab[data-os]')) tab.hidden = !ua.includes(tab.dataset.os);
  const canApply = !!(state.stats && state.stats.blocks && state.stats.blocks.supported);
  $('modal-apply').hidden = !canApply;
  $('modal-apply').disabled = false;
  $('modal-note').className = 'note';
  $('modal-note').textContent = canApply
    ? 'Block now edits your hosts file and firewall for you (one Windows admin prompt) — undo anytime under "Blocked". Or copy the rules and apply them yourself.'
    : 'Add these to your hosts file / firewall to block. (One-click blocking is Windows-only for now.)';
  $('modal').hidden = false;
  loadRules();
  $('modal-copy').focus();
}

async function loadRules() {
  const seq = ++modal.seq; // ignore stale responses if the user switches tabs quickly
  for (const tab of document.querySelectorAll('.tab')) tab.classList.toggle('active', tab.dataset.format === modal.format);
  $('modal-text').textContent = 'Generating…';
  $('modal-summary').textContent = '';
  try {
    const res = await fetch('/api/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apps: modal.apps, format: modal.format }),
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    const out = await res.json();
    if (seq !== modal.seq) return;
    modal.text = out.text;
    modal.filename = out.filename;
    $('modal-text').textContent = out.text; // textContent: rule text is never parsed as HTML
    $('modal-summary').textContent = modal.format === 'hosts'
      ? `${plural(out.domains, 'domain')} to block`
      : `${plural(out.ips, 'IP rule')} · tracker domains go in the hosts file`;
  } catch (err) {
    if (seq === modal.seq) $('modal-text').textContent = `Couldn't generate rules: ${err.message}`;
  }
}

async function copyRules() {
  let copied = false;
  try {
    await navigator.clipboard.writeText(modal.text);
    copied = true;
  } catch {
    // Fallback for browsers that refuse the async clipboard API.
    const range = document.createRange();
    range.selectNodeContents($('modal-text'));
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    copied = document.execCommand('copy');
    if (copied) sel.removeAllRanges(); // otherwise leave it selected for a manual Ctrl+C
  }
  toast(copied
    ? 'Copied — paste into your hosts file / an admin PowerShell.'
    : "Couldn't copy automatically — the text is selected, press Ctrl+C.");
}

function saveRules() {
  const url = URL.createObjectURL(new Blob([modal.text], { type: 'text/plain' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: modal.filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function closeModal() {
  $('modal').hidden = true;
}

// ---------------------------------------------------------------- one-click block / undo

async function postJson(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const out = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(out.detail || res.statusText);
  return out;
}

async function applyBlock() {
  const button = $('modal-apply');
  button.disabled = true;
  button.textContent = 'Waiting for Windows…';
  $('modal-note').textContent = 'Approve the Windows admin prompt to apply the block (it may be behind this window).';
  try {
    const out = await postJson('/api/blocks/apply', { apps: modal.apps });
    if (!out.ok) throw new Error(out.error || 'not applied');
    renderBlocked(out);
    closeModal();
    toast(`Blocked ${plural(out.domains, 'domain')}${out.ips ? ` + ${plural(out.ips, 'IP')}` : ''}. Connections already open `
      + 'carry on until the app closes them (restart it to cut them now). Undo anytime under "Blocked".', 7000);
    if (out.warnings && out.warnings.length) setTimeout(() => toast(out.warnings[0], 7000), 5200);
  } catch (err) {
    $('modal-note').className = 'note modal-note-warn';
    $('modal-note').textContent = `Not blocked: ${err.message}`;
  } finally {
    button.disabled = false;
    button.textContent = 'Block now';
  }
}

async function undoBlocks(ids) {
  // Running as admin there is no Windows prompt in between, so "all" gets its own confirmation.
  if (!ids && !confirm('Remove every block netpulse added (hosts file and firewall rules)?')) return;
  toast('Approve the Windows admin prompt to undo…', 4000);
  try {
    const out = await postJson('/api/blocks/undo', ids ? { ids } : { all: true });
    if (!out.ok) throw new Error(out.error || 'not undone');
    renderBlocked(out);
    toast(ids ? 'Unblocked.' : 'All netpulse blocks removed.');
  } catch (err) {
    toast(`Couldn't undo: ${err.message}`, 6000);
  }
}

async function loadBlocked() {
  try { renderBlocked(await fetchJson('/api/blocks')); } catch { /* no blocks panel */ }
}

function renderBlocked(summary) {
  const entries = summary.entries || [];
  state.blockedDomains = new Set(entries.filter((e) => e.kind === 'domain' && e.active).map((e) => e.value));
  scheduleRender({ map: true });
  $('blocked-box').hidden = !entries.length;
  $('blocked-count').textContent = entries.length;
  $('blocked-list').innerHTML = entries.map((e) => `<div class="trusted-row ${e.active ? '' : 'inactive'}" title="${e.active ? '' : 'Not in the hosts file any more (edited by hand or reverted by antivirus)'}">
      <span class="v"><span class="kind">${esc(e.kind)}</span>${esc(e.value)} <span class="apps">· ${esc(e.apps.join(', '))}</span></span>
      <button type="button" data-undo="${esc(e.id)}">Undo</button>
    </div>`).join('');
}

// ---------------------------------------------------------------- map data (shared)

// Stable 0..1 per key, so each endpoint's line keeps the same arc height between renders.
function spreadOf(key) {
  let h = 2166136261;
  for (let i = 0; i < key.length; i++) h = Math.imul(h ^ key.charCodeAt(i), 16777619);
  return (h >>> 0) / 4294967296;
}

const isBlocked = (c) => state.blockedDomains.has(hostOf(c)) || state.blockedDomains.has(c.tracker_rule);

// A closed connection stays on the map for ARC_LINGER_MS — or, if it was a tracker/suspicious/
// malware endpoint, for as long as its app is still in Caught (short beacons would otherwise
// flash for a minute and vanish). Once blocked, or after "Clear list", it goes.
function onMap(c, now) {
  if (c.scope !== 'public' || c.lat == null) return false;
  if (!c.closedAt) return true;
  if (isBlocked(c)) return false;
  if (now - c.closedAt <= ARC_LINGER_MS) return true;
  return c.category !== 'normal' && isCulprit(state.procs.get(c.app));
}

function arcGroups() {
  const now = Date.now();
  const groups = new Map();
  for (const c of state.history.values()) {
    if (!onMap(c, now)) continue;
    // One line per remote endpoint (GeoIP is country-level, so they'd all overlap: each gets its
    // own arc height instead).
    const key = `${hostOf(c)}|${c.category}`;
    let g = groups.get(key);
    if (!g) {
      // Land each line a little way off the country's centre (up to ~2°), in its own direction.
      const turn = spreadOf(key + '#') * 2 * Math.PI, reach = 0.5 + 1.5 * spreadOf(key + '@');
      g = { key, country: c.country, category: c.category, clat: c.lat, clon: c.lon,
            lat: c.lat + Math.sin(turn) * reach, lon: c.lon + Math.cos(turn) * reach,
            count: 0, open: 0, apps: new Map(), hosts: new Map(), spread: spreadOf(key) };
      groups.set(key, g);
    }
    g.count += 1;
    if (!c.closedAt) g.open += 1;
    g.apps.set(c.process_name, (g.apps.get(c.process_name) || 0) + 1);
    g.hosts.set(hostOf(c), (g.hosts.get(hostOf(c)) || 0) + 1);
  }
  return groups;
}

function topEntries(m, n) {
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
}

function groupTip(g) {
  const apps = topEntries(g.apps, 3).map(([a, n]) => esc(a) + (n > 1 ? ` ×${n}` : '')).join(', ');
  const hosts = topEntries(g.hosts, 4).map(([h]) => esc(h)).join('<br>');
  return `<div class="cat" style="color:${COLORS[g.category]}">${esc(g.category)}</div>
    <div><b>${esc(countryName(g.country))}</b> · ${plural(g.count, 'connection')} (${g.open} open)</div>
    <div>${apps}</div>
    <div class="mono">${hosts}</div>`;
}

function endpoints(groups) {
  // One dot per country, colored by its worst category.
  const byCountry = new Map();
  for (const g of groups.values()) {
    const e = byCountry.get(g.country);
    if (!e) byCountry.set(g.country, { lat: g.clat, lon: g.clon, count: g.count, category: g.category, groups: [g] });
    else {
      e.count += g.count;
      e.groups.push(g);
      if (RANK[g.category] > RANK[e.category]) e.category = g.category;
    }
  }
  return [...byCountry.values()];
}

function endpointTip(e) {
  return e.groups.sort((a, b) => RANK[b.category] - RANK[a.category]).map(groupTip).join('<hr>');
}

// Arc height grows with distance; `spread` (0..1) fans out lines that land in the same country.
function arcAltitude(o, lat, lon, spread) {
  const r = Math.PI / 180;
  const cos = Math.sin(o.lat * r) * Math.sin(lat * r) + Math.cos(o.lat * r) * Math.cos(lat * r) * Math.cos((lon - o.lon) * r);
  const angle = Math.acos(Math.max(-1, Math.min(1, cos)));
  return Math.max(0.03 + 0.05 * spread, angle * (0.1 + 0.22 * spread));
}

function updateMap() {
  const groups = arcGroups();
  map.update(groups);
  $('map-empty').hidden = groups.size > 0;
}

// ---------------------------------------------------------------- globe

function createGlobeMap(container, world) {
  const arcs = new Map(); // stable objects so globe.gl keeps arc animations running
  let rings = [];
  let activeKey = '';
  let active = new Set();
  // Countries we're talking to get a slightly brighter outline. (Plain polygons, not hexPolygons:
  // globe.gl's h3-based hex layer throws on some Natural Earth shapes and skips the rest of the map.)
  const capColor = (f) => (active.has(f.properties.iso) ? 'rgba(230,227,220,0.06)' : 'rgba(0,0,0,0)');
  const strokeColor = (f) => (active.has(f.properties.iso) ? 'rgba(230,227,220,0.55)' : 'rgba(230,227,220,0.16)');

  const globe = Globe({ animateIn: true })(container)
    .backgroundColor('rgba(0,0,0,0)')
    .showAtmosphere(false)
    .showGraticules(true)
    .polygonsData(world.features)
    .polygonAltitude(0.006)
    .polygonCapColor((f) => capColor(f))
    .polygonSideColor(() => 'rgba(0,0,0,0)')
    .polygonStrokeColor((f) => strokeColor(f))
    .polygonsTransitionDuration(0)
    .polygonLabel((f) => `<div class="globe-tip">${esc(f.properties.name)}</div>`)
    .arcStartLat('startLat').arcStartLng('startLng').arcEndLat('endLat').arcEndLng('endLng')
    // Red and yellow lines are solid in their category colour end to end (dimmer once the app has
    // no connection open there); normal ones are a quieter grey so the problems stand out.
    .arcColor((d) => (d.category === 'normal' ? [hexA(COLORS.normal, 0.25), hexA(COLORS.normal, 0.75)]
      : d.live ? COLORS[d.category] : hexA(COLORS[d.category], 0.5)))
    // Malware: heaviest and still; trackers/suspicious: a long moving dash; normal: a thin dash.
    .arcStroke((d) => (d.category === 'malware' ? 1.6 : Math.min(1.2, (d.category === 'normal' ? 0.3 : 0.6) + Math.log2(1 + d.count) * 0.1)))
    .arcDashLength((d) => ({ malware: 1, tracker: 0.7, suspicious: 0.7 }[d.category] ?? 0.35))
    .arcDashGap((d) => ({ malware: 0, tracker: 0.15, suspicious: 0.15 }[d.category] ?? 0.4))
    .arcDashInitialGap(() => Math.random())
    .arcDashAnimateTime((d) => ({ malware: 0, tracker: 1800, suspicious: 2600 }[d.category] ?? 4500))
    .arcAltitude('alt')
    .arcLabel((d) => `<div class="globe-tip">${groupTip(d.group)}</div>`)
    .pointLat('lat').pointLng('lng').pointColor('color').pointAltitude(0.012).pointRadius('radius')
    .pointLabel((d) => `<div class="globe-tip">${d.tip}</div>`)
    .ringLat('lat').ringLng('lng')
    .ringColor((d) => (t) => hexA(d.color, Math.max(0, 1 - t)))
    .ringMaxRadius('maxR')
    .ringPropagationSpeed(2.5)
    .ringRepeatPeriod('period');

  const material = globe.globeMaterial();
  material.color.set('#1a1a1a');
  if (material.emissive) material.emissive.set('#111111');
  material.shininess = 0;

  const controls = globe.controls();
  controls.autoRotate = storageGet('netpulse.rotate') !== 'off';
  controls.autoRotateSpeed = 0.2;

  const fit = () => globe.width(container.clientWidth).height(container.clientHeight);
  new ResizeObserver(fit).observe(container);
  fit();

  function originRing() {
    return { lat: state.origin.lat, lng: state.origin.lon, color: ORIGIN_COLOR, maxR: 2, period: 2400, origin: true };
  }

  function setRings() {
    globe.ringsData([originRing(), ...rings]);
  }

  return {
    get rotating() { return controls.autoRotate; },
    setRotating(on) { controls.autoRotate = on; },
    setOrigin(o) {
      // Look from ~20° north of the origin so polar routes (e.g. Asia -> US) read as arcs, not spikes.
      globe.pointOfView({ lat: Math.max(-60, Math.min(60, o.lat + 20)), lng: o.lon, altitude: 1.9 }, 1500);
      setRings();
    },
    ping(c) {
      const off = OFFSET[c.category];
      const ring = { lat: c.lat + off[0], lng: c.lon + off[1], color: COLORS[c.category], maxR: 4, period: 900 };
      rings.push(ring);
      setRings();
      setTimeout(() => { rings = rings.filter((r) => r !== ring); setRings(); }, 3200);
    },
    update(groups) {
      const o = state.origin;
      let changed = false;
      for (const g of groups.values()) {
        let a = arcs.get(g.key);
        if (!a) { a = { key: g.key }; arcs.set(g.key, a); changed = true; }
        const off = OFFSET[g.category];
        const endLat = g.lat + off[0], endLng = g.lon + off[1];
        const next = { startLat: o.lat, startLng: o.lon, endLat, endLng, category: g.category, count: g.count,
                       live: g.open > 0, alt: arcAltitude(o, endLat, endLng, g.spread) };
        for (const k in next) if (a[k] !== next[k]) { a[k] = next[k]; changed = true; }
        a.group = g;
      }
      for (const k of [...arcs.keys()]) if (!groups.has(k)) { arcs.delete(k); changed = true; }
      if (changed) {
        globe.arcsData([...arcs.values()]);
        const points = endpoints(groups).map((e) => ({
          lat: e.lat, lng: e.lon, color: COLORS[e.category], radius: 0.25 + Math.min(0.6, Math.log2(1 + e.count) * 0.12), tip: endpointTip(e),
        }));
        points.push({ lat: o.lat, lng: o.lon, color: ORIGIN_COLOR, radius: 0.45, tip: `<b>${esc(o.label)}</b>` });
        globe.pointsData(points);
      }
      const nextActive = new Set([...groups.values()].map((g) => g.country));
      const key = [...nextActive].sort().join(',');
      if (key !== activeKey) {
        activeKey = key;
        active = nextActive;
        // New accessors => globe.gl re-evaluates the highlight.
        globe.polygonCapColor((f) => capColor(f)).polygonStrokeColor((f) => strokeColor(f));
      }
    },
  };
}

// ---------------------------------------------------------------- 2D fallback

function createFlatMap(canvas, world) {
  const tip = $('flat-tip');
  const ctx = canvas.getContext('2d');
  const land = document.createElement('canvas');
  let W = 0, H = 0, dpr = 1, scale = 1, ox = 0, oy = 0;
  let groups = new Map();
  let dots = [];
  let pings = [];
  const LAT_TOP = 80, LAT_SPAN = 138; // crop Antarctica

  const proj = (lat, lon) => [ox + (lon + 180) * scale, oy + (LAT_TOP - lat) * scale];

  function resize() {
    dpr = window.devicePixelRatio || 1;
    W = canvas.clientWidth;
    H = canvas.clientHeight;
    canvas.width = land.width = W * dpr;
    canvas.height = land.height = H * dpr;
    scale = Math.min((W - 40) / 360, (H - 60) / LAT_SPAN);
    ox = (W - 360 * scale) / 2;
    oy = (H - LAT_SPAN * scale) / 2;
    const l = land.getContext('2d');
    l.setTransform(dpr, 0, 0, dpr, 0, 0);
    l.clearRect(0, 0, W, H);
    // Faint 30° graticule, then outlines.
    l.strokeStyle = 'rgba(230,227,220,0.05)';
    l.lineWidth = 1;
    for (let lon = -180; lon <= 180; lon += 30) {
      const [x1, y1] = proj(LAT_TOP, lon), [x2, y2] = proj(LAT_TOP - LAT_SPAN, lon);
      l.beginPath(); l.moveTo(x1, y1); l.lineTo(x2, y2); l.stroke();
    }
    for (let lat = -30; lat <= 60; lat += 30) {
      const [x1, y1] = proj(lat, -180), [x2, y2] = proj(lat, 180);
      l.beginPath(); l.moveTo(x1, y1); l.lineTo(x2, y2); l.stroke();
    }
    l.fillStyle = 'rgba(230,227,220,0.025)';
    l.strokeStyle = 'rgba(230,227,220,0.2)';
    l.lineWidth = 0.6;
    for (const f of world.features) {
      const polys = f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates;
      for (const poly of polys) {
        l.beginPath();
        for (const ringPts of poly) {
          ringPts.forEach(([lon, lat], i) => { const [x, y] = proj(lat, lon); i ? l.lineTo(x, y) : l.moveTo(x, y); });
          l.closePath();
        }
        l.fill('evenodd');
        l.stroke();
      }
    }
  }

  function frame(t) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    ctx.drawImage(land, 0, 0, W, H);
    const [sx, sy] = proj(state.origin.lat, state.origin.lon);
    const ordered = [...groups.values()].sort((a, b) => RANK[a.category] - RANK[b.category]);
    for (const g of ordered) {
      const off = OFFSET[g.category];
      const [ex, ey] = proj(g.lat + off[0], g.lon + off[1]);
      const cx = (sx + ex) / 2, cy = (sy + ey) / 2 - Math.hypot(ex - sx, ey - sy) * (0.15 + 0.3 * g.spread) - 6 * g.spread;
      const color = COLORS[g.category];
      const malware = g.category === 'malware';
      ctx.lineWidth = malware ? 2.5 : Math.min(1.6, 0.8 + Math.log2(1 + g.count) * 0.25);
      ctx.setLineDash([]);
      ctx.strokeStyle = hexA(color, malware ? 0.95 : g.category === 'normal' ? 0.14 : 0.45);
      ctx.beginPath(); ctx.moveTo(sx, sy); ctx.quadraticCurveTo(cx, cy, ex, ey); ctx.stroke();
      if (!malware) {  // malware stays a solid line; the rest get a slow moving dash
        ctx.setLineDash([6, 10]);
        ctx.lineDashOffset = -t / (g.category === 'tracker' ? 30 : 70);
        ctx.strokeStyle = hexA(color, g.category === 'normal' ? 0.55 : 0.9);
        ctx.beginPath(); ctx.moveTo(sx, sy); ctx.quadraticCurveTo(cx, cy, ex, ey); ctx.stroke();
      }
    }
    ctx.setLineDash([]);
    for (const d of dots) {
      ctx.fillStyle = COLORS[d.category];
      ctx.beginPath(); ctx.arc(d.x, d.y, Math.max(2, d.r * 0.7), 0, Math.PI * 2); ctx.fill();
    }
    const now = performance.now();
    pings = pings.filter((p) => now - p.t0 < 2400);
    for (const p of pings) {
      const k = (now - p.t0) / 2400;
      const [px, py] = proj(p.lat, p.lon);
      ctx.strokeStyle = hexA(p.color, 1 - k);
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(px, py, 3 + k * 16, 0, Math.PI * 2); ctx.stroke();
    }
    ctx.fillStyle = ORIGIN_COLOR;
    ctx.beginPath(); ctx.arc(sx, sy, 3.5, 0, Math.PI * 2); ctx.fill();
    ctx.strokeStyle = hexA(ORIGIN_COLOR, 0.35);
    ctx.beginPath(); ctx.arc(sx, sy, 8, 0, Math.PI * 2); ctx.stroke();
    requestAnimationFrame(frame);
  }

  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    const hit = dots.find((d) => Math.hypot(d.x - mx, d.y - my) < d.r + 8);
    tip.hidden = !hit;
    if (hit) {
      tip.innerHTML = hit.tip;
      tip.style.left = `${Math.min(mx + 14, W - 330)}px`;
      tip.style.top = `${my + 14}px`;
    }
  });
  canvas.addEventListener('mouseleave', () => { tip.hidden = true; });

  new ResizeObserver(() => { resize(); placeDots(); }).observe(canvas);
  resize();
  requestAnimationFrame(frame);

  function placeDots() {
    dots = endpoints(groups).map((e) => {
      const [x, y] = proj(e.lat, e.lon);
      return { x, y, r: 3 + Math.min(6, Math.log2(1 + e.count) * 1.4), category: e.category, tip: endpointTip(e) };
    });
  }

  return {
    setOrigin() {},
    ping(c) {
      const off = OFFSET[c.category];
      pings.push({ lat: c.lat + off[0], lon: c.lon + off[1], color: COLORS[c.category], t0: performance.now() });
    },
    update(g) { groups = g; placeDots(); },
  };
}

// ---------------------------------------------------------------- boot

let map = { setOrigin() {}, ping() {}, update() {} }; // until the world data has loaded

function webglAvailable() {
  try {
    const c = document.createElement('canvas');
    return !!(window.WebGLRenderingContext && (c.getContext('webgl2') || c.getContext('webgl')));
  } catch {
    return false;
  }
}

async function initMap() {
  let world = { type: 'FeatureCollection', features: [] };
  try {
    world = await (await fetch('/static/vendor/world.geojson')).json();
  } catch (err) {
    console.warn('world map unavailable', err);
    toast('World outlines failed to load — arcs still work, countries just won\'t be drawn.');
  }
  for (const f of world.features) if (f.properties.iso) state.countryNames.set(f.properties.iso, f.properties.name);

  const force2d = new URLSearchParams(location.search).get('map') === '2d';
  if (!force2d && typeof Globe === 'function' && webglAvailable()) {
    try {
      map = createGlobeMap($('globe'), world);
    } catch (err) {
      console.warn('globe failed, using 2D map', err);
      map = null;
    }
  }
  if (!map || force2d || typeof Globe !== 'function' || !webglAvailable()) {
    $('globe').hidden = true;
    $('flatmap').hidden = false;
    map = createFlatMap($('flatmap'), world);
  }
  map.setOrigin(state.origin);
  updateMap();
  if (map.setRotating) {
    const btn = $('btn-rotate');
    const label = () => { btn.textContent = map.rotating ? 'Stop rotation' : 'Rotate'; };
    btn.hidden = false;
    label();
    btn.addEventListener('click', () => {
      map.setRotating(!map.rotating);
      storageSet('netpulse.rotate', map.rotating ? 'on' : 'off');
      label();
    });
  }
}

function bindUi() {
  $('caught-list').addEventListener('click', (e) => {
    const block = e.target.closest('[data-block]');
    if (block) { openBlock(block.dataset.block); return; }
    const trust = e.target.closest('[data-trust-app]');
    if (trust) { trustApp(trust.dataset.trustApp); return; }
    const row = e.target.closest('.culprit');
    if (row) openDetail(row.dataset.app);
  });
  $('btn-detail-block').addEventListener('click', () => openBlock(state.selected));
  $('btn-explain').addEventListener('click', explainTrackers);
  $('btn-alerts').addEventListener('click', cycleAlerts);
  $('btn-clear-map').addEventListener('click', () => resetArea('map'));
  $('btn-clear-panel').addEventListener('click', () => resetArea(state.view === 'timeline' ? 'timeline' : 'caught'));
  $('btn-clear-trust').addEventListener('click', () => resetArea('trust'));
  $('btn-report-reset').addEventListener('click', () => resetArea('report'));
  $('btn-detail-trust').addEventListener('click', () => trustApp(state.selected));
  $('detail').addEventListener('click', (e) => {
    const el = e.target.closest('[data-trust-domain]');
    if (el) trustDomain(el.dataset.trustDomain, el.dataset.category);
  });
  $('trusted-list').addEventListener('click', (e) => {
    const el = e.target.closest('[data-untrust]');
    if (el) setTrust(el.dataset.untrustKind, el.dataset.untrust, el.dataset.name, false);
  });
  $('btn-back').addEventListener('click', closeDetail);
  $('tab-caught').addEventListener('click', () => { if (state.selected) closeDetail(); setView('caught'); });
  $('tab-timeline').addEventListener('click', () => { if (state.selected) closeDetail(); setView('timeline'); });
  $('timeline-all').addEventListener('change', loadTimeline);
  $('timeline-list').addEventListener('click', (e) => {
    const el = e.target.closest('[data-app]');
    if (!el) return;
    if (state.procs.has(el.dataset.app)) openDetail(el.dataset.app);
    else toast("That app hasn't been active since netpulse started.");
  });
  $('btn-export').addEventListener('click', () => openBlock(null));
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => { modal.format = tab.dataset.format; loadRules(); });
  }
  $('modal-copy').addEventListener('click', copyRules);
  $('modal-apply').addEventListener('click', applyBlock);
  $('btn-undo-all').addEventListener('click', () => undoBlocks(null));
  $('blocked-list').addEventListener('click', (e) => {
    const el = e.target.closest('[data-undo]');
    if (el) undoBlocks([el.dataset.undo]);
  });
  $('modal-save').addEventListener('click', saveRules);
  $('modal-close').addEventListener('click', closeModal);
  $('modal').addEventListener('click', (e) => { if (e.target === $('modal')) closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('modal').hidden) closeModal(); });
  $('show-all').addEventListener('change', (e) => { state.showAll = e.target.checked; renderPanel(); });
  $('btn-pause').addEventListener('click', async () => {
    const next = !state.paused;
    try {
      const res = await fetch(next ? '/api/pause' : '/api/resume', { method: 'POST' });
      if (!res.ok) throw new Error(res.statusText);
      updateStats({ ...(state.stats || {}), paused: next });
      toast(next ? 'Paused — the map is frozen until you resume.' : 'Watching again.');
    } catch (err) {
      toast(`Couldn't ${next ? 'pause' : 'resume'}: ${err.message}`);
    }
  });
}

let errorToasted = false;
window.addEventListener('error', (e) => {
  console.error(e.error || e.message);
  if (!errorToasted) {
    errorToasted = true;
    toast('Something went wrong drawing the dashboard — if it looks stuck, reload the page.', 6000);
  }
});

bindUi();
renderPanel();
loadBlocked();
initMap().finally(connect);
// Expire lingering arcs even when no events arrive.
setInterval(() => scheduleRender({ map: true }), 5000);
// Keep the timeline fresh while it's on screen.
setInterval(() => { if (state.view === 'timeline' && !state.selected) loadTimeline(); }, 15000);
