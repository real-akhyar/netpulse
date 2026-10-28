'use strict';
/* netpulse dashboard — vanilla JS, no build step. Globe via bundled globe.gl (three.js inside);
   automatic 2D canvas fallback when WebGL is unavailable (or with ?map=2d). */

const COLORS = { tracker: '#ff3b5c', suspicious: '#ffb020', normal: '#2de2e6', local: '#5b6478' };
const RANK = { tracker: 3, suspicious: 2, normal: 1, local: 0 };
// Arcs to the same country fan out slightly by category instead of overlapping.
const OFFSET = { tracker: [1.6, 1.6], suspicious: [-1.6, -1.6], normal: [0, 0], local: [0, 0] };
const ARC_LINGER_MS = 60000; // keep an arc this long after its socket closes
const HISTORY_MAX = 4000;
const RENDER_DELAY_MS = 250;

const state = {
  origin: { lat: 20, lon: 0, label: 'You' },
  open: new Map(), // id -> connection currently open
  history: new Map(), // id -> connection incl. closed ones (closedAt), for arcs + detail
  procs: new Map(), // app -> ProcessAgg
  stats: null,
  paused: false,
  selected: null, // app key shown in the detail view
  showAll: false,
  fresh: new Set(), // apps that just became culprits (row flash)
  explanations: new Map(), // tracker domain -> one sentence (optional LLM explainer)
  countryNames: new Map(),
};

const $ = (id) => document.getElementById(id);
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
// Hostnames come from DNS (attacker-controllable) — everything rendered as HTML goes through esc().
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const SEVERITY = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const isCulprit = (p) => !!p && (p.tracker_count > 0 || p.suspicious_count > 0)
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
  }
}

function upsert(c) {
  const prev = state.history.get(c.id);
  c.closedAt = null;
  state.open.set(c.id, c);
  state.history.set(c.id, c);
  const escalated = c.lat != null && (c.category === 'tracker' || c.category === 'suspicious')
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
  scheduleRender({ panel: true });
}

function updateStats(s) {
  const prev = state.stats;
  state.stats = s;
  setPill('pill-apps', s.apps);
  setPill('pill-trackers', s.trackers, prev && s.trackers > prev.trackers);
  setPill('pill-countries', s.countries);
  setPill('pill-suspicious', s.suspicious, prev && s.suspicious > prev.suspicious);
  state.paused = !!s.paused;
  document.body.classList.toggle('paused', state.paused);
  $('btn-pause').textContent = state.paused ? 'Resume' : 'Pause';
  $('map-paused').hidden = !state.paused;
  if (prev && prev.min_severity !== s.min_severity) scheduleRender({ panel: true });
  renderUnattributed(s.unattributed || []);
}

function setPill(id, value, bump) {
  const el = $(id);
  el.querySelector('b').textContent = value;
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
  }
  state.fresh.clear();
}
let lastPanelHtml = '';

function culpritRow(p) {
  const kind = p.tracker_count ? '' : isCulprit(p) ? 'mild' : 'clean';
  const fresh = state.fresh.has(p.app) ? 'fresh' : '';
  const sigChip = p.info && (p.info.signature === 'unsigned' || p.info.signature === 'invalid')
    ? `<span class="chip suspicious">${p.info.signature === 'unsigned' ? '⚠ unsigned' : '✖ bad signature'}</span>` : '';
  const chips = p.top_trackers.length || sigChip
    ? `<div class="chips">${sigChip}${p.top_trackers.slice(0, 4).map((d) => `<span class="chip tracker">${esc(d)}</span>`).join('')}</div>`
    : '';
  const block = isCulprit(p) ? `<button type="button" class="block" data-block="${esc(p.app)}">Block</button>` : '';
  return `<div class="culprit ${kind} ${fresh}" data-app="${esc(p.app)}">
    <div class="glyph">${esc((p.name || '?')[0].toUpperCase())}</div>
    <div class="c-body">
      <div class="c-top"><span class="c-name" title="${esc(p.exe || p.name)}">${esc(p.name)}</span>
        <span class="c-score" title="nosiness">${Math.round(p.nosiness)}</span></div>
      <div class="meter"><i style="width:${Math.max(3, Math.min(100, p.nosiness))}%"></i></div>
      <div class="verdict">${esc(p.verdict_text)}</div>
      ${chips}
    </div>
    ${block}
  </div>`;
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
    const r = rows.get(key) || { host: hostOf(c), ip: c.raddr, port: c.rport, category: c.category, country: c.country, n: 0, open: 0 };
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
    <div class="section">Connections (${sorted.length})</div>
    <div class="conn-list">
      ${sorted.slice(0, 150).map((r) => `<div class="conn ${r.open ? '' : 'closed'}">
        <span class="host" title="${esc(r.ip)}">${esc(r.host)}:${r.port}</span>
        <span class="meta">${esc(r.country || '—')}${r.n > 1 ? ` ×${r.n}` : ''}</span>
        <span class="chip ${esc(r.category)}">${esc(r.category)}</span>
      </div>`).join('')}
    </div>`;
  // The Block button lives outside the re-rendered area so it's never swapped out under a click.
  const block = $('btn-detail-block');
  block.hidden = !isCulprit(p);
  block.textContent = `Block ${p.name}`;
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
  valid: (i) => `<span class="sig ok">✓ ${esc(i.signer || 'Signed')}</span> <span class="k">verified publisher</span>`,
  unsigned: () => '<span class="sig warn">⚠ Unsigned</span> <span class="k">no verified publisher</span>',
  invalid: (i) => `<span class="sig bad">✖ Signature invalid or untrusted</span>${i.signer ? ` <span class="k">claims ${esc(i.signer)}</span>` : ''}`,
  unknown: () => '<span class="sig">? Publisher unknown</span>',
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
  $('detail-view').hidden = false;
  $('panel').scrollTop = 0;
  renderDetail();
}

function closeDetail() {
  state.selected = null;
  $('detail-view').hidden = true;
  $('caught-view').hidden = false;
  lastDetailHtml = '';
  renderPanel();
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

// ---------------------------------------------------------------- map data (shared)

function arcGroups() {
  const now = Date.now();
  const groups = new Map();
  for (const c of state.history.values()) {
    if (c.scope !== 'public' || c.lat == null) continue;
    if (c.closedAt && now - c.closedAt > ARC_LINGER_MS) continue;
    const key = `${c.country}|${c.category}`;
    let g = groups.get(key);
    if (!g) {
      g = { key, country: c.country, category: c.category, lat: c.lat, lon: c.lon, count: 0, open: 0, apps: new Map(), hosts: new Map() };
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
    if (!e) byCountry.set(g.country, { lat: g.lat, lon: g.lon, count: g.count, category: g.category, groups: [g] });
    else {
      e.count += g.count;
      e.groups.push(g);
      if (RANK[g.category] > RANK[e.category]) e.category = g.category;
    }
  }
  return [...byCountry.values()];
}

function endpointTip(e) {
  return e.groups.sort((a, b) => RANK[b.category] - RANK[a.category]).map(groupTip).join('<hr style="border:0;border-top:1px solid rgba(120,160,255,.15)">');
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
  // Countries we're talking to glow brighter. (Plain polygons, not hexPolygons: globe.gl's h3-based
  // hex layer throws on some Natural Earth shapes and then skips the rest of the map.)
  const capColor = (f) => (active.has(f.properties.iso) ? 'rgba(45,226,230,0.22)' : 'rgba(80,110,220,0.07)');
  const strokeColor = (f) => (active.has(f.properties.iso) ? 'rgba(45,226,230,0.9)' : 'rgba(110,140,255,0.35)');

  const globe = Globe({ animateIn: true })(container)
    .backgroundColor('rgba(0,0,0,0)')
    .showAtmosphere(true)
    .atmosphereColor('#2de2e6')
    .atmosphereAltitude(0.16)
    .polygonsData(world.features)
    .polygonAltitude(0.006)
    .polygonCapColor((f) => capColor(f))
    .polygonSideColor(() => 'rgba(0,0,0,0)')
    .polygonStrokeColor((f) => strokeColor(f))
    .polygonsTransitionDuration(0)
    .polygonLabel((f) => `<div class="globe-tip">${esc(f.properties.name)}</div>`)
    .arcStartLat('startLat').arcStartLng('startLng').arcEndLat('endLat').arcEndLng('endLng')
    .arcColor((d) => [hexA(COLORS[d.category], 0.2), hexA(COLORS[d.category], 1)])
    .arcStroke((d) => Math.min(1.8, (d.category === 'tracker' ? 0.6 : 0.35) + Math.log2(1 + d.count) * 0.22))
    .arcDashLength(0.45)
    .arcDashGap(0.25)
    .arcDashInitialGap(() => Math.random())
    .arcDashAnimateTime((d) => (d.category === 'tracker' ? 1100 : d.category === 'suspicious' ? 1700 : 3200))
    .arcAltitudeAutoScale(0.3)
    .arcLabel((d) => `<div class="globe-tip">${groupTip(d.group)}</div>`)
    .pointLat('lat').pointLng('lng').pointColor('color').pointAltitude(0.012).pointRadius('radius')
    .pointLabel((d) => `<div class="globe-tip">${d.tip}</div>`)
    .ringLat('lat').ringLng('lng')
    .ringColor((d) => (t) => hexA(d.color, Math.max(0, 1 - t)))
    .ringMaxRadius('maxR')
    .ringPropagationSpeed(2.5)
    .ringRepeatPeriod('period');

  const material = globe.globeMaterial();
  material.color.set('#081028');
  if (material.emissive) material.emissive.set('#050a1c');
  material.shininess = 6;

  const controls = globe.controls();
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.35;

  const fit = () => globe.width(container.clientWidth).height(container.clientHeight);
  new ResizeObserver(fit).observe(container);
  fit();

  function originRing() {
    return { lat: state.origin.lat, lng: state.origin.lon, color: '#b46bff', maxR: 3, period: 1600, origin: true };
  }

  function setRings() {
    globe.ringsData([originRing(), ...rings]);
  }

  return {
    setOrigin(o) {
      // Look from ~20° north of the origin so polar routes (e.g. Asia -> US) read as arcs, not spikes.
      globe.pointOfView({ lat: Math.max(-60, Math.min(60, o.lat + 20)), lng: o.lon, altitude: 1.9 }, 1500);
      setRings();
    },
    ping(c) {
      const off = OFFSET[c.category];
      const ring = { lat: c.lat + off[0], lng: c.lon + off[1], color: COLORS[c.category], maxR: 7, period: 650 };
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
        const next = { startLat: o.lat, startLng: o.lon, endLat: g.lat + off[0], endLng: g.lon + off[1], category: g.category, count: g.count };
        for (const k in next) if (a[k] !== next[k]) { a[k] = next[k]; changed = true; }
        a.group = g;
      }
      for (const k of [...arcs.keys()]) if (!groups.has(k)) { arcs.delete(k); changed = true; }
      if (changed) {
        globe.arcsData([...arcs.values()]);
        const points = endpoints(groups).map((e) => ({
          lat: e.lat, lng: e.lon, color: COLORS[e.category], radius: 0.35 + Math.min(0.9, Math.log2(1 + e.count) * 0.18), tip: endpointTip(e),
        }));
        points.push({ lat: o.lat, lng: o.lon, color: '#b46bff', radius: 0.6, tip: `<b>${esc(o.label)}</b>` });
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
    l.fillStyle = 'rgba(110,140,255,0.09)';
    l.strokeStyle = 'rgba(110,140,255,0.38)';
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
      const cx = (sx + ex) / 2, cy = (sy + ey) / 2 - Math.hypot(ex - sx, ey - sy) * 0.3;
      const color = COLORS[g.category];
      ctx.lineWidth = Math.min(3, 1 + Math.log2(1 + g.count) * 0.5);
      ctx.setLineDash([]);
      ctx.strokeStyle = hexA(color, 0.18);
      ctx.beginPath(); ctx.moveTo(sx, sy); ctx.quadraticCurveTo(cx, cy, ex, ey); ctx.stroke();
      ctx.setLineDash([10, 12]);
      ctx.lineDashOffset = -t / (g.category === 'tracker' ? 14 : 40);
      ctx.strokeStyle = hexA(color, 0.95);
      ctx.shadowColor = color;
      ctx.shadowBlur = 8;
      ctx.beginPath(); ctx.moveTo(sx, sy); ctx.quadraticCurveTo(cx, cy, ex, ey); ctx.stroke();
      ctx.shadowBlur = 0;
    }
    ctx.setLineDash([]);
    for (const d of dots) {
      ctx.fillStyle = COLORS[d.category];
      ctx.shadowColor = COLORS[d.category];
      ctx.shadowBlur = 10;
      ctx.beginPath(); ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2); ctx.fill();
    }
    ctx.shadowBlur = 0;
    const now = performance.now();
    pings = pings.filter((p) => now - p.t0 < 2400);
    for (const p of pings) {
      const k = (now - p.t0) / 2400;
      const [px, py] = proj(p.lat, p.lon);
      ctx.strokeStyle = hexA(p.color, 1 - k);
      ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(px, py, 4 + k * 26, 0, Math.PI * 2); ctx.stroke();
    }
    const pulse = 5 + Math.sin(t / 300) * 1.5;
    ctx.fillStyle = '#b46bff';
    ctx.shadowColor = '#b46bff';
    ctx.shadowBlur = 16;
    ctx.beginPath(); ctx.arc(sx, sy, pulse, 0, Math.PI * 2); ctx.fill();
    ctx.shadowBlur = 0;
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
}

function bindUi() {
  $('caught-list').addEventListener('click', (e) => {
    const block = e.target.closest('[data-block]');
    if (block) { openBlock(block.dataset.block); return; }
    const row = e.target.closest('.culprit');
    if (row) openDetail(row.dataset.app);
  });
  $('btn-detail-block').addEventListener('click', () => openBlock(state.selected));
  $('btn-explain').addEventListener('click', explainTrackers);
  $('btn-back').addEventListener('click', closeDetail);
  $('btn-export').addEventListener('click', () => openBlock(null));
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => { modal.format = tab.dataset.format; loadRules(); });
  }
  $('modal-copy').addEventListener('click', copyRules);
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
initMap().finally(connect);
// Expire lingering arcs even when no events arrive.
setInterval(() => scheduleRender({ map: true }), 5000);
