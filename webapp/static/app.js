/* Vulnify dashboard application logic. Vanilla JS, no build step. */
'use strict';

const State = {
  data: null, catalog: null, connectors: null, prefs: null, live: null,
  view: 'overview', sort: { key: 'urgency', dir: -1 },
  filter: 'all', query: '', liveFilter: 'all', sectorFilter: null,
  analyzedVersion: 0, mapRAF: null,
};
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = n => (n == null ? '0' : Number(n).toLocaleString());
const SEV_CLASS = { CRITICAL: 'b-crit', HIGH: 'b-high', MEDIUM: 'b-med', LOW: 'b-low', UNRATED: 'b-unrated' };
const SEV_COLOR = { CRITICAL: '#ff3b5c', HIGH: '#ff8a3d', MEDIUM: '#f5c451', LOW: '#2bd4a0', UNRATED: '#5e6b7d' };
const icon = (n, s) => window.VIcons.icon(n, s);

const LOGO = `<svg viewBox="0 0 48 48"><defs><linearGradient id="bm" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2ee6a6"/><stop offset="1" stop-color="#0fa97a"/></linearGradient></defs>
<path d="M24 3.5 L40.5 8.8 V23.5 C40.5 33.7 33.4 40.8 24 44 C14.6 40.8 7.5 33.7 7.5 23.5 V8.8 Z" fill="none" stroke="url(#bm)" stroke-width="2.4" stroke-linejoin="round"/>
<path d="M24 3.5 L40.5 8.8 V23.5 C40.5 33.7 33.4 40.8 24 44 C14.6 40.8 7.5 33.7 7.5 23.5 V8.8 Z" fill="url(#bm)" opacity="0.1"/>
<path d="M13 23 H18 L21 16 L24 31 L27 20 L29.5 23 H35" fill="none" stroke="url(#bm)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="35" cy="23" r="2.1" fill="#f5b73d"/></svg>`;

/* ---------- boot ---------- */
window.addEventListener('DOMContentLoaded', () => {
  $('#brandMark').innerHTML = LOGO;
  window.VIcons.hydrateIcons();
  buildConstellation();
  wireNav(); wireControls();
  loadPrefs();
  connectStream();
  loadLiveSnapshot();
  loadConnectors();
  analyze();
});

function wireNav() {
  $$('.nav-item').forEach(el => el.addEventListener('click', () => switchView(el.dataset.view)));
}
function switchView(view) {
  State.view = view;
  $$('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
  $$('.view').forEach(el => el.classList.toggle('active', el.id === 'view-' + view));
  if (view === 'catalog' && !State.catalog) loadCatalog();
  if (view === 'connectors') renderConnectors();
  if (view === 'settings') renderSettings();
  if (view === 'live') renderStream();
  if (view === 'threatmap') startThreatMap(); else stopThreatMap();
}

function wireControls() {
  $('#run').addEventListener('click', analyze);
  $('#kevToggle').addEventListener('click', e => e.currentTarget.classList.toggle('on'));
  const search = $('#search');
  search.addEventListener('input', e => {
    State.query = e.target.value.trim().toLowerCase();
    if (State.view !== 'vulnerabilities') switchView('vulnerabilities');
    renderVulns();
  });
  $('#fileBtn').addEventListener('click', () => $('#file').click());
  $('#file').addEventListener('change', e => {
    const f = e.target.files[0]; if (!f) return;
    const r = new FileReader();
    r.onload = ev => { $('#assets').value = ev.target.result; $('#fileName').textContent = f.name; };
    r.readAsText(f);
  });
  $('#dlBtn').addEventListener('click', downloadCsv);
  $('#scrim').addEventListener('click', closeDrawer);
  $('#drawerClose').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeDrawer(); hidePopover(); } });
  $('#liveRefresh').addEventListener('click', () => triggerRefresh());
  $('#importRefresh').addEventListener('click', () => triggerRefresh());
  $$('#view-live .chip[data-lf]').forEach(c => c.addEventListener('click', () => {
    State.liveFilter = c.dataset.lf; renderStream();
  }));
  // Connector add form
  $('#addConnBtn').addEventListener('click', () => $('#connform').style.display = '');
  $('#connClose').addEventListener('click', () => $('#connform').style.display = 'none');
  $('#connSave').addEventListener('click', saveConnector);
  $('#prefsSave').addEventListener('click', savePrefs);
}

/* ---------- analyze ---------- */
async function analyze() {
  const btn = $('#run');
  btn.disabled = true; btn.innerHTML = '<span class="loader"></span> Analysing';
  try {
    const body = {
      asset_text: $('#assets').value,
      min_epss: parseFloat($('#minEpss').value) || 0,
      kev_only: $('#kevToggle').classList.contains('on')
    };
    const res = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    if (!res.ok) { toast(data.error || 'Error', 'err'); return; }
    State.data = data;
    State.analyzedVersion = State.live ? State.live.data_version : 0;
    renderAll();
  } catch (err) { toast('Request failed: ' + err.message, 'err'); }
  finally { btn.disabled = false; btn.innerHTML = icon('play', 16) + ' Run analysis'; }
}

function renderAll() {
  updateNavCounts();
  renderOverview();
  renderVulns();
  renderImports();
  renderAssets();
  renderSectors();
  renderThreatPanels();
}

function updateNavCounts() {
  const s = State.data.stats;
  $('#nav-vuln-count').textContent = fmt(State.data.results_total);
  $('#nav-asset-count').textContent = s.assets_supplied;
}

/* ---------- preferences ---------- */
async function loadPrefs() {
  try { State.prefs = await (await fetch('/api/preferences')).json(); }
  catch (_) { State.prefs = { widgets: {}, sectors: [], default_filter: 'all', live: true }; }
  State.filter = State.prefs.default_filter || 'all';
  if (State.data) { renderOverview(); renderVulns(); }
}
function widgetOn(name) { return !State.prefs || !State.prefs.widgets || State.prefs.widgets[name] !== false; }

/* ---------- overview ---------- */
function renderOverview() {
  if (!State.data) return;
  const d = State.data.dashboard, k = d.kpis;
  $('#gauges').style.display = widgetOn('gauges') ? '' : 'none';
  if (widgetOn('gauges')) renderGauges(d.gauges);

  const zerodays = State.data.results.filter(r => r.is_zero_day).length;
  const kpis = [
    { l: 'Relevant CVEs', v: k.relevant_cves, cls: 'info', sub: `${fmt(State.data.stats.cve_records_scanned)} scanned`, ic: 'bug' },
    { l: 'Confirmed exploited', v: k.confirmed, cls: 'crit', sub: 'in CISA KEV catalogue', ic: 'target' },
    { l: 'Zero-day class', v: zerodays, cls: 'gold', sub: 'exploited at disclosure', ic: 'bolt' },
    { l: 'Ransomware linked', v: k.ransomware, cls: 'crit', sub: 'known campaign use', ic: 'fire' },
    { l: 'Critical severity', v: k.critical, cls: 'warn', sub: `${fmt(k.high)} high`, ic: 'alert' },
    { l: 'Mean CVSS', v: k.avg_cvss, cls: 'warn', sub: 'across matches', ic: 'gauge', dec: 1 },
    { l: 'Mean confidence', v: k.avg_confidence, cls: 'good', sub: 'data completeness', ic: 'shield' },
    { l: 'Peak EPSS', v: k.max_epss, cls: 'info', sub: 'top exploitation odds', ic: 'trend', dec: 4 }
  ];
  $('#kpis').innerHTML = kpis.map(c => `
    <div class="kpi ${c.cls}"><div class="glow"></div>
      <div class="k-label">${c.l}</div>
      <div class="k-val" data-count="${c.v}" data-dec="${c.dec || 0}">0</div>
      <div class="k-sub">${esc(c.sub)}</div>
      <div class="k-icon">${icon(c.ic, 22)}</div>
    </div>`).join('');

  $('#ov-warn').innerHTML = State.data.unrecognised.length
    ? `<div class="warn-banner"><b>${State.data.unrecognised.length} unrecognised asset(s):</b> ${State.data.unrecognised.map(esc).join(', ')}. These have no confident CPE mapping and may hide real vulnerabilities.</div>` : '';

  let html = '';
  if (widgetOn('severity') || widgetOn('status'))
    html += `<div class="grid g-2">
      ${widgetOn('severity') ? donutPanel('Severity distribution', 'CVSS qualitative rating', d.severity, k.relevant_cves, 'Total') : ''}
      ${widgetOn('status') ? donutPanel('Exploitation status', 'Confirmed by CISA KEV vs predicted', d.status_split, k.confirmed, 'Confirmed') : ''}
    </div>`;
  if (widgetOn('heatmap'))
    html += `<div class="panel mt14"><div class="panel-head"><h3>Sector × severity heatmap</h3><div class="sub">where exposure concentrates by organisation sector</div></div><div id="ov-heat"></div></div>`;
  if (widgetOn('threat_map'))
    html += `<div class="panel mt14"><div class="panel-head"><h3>Threat map</h3><div class="sub">affected-technology vendor headquarters (stylised, heuristic)</div></div>
      <div class="mapwrap" style="height:320px;border:0"><canvas id="ov-canvas"></canvas></div></div>`;
  if (widgetOn('epss') || widgetOn('cwe'))
    html += `<div class="grid g-2 mt14">
      ${widgetOn('epss') ? barPanel('Exploitation probability (EPSS)', 'how likely, in the next 30 days', d.epss_bands) : ''}
      ${widgetOn('cwe') ? barPanel('Top weakness types (CWE)', 'most common root causes', d.by_cwe.map(x => ({ label: x.name, value: x.value }))) : ''}
    </div>`;
  if (widgetOn('category') || widgetOn('vendor'))
    html += `<div class="grid g-2 mt14">
      ${widgetOn('category') ? barPanel('By product category', 'where the risk concentrates', d.by_category) : ''}
      ${widgetOn('vendor') ? barPanel('By vendor', 'most affected vendors', d.by_vendor) : ''}
    </div>`;
  if (widgetOn('timelines'))
    html += `<div class="grid g-2 mt14">
      ${sparkPanel('CVEs by publication month', d.pub_timeline, '#18d39a')}
      ${sparkPanel('KEV additions by month', d.kev_timeline, '#ff3b5c')}
    </div>`;
  if (widgetOn('assets'))
    html += `<div class="panel mt14"><div class="panel-head"><h3>Exposure by asset</h3></div>${barListAssets(d.top_assets)}</div>`;
  $('#ov-charts').innerHTML = html;

  if (widgetOn('heatmap')) renderHeatmap($('#ov-heat'), d.heatmap);
  if (widgetOn('threat_map')) drawThreatMap($('#ov-canvas'), d.threat_map, false);
  requestAnimationFrame(() => { animateCounts(); animateBars(); });
}

function renderGauges(g) {
  const risk = v => v >= 75 ? '#ff3b5c' : v >= 45 ? '#ff8a3d' : v >= 20 ? '#f5b73d' : '#18d39a';
  const cov = v => v >= 80 ? '#18d39a' : v >= 50 ? '#f5b73d' : '#ff8a3d';
  const items = [
    { key: 'overall', title: 'Composite risk', color: risk(g.overall.value), d: g.overall },
    { key: 'exploitation', title: 'Exploitation', color: risk(g.exploitation.value), d: g.exploitation },
    { key: 'coverage', title: 'Asset coverage', color: cov(g.coverage.value), d: g.coverage },
  ];
  $('#gauges').innerHTML = items.map(it => `
    <div class="gpanel"><div>${Charts.gauge(it.d.value, it.color, it.key)}</div>
      <div class="gmeta"><div class="gt">${it.title}</div>
        <div class="gband" style="color:${it.color}">${esc(it.d.label)}</div>
        <div class="gcap">${esc(it.d.caption)}</div></div></div>`).join('');
}

function donutPanel(title, sub, segments, centerVal, centerLabel) {
  const legend = segments.map(s => `<div class="lr"><span class="sw" style="background:${s.color}"></span>
      <span class="ln">${esc(s.label)}</span><span class="lv">${fmt(s.value)}</span></div>`).join('');
  return `<div class="panel"><h3>${title}</h3><div class="sub">${sub}</div>
    <div class="donut-wrap"><div class="donut">${Charts.donut(segments)}<div class="center"><b>${fmt(centerVal)}</b><span>${centerLabel}</span></div></div>
      <div class="legend">${legend}</div></div></div>`;
}
function barPanel(title, sub, rows) { return `<div class="panel"><h3>${title}</h3><div class="sub">${sub}</div>${barList(rows)}</div>`; }
function barList(rows) {
  if (!rows || !rows.length) return '<div class="empty">No data</div>';
  const max = Math.max(...rows.map(r => r.value), 1);
  return `<div class="barlist">` + rows.map(r => `
    <div class="barrow"><div class="bl" title="${esc(r.label)}">${esc(r.label)}</div>
      <div class="bt"><i data-w="${(r.value / max * 100).toFixed(1)}"></i></div>
      <div class="bv">${fmt(r.value)}</div></div>`).join('') + `</div>`;
}
function barListAssets(rows) {
  if (!rows || !rows.length) return '<div class="empty">No data</div>';
  const max = Math.max(...rows.map(r => r.cves), 1);
  return `<div class="barlist">` + rows.map(r => `
    <div class="barrow"><div class="bl" title="${esc(r.asset)}">${esc(r.asset)}</div>
      <div class="bt"><i data-w="${(r.cves / max * 100).toFixed(1)}"></i></div>
      <div class="bv">${fmt(r.cves)}${r.kev ? ` <span class="badge b-confirmed" style="font-size:9px">${r.kev} KEV</span>` : ''}</div></div>`).join('') + `</div>`;
}
function sparkPanel(title, points, color) { return `<div class="panel"><h3>${title}</h3><div class="sub">trend over time</div>${Charts.sparkArea(points, color)}</div>`; }

/* ---------- heatmap ---------- */
function renderHeatmap(el, rows) {
  if (!el) return;
  if (!rows || !rows.length) { el.innerHTML = '<div class="empty">Run an analysis to populate the heatmap.</div>'; return; }
  const sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNRATED'];
  let max = 1;
  rows.forEach(r => r.cells.forEach(c => { if (c.value > max) max = c.value; }));
  let html = `<div class="heat-head"><div class="hh">Sector</div>${sevs.map(s => `<div class="hh">${s[0] + s.slice(1).toLowerCase()}</div>`).join('')}</div>`;
  html += rows.map(r => {
    const cells = r.cells.map(c => {
      if (!c.value) return `<div class="heatcell zero">·</div>`;
      const alpha = 0.18 + 0.82 * (c.value / max);
      return `<div class="heatcell" style="background:${hexA(SEV_COLOR[c.sev], alpha)}" title="${esc(r.name)} · ${c.sev}: ${c.value}">${fmt(c.value)}</div>`;
    }).join('');
    return `<div class="heatrow"><div class="hl" data-sector="${r.key}"><span class="sdot" style="background:${r.color}"></span>${esc(r.name)}</div>${cells}</div>`;
  }).join('');
  el.innerHTML = html;
  el.querySelectorAll('.hl[data-sector]').forEach(h => h.addEventListener('click', () => filterBySector(h.dataset.sector)));
}
function hexA(hex, a) {
  const m = hex.replace('#', ''); const r = parseInt(m.slice(0, 2), 16), g = parseInt(m.slice(2, 4), 16), b = parseInt(m.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${a.toFixed(3)})`;
}

/* ---------- sectors ---------- */
function renderSectors() {
  if (!State.data) return;
  renderHeatmap($('#heatmap'), State.data.dashboard.heatmap);
  const rows = State.data.dashboard.by_sector;
  const myS = (State.prefs && State.prefs.sectors) || [];
  if (!rows.length) { $('#sectors-grid').innerHTML = '<div class="empty">No sector data.</div>'; return; }
  const max = Math.max(...rows.map(r => r.cves), 1);
  $('#sectors-grid').innerHTML = rows.map(s => `
    <div class="card sector-card" data-sector="${s.key}">
      <div class="ct"><span class="ic" style="color:${s.color}">${icon(s.icon, 17)}</span> ${esc(s.name)}
        ${myS.includes(s.key) ? '<span class="zbadge">MY SECTOR</span>' : ''}</div>
      <div class="cc">${esc(s.description)}</div>
      <div class="crow">
        <div><div class="n">${fmt(s.cves)}</div><div class="l">CVEs</div></div>
        <div><div class="n" style="color:var(--crit)">${fmt(s.kev)}</div><div class="l">Exploited</div></div>
      </div>
      <div class="bar"><i style="width:${(s.cves / max * 100).toFixed(1)}%;background:${s.color}"></i></div>
    </div>`).join('');
  $$('#sectors-grid .sector-card').forEach(c => c.addEventListener('click', () => filterBySector(c.dataset.sector)));
}
function filterBySector(key) {
  State.sectorFilter = key; State.filter = 'all';
  switchView('vulnerabilities'); renderVulns();
}

/* ---------- vulnerabilities ---------- */
function renderVulns() {
  if (!State.data) return;
  let rows = State.data.results.slice();
  const q = State.query;
  if (q) rows = rows.filter(r =>
    r.cve_id.toLowerCase().includes(q) || (r.asset || '').toLowerCase().includes(q) ||
    (r.description || '').toLowerCase().includes(q) || (r.sector_name || '').toLowerCase().includes(q) ||
    r.cwes.some(c => c.name.toLowerCase().includes(q)));
  if (State.sectorFilter) rows = rows.filter(r => r.sector === State.sectorFilter);
  const f = State.filter;
  if (f === 'kev') rows = rows.filter(r => r.kev);
  else if (f === 'zeroday') rows = rows.filter(r => r.is_zero_day);
  else if (f === 'ransomware') rows = rows.filter(r => r.ransomware);
  else if (f === 'critical') rows = rows.filter(r => r.cvss_severity === 'CRITICAL');
  else if (f === 'high') rows = rows.filter(r => r.cvss_severity === 'HIGH' || r.cvss_severity === 'CRITICAL');
  else if (f === 'epss') rows = rows.filter(r => (r.epss_raw || 0) >= 0.5);

  const sk = State.sort.key, dir = State.sort.dir;
  rows.sort((a, b) => {
    let va = a[sk], vb = b[sk];
    if (sk === 'cvss') { va = a.cvss_raw || 0; vb = b.cvss_raw || 0; }
    if (sk === 'epss') { va = a.epss_raw || 0; vb = b.epss_raw || 0; }
    if (typeof va === 'string') return va.localeCompare(vb) * dir;
    return ((va || 0) - (vb || 0)) * dir;
  });

  const secNote = $('#sector-filter-note');
  if (State.sectorFilter) {
    const sm = State.data.sectors.find(s => s.key === State.sectorFilter);
    secNote.innerHTML = `Sector: <b style="color:${sm ? sm.color : '#fff'}">${esc(sm ? sm.name : State.sectorFilter)}</b> <a href="#" id="clearSector">clear</a>`;
    secNote.querySelector('#clearSector').onclick = e => { e.preventDefault(); State.sectorFilter = null; renderVulns(); };
  } else secNote.innerHTML = '';

  $('#vuln-count').textContent = `${fmt(rows.length)} shown of ${fmt(State.data.results_total)} matched`;
  const cols = [['urgency', 'Urgency'], ['cve_id', 'CVE'], ['asset', 'Affected asset'], ['cvss', 'Severity'], ['epss', 'EPSS'], ['status', 'Status'], ['confidence', 'Confidence'], ['sector', 'Sector'], ['', 'Weakness']];
  $('#vuln-thead').innerHTML = '<tr>' + cols.map(([key, lbl]) => `<th data-sort="${key}">${lbl}${key === sk ? (dir === -1 ? ' ▼' : ' ▲') : ''}</th>`).join('') + '</tr>';
  $$('#vuln-thead th').forEach(th => th.addEventListener('click', () => {
    const key = th.dataset.sort; if (!key) return;
    if (State.sort.key === key) State.sort.dir *= -1; else State.sort = { key, dir: -1 };
    renderVulns();
  }));

  const body = rows.slice(0, 600).map(r => {
    const sev = SEV_CLASS[r.cvss_severity] || 'b-unrated';
    const statusBadge = r.ransomware ? '<span class="badge b-ransom">Ransomware</span>'
      : r.kev ? '<span class="badge b-confirmed">Confirmed</span>' : '<span class="badge b-unconfirmed">Unconfirmed</span>';
    const cwe = r.cwes[0] ? `<span class="subt">${esc(r.cwes[0].name)}</span>` : '<span class="subt">n/a</span>';
    return `<tr data-cve="${r.cve_id}">
      <td class="mono"><b>${r.urgency.toFixed(2)}</b></td>
      <td class="cve">${r.cve_id}${r.is_zero_day ? '<span class="zbadge">0-DAY</span>' : ''}</td>
      <td>${esc(r.asset)}<div class="subt">${esc(r.cpe.join(', '))}</div></td>
      <td><span class="badge ${sev}">${cap(r.cvss_severity)} ${r.cvss}</span></td>
      <td class="mono">${r.epss}${r.epss_pct != null ? `<div class="subt">${r.epss_pct} pct</div>` : ''}</td>
      <td>${statusBadge}</td>
      <td><div class="conf"><div class="meter"><i style="width:${r.confidence}%;background:${confColor(r.confidence)}"></i></div><span class="cv">${r.confidence}</span></div></td>
      <td><span class="secchip" style="background:${hexA(r.sector_color, .16)};color:${r.sector_color}">${esc(r.sector_name)}</span></td>
      <td>${cwe}</td>
    </tr>`;
  }).join('');
  $('#vuln-tbody').innerHTML = body || '<tr><td colspan="9" class="empty">No CVEs match the current filters.</td></tr>';
  $$('#vuln-tbody tr[data-cve]').forEach(tr => {
    tr.addEventListener('click', () => openDetail(tr.dataset.cve));
    tr.addEventListener('mouseenter', e => showPopover(tr.dataset.cve, e));
    tr.addEventListener('mouseleave', hidePopover);
  });
  $$('#vuln-filters .chip').forEach(c => {
    c.classList.toggle('active', c.dataset.f === State.filter);
    c.onclick = () => { State.filter = c.dataset.f; renderVulns(); };
  });
}
const cap = s => s ? s[0] + s.slice(1).toLowerCase() : s;
function confColor(v) { return v >= 75 ? '#18d39a' : v >= 50 ? '#f5c451' : '#ff8a3d'; }

/* ---------- hover popover ---------- */
let popTimer = null;
function showPopover(cveId, ev) {
  clearTimeout(popTimer);
  const r = State.data.results.find(x => x.cve_id === cveId); if (!r) return;
  const p = $('#popover');
  const m = r.mitigation || {};
  const link = (m.doc_links && m.doc_links[0]) || { url: r.doc_url, label: 'NVD detail' };
  p.innerHTML = `
    <div class="pv-head"><span class="pv-cve">${r.cve_id}</span>
      ${r.is_zero_day ? '<span class="badge b-zero">Zero-day</span>' : ''}
      <span class="badge ${SEV_CLASS[r.cvss_severity]}">${cap(r.cvss_severity)} ${r.cvss}</span>
      <span class="pv-prio prio-${m.priority || 'Routine'}">${m.priority || 'Routine'}</span></div>
    <div class="pv-desc">${esc((r.description || 'No description available.').slice(0, 320))}</div>
    <div class="pv-sec">Risk summary</div><div class="pv-mit">${esc(r.summary)}</div>
    <div class="pv-sec">Risk mitigation</div><div class="pv-mit">${esc(m.summary || 'Apply the latest vendor update.')}</div>
    <a class="pv-link" href="${esc(link.url)}" target="_blank" rel="noopener">${icon('link', 13)} ${esc(link.label)} — official documentation</a>`;
  p.classList.add('show');
  const px = Math.min(ev.clientX + 18, window.innerWidth - p.offsetWidth - 14);
  const py = Math.min(ev.clientY + 8, window.innerHeight - p.offsetHeight - 14);
  p.style.left = Math.max(12, px) + 'px';
  p.style.top = Math.max(12, py) + 'px';
}
function hidePopover() { popTimer = setTimeout(() => $('#popover').classList.remove('show'), 60); }

/* ---------- imports & live feeds ---------- */
function renderImports() {
  const jobs = (State.data && State.data.stats.import_jobs) || [];
  const live = State.live ? State.live.feeds : [];
  const byKey = {}; jobs.forEach(j => byKey[j.key] = j);
  const totalRec = live.reduce((a, f) => a + (f.records || 0), 0) || jobs.reduce((a, j) => a + j.records, 0);
  const healthy = live.filter(f => f.status === 'live' || f.status === 'completed').length;
  const t = State.data ? State.data.stats.timings : { match_s: 0, rank_s: 0 };
  $('#import-summary').innerHTML = `
    <div class="kpi info"><div class="glow"></div><div class="k-label">Records ingested</div>
      <div class="k-val" data-count="${totalRec}">0</div><div class="k-sub">across ${(live.length || jobs.length)} feeds</div><div class="k-icon">${icon('stack', 22)}</div></div>
    <div class="kpi good"><div class="glow"></div><div class="k-label">Live feeds healthy</div>
      <div class="k-val" data-count="${healthy}">0</div><div class="k-sub">of ${(live.length || jobs.length)} sources</div><div class="k-icon">${icon('shield', 22)}</div></div>
    <div class="kpi info"><div class="glow"></div><div class="k-label">Match + rank</div>
      <div class="k-val" data-count="${(((t.match_s || 0) + (t.rank_s || 0)) * 1000).toFixed(0)}">0</div><div class="k-sub">milliseconds</div><div class="k-icon">${icon('bolt', 22)}</div></div>
    <div class="kpi ${State.live && State.live.online ? 'good' : 'warn'}"><div class="glow"></div><div class="k-label">Ingestion</div>
      <div class="k-val" style="font-size:22px">${State.live && State.live.online ? 'LIVE' : 'OFFLINE'}</div><div class="k-sub">${State.live && State.live.online ? 'streaming from sources' : 'serving bundled snapshot'}</div><div class="k-icon">${icon('pulse', 22)}</div></div>`;

  const icons = { nvd: 'db', kev: 'target', epss: 'trend' };
  const feeds = live.length ? live : jobs.map(j => ({ key: j.key, name: j.source, provider: j.provider, status: j.status, records: j.records, source: 'bundled', message: '', category: j.category, format: j.format }));
  $('#import-jobs').innerHTML = feeds.map(f => {
    const job = byKey[f.key] || {};
    const mit = job.mitigation || {};
    return `<div class="job"><div class="top">
        <div class="ico">${icon(icons[f.key] || 'plug', 22)}</div>
        <div><div class="tt">${esc(f.name)}</div><div class="pv">${esc(f.provider || '')}</div></div>
        <div class="fstat s-${f.status} st" style="margin-left:auto">${f.status === 'live' ? '<span class="sdot"></span>live' : `<span class="sdot"></span>${esc(f.status)}`}</div>
      </div>
      <div class="meta">
        <div class="m"><div class="ml">Records</div><div class="mv">${fmt(f.records)}</div></div>
        <div class="m"><div class="ml">Source</div><div class="mv" style="font-size:13px;text-transform:capitalize">${esc(f.source || 'bundled')}${f.new_since_last ? ` <span class="newpill">+${fmt(f.new_since_last)}</span>` : ''}</div></div>
      </div>
      <div class="progress"><i data-w="100"></i></div>
      <div style="margin-top:6px">${(job.category || f.category) ? `<span class="cat">${esc(job.category || f.category)}</span>` : ''}${(job.format || f.format) ? `<span class="cat">${esc(job.format || f.format)}</span>` : ''}</div>
      ${f.message ? `<div class="fmsg">${esc(f.message)}</div>` : ''}
      ${mit.summary ? `<div class="mit"><b>Act on it:</b> ${esc(mit.action || mit.summary)}</div>` : ''}
    </div>`;
  }).join('');
  requestAnimationFrame(() => { animateCounts(); animateBars(); });
}

/* ---------- live feed view ---------- */
function loadLiveSnapshot() {
  fetch('/api/live').then(r => r.json()).then(s => { State.live = s; renderLiveState(); }).catch(() => { });
}
function connectStream() {
  if (!window.EventSource) { setLivePill(false, 'No stream'); return; }
  let es;
  try { es = new EventSource('/api/stream'); } catch (_) { return; }
  es.onmessage = e => { try { onLiveMessage(JSON.parse(e.data)); } catch (_) { } };
  es.onerror = () => setLivePill(State.live && State.live.online, 'Reconnecting…');
}
function onLiveMessage(m) {
  if (m.kind === 'state') { State.live = m.state; renderLiveState(); maybeDataUpdated(); }
  else if (m.kind === 'event') { addLiveEvent(m.event); }
}
function maybeDataUpdated() {
  if (State.data && State.live && State.live.data_version > State.analyzedVersion) {
    toast('Live data updated — re-run analysis for the latest matches', 'info', () => analyze());
  }
}
function renderLiveState() {
  if (!State.live) return;
  setLivePill(State.live.online, State.live.online ? 'Live' : 'Offline', State.live.last_sync);
  const confirmed = (State.live.events || []).filter(e => e.status === 'Confirmed').length;
  $('#nav-live-count').textContent = fmt(confirmed);
  renderFeedStrip();
  renderImports();
  if (State.view === 'live') renderStream();
}
function setLivePill(online, text, sync) {
  const p = $('#livepill');
  p.classList.toggle('online', !!online); p.classList.toggle('offline', !online);
  $('#lp-text').textContent = text || (online ? 'Live' : 'Offline');
  $('#lp-sync').textContent = sync ? '· ' + timeAgo(sync) : '';
}
function renderFeedStrip() {
  const feeds = State.live.feeds || [];
  const icons = { nvd: 'db', kev: 'target', epss: 'trend' };
  $('#feedstrip').innerHTML = feeds.map(f => `
    <div class="fcard"><div class="ftop">
        <div class="fico">${icon(icons[f.key] || 'plug', 18)}</div>
        <div><div class="fn">${esc(f.name)}</div><div class="fp">${esc(f.provider || '')}</div></div>
        <div class="fstat s-${f.status}"><span class="sdot"></span>${f.status === 'live' ? 'live' : esc(f.status)}<span class="srctag">${esc(f.source)}</span></div>
      </div>
      <div class="fmeta">
        <div><div class="fv">${fmt(f.records)}</div><div class="fl">Records</div></div>
        <div><div class="fv">${f.new_since_last ? '+' + fmt(f.new_since_last) : '—'}</div><div class="fl">New</div></div>
        <div><div class="fv" style="font-size:13px">${f.last_run ? timeAgo(f.last_run) : '—'}</div><div class="fl">Last sync</div></div>
      </div>
      <div class="fmsg">${esc(f.message || '')}</div>
    </div>`).join('');
}
function renderStream() {
  if (!State.live) return;
  let evs = (State.live.events || []).slice();
  if (State.liveFilter !== 'all') evs = evs.filter(e => e.status === State.liveFilter);
  const c = State.live.counts || {};
  $('#live-meta').textContent = `${fmt(c.confirmed || 0)} confirmed · ${fmt(c.unconfirmed || 0)} unconfirmed in buffer`;
  $$('#view-live .chip[data-lf]').forEach(ch => ch.classList.toggle('active', ch.dataset.lf === State.liveFilter));
  $('#stream').innerHTML = evs.slice(0, 80).map(eventRow).join('') || '<div class="empty">Awaiting live activity…</div>';
  $$('#stream .ev').forEach(el => el.addEventListener('click', () => openEvent(el.dataset.cve)));
}
function eventRow(e) {
  const sev = SEV_COLOR[e.severity] || SEV_COLOR.UNRATED;
  const badge = e.ransomware ? '<span class="badge b-ransom">Ransomware</span>'
    : e.status === 'Confirmed' ? '<span class="badge b-confirmed">Confirmed</span>' : '<span class="badge b-unconfirmed">Unconfirmed</span>';
  return `<div class="ev" data-cve="${esc(e.cve_id)}">
    <span class="evsev" style="background:${sev}"></span>
    <span class="evcve">${esc(e.cve_id)}</span>
    ${badge}
    <span class="evtitle">${esc(e.title)}</span>
    ${e.epss != null ? `<span class="subt mono">EPSS ${e.epss}</span>` : ''}
    <span class="secchip" style="background:${hexA(e.sector_color || '#8aa0c6', .16)};color:${e.sector_color || '#8aa0c6'}">${esc(e.sector_name || 'Cross-sector')}</span>
    <span class="evtime">${timeAgo(e.ts)}</span></div>`;
}
function addLiveEvent(e) {
  if (!State.live) State.live = { events: [], counts: { confirmed: 0, unconfirmed: 0 }, feeds: [] };
  State.live.events = State.live.events || [];
  State.live.events.unshift(e);
  if (State.live.events.length > 200) State.live.events.pop();
  const confirmed = State.live.events.filter(x => x.status === 'Confirmed').length;
  $('#nav-live-count').textContent = fmt(confirmed);
  if (State.view === 'live' && (State.liveFilter === 'all' || State.liveFilter === e.status)) {
    const div = document.createElement('div');
    div.innerHTML = eventRow(e);
    const node = div.firstElementChild; node.classList.add('flash');
    node.addEventListener('click', () => openEvent(e.cve_id));
    $('#stream').prepend(node);
    const kids = $('#stream').children; while (kids.length > 80) $('#stream').removeChild(kids[kids.length - 1]);
  }
}
function openEvent(cveId) {
  if (State.data && State.data.results.some(r => r.cve_id === cveId)) openDetail(cveId);
  else if (/^CVE-/.test(cveId)) window.open('https://nvd.nist.gov/vuln/detail/' + cveId, '_blank', 'noopener');
}
async function triggerRefresh(feed) {
  try { await fetch('/api/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ feed: feed || null }) }); toast('Sync triggered', 'info'); }
  catch (_) { toast('Could not trigger sync', 'err'); }
}

/* ---------- threat map (canvas) ---------- */
const CONTINENTS = [
  [0.20, 0.34, 0.12, 0.17], [0.30, 0.68, 0.07, 0.16], [0.49, 0.27, 0.06, 0.09],
  [0.53, 0.55, 0.09, 0.17], [0.67, 0.33, 0.17, 0.15], [0.82, 0.71, 0.07, 0.06], [0.58, 0.20, 0.10, 0.05],
];
function isLand(nx, ny) {
  for (const [cx, cy, rx, ry] of CONTINENTS) {
    const dx = (nx - cx) / rx, dy = (ny - cy) / ry;
    if (dx * dx + dy * dy <= 1) return true;
  }
  return false;
}
function drawThreatMap(canvas, nodes, animate) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = Math.min(2, window.devicePixelRatio || 1);
  function resize() {
    const r = canvas.parentElement.getBoundingClientRect();
    canvas.width = r.width * dpr; canvas.height = r.height * dpr;
    canvas.style.width = r.width + 'px'; canvas.style.height = r.height + 'px';
  }
  resize();
  const W = () => canvas.width, H = () => canvas.height;
  const maxC = Math.max(1, ...(nodes || []).map(n => n.cves));
  function frame(t) {
    const w = W(), h = H();
    ctx.clearRect(0, 0, w, h);
    // dot-matrix world
    const step = 13 * dpr;
    for (let x = step; x < w; x += step) for (let y = step; y < h; y += step) {
      const land = isLand(x / w, y / h);
      ctx.fillStyle = land ? 'rgba(24,211,154,0.16)' : 'rgba(120,140,165,0.05)';
      ctx.beginPath(); ctx.arc(x, y, (land ? 1.5 : 1) * dpr, 0, 7); ctx.fill();
    }
    // nodes
    (nodes || []).forEach(n => {
      const x = n.x * w, y = n.y * h;
      const base = (5 + 14 * Math.sqrt(n.cves / maxC)) * dpr;
      const col = n.kev > 0 ? '#ff4d6d' : '#18d39a';
      if (animate && !reduceMotion) {
        const pulse = base + (Math.sin(t / 600 + n.x * 8) + 1) * 4 * dpr;
        ctx.beginPath(); ctx.arc(x, y, pulse, 0, 7);
        ctx.fillStyle = (n.kev > 0 ? 'rgba(255,77,109,' : 'rgba(24,211,154,') + '0.10)'; ctx.fill();
      }
      const g = ctx.createRadialGradient(x, y, 0, x, y, base);
      g.addColorStop(0, col); g.addColorStop(1, col + '00');
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, base, 0, 7); ctx.fill();
      ctx.fillStyle = col; ctx.beginPath(); ctx.arc(x, y, 2.4 * dpr, 0, 7); ctx.fill();
    });
    if (animate && !reduceMotion) State.mapRAF = requestAnimationFrame(frame);
  }
  frame(0);
  if (animate) {
    canvas._nodes = nodes; canvas._dpr = dpr;
    canvas.onmousemove = ev => mapHover(canvas, ev, nodes);
    canvas.onmouseleave = () => $('#map-tip').classList.remove('show') || ($('#map-tip').style.opacity = 0);
    window.addEventListener('resize', resize);
  }
}
function mapHover(canvas, ev, nodes) {
  const r = canvas.getBoundingClientRect(); const tip = $('#map-tip');
  const mx = ev.clientX - r.left, my = ev.clientY - r.top;
  let hit = null;
  (nodes || []).forEach(n => {
    const dx = mx - n.x * r.width, dy = my - n.y * r.height;
    if (Math.hypot(dx, dy) < 16) hit = n;
  });
  if (hit) {
    tip.innerHTML = `<b>${esc(hit.vendor)}</b> · ${esc(hit.location)}<br>${fmt(hit.cves)} CVEs · ${fmt(hit.kev)} exploited · ${fmt(hit.critical)} critical`;
    tip.style.left = Math.min(mx + 14, r.width - 200) + 'px'; tip.style.top = (my + 12) + 'px';
    tip.style.opacity = 1; tip.classList.add('show');
  } else { tip.style.opacity = 0; }
}
function startThreatMap() {
  if (!State.data) return;
  stopThreatMap();
  const d = State.data.dashboard;
  drawThreatMap($('#threat-canvas'), d.threat_map, true);
  if (!$('.mapwrap .maplegend')) {
    const lg = document.createElement('div'); lg.className = 'maplegend';
    lg.innerHTML = `<span><i style="background:#ff4d6d"></i>Confirmed exploited present</span><span><i style="background:#18d39a"></i>Predicted only</span>`;
    $('.mapwrap').appendChild(lg);
  }
}
function stopThreatMap() { if (State.mapRAF) { cancelAnimationFrame(State.mapRAF); State.mapRAF = null; } }
function renderThreatPanels() {
  if (!State.data) return;
  const d = State.data.dashboard;
  const regions = d.regions || [];
  const rmax = Math.max(1, ...regions.map(r => r.cves));
  $('#region-list').innerHTML = regions.length ? `<div class="barlist">` + regions.map(r => `
    <div class="barrow"><div class="bl">${esc(r.country)}</div>
      <div class="bt"><i data-w="${(r.cves / rmax * 100).toFixed(1)}"></i></div>
      <div class="bv">${fmt(r.cves)}${r.kev ? ` <span class="badge b-confirmed" style="font-size:9px">${r.kev}</span>` : ''}</div></div>`).join('') + `</div>` : '<div class="empty">No data</div>';
  $('#map-vendors').innerHTML = barList(d.by_vendor);
  requestAnimationFrame(animateBars);
  if (State.view === 'threatmap') startThreatMap();
}

/* ---------- assets ---------- */
function renderAssets() {
  const items = State.data.assets;
  $('#assets-grid').innerHTML = items.map(a => `
    <div class="card">
      <div class="ct">${a.recognised ? icon('check', 16) : icon('warn', 16)} ${esc(a.product)}</div>
      <div class="cc">${esc(a.raw)}${a.version ? ' · ' + esc(a.version) : ''} · <span style="color:${a.sector_color}">${esc(a.sector_name)}</span></div>
      ${a.recognised ? `<div class="crow">
          <div><div class="n">${fmt(a.cves)}</div><div class="l">CVEs</div></div>
          <div><div class="n" style="color:var(--crit)">${fmt(a.kev)}</div><div class="l">Exploited</div></div>
          <div><div class="n" style="color:var(--ok)">${a.score}</div><div class="l">Match</div></div>
        </div>
        <div class="cpe">${a.cpe.map(c => `<span class="tag">${esc(c)}</span>`).join('')}</div>`
      : `<div class="crow"><div><div class="n" style="color:var(--high)">Unmapped</div><div class="l">no confident CPE</div></div></div>
         <div class="cc" style="margin-top:10px">Review the spelling or extend the catalogue so its CVEs are not missed.</div>`}
    </div>`).join('');
}

/* ---------- catalog ---------- */
async function loadCatalog() {
  try { State.catalog = await (await fetch('/api/catalog')).json(); } catch (e) { return; }
  $('#catalog-grid').innerHTML = State.catalog.products.map(p => `
    <div class="card"><div class="ct">${icon('stack', 17)} ${esc(p.name)}</div>
      <div class="cc">${esc(p.category)}</div>
      <div class="cpe">${p.cpe.map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>
      <div class="cpe" style="margin-top:7px">${p.aliases.slice(0, 5).map(x => `<span class="alias">${esc(x)}</span>`).join('')}</div>
    </div>`).join('');
}

/* ---------- connectors ---------- */
async function loadConnectors() {
  try { State.connectors = (await (await fetch('/api/connectors')).json()).connectors; } catch (_) { State.connectors = []; }
  if (State.view === 'connectors') renderConnectors();
}
function renderConnectors() {
  const list = State.connectors || [];
  const icons = { nvd: 'db', kev: 'target', epss: 'trend' };
  $('#connectors-grid').innerHTML = list.map(c => `
    <div class="card conn-card">
      <div class="ctop"><div class="fico" style="width:36px;height:36px;border-radius:9px;display:grid;place-items:center;background:var(--grad-soft);color:var(--brand-3)">${icon(icons[c.id] || 'plug', 18)}</div>
        <div><div class="ct" style="font-size:14px">${esc(c.name)}</div><div class="cc">${esc(c.provider || '')}</div></div>
        ${c.builtin ? '<span class="badge builtin" style="margin-left:auto">Built-in</span>' : '<span class="badge b-soft" style="margin-left:auto">Custom</span>'}</div>
      <div class="cc" style="word-break:break-all">${esc(c.url)}</div>
      <div class="crow" style="margin-top:12px">
        <div><div class="l">Category</div><div style="font-size:12.5px;margin-top:2px">${esc(c.category || '')}</div></div>
        <div><div class="l">Every</div><div style="font-size:12.5px;margin-top:2px">${fmt(c.interval)}s</div></div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;margin-top:14px">
        <span class="toggle ${c.enabled ? 'on' : ''}" data-toggle="${c.id}"><span class="box"></span><span class="nl2" style="font-size:11px">${c.enabled ? 'Enabled' : 'Disabled'}</span></span>
        <div style="flex:1"></div>
        <button class="btn ghost sm" data-sync="${c.id}">${icon('refresh', 14)} Sync</button>
        ${c.builtin ? '' : `<button class="btn ghost sm" data-del="${c.id}">Remove</button>`}
      </div>
    </div>`).join('') || '<div class="empty">No connectors.</div>';
  $$('#connectors-grid [data-toggle]').forEach(t => t.addEventListener('click', () => toggleConnector(t.dataset.toggle, !t.classList.contains('on'))));
  $$('#connectors-grid [data-sync]').forEach(b => b.addEventListener('click', () => triggerRefresh(b.dataset.sync)));
  $$('#connectors-grid [data-del]').forEach(b => b.addEventListener('click', () => removeConnector(b.dataset.del)));
}
async function toggleConnector(id, enabled) {
  await fetch('/api/connectors/' + id, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) });
  await loadConnectors(); renderConnectors();
  toast(`Connector ${enabled ? 'enabled' : 'disabled'}`, 'info');
}
async function removeConnector(id) {
  await fetch('/api/connectors/' + id, { method: 'DELETE' });
  await loadConnectors(); renderConnectors(); toast('Connector removed', 'info');
}
async function saveConnector() {
  const body = {
    name: $('#cf-name').value, provider: $('#cf-provider').value, url: $('#cf-url').value,
    format: $('#cf-format').value, category: $('#cf-category').value,
    interval: parseInt($('#cf-interval').value) || 900, auth_header: $('#cf-auth').value,
  };
  if (!body.name || !body.url) { toast('Name and URL are required', 'err'); return; }
  const res = await fetch('/api/connectors', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!res.ok) { const e = await res.json(); toast(e.error || 'Failed', 'err'); return; }
  $('#connform').style.display = 'none';
  ['cf-name', 'cf-provider', 'cf-url', 'cf-category', 'cf-auth'].forEach(id => $('#' + id).value = '');
  await loadConnectors(); renderConnectors(); toast('Connector added', 'info');
}

/* ---------- settings ---------- */
const WIDGET_LABELS = { gauges: 'Risk gauges', heatmap: 'Sector heatmap', threat_map: 'Threat map', severity: 'Severity', status: 'Exploitation status', epss: 'EPSS bands', cwe: 'Weakness types', category: 'By category', vendor: 'By vendor', timelines: 'Timelines', assets: 'By asset' };
function renderSettings() {
  if (!State.prefs) return;
  const sectors = (State.data && State.data.sectors) || [];
  const my = State.prefs.sectors || [];
  $('#pref-sectors').innerHTML = sectors.map(s => `<span class="p ${my.includes(s.key) ? 'on' : ''}" data-sec="${s.key}">${esc(s.short || s.name)}</span>`).join('');
  $$('#pref-sectors .p').forEach(p => p.addEventListener('click', () => p.classList.toggle('on')));
  const w = State.prefs.widgets || {};
  $('#pref-widgets').innerHTML = Object.keys(WIDGET_LABELS).map(k => `<span class="p ${w[k] !== false ? 'on' : ''}" data-w="${k}">${WIDGET_LABELS[k]}</span>`).join('');
  $$('#pref-widgets .p').forEach(p => p.addEventListener('click', () => p.classList.toggle('on')));
  $('#pref-live').classList.toggle('on', State.prefs.live !== false);
  $('#pref-live').onclick = () => $('#pref-live').classList.toggle('on');
  $('#pref-filter').value = State.prefs.default_filter || 'all';
}
async function savePrefs() {
  const sectors = $$('#pref-sectors .p.on').map(p => p.dataset.sec);
  const widgets = {}; $$('#pref-widgets .p').forEach(p => widgets[p.dataset.w] = p.classList.contains('on'));
  const live = $('#pref-live').classList.contains('on');
  const body = { sectors, widgets, live, default_filter: $('#pref-filter').value };
  State.prefs = await (await fetch('/api/preferences', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json();
  await fetch('/api/live/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: live }) });
  renderOverview(); renderSectors();
  toast('Settings saved', 'info');
}

/* ---------- detail drawer ---------- */
function openDetail(cveId) {
  const r = State.data.results.find(x => x.cve_id === cveId); if (!r) return;
  const sev = SEV_CLASS[r.cvss_severity] || 'b-unrated';
  const vector = parseVector(r.cvss_vector);
  const m = r.mitigation || {};
  const statusBadge = r.ransomware ? '<span class="badge b-ransom">Ransomware</span>'
    : r.kev ? '<span class="badge b-confirmed">Confirmed exploited</span>' : '<span class="badge b-unconfirmed">Unconfirmed</span>';
  $('#drawer-title').innerHTML = `<div class="cve" style="font-size:18px">${r.cve_id}</div>
    <div style="margin-top:8px;display:flex;gap:7px;flex-wrap:wrap">
      <span class="badge ${sev}">${cap(r.cvss_severity)} ${r.cvss}</span>${statusBadge}
      ${r.is_zero_day ? '<span class="badge b-zero">Zero-day</span>' : ''}
      <span class="badge b-soft">Urgency ${r.urgency.toFixed(2)}</span></div>`;
  const zd = r.zero_day;
  $('#drawer-body').innerHTML = `
    ${zd ? `<div class="zerobox"><div class="zt">${icon('bolt', 18)} ${esc(zd.official_name)}</div>
      <div class="desc" style="margin-top:6px">${esc(zd.note)}</div>
      <div class="zr">
        <div><div class="zl">Vendor</div>${esc(zd.vendor || 'n/a')}</div>
        <div><div class="zl">Product</div>${esc(zd.product || 'n/a')}</div>
        <div><div class="zl">Added to KEV</div>${esc(zd.added_to_kev || 'n/a')}</div>
        <div><div class="zl">Published</div>${esc(zd.published || 'n/a')}</div>
      </div>${zd.summary ? `<div class="desc" style="margin-top:9px">${esc(zd.summary)}</div>` : ''}</div>` : ''}
    <div class="dsection"><div class="dt">Description</div><div class="desc">${esc(r.description) || 'No description available.'}</div></div>
    <div class="dsection"><div class="dgrid">
      <div class="metric"><div class="ml">CVSS ${esc(r.cvss_version)}</div><div class="mv" style="color:var(--high)">${r.cvss}</div></div>
      <div class="metric"><div class="ml">EPSS probability</div><div class="mv" style="color:var(--brand-3)">${r.epss}</div>${r.epss_pct != null ? `<div class="ml">${r.epss_pct} percentile</div>` : ''}</div>
    </div></div>
    <div class="dsection" style="display:flex;gap:18px;align-items:center">
      <div>${Charts.gauge(r.confidence, confColor(r.confidence), 'confidence')}</div>
      <div><div class="dt">Data confidence: ${r.confidence_band}</div>
        <div class="desc">Based on NVD status (${esc(r.vuln_status) || 'n/a'}), and the presence of CVSS, CWE, references, and CPE data.</div></div>
    </div>
    <div class="dsection"><div class="dt">Risk summary</div><div class="desc">${esc(r.summary)}</div></div>
    <div class="dsection"><div class="dt">Recommended action</div><div class="action-box">${esc(r.action)}</div></div>
    <div class="dsection"><div class="dt">Risk mitigation <span class="pv-prio prio-${m.priority || 'Routine'}">${m.priority || 'Routine'}</span></div>
      <div class="mitbox"><ol>${(m.steps || []).map(s => `<li>${esc(s)}</li>`).join('')}</ol></div></div>
    <div class="dsection"><div class="dt">Affected assets</div>
      <div class="vector">${r.asset.split('; ').map(a => `<span class="vchip">${esc(a)}</span>`).join('')}</div>
      <div class="vector" style="margin-top:8px">${r.cpe.map(c => `<span class="vchip"><b>${esc(c)}</b></span>`).join('')}</div></div>
    ${vector.length ? `<div class="dsection"><div class="dt">CVSS vector</div><div class="vector">${vector.map(v => `<span class="vchip"><b>${esc(v.k)}</b> ${esc(v.v)}</span>`).join('')}</div></div>` : ''}
    ${r.cwes.length ? `<div class="dsection"><div class="dt">Weaknesses</div><div class="vector">${r.cwes.map(c => `<span class="vchip">${esc(c.id)} · ${esc(c.name)}</span>`).join('')}</div></div>` : ''}
    ${r.kev ? `<div class="dsection"><div class="dt">CISA KEV</div><div class="desc">${esc(r.kev_name || '')}${r.kev_name ? '. ' : ''}Added ${esc(r.kev_date)}.${r.kev_due ? ' Remediation due by ' + esc(r.kev_due) + '.' : ''} ${esc(r.kev_desc)}</div></div>` : ''}
    <div class="dsection"><div class="dt">Official documentation</div>
      <div class="doclinks">${(m.doc_links || [{ label: 'NVD detail', url: r.doc_url }]).map(l => `<a class="doclink" href="${esc(l.url)}" target="_blank" rel="noopener">${icon('link', 13)} ${esc(l.label)}</a>`).join('')}</div></div>
    ${r.references.length ? `<div class="dsection"><div class="dt">References</div><div class="reflist">${r.references.map(u => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`).join('')}</div></div>` : ''}
    <div class="dsection"><div class="dt">Timeline</div><div class="desc">Published ${esc((r.published || '').slice(0, 10))} · last modified ${esc((r.last_modified || '').slice(0, 10))}</div></div>`;
  $('#scrim').classList.add('open'); $('#drawer').classList.add('open');
}
function closeDrawer() { $('#scrim').classList.remove('open'); $('#drawer').classList.remove('open'); }
function parseVector(v) {
  if (!v) return [];
  const names = { AV: 'Attack vector', AC: 'Complexity', PR: 'Privileges', UI: 'User interaction', S: 'Scope', C: 'Confidentiality', I: 'Integrity', A: 'Availability' };
  return v.replace(/^CVSS:[\d.]+\//, '').split('/').map(p => { const [k, val] = p.split(':'); return { k: names[k] || k, v: val }; }).filter(x => x.v);
}

/* ---------- csv export ---------- */
function downloadCsv() {
  if (!State.data || !State.data.results.length) { toast('Run an analysis first.', 'err'); return; }
  const cols = ['rank', 'cve_id', 'asset', 'sector_name', 'status', 'is_zero_day', 'cvss', 'cvss_severity', 'epss', 'epss_pct', 'kev', 'ransomware', 'confidence', 'urgency', 'action', 'doc_url'];
  const rows = State.data.results.map(r => cols.map(c => csvCell(r[c])).join(','));
  rows.unshift(cols.join(','));
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'vulnify_cve_priorities.csv'; a.click();
  URL.revokeObjectURL(url);
}
function csvCell(v) { v = String(v == null ? '' : v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }

/* ---------- toast ---------- */
let toastTimer = null;
function toast(msg, kind, onClick) {
  let t = $('#toast');
  if (!t) { t = document.createElement('div'); t.id = 'toast'; document.body.appendChild(t); styleToast(t); }
  t.textContent = msg; t.dataset.kind = kind || 'info';
  t.style.borderColor = kind === 'err' ? 'var(--crit)' : 'var(--brand)';
  t.style.cursor = onClick ? 'pointer' : 'default';
  t.onclick = onClick || null;
  t.style.opacity = 1; t.style.transform = 'translateY(0)';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.style.opacity = 0; t.style.transform = 'translateY(12px)'; }, onClick ? 6000 : 3200);
}
function styleToast(t) {
  Object.assign(t.style, { position: 'fixed', bottom: '22px', left: '50%', transform: 'translateX(-50%) translateY(12px)', zIndex: 200, background: 'rgba(10,13,18,.98)', border: '1px solid var(--brand)', color: 'var(--text)', padding: '11px 16px', borderRadius: '10px', fontSize: '13px', boxShadow: 'var(--shadow)', opacity: 0, transition: 'opacity .2s, transform .2s', maxWidth: '90vw' });
}

/* ---------- animations ---------- */
function animateCounts() {
  $$('.k-val[data-count]').forEach(el => {
    const target = parseFloat(el.dataset.count) || 0, dec = parseInt(el.dataset.dec || 0);
    if (reduceMotion) { el.textContent = fmtNum(target, dec); return; }
    const dur = 800, t0 = performance.now();
    function step(t) { const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3); el.textContent = fmtNum(target * e, dec); if (p < 1) requestAnimationFrame(step); }
    requestAnimationFrame(step);
  });
}
function fmtNum(v, dec) { return dec ? v.toFixed(dec) : Math.round(v).toLocaleString(); }
function animateBars() {
  $$('.bt i[data-w], .progress i[data-w]').forEach(el => {
    const w = el.dataset.w + '%';
    if (reduceMotion) { el.style.width = w; return; }
    requestAnimationFrame(() => { el.style.width = w; });
  });
}

/* ---------- time ---------- */
function timeAgo(iso) {
  if (!iso) return '';
  const d = new Date(iso); const s = (Date.now() - d.getTime()) / 1000;
  if (isNaN(s)) return '';
  if (s < 60) return Math.max(0, Math.floor(s)) + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  if (s < 86400 * 30) return Math.floor(s / 86400) + 'd ago';
  return iso.slice(0, 10);
}

/* ---------- constellation background ---------- */
function buildConstellation() {
  if (reduceMotion) return;
  const cv = $('#bg-canvas'); if (!cv) return;
  const ctx = cv.getContext('2d');
  let w, h, pts, dpr = Math.min(2, window.devicePixelRatio || 1);
  function size() {
    w = cv.width = innerWidth * dpr; h = cv.height = innerHeight * dpr;
    cv.style.width = innerWidth + 'px'; cv.style.height = innerHeight + 'px';
    const n = Math.min(64, Math.floor(innerWidth / 30));
    pts = Array.from({ length: n }, () => ({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .22 * dpr, vy: (Math.random() - .5) * .22 * dpr }));
  }
  size(); addEventListener('resize', size);
  let raf;
  function draw() {
    ctx.clearRect(0, 0, w, h);
    for (const p of pts) { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > w) p.vx *= -1; if (p.y < 0 || p.y > h) p.vy *= -1; }
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
      const a = pts[i], b = pts[j], dist = Math.hypot(a.x - b.x, a.y - b.y), max = 150 * dpr;
      if (dist < max) { ctx.strokeStyle = `rgba(24,211,154,${(1 - dist / max) * 0.14})`; ctx.lineWidth = dpr; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
    }
    for (const p of pts) { ctx.fillStyle = 'rgba(46,230,166,.45)'; ctx.beginPath(); ctx.arc(p.x, p.y, 1.4 * dpr, 0, 7); ctx.fill(); }
    raf = requestAnimationFrame(draw);
  }
  draw();
  document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else draw(); });
}
