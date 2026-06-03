/* Lodestar dashboard application logic. Vanilla JS, no build step. */
'use strict';

const State = { data: null, catalog: null, view: 'overview', sort: { key: 'urgency', dir: -1 }, filter: 'all', query: '' };
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = n => (n == null ? '0' : Number(n).toLocaleString());

const SEV_CLASS = { CRITICAL: 'b-crit', HIGH: 'b-high', MEDIUM: 'b-med', LOW: 'b-low', UNRATED: 'b-unrated' };

/* ---------- boot ---------- */
window.addEventListener('DOMContentLoaded', () => {
  buildConstellation();
  wireNav();
  wireControls();
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
}

function wireControls() {
  $('#run').addEventListener('click', analyze);
  $('#kevToggle').addEventListener('click', e => { e.currentTarget.classList.toggle('on'); });
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
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });
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
    if (!res.ok) { alert(data.error || 'Error'); return; }
    State.data = data;
    renderAll();
  } catch (err) { alert('Request failed: ' + err.message); }
  finally { btn.disabled = false; btn.textContent = 'Run analysis'; }
}

function renderAll() {
  updateNavCounts();
  renderOverview();
  renderVulns();
  renderImports();
  renderAssets();
  attachTilt();
}

function updateNavCounts() {
  const s = State.data.stats;
  $('#nav-vuln-count').textContent = fmt(State.data.results_total);
  $('#nav-import-count').textContent = State.data.stats.import_jobs.length;
  $('#nav-asset-count').textContent = s.assets_supplied;
  $('#statusline').innerHTML = `<span class="dot"></span>${fmt(s.cve_records_scanned)} CVEs indexed`;
}

/* ---------- overview ---------- */
function renderOverview() {
  const d = State.data.dashboard, k = d.kpis;
  const kpis = [
    { l: 'Relevant CVEs', v: k.relevant_cves, cls: 'info', sub: `${fmt(State.data.stats.cve_records_scanned)} scanned`, icon: iconBug },
    { l: 'Confirmed exploited', v: k.confirmed, cls: 'crit', sub: 'in CISA KEV catalogue', icon: iconTarget },
    { l: 'Ransomware linked', v: k.ransomware, cls: 'crit', sub: 'known campaign use', icon: iconFire },
    { l: 'Critical severity', v: k.critical, cls: 'warn', sub: `${fmt(k.high)} high`, icon: iconAlert },
    { l: 'Mean CVSS', v: k.avg_cvss, cls: 'warn', sub: 'across matches', icon: iconGauge, dec: 1 },
    { l: 'Mean confidence', v: k.avg_confidence, cls: 'good', sub: 'data completeness', icon: iconShield },
    { l: 'Assets covered', v: k.assets_recognised, cls: 'good', sub: `of ${k.assets_supplied} supplied`, icon: iconStack },
    { l: 'Peak EPSS', v: k.max_epss, cls: 'info', sub: 'top exploitation odds', icon: iconTrend, dec: 4 }
  ];
  $('#kpis').innerHTML = kpis.map(c => `
    <div class="kpi ${c.cls}"><div class="glow"></div>
      <div class="k-label">${c.l}</div>
      <div class="k-val" data-count="${c.v}" data-dec="${c.dec || 0}">0</div>
      <div class="k-sub">${esc(c.sub)}</div>
      <div class="k-icon">${c.icon}</div>
    </div>`).join('');

  const warn = State.data.unrecognised.length
    ? `<div class="warn-banner"><b>${State.data.unrecognised.length} unrecognised asset(s):</b> ${State.data.unrecognised.map(esc).join(', ')}. These have no confident CPE mapping and may hide real vulnerabilities.</div>` : '';
  $('#ov-warn').innerHTML = warn;

  $('#ov-charts').innerHTML = `
    <div class="grid g-2">
      ${donutPanel('Severity distribution', 'CVSS qualitative rating', d.severity, k.relevant_cves, 'Total')}
      ${donutPanel('Exploitation status', 'Confirmed by CISA KEV vs predicted', d.status_split, k.confirmed, 'Confirmed')}
    </div>
    <div class="grid g-2" style="margin-top:14px">
      ${barPanel('Exploitation probability (EPSS)', 'how likely, in the next 30 days', d.epss_bands)}
      ${barPanel('Top weakness types (CWE)', 'most common root causes', d.by_cwe.map(x => ({ label: x.name, value: x.value })))}
    </div>
    <div class="grid g-2" style="margin-top:14px">
      ${barPanel('By product category', 'where the risk concentrates', d.by_category)}
      ${barPanel('By vendor', 'most affected vendors', d.by_vendor)}
    </div>
    <div class="grid g-2" style="margin-top:14px">
      ${sparkPanel('CVEs by publication month', d.pub_timeline, '#38bdf8')}
      ${sparkPanel('KEV additions by month', d.kev_timeline, '#ff3b6b')}
    </div>
    <div class="panel" style="margin-top:14px">
      <div class="panel-head"><h3>Exposure by asset</h3></div>
      ${barListAssets(d.top_assets)}
    </div>`;

  requestAnimationFrame(() => { animateCounts(); animateBars(); });
}

function donutPanel(title, sub, segments, centerVal, centerLabel) {
  const legend = segments.map(s => `<div class="lr"><span class="sw" style="background:${s.color}"></span>
      <span class="ln">${esc(s.label)}</span><span class="lv">${fmt(s.value)}</span></div>`).join('');
  return `<div class="panel"><h3>${title}</h3><div class="sub">${sub}</div>
    <div class="donut-wrap">
      <div class="donut">${Charts.donut(segments)}<div class="center"><b>${fmt(centerVal)}</b><span>${centerLabel}</span></div></div>
      <div class="legend">${legend}</div>
    </div></div>`;
}

function barPanel(title, sub, rows) {
  return `<div class="panel"><h3>${title}</h3><div class="sub">${sub}</div>${barList(rows)}</div>`;
}

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
  return `<div class="barlist">` + rows.map(r => {
    const kevPct = r.cves ? (r.kev / r.cves * 100) : 0;
    return `<div class="barrow"><div class="bl" title="${esc(r.asset)}">${esc(r.asset)}</div>
      <div class="bt" style="position:relative"><i data-w="${(r.cves / max * 100).toFixed(1)}"></i></div>
      <div class="bv">${fmt(r.cves)}${r.kev ? ` <span class="badge b-confirmed" style="font-size:9px">${r.kev} KEV</span>` : ''}</div></div>`;
  }).join('') + `</div>`;
}

function sparkPanel(title, points, color) {
  return `<div class="panel"><h3>${title}</h3><div class="sub">trend over time</div>${Charts.sparkArea(points, color)}</div>`;
}

/* ---------- vulnerabilities ---------- */
function renderVulns() {
  if (!State.data) return;
  let rows = State.data.results.slice();
  const q = State.query;
  if (q) rows = rows.filter(r =>
    r.cve_id.toLowerCase().includes(q) || (r.asset || '').toLowerCase().includes(q) ||
    (r.description || '').toLowerCase().includes(q) || r.cwes.some(c => c.name.toLowerCase().includes(q)));
  const f = State.filter;
  if (f === 'kev') rows = rows.filter(r => r.kev);
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

  $('#vuln-count').textContent = `${fmt(rows.length)} shown of ${fmt(State.data.results_total)} matched`;
  const cols = [['urgency', 'Urgency'], ['cve_id', 'CVE'], ['asset', 'Affected asset'], ['cvss', 'Severity'], ['epss', 'EPSS'], ['status', 'Status'], ['confidence', 'Confidence'], ['', 'Weakness']];
  $('#vuln-thead').innerHTML = '<tr>' + cols.map(([key, lbl]) =>
    `<th data-sort="${key}">${lbl}${key === sk ? (dir === -1 ? ' ▼' : ' ▲') : ''}</th>`).join('') + '</tr>';
  $$('#vuln-thead th').forEach(th => th.addEventListener('click', () => {
    const key = th.dataset.sort; if (!key) return;
    if (State.sort.key === key) State.sort.dir *= -1; else State.sort = { key, dir: -1 };
    renderVulns();
  }));

  const body = rows.slice(0, 600).map(r => {
    const sev = SEV_CLASS[r.cvss_severity] || 'b-unrated';
    const conf = confColor(r.confidence);
    const cwe = r.cwes[0] ? `<span class="subt">${esc(r.cwes[0].name)}</span>` : '<span class="subt">n/a</span>';
    const statusBadge = r.ransomware ? '<span class="badge b-ransom">Ransomware</span>'
      : r.kev ? '<span class="badge b-confirmed">Confirmed</span>' : '<span class="badge b-unconfirmed">Unconfirmed</span>';
    return `<tr data-cve="${r.cve_id}">
      <td class="mono"><b>${r.urgency.toFixed(2)}</b></td>
      <td class="cve">${r.cve_id}</td>
      <td>${esc(r.asset)}<div class="subt">${esc(r.cpe.join(', '))}</div></td>
      <td><span class="badge ${sev}">${r.cvss_severity[0] + r.cvss_severity.slice(1).toLowerCase()} ${r.cvss}</span></td>
      <td class="mono">${r.epss}${r.epss_pct != null ? `<div class="subt">${r.epss_pct} pct</div>` : ''}</td>
      <td>${statusBadge}</td>
      <td><div class="conf"><div class="meter"><i style="width:${r.confidence}%;background:${conf}"></i></div><span class="cv">${r.confidence}</span></div></td>
      <td>${cwe}</td>
    </tr>`;
  }).join('');
  $('#vuln-tbody').innerHTML = body || '<tr><td colspan="8" class="empty">No CVEs match the current filters.</td></tr>';
  $$('#vuln-tbody tr[data-cve]').forEach(tr => tr.addEventListener('click', () => openDetail(tr.dataset.cve)));

  $$('#vuln-filters .chip').forEach(c => {
    c.classList.toggle('active', c.dataset.f === State.filter);
    c.onclick = () => { State.filter = c.dataset.f; renderVulns(); };
  });
}

function confColor(v) { return v >= 75 ? '#27d29b' : v >= 50 ? '#ffc24b' : '#ff8a3d'; }

/* ---------- imports ---------- */
function renderImports() {
  const jobs = State.data.stats.import_jobs;
  const totalRec = jobs.reduce((a, j) => a + j.records, 0);
  const totalT = jobs.reduce((a, j) => a + j.duration_s, 0);
  const t = State.data.stats.timings;
  $('#import-summary').innerHTML = `
    <div class="kpi info"><div class="glow"></div><div class="k-label">Records ingested</div>
      <div class="k-val" data-count="${totalRec}">0</div><div class="k-sub">across ${jobs.length} feeds</div><div class="k-icon">${iconStack}</div></div>
    <div class="kpi good"><div class="glow"></div><div class="k-label">Ingest time</div>
      <div class="k-val" data-count="${(totalT * 1000).toFixed(0)}">0</div><div class="k-sub">milliseconds, offline</div><div class="k-icon">${iconBolt}</div></div>
    <div class="kpi info"><div class="glow"></div><div class="k-label">Match + rank</div>
      <div class="k-val" data-count="${((t.match_s + t.rank_s) * 1000).toFixed(0)}">0</div><div class="k-sub">milliseconds</div><div class="k-icon">${iconBolt}</div></div>
    <div class="kpi good"><div class="glow"></div><div class="k-label">Feeds healthy</div>
      <div class="k-val" data-count="${jobs.filter(j => j.status === 'completed').length}">0</div><div class="k-sub">of ${jobs.length} sources</div><div class="k-icon">${iconShield}</div></div>`;

  const icons = { nvd: iconDb, kev: iconTarget, epss: iconTrend };
  $('#import-jobs').innerHTML = jobs.map(j => `
    <div class="job"><div class="glow"></div>
      <div class="top">
        <div class="ico">${icons[j.key] || iconDb}</div>
        <div><div class="tt">${esc(j.source)}</div><div class="pv">${esc(j.provider)}</div></div>
        <div class="st"><span class="dot"></span>${esc(j.status)}</div>
      </div>
      <div class="meta">
        <div class="m"><div class="ml">Records</div><div class="mv">${fmt(j.records)}</div></div>
        <div class="m"><div class="ml">Ingest speed</div><div class="mv">${fmt(j.speed)} <small>/s</small></div></div>
      </div>
      <div class="progress"><i data-w="100"></i></div>
      <div class="contributes">${esc(j.contributes)}</div>
      <div><span class="cat">${esc(j.category)}</span> <span class="cat">${esc(j.format)}</span> <span class="cat">${esc(j.confidence)}</span></div>
    </div>`).join('');
  requestAnimationFrame(() => { animateCounts(); animateBars(); });
}

/* ---------- assets ---------- */
function renderAssets() {
  const items = State.data.assets;
  $('#assets-grid').innerHTML = items.map(a => `
    <div class="card">
      <div class="ct">${a.recognised ? iconCheck : iconWarn} ${esc(a.product)}</div>
      <div class="cc">${esc(a.raw)}${a.version ? ' · ' + esc(a.version) : ''} · ${esc(a.category)}</div>
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
  try {
    const res = await fetch('/api/catalog');
    State.catalog = await res.json();
  } catch (e) { return; }
  const c = State.catalog;
  $('#catalog-grid').innerHTML = c.products.map(p => `
    <div class="card">
      <div class="ct">${iconStack} ${esc(p.name)}</div>
      <div class="cc">${esc(p.category)}</div>
      <div class="cpe">${p.cpe.map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>
      <div class="cpe" style="margin-top:7px">${p.aliases.slice(0, 5).map(x => `<span class="alias">${esc(x)}</span>`).join('')}</div>
    </div>`).join('');
}

/* ---------- detail drawer ---------- */
function openDetail(cveId) {
  const r = State.data.results.find(x => x.cve_id === cveId);
  if (!r) return;
  const sev = SEV_CLASS[r.cvss_severity] || 'b-unrated';
  const vector = parseVector(r.cvss_vector);
  const statusBadge = r.ransomware ? '<span class="badge b-ransom">Ransomware</span>'
    : r.kev ? '<span class="badge b-confirmed">Confirmed exploited</span>' : '<span class="badge b-unconfirmed">Unconfirmed</span>';
  $('#drawer-title').innerHTML = `<div class="cve" style="font-size:18px">${r.cve_id}</div>
    <div style="margin-top:8px;display:flex;gap:7px;flex-wrap:wrap">
      <span class="badge ${sev}">${r.cvss_severity[0] + r.cvss_severity.slice(1).toLowerCase()} ${r.cvss}</span>
      ${statusBadge}<span class="badge b-soft">Urgency ${r.urgency.toFixed(2)}</span></div>`;
  $('#drawer-body').innerHTML = `
    <div class="dsection"><div class="dt">Description</div><div class="desc">${esc(r.description) || 'No description available.'}</div></div>
    <div class="dsection"><div class="dgrid">
      <div class="metric"><div class="ml">CVSS ${esc(r.cvss_version)}</div><div class="mv" style="color:var(--high)">${r.cvss}</div></div>
      <div class="metric"><div class="ml">EPSS probability</div><div class="mv" style="color:var(--accent)">${r.epss}</div>${r.epss_pct != null ? `<div class="ml">${r.epss_pct} percentile</div>` : ''}</div>
    </div></div>
    <div class="dsection" style="display:flex;gap:18px;align-items:center">
      <div>${Charts.gauge(r.confidence, confColor(r.confidence))}</div>
      <div><div class="dt">Data confidence: ${r.confidence_band}</div>
        <div class="desc">Based on NVD status (${esc(r.vuln_status) || 'n/a'}), and the presence of CVSS, CWE, references, and CPE data.</div></div>
    </div>
    <div class="dsection"><div class="dt">Affected assets</div>
      <div class="vector">${r.asset.split('; ').map(a => `<span class="vchip">${esc(a)}</span>`).join('')}</div>
      <div class="vector" style="margin-top:8px">${r.cpe.map(c => `<span class="vchip"><b>${esc(c)}</b></span>`).join('')}</div></div>
    ${vector.length ? `<div class="dsection"><div class="dt">CVSS vector</div><div class="vector">${vector.map(v => `<span class="vchip"><b>${esc(v.k)}</b> ${esc(v.v)}</span>`).join('')}</div></div>` : ''}
    ${r.cwes.length ? `<div class="dsection"><div class="dt">Weaknesses</div><div class="vector">${r.cwes.map(c => `<span class="vchip">${esc(c.id)} · ${esc(c.name)}</span>`).join('')}</div></div>` : ''}
    ${r.kev ? `<div class="dsection"><div class="dt">CISA KEV</div><div class="desc">Added ${esc(r.kev_date)}. ${esc(r.kev_desc)}</div></div>` : ''}
    <div class="dsection"><div class="dt">Recommended action</div><div class="action-box">${esc(r.action)}</div></div>
    <div class="dsection"><div class="dt">Plain-English summary</div><div class="desc">${esc(r.summary)}</div></div>
    ${r.references.length ? `<div class="dsection"><div class="dt">References</div><div class="reflist">${r.references.map(u => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`).join('')}</div></div>` : ''}
    <div class="dsection"><div class="dt">Timeline</div><div class="desc">Published ${esc(r.published.slice(0, 10))} · last modified ${esc(r.last_modified.slice(0, 10))}</div></div>`;
  $('#scrim').classList.add('open');
  $('#drawer').classList.add('open');
}
function closeDrawer() { $('#scrim').classList.remove('open'); $('#drawer').classList.remove('open'); }

function parseVector(v) {
  if (!v) return [];
  const names = { AV: 'Attack vector', AC: 'Complexity', PR: 'Privileges', UI: 'User interaction', S: 'Scope', C: 'Confidentiality', I: 'Integrity', A: 'Availability' };
  return v.replace(/^CVSS:[\d.]+\//, '').split('/').map(p => { const [k, val] = p.split(':'); return { k: names[k] || k, v: val }; }).filter(x => x.v);
}

/* ---------- csv export (browser side, Blob) ---------- */
function downloadCsv() {
  if (!State.data || !State.data.results.length) { alert('Run an analysis first.'); return; }
  const cols = ['rank', 'cve_id', 'asset', 'status', 'cvss', 'cvss_severity', 'epss', 'epss_pct', 'kev', 'ransomware', 'confidence', 'urgency', 'action', 'summary'];
  const head = cols.join(',');
  const lines = State.data.results.map(r => cols.map(c => csvCell(r[c])).join(','));
  const blob = new Blob([head + '\n' + lines.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'lodestar_cve_priorities.csv'; a.click();
  URL.revokeObjectURL(url);
}
function csvCell(v) { v = String(v == null ? '' : v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }

/* ---------- animations ---------- */
function animateCounts() {
  $$('.k-val[data-count]').forEach(el => {
    const target = parseFloat(el.dataset.count) || 0, dec = parseInt(el.dataset.dec || 0);
    if (reduceMotion) { el.textContent = fmtNum(target, dec); return; }
    const dur = 850, t0 = performance.now();
    function step(t) {
      const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3);
      el.textContent = fmtNum(target * e, dec);
      if (p < 1) requestAnimationFrame(step);
    }
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

/* ---------- 3D tilt on cards ---------- */
function attachTilt() {
  if (reduceMotion) return;
  $$('.kpi, .card, .job').forEach(card => {
    if (card._tilt) return; card._tilt = true;
    card.addEventListener('mousemove', e => {
      const r = card.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width - 0.5, py = (e.clientY - r.top) / r.height - 0.5;
      card.style.transform = `perspective(800px) rotateX(${(-py * 5).toFixed(2)}deg) rotateY(${(px * 6).toFixed(2)}deg) translateZ(6px)`;
    });
    card.addEventListener('mouseleave', () => { card.style.transform = ''; });
  });
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
    const n = Math.min(70, Math.floor(innerWidth / 26));
    pts = Array.from({ length: n }, () => ({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .25 * dpr, vy: (Math.random() - .5) * .25 * dpr }));
  }
  size(); addEventListener('resize', size);
  let raf;
  function draw() {
    ctx.clearRect(0, 0, w, h);
    for (const p of pts) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > w) p.vx *= -1; if (p.y < 0 || p.y > h) p.vy *= -1;
    }
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        const a = pts[i], b = pts[j], dx = a.x - b.x, dy = a.y - b.y, dist = Math.hypot(dx, dy);
        const max = 150 * dpr;
        if (dist < max) {
          ctx.strokeStyle = `rgba(56,189,248,${(1 - dist / max) * 0.16})`;
          ctx.lineWidth = dpr;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
    }
    for (const p of pts) { ctx.fillStyle = 'rgba(139,92,255,.5)'; ctx.beginPath(); ctx.arc(p.x, p.y, 1.4 * dpr, 0, 7); ctx.fill(); }
    raf = requestAnimationFrame(draw);
  }
  draw();
  document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else draw(); });
}

/* ---------- inline icons ---------- */
const iconBug = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 9h6v5a3 3 0 0 1-6 0V9zM12 3v3M5 8l2 2M19 8l-2 2M4 15h3M17 15h3"/></svg>';
const iconTarget = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/></svg>';
const iconFire = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3c1 4 5 5 5 9a5 5 0 0 1-10 0c0-2 1-3 2-4 .5 2 3 2 3-5z"/></svg>';
const iconAlert = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/></svg>';
const iconGauge = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18l4-5"/></svg>';
const iconShield = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z"/></svg>';
const iconStack = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/></svg>';
const iconTrend = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 17l6-6 4 4 8-8"/><path d="M21 7v5h-5"/></svg>';
const iconBolt = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 3L4 14h7l-1 7 9-11h-7z"/></svg>';
const iconDb = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/></svg>';
const iconCheck = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#27d29b" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>';
const iconWarn = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#ff8a3d" stroke-width="2.5"><path d="M12 3l9 16H3z"/><path d="M12 10v4"/></svg>';
