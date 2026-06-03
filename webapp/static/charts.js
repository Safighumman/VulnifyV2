/* Lightweight, dependency-free SVG charts for Vulnify.
   Everything returns an SVG string so it can be injected directly. */
(function (global) {
  function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

  // Area + line sparkline for a timeline of {date, value}.
  function sparkArea(points, color) {
    color = color || '#18d39a';
    const W = 320, H = 90, P = 6;
    if (!points || points.length === 0) {
      return `<svg class="spark" viewBox="0 0 ${W} ${H}"><text x="${W / 2}" y="${H / 2}" fill="#5e6b7d" font-size="12" text-anchor="middle">No data</text></svg>`;
    }
    const vals = points.map(p => p.value);
    const max = Math.max(...vals, 1);
    const n = points.length;
    const x = i => P + (n === 1 ? (W - 2 * P) / 2 : i * (W - 2 * P) / (n - 1));
    const y = v => H - P - (v / max) * (H - 2 * P - 8);
    const uid = 'sg' + Math.random().toString(36).slice(2, 7);
    let line = '';
    points.forEach((p, i) => { line += `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(p.value).toFixed(1)} `; });
    const area = `M${x(0).toFixed(1)},${(H - P)} ` + points.map((p, i) => `L${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join(' ') + ` L${x(n - 1).toFixed(1)},${H - P} Z`;
    const dots = points.map((p, i) => `<circle cx="${x(i).toFixed(1)}" cy="${y(p.value).toFixed(1)}" r="2.3" fill="${color}"/>`).join('');
    const len = 600;
    return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
      <defs><linearGradient id="${uid}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="${color}" stop-opacity=".35"/>
        <stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
      <path d="${area}" fill="url(#${uid})"/>
      <path d="${line}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
        style="stroke-dasharray:${len};stroke-dashoffset:${len};animation:draw 1.1s ease forwards"/>
      ${dots}
    </svg>`;
  }

  // Circular gauge (270 degree sweep) for a 0..100 percent, with a custom label.
  function gauge(percent, color, label) {
    percent = Math.max(0, Math.min(100, percent || 0));
    color = color || '#18d39a';
    label = (label || 'SCORE').toUpperCase();
    const S = 118, c = S / 2, r = 47, sweep = 0.75;
    const circ = 2 * Math.PI * r;
    const track = circ * sweep;
    const val = track * (percent / 100);
    return `<svg class="gauge" viewBox="0 0 ${S} ${S}">
      <g transform="rotate(135 ${c} ${c})">
        <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="#161a22" stroke-width="9"
          stroke-dasharray="${track} ${circ}" stroke-linecap="round"/>
        <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${color}" stroke-width="9"
          stroke-dasharray="${val} ${circ}" stroke-linecap="round"
          style="transition:stroke-dasharray 1.1s cubic-bezier(.2,.8,.2,1);filter:drop-shadow(0 0 5px ${color}88)"/>
      </g>
      <text x="${c}" y="${c - 1}" text-anchor="middle" fill="#e8edf4" font-size="27" font-weight="800">${Math.round(percent)}</text>
      <text x="${c}" y="${c + 16}" text-anchor="middle" fill="#94a2b6" font-size="9" letter-spacing="1">${esc(label)}</text>
    </svg>`;
  }

  // Donut via stacked SVG arcs, with a clean center hole.
  function donut(segments) {
    const total = segments.reduce((a, s) => a + s.value, 0) || 1;
    const S = 150, c = S / 2, r = 56, sw = 22;
    const circ = 2 * Math.PI * r;
    let offset = 0, arcs = '';
    segments.forEach((s, i) => {
      const len = (s.value / total) * circ;
      arcs += `<circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${sw}"
        stroke-dasharray="${len} ${circ - len}" stroke-dashoffset="${-offset}"
        transform="rotate(-90 ${c} ${c})"
        style="opacity:0;animation:fadeSeg .5s ease forwards ${0.12 * i + 0.1}s"/>`;
      offset += len;
    });
    return `<svg viewBox="0 0 ${S} ${S}" style="width:150px;height:150px">${arcs}</svg>`;
  }

  global.Charts = { sparkArea, gauge, donut, esc };
})(window);
