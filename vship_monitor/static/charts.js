/* Tiny dependency-free SVG charts: lines with a crosshair, stacked bars with
   per-bar hover. Written in-house so the app needs no internet / CDN. */
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const tip = () => document.getElementById("tooltip");

  function el(tag, attrs, parent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

  // Round the axis top so the 4 gridlines land on whole, readable numbers.
  function niceMax(v) {
    if (v <= 0) return 4;
    const raw = v / 4, p = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= raw) return Math.max(4, Math.ceil(m * p) * 4);
    return 40 * p;
  }
  function fmtNum(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
    if (n >= 1e4) return Math.round(n / 1e3) + "k";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
    return String(Math.round(n));
  }
  function fmtTime(d, spanMin) {
    const o = spanMin > 1440 ? { weekday: "short", hour: "2-digit", minute: "2-digit" }
                             : { hour: "2-digit", minute: "2-digit" };
    return d.toLocaleString([], o);
  }

  function showTip(evt, head, rows) {
    const t = tip();
    t.replaceChildren();
    const h = document.createElement("div"); h.className = "tt-h"; h.textContent = head; t.appendChild(h);
    for (const r of rows) {
      const row = document.createElement("div"); row.className = "tt-r";
      const i = document.createElement("i"); i.style.background = r.color;
      const b = document.createElement("b"); b.textContent = r.value;
      const s = document.createElement("span"); s.textContent = r.name;
      row.append(i, b, s); t.appendChild(row);
    }
    t.style.display = "block";
    const w = t.offsetWidth, hgt = t.offsetHeight;
    let x = evt.clientX + 14, y = evt.clientY + 14;
    if (x + w > innerWidth - 8) x = evt.clientX - w - 14;
    if (y + hgt > innerHeight - 8) y = evt.clientY - hgt - 14;
    t.style.left = x + "px"; t.style.top = y + "px";
  }
  function hideTip() { tip().style.display = "none"; }

  function legend(container, series, kind) {
    if (series.length < 2) return;
    const lg = document.createElement("div"); lg.className = "chart-legend";
    for (const s of series) {
      const k = document.createElement("span"); k.className = "key";
      const i = document.createElement("i"); if (kind === "line") i.className = "line";
      i.style.background = css(s.color);
      k.append(i, document.createTextNode(s.name)); lg.appendChild(k);
    }
    container.appendChild(lg);
  }

  /* Shared frame: x = time buckets, y = counts. */
  function frame(container, opts) {
    container.replaceChildren();
    const wrap = document.createElement("div"); wrap.style.position = "relative";
    legend(container, opts.series, opts.kind);
    container.appendChild(wrap);
    const W = container.clientWidth || 800;
    const H = (container.clientHeight || 240) - (opts.series.length > 1 ? 26 : 0);
    const m = { l: 44, r: 12, t: 8, b: 24 };
    const svg = el("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}` }, wrap);
    return { svg, W, H, m, iw: W - m.l - m.r, ih: H - m.t - m.b };
  }

  function axes(f, xs, maxY, spanMin) {
    const g = el("g", { class: "grid" }, f.svg);
    const ax = el("g", { class: "axis" }, f.svg);
    for (let i = 0; i <= 4; i++) {
      const v = maxY * i / 4, y = f.m.t + f.ih - f.ih * i / 4;
      if (i > 0) el("line", { x1: f.m.l, x2: f.m.l + f.iw, y1: y, y2: y }, g);
      const t = el("text", { x: f.m.l - 8, y: y + 4, "text-anchor": "end" }, ax); t.textContent = fmtNum(v);
    }
    el("line", { class: "baseline", x1: f.m.l, x2: f.m.l + f.iw, y1: f.m.t + f.ih, y2: f.m.t + f.ih }, f.svg);
    const n = xs.length, want = Math.max(2, Math.floor(f.iw / 90));
    const step = Math.max(1, Math.ceil(n / want));
    for (let i = 0; i < n; i += step) {
      const x = f.m.l + (n === 1 ? f.iw / 2 : f.iw * i / (n - 1));
      const t = el("text", { x, y: f.H - 6, "text-anchor": "middle" }, ax);
      t.textContent = fmtTime(xs[i], spanMin);
    }
  }

  /* opts: {xs:[Date], series:[{name,color(css var),values:[]}], spanMin, bucketMin} */
  function line(container, opts) {
    opts.kind = "line";
    const f = frame(container, opts);
    const xs = opts.xs, n = xs.length;
    if (!n) { const t = el("text", { x: f.W / 2, y: f.H / 2, "text-anchor": "middle", fill: css("--text-muted") }, f.svg); t.textContent = "No data in this period"; return; }
    let maxY = 0; for (const s of opts.series) for (const v of s.values) maxY = Math.max(maxY, v);
    maxY = niceMax(maxY);
    axes(f, xs, maxY, opts.spanMin);
    const X = i => f.m.l + (n === 1 ? f.iw / 2 : f.iw * i / (n - 1));
    const Y = v => f.m.t + f.ih - (v / maxY) * f.ih;
    for (const s of opts.series) {
      const d = s.values.map((v, i) => `${i ? "L" : "M"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join("");
      el("path", { d, fill: "none", stroke: css(s.color), "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, f.svg);
      if (n === 1) el("circle", { cx: X(0), cy: Y(s.values[0]), r: 4, fill: css(s.color) }, f.svg);
    }
    const xh = el("line", { class: "xhair", y1: f.m.t, y2: f.m.t + f.ih, visibility: "hidden" }, f.svg);
    const dots = opts.series.map(s => el("circle", { r: 4, fill: css(s.color), stroke: css("--surface-1"), "stroke-width": 2, visibility: "hidden" }, f.svg));
    const hit = el("rect", { x: f.m.l, y: f.m.t, width: f.iw, height: f.ih, fill: "transparent" }, f.svg);
    hit.addEventListener("pointermove", e => {
      const r = f.svg.getBoundingClientRect();
      const i = Math.max(0, Math.min(n - 1, Math.round((e.clientX - r.left - f.m.l) / f.iw * (n - 1))));
      xh.setAttribute("x1", X(i)); xh.setAttribute("x2", X(i)); xh.setAttribute("visibility", "visible");
      opts.series.forEach((s, k) => { dots[k].setAttribute("cx", X(i)); dots[k].setAttribute("cy", Y(s.values[i])); dots[k].setAttribute("visibility", "visible"); });
      const end = new Date(xs[i].getTime() + opts.bucketMin * 60000);
      showTip(e, `${fmtTime(xs[i], opts.spanMin)} - ${fmtTime(end, 0)}`,
        opts.series.map(s => ({ name: s.name, value: s.values[i].toLocaleString(), color: css(s.color) })));
    });
    hit.addEventListener("pointerleave", () => { xh.setAttribute("visibility", "hidden"); dots.forEach(d => d.setAttribute("visibility", "hidden")); hideTip(); });
  }

  /* Stacked bars; series[0] sits on the baseline. */
  function stacked(container, opts) {
    opts.kind = "bar";
    const f = frame(container, opts);
    const xs = opts.xs, n = xs.length;
    if (!n) { const t = el("text", { x: f.W / 2, y: f.H / 2, "text-anchor": "middle", fill: css("--text-muted") }, f.svg); t.textContent = "No data in this period"; return; }
    const totals = xs.map((_, i) => opts.series.reduce((a, s) => a + s.values[i], 0));
    const maxY = niceMax(Math.max(...totals));
    axes(f, xs, maxY, opts.spanMin);
    const slot = f.iw / n, bw = Math.max(2, Math.min(28, slot - 2));
    const Y = v => (v / maxY) * f.ih;
    xs.forEach((x, i) => {
      const cx = f.m.l + (n === 1 ? f.iw / 2 : f.iw * i / (n - 1));
      let base = f.m.t + f.ih;
      const g = el("g", {}, f.svg);
      const segs = opts.series.map(s => ({ s, v: s.values[i] })).filter(o => o.v > 0);
      segs.forEach((o, k) => {
        const h = Y(o.v), top = k === segs.length - 1;
        const gap = k > 0 ? 2 : 0;          // 2px surface gap between stacked segments
        const y = base - h, hh = Math.max(0, h - gap);
        const r = top ? Math.min(4, bw / 2, hh) : 0;
        const x0 = cx - bw / 2;
        const d = r > 0
          ? `M${x0},${y + hh} V${y + r} Q${x0},${y} ${x0 + r},${y} H${x0 + bw - r} Q${x0 + bw},${y} ${x0 + bw},${y + r} V${y + hh} Z`
          : `M${x0},${y} H${x0 + bw} V${y + hh} H${x0} Z`;
        el("path", { d, fill: css(o.s.color) }, g);
        base = y;
      });
      const hit = el("rect", { x: cx - slot / 2, y: f.m.t, width: slot, height: f.ih, fill: "transparent" }, g);
      hit.addEventListener("pointermove", e => {
        g.style.filter = "brightness(1.15)";
        const end = new Date(x.getTime() + opts.bucketMin * 60000);
        showTip(e, `${fmtTime(x, opts.spanMin)} - ${fmtTime(end, 0)}`,
          opts.series.map(s => ({ name: s.name, value: s.values[i].toLocaleString(), color: css(s.color) }))
            .concat(opts.series.length > 1 ? [{ name: "total", value: totals[i].toLocaleString(), color: "transparent" }] : []));
      });
      hit.addEventListener("pointerleave", () => { g.style.filter = ""; hideTip(); });
    });
  }

  window.Charts = { line, stacked, fmtNum, showTip, hideTip };
})();
