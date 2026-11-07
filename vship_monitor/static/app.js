/* Vessel network monitor - front end. Plain JS, no build step, no CDN. */
(function () {
  "use strict";

  // ---------- tiny helpers ----------
  const $ = id => document.getElementById(id);
  // h("div", {class: "x"}, "text", childNode, ...) - strings become text nodes (safe for log data)
  function h(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const k in (attrs || {})) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else if (k === "class") n.className = v;
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false)
      n.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
    return n;
  }
  const fmt = n => (n ?? 0).toLocaleString();
  const pct = (a, b) => b ? Math.round(100 * a / b) + "%" : "-";
  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) throw new Error(`${r.status} ${path}`);
    return r.json();
  }
  function ago(iso, nowIso) {
    if (!iso) return "never";
    const s = (new Date(nowIso || Date.now()) - new Date(iso)) / 1000;
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    return Math.floor(s / 86400) + " d ago";
  }
  const time = iso => iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
  const dateTime = iso => iso ? new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "";
  const ICON = { ok: "●", warning: "▲", critical: "■", info: "i", silent: "○" };
  const statusTag = (s, text) => h("span", { class: `st st-${s}` }, `${ICON[s] || "●"} ${text}`);
  const CLASS_NAMES = { wifi: "Wi-Fi", server: "Servers", firewall: "Firewall", switch: "Switches", other: "Other" };
  const SERIES = { wifi: "--series-wifi", server: "--series-server", firewall: "--series-firewall", switch: "--series-switch" };

  const PHONE = matchMedia("(max-width: 700px)");

  // ---------- app state ----------
  const S = {
    tab: "infra", window: "1h", metric: "e", alertFilter: "active",
    status: null, seenAlerts: null, notify: localStorage.getItem("notify") === "1",
    drawerId: null, timer: null,
  };

  // ---------- theme ----------
  function applyTheme(t) {
    document.documentElement.dataset.theme = t;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", t === "light" ? "#fcfcfb" : "#1a1a19");
    try { localStorage.setItem("theme", t); } catch (e) {}
  }
  applyTheme((() => { try { return localStorage.getItem("theme"); } catch (e) { return null; } })() || "dark");
  $("theme-btn").onclick = () => { applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"); refreshTab(); };

  // ---------- notifications ----------
  // Android Chrome only shows notifications through a service worker; desktops
  // and iPhone home-screen apps accept either. The phone gets the same alerts
  // as the laptop - while the app is open on the phone.
  const SW = ("serviceWorker" in navigator && window.isSecureContext)
    ? navigator.serviceWorker.register("/sw.js").catch(() => null) : Promise.resolve(null);
  async function notify(title, opts) {
    try {
      const reg = await SW;
      if (reg && reg.showNotification) { await reg.showNotification(title, { icon: "/static/icons/icon-192.png", ...opts }); return; }
    } catch (e) {}
    try { new Notification(title, opts); } catch (e) {}
  }
  if (!("Notification" in window)) $("notify-btn").hidden = true;   // e.g. iPhone Safari outside the home-screen app
  function paintNotify() {
    $("notify-btn").classList.toggle("on", S.notify);
    $("notify-label").textContent = S.notify ? "Notify on" : "Notify off";
  }
  $("notify-btn").onclick = async () => {
    if (!S.notify && "Notification" in window && Notification.permission !== "granted") {
      const p = await Notification.requestPermission();
      if (p !== "granted") return;
    }
    S.notify = !S.notify;
    try { localStorage.setItem("notify", S.notify ? "1" : "0"); } catch (e) {}
    paintNotify();
  };
  paintNotify();

  // ---------- tabs / range ----------
  document.querySelectorAll(".tabs [role=tab]").forEach(b => b.onclick = () => {
    document.querySelectorAll(".tabs [role=tab]").forEach(x => x.classList.toggle("active", x === b));
    S.tab = b.dataset.tab;
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.id === "tab-" + S.tab));
    if (S.tab === "explorer" && !$("ex-results").childElementCount && !EX.busy) renderExplorer();
    if (PHONE.matches) scrollTo(0, 0);
    refreshTab();
  });
  function setRange(w) {
    $("range").querySelectorAll("button").forEach(x => x.classList.toggle("active", x.dataset.w === w));
    S.window = w; refreshTab(); if (S.drawerId) openDevice(S.drawerId);
    if (S.tab === "explorer") renderExplorer();
  }
  $("range").querySelectorAll("button").forEach(b => b.onclick = () => setRange(b.dataset.w));
  $("infra-metric").querySelectorAll("button").forEach(b => b.onclick = () => {
    $("infra-metric").querySelectorAll("button").forEach(x => x.classList.toggle("active", x === b));
    S.metric = b.dataset.m; refreshTab();
  });
  $("alert-filter").querySelectorAll("button").forEach(b => b.onclick = () => {
    $("alert-filter").querySelectorAll("button").forEach(x => x.classList.toggle("active", x === b));
    S.alertFilter = b.dataset.s; renderAlertsTab();
  });

  // ---------- status bar ----------
  const AREA_LABELS = [["wifi", "Wi-Fi"], ["server", "Servers"], ["switch", "Switches"],
                       ["firewall", "Firewall"], ["security", "Security"], ["feed", "Feed"]];
  async function refreshStatus() {
    let st;
    try { st = await api(`/api/status?viewing=${!document.hidden}`); } catch (e) {
      $("mode").textContent = "OFFLINE"; $("mode").className = "pill error";
      $("feed-text").textContent = "Can't reach the monitor - is it still running?";
      return;
    }
    S.status = st;
    $("vessel").textContent = st.vessel;
    document.title = `${st.vessel} - Network monitor`;
    const src = st.source || {};
    const m = $("mode");
    if (st.mode === "replay") {
      m.textContent = `REPLAY ${src.speed ? "×" + src.speed : "max"}`; m.className = "pill replay";
    } else if (src.state === "error") {
      m.textContent = "FEED ERROR"; m.className = "pill error";
    } else { m.textContent = "LIVE"; m.className = "pill live"; }
    const parts = [];
    if (st.last_event) parts.push(`Data time ${new Date(st.now).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}`);
    parts.push(`${st.events_per_sec}/s`);
    parts.push(`${fmt(st.events_total)} messages`);
    if (src.type === "graylog") parts.push(src.state === "error" ? `Graylog: ${src.last_error}` : `Graylog ${src.state}`);
    if (src.type === "syslog") parts.push(`syslog ${src.listen}`);
    if (src.type === "replay" && src.state === "finished") parts.push("replay finished");
    $("feed-text").textContent = parts.join("  ·  ");
    $("feed-text").title = parts.join("\n");

    const ar = $("areas"); ar.replaceChildren();
    for (const [k, label] of AREA_LABELS) {
      const s = st.areas[k] || "ok";
      const text = s === "ok" ? "OK" : s === "critical" ? "Critical" : "Warning";
      ar.appendChild(h("span", { class: `area ${s}`, title: `${label}: ${text}` },
        h("span", { class: "ico" }, ICON[s]), `${label}`, h("span", { class: "muted" }, s === "ok" ? "" : text)));
    }
    const c = st.alert_counts, total = c.critical + c.warning + c.info;
    $("alert-badge").textContent = total;
    $("alert-badge").className = "badge" + (c.critical ? " hot" : "");
    $("learning").hidden = !st.learning;
    $("mask-note").textContent = st.mask_clients ? "Device identities are masked (privacy setting)" : "";
    if (st.catching_up) $("feed-text").textContent = `Loading missed messages… ${Math.round(100 * (st.catchup_progress || 0))}%  ·  ` + $("feed-text").textContent;
    if (st.away_pending && !AWAY.open) openAway();
  }

  // ---------- alerts ----------
  let ACTIVE = [];
  async function refreshAlerts() {
    try { ACTIVE = await api("/api/alerts?state=active"); } catch (e) { return; }
    // desktop notifications for alerts we haven't seen before
    const ids = new Set(ACTIVE.map(a => a.id));
    if (S.seenAlerts && S.notify && "Notification" in window && Notification.permission === "granted") {
      const min = { critical: 0, warning: 1, info: 2 }[S.status?.notify_min || "warning"];
      for (const a of ACTIVE) if (!S.seenAlerts.has(a.id) && !a.catchup && { critical: 0, warning: 1, info: 2 }[a.severity] <= min) {
        notify(`${a.severity.toUpperCase()}: ${a.title}`, { body: a.detail || "", tag: "vship-" + a.id });
      }
    }
    S.seenAlerts = new Set([...(S.seenAlerts || []), ...ids]);
    renderStrip();
    if (S.tab === "alerts") renderAlertsTab();
  }
  function alertRow(a, withAck) {
    const now = S.status?.now;
    return h("div", { class: `alert-row ${a.severity} ${a.active ? "" : "resolved"}` },
      h("span", { class: `sev-tag ${a.severity}` }, `${ICON[a.severity]} ${a.severity}`),
      h("div", {},
        h("div", { class: "title" }, a.title, a.count > 1 ? h("span", { class: "muted small" }, `  ×${fmt(a.count)}`) : null),
        a.detail ? h("div", { class: "detail" }, a.detail) : null),
      h("div", { class: "when" },
        a.active ? `since ${ago(a.first_seen, now)}` : `resolved ${ago(a.resolved_at, now)}`,
        h("br"), h("span", {}, dateTime(a.first_seen))),
      h("div", {},
        a.device ? h("button", { class: "btn", onclick: () => openDevice(a.device) }, "Device") : null, " ",
        withAck && a.active && !a.acked ? h("button", { class: "btn", onclick: async () => {
          await api(`/api/alerts/${a.id}/ack`, { method: "POST" }); refreshAlerts(); } }, "Acknowledge") : null,
        a.acked ? h("span", { class: "muted small" }, "acknowledged") : null));
  }
  function renderStrip() {
    const strip = $("alert-strip"); strip.replaceChildren();
    if (S.tab === "alerts" || S.tab === "explorer") return;
    const area = S.tab === "infra" ? ["wifi", "server", "switch", "feed", "other"] : ["firewall", "security", "feed"];
    const rows = ACTIVE.filter(a => !a.acked && a.severity !== "info" && area.includes(a.area)).slice(0, PHONE.matches ? 2 : 4);
    rows.forEach(a => strip.appendChild(alertRow(a, true)));
    const more = ACTIVE.filter(a => area.includes(a.area)).length - rows.length;
    if (more > 0) strip.appendChild(h("div", { class: "small muted" },
      h("button", { class: "link", onclick: () => document.querySelector('[data-tab=alerts]').click() },
        `${more} more alert${more > 1 ? "s" : ""} (including info and acknowledged) →`)));
  }
  async function renderAlertsTab() {
    const list = S.alertFilter === "active" ? ACTIVE : await api("/api/alerts?state=all");
    const box = $("alert-list"); box.replaceChildren();
    if (!list.length) { box.appendChild(h("div", { class: "empty" }, S.alertFilter === "active" ? "No active alerts." : "No alerts yet.")); return; }
    const wrap = h("div", { class: "alert-strip" });
    list.forEach(a => wrap.appendChild(alertRow(a, true)));
    box.appendChild(wrap);
  }

  // ---------- chart data helpers ----------
  function buckets(d) {
    const b = d.bucket_min * 60000;
    const start = Math.floor(new Date(d.start).getTime() / b) * b + b;
    const end = Math.floor(new Date(d.end).getTime() / b) * b;
    const xs = []; for (let t = start; t <= end; t += b) xs.push(t);
    return xs;
  }
  function spanMin() {
    if (S.window === "custom" && S.range) return Math.max(1, (new Date(S.range.to) - new Date(S.range.from)) / 60000);
    return { "15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080 }[S.window];
  }
  function rangeObj() {
    return S.window === "custom" && S.range ? { window: "custom", from: S.range.from, to: S.range.to } : { window: S.window };
  }
  function rangeQS() { return new URLSearchParams(rangeObj()).toString(); }

  // ---------- infrastructure ----------
  async function renderInfra() {
    const sec = $("tab-infra"); sec.classList.add("loading");
    let d; try { d = await api(`/api/infra?${rangeQS()}`); } finally { sec.classList.remove("loading"); }
    const now = S.status?.now || d.end;
    const devs = d.devices;
    const aps = devs.filter(x => x.cls === "wifi"), srvs = devs.filter(x => x.cls === "server"), sws = devs.filter(x => x.cls === "switch");
    const silent = x => x.status !== "ok" && ACTIVE.some(a => a.device === x.id && a.rule === "device_silent");
    const apsUp = aps.filter(x => !silent(x)).length;
    const portsDown = sws.reduce((a, x) => a + x.ports_down.length, 0);
    const warn = devs.reduce((a, x) => a + x.warnings, 0), errs = devs.reduce((a, x) => a + x.errors, 0);
    const k = $("infra-kpis"); k.replaceChildren(
      kpi("Wi-Fi access points reporting", h("span", {}, apsUp, h("small", {}, ` / ${aps.length}`)),
          aps.length - apsUp ? statusTag("critical", `${aps.length - apsUp} silent`) : statusTag("ok", "all reporting")),
      kpi("Servers reporting", h("span", {}, srvs.filter(x => !silent(x)).length, h("small", {}, ` / ${srvs.length}`)),
          srvs.some(silent) ? statusTag("critical", srvs.filter(silent).map(x => x.name).join(", ") + " silent") : statusTag("ok", "all reporting")),
      kpi("Switch ports down", portsDown, portsDown ? statusTag("warning", sws.filter(x => x.ports_down.length).map(x => x.name).join(", ")) : statusTag("ok", "none")),
      kpi("Wi-Fi client devices", fmt(d.wifi_clients), h("span", {}, "seen in this period")),
      kpi("Warnings & errors", fmt(warn), h("span", {}, `${fmt(errs)} errors · known noise excluded`)),
    );

    // chart
    const xs = buckets(d), idx = new Map(xs.map((t, i) => [t, i]));
    const classes = ["wifi", "server", "firewall", "switch"];
    const series = classes.map(c => ({ name: CLASS_NAMES[c], color: SERIES[c], values: xs.map(() => 0) }));
    for (const r of d.timeseries) {
      const i = idx.get(new Date(r.t).getTime()), ci = classes.indexOf(r.dev_class);
      if (i !== undefined && ci >= 0) series[ci].values[i] += S.metric === "e" ? r.e : r.n;
    }
    $("infra-chart-title").textContent = (S.metric === "e" ? "Warnings and errors" : "Messages") + ` per ${d.bucket_min} min, by device type`;
    Charts.line($("infra-chart"), { xs: xs.map(t => new Date(t)), series, spanMin: spanMin(), bucketMin: d.bucket_min });

    // AP grid by deck
    const grid = $("ap-grid"); grid.replaceChildren();
    const decks = {};
    for (const a of aps) (decks[a.location || "Unassigned"] ||= []).push(a);
    const order = Object.keys(decks).sort((a, b) => (parseInt(a.replace(/\D/g, "")) || 99) - (parseInt(b.replace(/\D/g, "")) || 99));
    for (const dk of order) {
      grid.appendChild(h("div", { class: "deck-row" }, h("div", { class: "deck-name" }, dk),
        h("div", { class: "deck-aps" }, decks[dk].map(a => {
          const st = silent(a) ? "silent" : a.status;
          const label = a.name.replace(/^Deck\d+_?/i, "") || a.name;
          return h("button", { class: `ap ${st}`, onclick: () => openDevice(a.id),
              title: `${a.name}\nIP ${a.ip}\nLast message ${ago(a.last_seen, now)}\n${a.warnings} warnings/errors in period` },
            h("span", { class: "nm" }, h("span", { class: "ico" }, ICON[st]), label),
            h("span", { class: "meta" },
              h("span", {}, `${a.clients_now} clients`),
              st === "silent" ? h("span", {}, `silent ${ago(a.last_seen, now).replace(" ago", "")}`)
                              : h("span", {}, `${fmt(a.warnings)} warn`)));
        }))));
    }

    // servers
    const sv = $("servers"); sv.replaceChildren();
    if (!d.servers.length) sv.appendChild(h("div", { class: "empty" }, "No servers seen yet."));
    for (const s of d.servers) {
      const isSilent = ACTIVE.some(a => a.device === s.id && a.rule === "device_silent");
      const hw = s.hardware;
      const hwTag = !hw ? h("span", { class: "muted small" }, "no sensor report yet")
        : Object.keys(hw.bad || {}).length ? statusTag("critical", "Sensors: " + Object.entries(hw.bad).map(([a, b]) => `${a} ${b}`).join(", "))
        : statusTag("ok", `All hardware sensors green (${ago(hw.ts, now)})`);
      sv.appendChild(h("div", { class: "srv" },
        h("div", { class: "srv-head" },
          h("button", { class: "link nm", onclick: () => openDevice(s.id) }, s.name),
          isSilent ? statusTag("critical", `silent since ${time(s.last_seen)}`) : statusTag(s.status === "ok" ? "ok" : s.status, s.status === "ok" ? "reporting" : s.status),
          h("span", { class: "muted small", style: "margin-left:auto" }, `${fmt(s.events)} msgs · ${fmt(s.warnings)} warn/err`)),
        h("div", { style: "margin-bottom:6px" }, hwTag),
        s.programs.length ? table(["Component", "Messages", "Warnings/errors"],
          s.programs.map(p => [p.program === "sut" ? "sut (HPE iLO tools)" : p.program, fmt(p.events), fmt(p.warnings)]), [false, true, true])
          : h("div", { class: "empty" }, "No messages in this period.")));
    }

    // switches
    const sw = $("switches"); sw.replaceChildren();
    const linkBy = {}; for (const l of d.links) (linkBy[l.device] ||= []).push(l);
    const rows = sws.map(s => {
      const ls = linkBy[s.id] || [];
      const flaps = ls.reduce((a, l) => a + l.downs, 0);
      return [h("button", { class: "link", onclick: () => openDevice(s.id) }, s.name),
              s.ports_down.length ? statusTag("warning", `down: ${s.ports_down.join(", ")}`) : statusTag("ok", "all up"),
              fmt(flaps), ago(s.last_seen, now)];
    });
    sw.appendChild(rows.length ? table(["Switch", "Ports", "Link drops in period", "Last message"], rows, [false, false, true, true])
                               : h("div", { class: "empty" }, "No switches seen yet."));
    if (d.links.length) {
      sw.appendChild(h("h3", { class: "small muted", style: "margin:14px 0 6px" }, "Port link changes in this period"));
      sw.appendChild(table(["Switch", "Port", "Went down", "Came up", "Now", "Last change"],
        d.links.slice(0, 10).map(l => [l.name, h("span", { class: "mono" }, l.port), fmt(l.downs), fmt(l.ups),
          l.state === "down" ? statusTag("warning", "down") : statusTag("ok", "up"), time(l.last)]), [false, false, true, true, false, true]));
    }

    // issues
    const is = $("issues"); is.replaceChildren();
    is.appendChild(d.issues.length ? table(["Message type", "Device type", "Count", "Devices", "Severity", "Last seen", ""],
      d.issues.map(i => [h("span", { class: "tpl" }, i.text), CLASS_NAMES[i.dev_class] || i.dev_class, fmt(i.n), fmt(i.devices),
        h("span", { class: `sv-${i.sev}` }, i.sev_name), time(i.last),
        h("button", { class: "btn", title: "Treat this message type as harmless noise", onclick: async () => {
          if (!confirm(`Hide this message type as noise?\n\n${i.text}\n\nIt will still be stored and searchable.`)) return;
          await api(`/api/templates/${i.template_id}/noise?on=true`, { method: "POST" }); refreshTab(); } }, "Hide")]),
      [false, false, true, true, false, true, false]) : h("div", { class: "empty" }, "No warnings or errors in this period."));
  }

  function kpi(label, value, sub) {
    return h("div", { class: "kpi" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), h("div", { class: "sub" }, sub));
  }
  function table(head, rows, right) {
    return h("div", { class: "tbl-wrap" },
      h("table", {}, h("thead", {}, h("tr", {}, head.map((x, i) => h("th", { class: right && right[i] ? "r" : "" }, x)))),
        h("tbody", {}, rows.map(r => h("tr", {}, r.map((c, i) => h("td", { class: right && right[i] ? "r" : "" }, c)))))));
  }
  function hbars(rows, opts = {}) {
    const max = Math.max(1, ...rows.map(r => r.blocked + (r.allowed || 0)));
    const box = h("div", {},
      h("div", { style: "margin-bottom:8px" }, h("span", { class: "key" }, h("i", { style: "background:var(--series-blocked)" }), "Blocked"),
        opts.noAllowed ? null : h("span", { class: "key" }, h("i", { style: "background:var(--series-allowed)" }), "Allowed")),
      h("div", { class: "hbars" }, rows.map(r => {
        const b = r.blocked, a = r.allowed || 0;
        const bar = h("div", { class: "track" },
          b ? h("div", { class: "seg-b", style: `width:${100 * b / max}%` }) : null,
          a ? h("div", { class: "seg-a", style: `width:${100 * a / max}%` }) : null);
        Charts.hover(bar, e => Charts.showTip(e, r.label, [
          { name: "blocked", value: fmt(b), color: getComputedStyle(document.documentElement).getPropertyValue("--series-blocked") },
          ...(opts.noAllowed ? [] : [{ name: "allowed", value: fmt(a), color: getComputedStyle(document.documentElement).getPropertyValue("--series-allowed") }]),
          ...(r.extra ? [{ name: r.extra, value: "", color: "transparent" }] : [])]), Charts.hideTip);
        return h("div", { class: "hbar" }, h("div", { class: "lbl", title: r.label }, r.label, r.sub ? h("small", {}, r.sub) : null), bar,
          h("div", { class: "val" }, opts.noAllowed ? fmt(b) : `${fmt(b)} / ${fmt(a)}`));
      })));
    return box;
  }

  // ---------- internet & security ----------
  async function renderSecurity() {
    const sec = $("tab-security"); sec.classList.add("loading");
    let d; try { d = await api(`/api/security?${rangeQS()}`); } finally { sec.classList.remove("loading"); }
    const k = d.kpis;
    $("sec-kpis").replaceChildren(
      kpi("Firewall events", fmt(k.total), h("span", {}, `${fmt(k.clients)} devices`)),
      kpi("Blocked", h("span", {}, pct(k.blocked, k.total)), h("span", {}, `${fmt(k.blocked)} connections blocked by policy`)),
      kpi("Allowed (logged)", fmt(k.allowed), h("span", {}, "apps detected and let through")),
      kpi("Security events", fmt(k.security), k.security ? statusTag("warning", "scans, spoofing, IPS, floods, VPN") : statusTag("ok", "none")),
      kpi("VPN / proxy bypass", fmt(k.proxy), k.proxy ? statusTag("warning", "attempts to get around the filter") : statusTag("ok", "none")),
    );
    const xs = buckets(d), idx = new Map(xs.map((t, i) => [t, i]));
    const blocked = xs.map(() => 0), allowed = xs.map(() => 0);
    for (const r of d.timeseries) { const i = idx.get(new Date(r.t).getTime()); if (i !== undefined) { blocked[i] += r.blocked; allowed[i] += r.allowed; } }
    Charts.stacked($("sec-chart"), { xs: xs.map(t => new Date(t)), spanMin: spanMin(), bucketMin: d.bucket_min,
      series: [{ name: "Blocked", color: "--series-blocked", values: blocked }, { name: "Allowed", color: "--series-allowed", values: allowed }] });

    $("apps").replaceChildren(d.apps.length ? hbars(d.apps.map(a => ({ label: a.app, sub: a.cat, blocked: a.blocked, allowed: a.allowed })))
      : h("div", { class: "empty" }, "No application traffic in this period."));
    $("cats").replaceChildren(d.categories.length ? hbars(d.categories.map(c => ({ label: c.cat || "(none)", blocked: c.blocked, allowed: c.allowed })))
      : h("div", { class: "empty" }, "Nothing in this period."));
    $("decks").replaceChildren(d.decks.length ? hbars(d.decks.map(x => ({ label: x.deck, sub: `${x.clients} devices`, blocked: x.blocked, extra: `${fmt(x.events)} events total` })), { noAllowed: true })
      : h("div", { class: "empty" }, "Nothing in this period."));
    $("clients").replaceChildren(d.clients.length ? table(["Device", "Type", "Near", "Events", "Blocked", "Top app", "Bypass"],
      d.clients.map(c => [h("span", { class: "mono" }, c.id + (c.ip ? ` (${c.ip})` : "")), c.os || "-", c.ap || "-", fmt(c.events), fmt(c.blocked), c.top_app || "-",
        c.proxy ? statusTag("warning", fmt(c.proxy)) : "-"]), [false, false, false, true, true, false, true])
      : h("div", { class: "empty" }, "No devices in this period."));
    const KIND = { proxy_access: "VPN / proxy bypass", port_scan: "Port scan", ip_spoof: "IP spoofing", ips: "Intrusion prevention",
                   flood: "Flood", vpn_error: "VPN tunnel error", web_denied: "Website blocked" };
    const evRows = S.allSecEvents ? d.events : d.events.slice(0, 25);
    $("sec-events").replaceChildren(d.events.length ? table(["Time", "Type", "Detail", "Device", "Remote address", "Action"],
      evRows.map(e => [time(e.ts), KIND[e.kind] || e.kind, h("span", { class: "tpl" }, e.what.replace(/^Application Control Detection Alert: /, "")),
        h("span", { class: "mono" }, e.client + (e.deck ? ` · ${e.deck}` : "")), h("span", { class: "mono" }, e.remote), e.action]))
      : h("div", { class: "empty" }, "No security events in this period."));
    if (d.events.length > 25) $("sec-events").appendChild(h("div", { style: "margin-top:8px" },
      h("button", { class: "btn", onclick: () => { S.allSecEvents = !S.allSecEvents; renderSecurity(); } },
        S.allSecEvents ? "Show fewer" : `Show all ${d.events.length} (newest first)`)));
  }

  // ---------- explorer ----------
  $("ex-form").onsubmit = e => { e.preventDefault(); renderExplorer(); };
  const EX = { busy: false, seq: 0 };
  async function renderExplorer() {
    const mySeq = ++EX.seq; EX.busy = true;
    const p = new URLSearchParams({ ...rangeObj(), q: $("ex-q").value, cls: $("ex-cls").value,
      device: $("ex-device").value, min_sev: $("ex-sev").value, hide_noise: $("ex-noise").checked });
    const box = $("ex-results"); box.classList.add("loading");
    let rows; try { rows = await api(`/api/events?${p}`); } finally { box.classList.remove("loading"); EX.busy = false; }
    if (mySeq !== EX.seq) return;          // a newer search was started; ignore this one
    box.replaceChildren();
    if (!rows.length) { box.appendChild(h("div", { class: "empty" }, "No messages match.")); return; }
    box.appendChild(h("div", { class: "small muted", style: "margin-bottom:6px" }, `Newest ${rows.length} messages`));
    for (const r of rows) box.appendChild(h("div", { class: "ln" + (r.noise ? " noise" : "") },
      h("span", {}, new Date(r.ts).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })),
      h("span", { class: `sv-${r.severity}` }, r.sev_name),
      h("button", { class: "link", style: "text-align:left", onclick: () => openDevice(r.device) }, r.device_name || r.device),
      h("span", { class: "raw" }, r.raw)));
  }

  // ---------- device drawer ----------
  $("dr-close").onclick = closeDrawer;
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });
  function closeDrawer() { $("drawer").classList.remove("open"); $("drawer").setAttribute("aria-hidden", "true"); S.drawerId = null; }
  async function openDevice(id) {
    S.drawerId = id;
    $("drawer").classList.add("open"); $("drawer").setAttribute("aria-hidden", "false");
    let d; try { d = await api(`/api/device?id=${encodeURIComponent(id)}&${rangeQS()}`); }
    catch (e) { $("dr-body").replaceChildren(h("div", { class: "empty" }, "Device not found.")); return; }
    const now = S.status?.now;
    $("dr-title").textContent = d.name || d.id;
    $("dr-sub").textContent = [CLASS_NAMES[d.cls], d.location, d.ip, d.id.split(":").slice(1).join(":")].filter(Boolean).join("  ·  ");
    const body = $("dr-body"); body.replaceChildren();
    const facts = [["Last message", ago(d.last_seen, now)], ["First seen", dateTime(d.first_seen)]];
    if (d.uptime_h != null) facts.push(["Uptime", `${d.uptime_h} h`]);
    if (d.cls === "wifi") facts.push(["Clients now", d.clients.length], ["Restarts seen", d.reboots]);
    if (d.hardware) facts.push(["Hardware sensors", Object.keys(d.hardware.bad || {}).length ? Object.entries(d.hardware.bad).map(([a, b]) => `${a} ${b}`).join(", ") : "All green"]);
    const down = Object.entries(d.link_state || {}).filter(([, v]) => v[0] === "down").map(([p]) => p);
    if (d.cls === "switch") facts.push(["Ports down", down.join(", ") || "none"]);
    body.appendChild(h("div", { class: "facts" }, facts.map(([k, v]) => h("div", { class: "fact" }, h("div", { class: "k" }, k), h("div", { class: "v" }, v)))));

    body.appendChild(h("h3", {}, `Activity (per ${d.bucket_min} min)`));
    const ch = h("div", { class: "chart", style: "height:180px" }); body.appendChild(ch);
    const xs = buckets(d), idx = new Map(xs.map((t, i) => [t, i]));
    const n = xs.map(() => 0), e = xs.map(() => 0);
    for (const r of d.timeseries) { const i = idx.get(new Date(r.t).getTime()); if (i !== undefined) { n[i] += r.n; e[i] += r.e; } }
    requestAnimationFrame(() => Charts.line(ch, { xs: xs.map(t => new Date(t)), spanMin: spanMin(), bucketMin: d.bucket_min,
      series: [{ name: "All messages", color: SERIES[d.cls] || "--series-wifi", values: n }, { name: "Warnings & errors", color: "--series-server", values: e }] }));

    if (d.alerts.length) {
      body.appendChild(h("h3", {}, "Alerts"));
      body.appendChild(h("div", { class: "alert-strip" }, d.alerts.map(a => alertRow(a, true))));
    }
    body.appendChild(h("h3", {}, "Message types"));
    body.appendChild(table(["Message", "Count", "Severity", ""], d.templates.map(t => [h("span", { class: "tpl" }, t.text), fmt(t.n),
      h("span", { class: `sv-${t.sev}` }, t.sev_name), t.noise ? h("span", { class: "muted small" }, "noise") : ""]), [false, true, false, false]));
    if (d.clients.length) {
      body.appendChild(h("h3", {}, `Connected clients (${d.clients.length})`));
      body.appendChild(table(["Device", "Type", "Last seen"], d.clients.slice(0, 40).map(c => [h("span", { class: "mono" }, c.id), c.os || "-", ago(c.last_seen, now)])));
    }
    body.appendChild(h("h3", {}, "Latest messages"));
    body.appendChild(h("div", { class: "log" }, d.lines.map(r => h("div", { class: "ln drawer-ln" + (r.noise ? " noise" : "") },
      h("span", {}, time(r.ts)), h("span", { class: `sv-${r.severity}` }, r.sev_name), h("span", { class: "raw" }, r.raw)))));
  }

  // ---------- while you were away ----------
  const AWAY = { open: false, data: null, timer: null, notified: false };
  const RULE_NAMES = { device_silent: "devices went silent", error_spike: "error spikes", hw_sensor: "hardware sensor warnings",
    link_flap: "flapping switch ports", link_down: "switch ports down", ap_reboot: "access point restarts",
    radio_reset: "Wi-Fi radio resets", conntrack_full: "AP connection tables full", dns_unreachable: "DNS outages",
    low_memory: "low-memory APs", new_message_type: "new message types", proxy_access: "VPN / proxy-bypass",
    noisy_client: "noisy devices", port_scan: "scanning / spoofing", flood: "floods", vpn_error: "VPN tunnel errors",
    admin_login: "admin logins", admin_login_failed: "failed admin logins", feed_stalled: "feed outages" };
  function duration(min) {
    min = Math.round(min);
    const d = Math.floor(min / 1440), hh = Math.floor((min % 1440) / 60), m = min % 60;
    return [d ? `${d} d` : "", hh ? `${hh} h` : "", (!d && m) ? `${m} min` : ""].filter(Boolean).join(" ") || "under a minute";
  }
  const longTime = iso => new Date(iso).toLocaleString([], { weekday: "short", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });

  async function openAway() {
    AWAY.open = true;
    $("away").hidden = false;
    await renderAway();
  }
  async function renderAway() {
    let d; try { d = await api("/api/away"); } catch (e) { return; }
    if (!d.pending) { closeAway(false); return; }
    AWAY.data = d;
    const mins = (new Date(d.to) - new Date(d.from)) / 60000;
    $("away-period").textContent = `${longTime(d.from)}  →  ${longTime(d.to)}  ·  ${duration(mins)}`
      + (d.mode === "replay" ? "  (data time in the replayed file)" : "");
    const body = $("away-body"); body.replaceChildren();
    if (!d.caught_up) {
      const pc = Math.round(100 * (d.progress || 0));
      body.appendChild(h("div", { class: "note" }, `Loading the messages you missed… ${pc}%. The summary fills in as they arrive.`,
        h("div", { class: "progress" }, h("i", { style: `width:${pc}%` }))));
    }
    if (d.note) body.appendChild(h("div", { class: "note" }, d.note));

    const cls = Object.fromEntries(d.by_class.map(r => [r.dev_class, r]));
    const sum = k => d.by_class.reduce((a, r) => a + r[k], 0);
    const crit = d.alerts.filter(a => a.severity === "critical").length;
    const fw = d.firewall || {};
    body.appendChild(h("div", { class: "kpis" },
      kpi("Alerts raised", fmt(d.alerts_total), crit ? statusTag("critical", `${crit} critical · ${d.still_active} still active`)
                                                  : h("span", {}, `${d.still_active} still active`)),
      kpi("Warnings & errors", fmt(sum("e")), h("span", {}, `${fmt(sum("err"))} errors · noise excluded`)),
      kpi("Messages received", fmt(sum("n")), h("span", {}, ["wifi", "server", "firewall", "switch"].filter(c => cls[c])
          .map(c => `${CLASS_NAMES[c]} ${Charts.fmtNum(cls[c].n)}`).join(" · "))),
      kpi("Firewall blocked", fmt(fw.blocked), h("span", {}, d.top_blocked.length ? "Top: " + d.top_blocked.map(a => a.app).join(", ") : "")),
      kpi("Attacks & bypass attempts", fmt((fw.attacks || 0) + (fw.proxy || 0)),
          h("span", {}, `${fmt(fw.attacks)} scans/spoofing/floods · ${fmt(fw.proxy)} VPN/proxy`))));

    if (Object.keys(d.alert_rules).length) {
      body.appendChild(h("h3", {}, "What happened"));
      body.appendChild(h("div", { class: "small" }, Object.entries(d.alert_rules).sort((a, b) => b[1] - a[1])
        .map(([r, n]) => h("span", { class: "key", style: "margin-bottom:4px" }, h("b", {}, n), " ", RULE_NAMES[r] || r))));
    }

    body.appendChild(h("h3", {}, `Warnings and errors per ${d.bucket_min} min`));
    const ch = h("div", { class: "chart", style: "height:170px" }); body.appendChild(ch);
    const xs = buckets({ start: d.from, end: d.to, bucket_min: d.bucket_min }), idx = new Map(xs.map((t, i) => [t, i]));
    const classes = ["wifi", "server", "firewall", "switch"];
    const series = classes.map(c => ({ name: CLASS_NAMES[c], color: SERIES[c], values: xs.map(() => 0) }));
    for (const r of d.timeseries) { const i = idx.get(new Date(r.t).getTime()), ci = classes.indexOf(r.dev_class); if (i !== undefined && ci >= 0) series[ci].values[i] += r.e; }
    requestAnimationFrame(() => Charts.line(ch, { xs: xs.map(t => new Date(t)), series, spanMin: mins, bucketMin: d.bucket_min }));

    body.appendChild(h("h3", {}, d.alerts.length ? `Alerts (${d.alerts_total}, most serious first)` : "Alerts"));
    if (!d.alerts.length) body.appendChild(h("div", { class: "empty" }, "No alerts in this period."));
    else body.appendChild(h("div", { class: "mini-alerts" }, d.alerts.slice(0, 15).map(a =>
      h("div", { class: `mini-alert ${a.severity}` },
        h("span", { class: `sev-tag ${a.severity}` }, `${ICON[a.severity]} ${a.severity}`),
        h("div", {}, h("div", {}, a.title), a.detail ? h("div", { class: "d" }, a.detail) : null),
        h("span", { class: "w" }, longTime(a.first_seen), h("br"), a.active ? "still active" : `resolved ${a.resolved_at ? time(a.resolved_at) : ""}`)))));
    if (d.alerts_total > 15) body.appendChild(h("div", { class: "small muted", style: "margin-top:6px" }, `…and ${d.alerts_total - 15} more on the alerts page.`));

    if (d.new_types.length) {
      body.appendChild(h("h3", {}, `New kinds of warning or error (${d.new_types.length})`));
      body.appendChild(table(["Message", "Device type", "First seen on", "First seen", "Count so far"],
        d.new_types.slice(0, 10).map(t => [h("span", { class: "tpl" }, t.text), CLASS_NAMES[t.cls] || t.cls, t.device || "-", longTime(t.first_seen), fmt(t.count)]),
        [false, false, false, false, true]));
    }

    // One desktop notification for the whole period, instead of one per alert.
    if (d.caught_up && !AWAY.notified && S.notify && "Notification" in window && Notification.permission === "granted") {
      AWAY.notified = true;
      notify("While you were away", { body: `${d.alerts_total} alerts (${crit} critical) between ${longTime(d.from)} and ${longTime(d.to)}`, tag: "vship-away" });
    }
    clearTimeout(AWAY.timer);
    if (!d.caught_up && AWAY.open) AWAY.timer = setTimeout(renderAway, 3000);
  }
  async function closeAway(markSeen = true) {
    clearTimeout(AWAY.timer);
    $("away").hidden = true;
    if (AWAY.data) {
      S.range = { from: AWAY.data.from, to: AWAY.data.to };
      $("range-away").hidden = false;
      try { localStorage.setItem("lastAway", JSON.stringify(S.range)); } catch (e) {}
    }
    if (markSeen) { try { await api("/api/away/seen", { method: "POST" }); } catch (e) {} }
    AWAY.open = false; AWAY.notified = false;
  }
  try {   // keep "Since last visit" available after a page reload
    const saved = JSON.parse(localStorage.getItem("lastAway") || "null");
    if (saved && saved.from) { S.range = saved; $("range-away").hidden = false; }
  } catch (e) {}
  $("away-ok").onclick = () => closeAway();
  $("away-close").onclick = () => closeAway();
  $("away-range").onclick = async () => { await closeAway(); setRange("custom"); };
  $("away-alerts").onclick = async () => { await closeAway(); document.querySelector("[data-tab=alerts]").click(); };
  $("away-explore").onclick = async () => {
    await closeAway();
    $("ex-sev").value = "4"; $("ex-noise").checked = true; $("ex-q").value = "";
    S.window = "custom";
    $("range").querySelectorAll("button").forEach(x => x.classList.toggle("active", x.dataset.w === "custom"));
    document.querySelector("[data-tab=explorer]").click();
    renderExplorer();
  };
  document.addEventListener("keydown", e => { if (e.key === "Escape" && AWAY.open) closeAway(); });

  // ---------- open on your phone (laptop only) ----------
  async function renderPhone(refresh) {
    const body = $("phone-body");
    if (refresh) body.replaceChildren(h("div", { class: "empty" }, "Checking Tailscale…"));
    let d; try { d = await api(`/api/phone${refresh ? "?refresh=1" : ""}`); }
    catch (e) { body.replaceChildren(h("div", { class: "note" }, "Couldn't check - is the monitor still running?")); return; }
    body.replaceChildren();
    if (d.url) {
      body.appendChild(h("p", { class: "small muted", style: "margin:0 0 4px;text-align:center" },
        "Scan with your phone's camera. The phone needs the Tailscale app, signed in to the same account."));
      if (d.qr_svg) { const q = h("div", { class: "qr" }); q.innerHTML = d.qr_svg; body.appendChild(q); }   // SVG built by our own server
      body.appendChild(h("div", { class: "phone-url" }, d.url));
      body.appendChild(h("ol", { class: "steps" },
        h("li", {}, "Open the address on the phone (point the camera, tap the link)."),
        h("li", {}, "Android, Chrome: menu ⋮ → ", h("b", {}, "Add to Home screen"), "."),
        h("li", {}, "iPhone, Safari: Share button → ", h("b", {}, "Add to Home Screen"), "."),
        h("li", {}, "The phone shows the dashboard whenever this laptop is on and the monitor window is open.")));
    } else {
      body.appendChild(h("div", { class: "note" }, d.hint || "Tailscale isn't set up yet."));
      if (d.enable_url) body.appendChild(h("p", {}, h("a", { href: d.enable_url, target: "_blank", rel: "noopener" }, "Turn on HTTPS for your Tailscale network →")));
      if (d.command) body.appendChild(h("p", { class: "small" }, "Or run this once in a Command Prompt: ", h("code", {}, d.command)));
      body.appendChild(h("p", { class: "small muted" }, "Step-by-step guide: PHONE_ACCESS.md in the monitor folder."));
    }
    body.appendChild(h("div", { style: "margin-top:12px;text-align:right" },
      h("button", { class: "btn", onclick: () => renderPhone(true) }, "Check again")));
  }
  $("phone-btn").onclick = () => { $("phone").hidden = false; renderPhone(false); };
  $("phone-close").onclick = () => { $("phone").hidden = true; };
  $("phone").addEventListener("click", e => { if (e.target === $("phone")) $("phone").hidden = true; });
  document.addEventListener("keydown", e => { if (e.key === "Escape") $("phone").hidden = true; });

  // ---------- refresh loop ----------
  let busy = false;
  async function refreshTab() {
    if (busy) return; busy = true;
    try {
      renderStrip();
      if (S.tab === "infra") await renderInfra();
      else if (S.tab === "security") await renderSecurity();
      else if (S.tab === "alerts") await renderAlertsTab();
    } catch (e) { console.warn(e); } finally { busy = false; }
  }
  async function tick() {
    await refreshStatus();
    await refreshAlerts();
    if (!document.hidden) await refreshTab();
  }
  tick();
  setInterval(tick, 5000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });
  let lastW = innerWidth;   // phone browsers fire "resize" when the address bar slides; only redraw on width changes
  window.addEventListener("resize", () => {
    if (innerWidth === lastW) return;
    lastW = innerWidth; clearTimeout(S.timer); S.timer = setTimeout(refreshTab, 200);
  });
  $("ex-cls").onchange = renderExplorer;
  $("ex-sev").onchange = renderExplorer;
})();
