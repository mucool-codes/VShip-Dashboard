"""The running application: ingest pipeline + local web server."""
from __future__ import annotations

import asyncio
import logging
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .alerts import AlertEngine
from .noise import NoiseFilter
from .parser import SEV_NAMES, parse
from .sources import GraylogSource, ReplaySource, SyslogSource
from .state import State, mask_mac
from .store import Store

log = logging.getLogger("vship")
STATIC = Path(__file__).parent / "static"

WINDOWS = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080}
SECURITY_KINDS = ("proxy_access", "port_scan", "ip_spoof", "ips", "flood", "vpn_error",
                  "web_denied")
_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")


def replay_signature(path: str) -> str:
    p = Path(path).resolve()
    st = p.stat()
    return f"{p}|{st.st_size}|{int(st.st_mtime)}"


def bucket_minutes(window: int) -> int:
    return 1 if window <= 60 else 5 if window <= 360 else 15 if window <= 1440 else 60


class Pipeline:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        src = cfg["source"]["type"]
        self.kind = src
        self.live = src != "replay"
        self.store = Store(cfg["storage"]["path"])
        self.state = State(live=self.live)
        self.mask = bool(cfg["privacy"]["mask_clients"])
        self.alerts = AlertEngine(cfg["alerts"], self.state, self.mask)
        self.user_noise: list[int] = []
        self._load()
        self.noise = NoiseFilter(cfg["noise"]["patterns"])
        self.away_min = float(cfg["away"]["min_minutes"])
        self.session = self.store.load_kv("session", {}) or {}
        self.away: dict | None = self.store.load_kv("away")   # an unseen summary from before
        self.catch_note = ""
        self.source = self._make_source(src)
        self._open_restart_period()
        self.catching_up = bool(self.source.status.get("caught_up") is False)
        self.state.catching_up = self.alerts.catchup = self.catching_up
        if not self.catching_up and self.away and not self.away.get("caught_up"):
            self.finish_catchup()      # nothing to load (e.g. syslog): the period ends now
        self.started = time.time()
        self.tasks: list[asyncio.Task] = []
        self._cache: dict = {}

    # ---- setup ----------------------------------------------------------------
    def _make_source(self, kind: str):
        c = self.cfg
        now = datetime.now(timezone.utc)
        latest = self.store.latest_ts()
        if kind == "graylog":
            g = c["graylog"]
            if not g["token"]:
                log.warning("No Graylog token set in config.toml - polling will fail.")
            resume = latest
            cap = now - timedelta(hours=float(g["max_catchup_hours"]))
            if resume and resume < cap:
                self.catch_note = (f"The app was closed for more than {g['max_catchup_hours']} h; only the "
                                   f"last {g['max_catchup_hours']} h were loaded (max_catchup_hours).")
                resume = cap
            return GraylogSource(g["url"], g["token"], g["query"], g["streams"], g["poll_seconds"],
                                 g["lag_seconds"], g["api"], g["verify_tls"], g["backfill_minutes"],
                                 resume_from=resume)
        if kind == "syslog":
            s = c["syslog"]
            if self.session.get("last_alive_wall"):
                self.catch_note = ("Syslog is only recorded while the app is running, so messages sent "
                                   "while it was closed were not received.")
            return SyslogSource(s["host"], s["udp_port"], s["tcp_port"])
        if kind == "replay":
            r = c["replay"]
            if not r["csv"] or not Path(r["csv"]).exists():
                raise SystemExit(f"Replay file not found: {r['csv']!r}. Set [replay] csv in config.toml "
                                 f"or pass --replay.")
            sig = replay_signature(r["csv"])
            resume_after = catchup_until = None
            if latest and self.session.get("replay_sig") == sig and not r["loop"]:
                # Same file as last time: carry on where it stopped, and fast-forward
                # through the data that "happened" while the app was closed.
                resume_after = latest
                gone = self._seconds_closed()
                if gone and r["speed"]:
                    catchup_until = latest + timedelta(seconds=gone * float(r["speed"]))
            self.session["replay_sig"] = sig
            return ReplaySource(r["csv"], r["speed"], r["loop"], resume_after=resume_after,
                                catchup_until=catchup_until)
        raise SystemExit(f"Unknown source type {kind!r} (use graylog, syslog or replay)")

    def _seconds_closed(self) -> float:
        t = self.session.get("last_alive_wall")
        if not t:
            return 0.0
        return max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(t)).total_seconds())

    def _open_restart_period(self):
        """On start-up, open a 'while you were away' period from when the dashboard
        was last viewed (or the app last ran, if that was earlier)."""
        s = self.session
        if not s.get("last_alive_wall"):
            return
        alive_w = datetime.fromisoformat(s["last_alive_wall"])
        view_w = datetime.fromisoformat(s["last_view_wall"]) if s.get("last_view_wall") else alive_w
        if view_w <= alive_w and s.get("last_view_data"):
            from_w, from_d = view_w, s["last_view_data"]
        else:
            from_w, from_d = alive_w, s.get("last_alive_data") or s["last_alive_wall"]
        now_w = datetime.now(timezone.utc)
        if (now_w - from_w).total_seconds() / 60 < self.away_min:
            return
        rec = {"reason": "restart", "from_wall": from_w.isoformat(), "from_data": from_d,
               "to_wall": now_w.isoformat(), "to_data": None, "caught_up": False,
               "closed_from": alive_w.isoformat(), "closed_to": now_w.isoformat(),
               "note": self.catch_note}
        if self.away and self.away.get("from_data", from_d) < from_d:   # earlier unseen period
            rec["from_wall"], rec["from_data"] = self.away["from_wall"], self.away["from_data"]
        self.away = rec

    def _load(self):
        self.state.load(self.store.load_kv("state"))
        self.alerts.load(self.store.load_kv("alerts"))
        self.user_noise = self.store.load_kv("user_noise", [])

    def save(self):
        self.store.flush()
        self.store.save_kv("state", self.state.to_dict())
        self.store.save_kv("alerts", self.alerts.to_dict())
        self.store.save_kv("user_noise", self.user_noise)
        self.save_session()

    def save_session(self):
        self.session["last_alive_wall"] = datetime.now(timezone.utc).isoformat()
        if self.state.clock:
            self.session["last_alive_data"] = (self.state.clock if not self.live
                                               else datetime.now(timezone.utc)).isoformat()
        self.store.save_kv("session", self.session)
        self.store.save_kv("away", self.away)

    # ---- the "while you were away" period ------------------------------------------
    def viewed(self):
        """Called while a browser tab is showing the dashboard."""
        now_w = datetime.now(timezone.utc)
        last = self.session.get("last_view_wall")
        if (last and not self.away and not self.catching_up
                and (now_w - datetime.fromisoformat(last)).total_seconds() / 60 >= self.away_min):
            self.away = {"reason": "page", "from_wall": last,
                         "from_data": self.session.get("last_view_data") or last,
                         "to_wall": now_w.isoformat(), "to_data": self.state.now().isoformat(),
                         "caught_up": True, "note": ""}
        self.session["last_view_wall"] = now_w.isoformat()
        self.session["last_view_data"] = self.state.now().isoformat()

    def away_seen(self):
        self.away = None
        self.viewed()
        self.store.save_kv("away", None)

    def finish_catchup(self):
        self.catching_up = self.state.catching_up = self.alerts.catchup = False
        if self.away and not self.away.get("caught_up"):
            self.away["caught_up"] = True
            end = self.state.clock or datetime.now(timezone.utc)
            target = self.source.status.get("catchup_target")   # replay: where fast-forward stopped
            if target and datetime.fromisoformat(target) < end:
                end = datetime.fromisoformat(target)
            self.away["to_data"] = end.isoformat()
            if self.live:
                self.away["to_data"] = max(self.away["to_data"], self.away["to_wall"])
            self.away["finished_wall"] = datetime.now(timezone.utc).isoformat()
        log.info("Caught up with missed data.")

    def catchup_progress(self) -> float | None:
        if not self.catching_up or not self.away:
            return None
        frm = datetime.fromisoformat(self.away["from_data"])
        target = self.source.status.get("catchup_target")
        target = datetime.fromisoformat(target) if target else datetime.now(timezone.utc)
        clock = self.state.clock or frm
        total = (target - frm).total_seconds()
        return 1.0 if total <= 0 else max(0.0, min(1.0, (clock - frm).total_seconds() / total))

    # ---- running ----------------------------------------------------------------
    async def run_source(self):
        async for ts, source, message, pri in self.source.stream():
            try:
                ev = parse(ts, source, message, pri)
            except Exception:  # never let one odd line stop the feed
                log.exception("Could not parse: %r", message[:200])
                continue
            ev.noise = ev.template_id in self.user_noise or self.noise.is_noise(ev.raw)
            dv, new_tpl = self.state.ingest(ev)
            self.alerts.on_event(ev, dv, new_tpl)
            self.store.add(ev)
            if self.state.total % 500 == 0:
                self.alerts.tick(self.state.now())
                if self.catching_up and self.source.status.get("caught_up"):
                    self.finish_catchup()
                await asyncio.sleep(0)
        if self.catching_up:
            self.finish_catchup()

    async def housekeeping(self):
        last_save = last_session = last_prune = time.time()
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(1)
            try:
                await loop.run_in_executor(None, self.store.flush)
                if self.catching_up and self.source.status.get("caught_up"):
                    self.finish_catchup()
                    await loop.run_in_executor(None, self.save)
                self.alerts.tick(self.state.now())
                if time.time() - last_session > 5:
                    last_session = time.time()
                    await loop.run_in_executor(None, self.save_session)
                if time.time() - last_save > 60:
                    last_save = time.time()
                    await loop.run_in_executor(None, self.save)
                if time.time() - last_prune > 3600:
                    last_prune = time.time()
                    await loop.run_in_executor(None, self.store.prune, self.state.now(),
                                               self.cfg["storage"]["retention_days"])
            except Exception:
                log.exception("housekeeping failed")

    async def start(self):
        self.tasks = [asyncio.create_task(self.run_source()), asyncio.create_task(self.housekeeping())]

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        self.save()
        self.store.close()

    # ---- queries ------------------------------------------------------------------
    async def q(self, sql, params=None):
        return await asyncio.get_running_loop().run_in_executor(None, self.store.query, sql, params)

    def span(self, window: str, frm: str = "", to: str = ""):
        """Time range for a query: a preset ("1h") or window="custom" with from/to."""
        if window == "custom" and frm:
            start = datetime.fromisoformat(frm.replace("Z", "+00:00"))
            end = datetime.fromisoformat(to.replace("Z", "+00:00")) if to else self.state.now()
            return start, end, max(1, int((end - start).total_seconds() // 60))
        mins = WINDOWS.get(window, 60)
        now = self.state.now()
        return now - timedelta(minutes=mins), now, mins

    async def cached(self, key, fn, ttl=3.0):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        val = await fn()
        self._cache[key] = (time.time(), val)
        return val

    def mask_raw(self, raw: str) -> str:
        if not self.mask:
            return raw
        return _MAC_RE.sub(lambda m: mask_mac(m.group(0)) if m.group(0).lower() in self.state.clients
                           else m.group(0), raw)


def create_app(cfg: dict) -> FastAPI:
    pipe = Pipeline(cfg)

    @asynccontextmanager
    async def lifespan(app):
        await pipe.start()
        yield
        await pipe.stop()

    app = FastAPI(title="V.Ships Vessel Network Monitor", lifespan=lifespan)
    app.state.pipe = pipe
    sev_err = "severity <= 4 AND NOT noise"

    # ---- status & alerts ------------------------------------------------------
    @app.get("/api/status")
    async def status(viewing: bool = False):
        if viewing:
            pipe.viewed()
        st = pipe.state
        now = st.now()
        counts = {"critical": 0, "warning": 0, "info": 0}
        for a in pipe.alerts.list(active_only=True):
            counts[a["severity"]] += 1
        return {"vessel": cfg["vessel"]["name"], "now": now.isoformat(),
                "mode": "live" if pipe.live else "replay", "source": pipe.source.status,
                "events_total": st.total, "events_per_sec": st.events_per_sec(),
                "last_event": st.clock.isoformat() if st.clock else None,
                "areas": pipe.alerts.area_status(), "alert_counts": counts,
                "mask_clients": pipe.mask,
                "catching_up": pipe.catching_up, "catchup_progress": pipe.catchup_progress(),
                "away_pending": bool(pipe.away),
                "notify_min": cfg["alerts"]["desktop_notify_min"],
                "learning": bool(st.first_clock and now - st.first_clock
                                 < timedelta(minutes=cfg["alerts"]["learning_minutes"]))}

    @app.get("/api/alerts")
    async def alerts(state: str = "active"):
        return pipe.alerts.list(active_only=(state == "active"))

    @app.post("/api/alerts/{aid}/ack")
    async def ack(aid: int):
        if not pipe.alerts.ack(aid):
            raise HTTPException(404)
        return {"ok": True}

    # ---- infrastructure view ----------------------------------------------------
    @app.get("/api/infra")
    async def infra(window: str = "1h", frm: str = Query("", alias="from"), to: str = ""):
        async def build():
            start, now, mins = pipe.span(window, frm, to)
            b = bucket_minutes(mins)
            p = [start, now]
            ts = await pipe.q(f"""
                SELECT time_bucket(INTERVAL '{b} minutes', ts) AS t, dev_class,
                       count(*) AS n, count(*) FILTER (WHERE {sev_err}) AS e
                FROM events WHERE ts > ? AND ts <= ? GROUP BY ALL ORDER BY t""", p)
            per_dev = await pipe.q(f"""
                SELECT device, count(*) AS n, count(*) FILTER (WHERE {sev_err}) AS e,
                       count(*) FILTER (WHERE severity <= 3 AND NOT noise) AS err,
                       count(DISTINCT client_mac) FILTER (WHERE kind = 'client_assoc') AS clients
                FROM events WHERE ts > ? AND ts <= ? GROUP BY device""", p)
            issues = await pipe.q(f"""
                SELECT template_id, dev_class, count(*) AS n, count(DISTINCT device) AS devices,
                       min(severity) AS sev, max(ts) AS last
                FROM events WHERE ts > ? AND ts <= ? AND {sev_err}
                GROUP BY ALL ORDER BY n DESC LIMIT 15""", p)
            links = await pipe.q("""
                SELECT device, port, count(*) FILTER (WHERE kind='link_down') AS downs,
                       count(*) FILTER (WHERE kind='link_up') AS ups, max(ts) AS last
                FROM events WHERE ts > ? AND ts <= ? AND kind IN ('link_down','link_up')
                GROUP BY ALL ORDER BY downs DESC""", p)
            srv = await pipe.q(f"""
                SELECT device, program, count(*) AS n, count(*) FILTER (WHERE {sev_err}) AS e
                FROM events WHERE ts > ? AND ts <= ? AND dev_class='server'
                GROUP BY ALL ORDER BY e DESC""", p)
            wifi_os = await pipe.q("""
                SELECT count(DISTINCT client_mac) AS n FROM events
                WHERE ts > ? AND ts <= ? AND dev_class='wifi' AND client_mac <> ''""", p)

            st = pipe.state
            stats = {r["device"]: r for r in per_dev}
            rank = {"critical": 0, "warning": 1, "info": 2}
            alerts_by_dev: dict[str, str] = {}
            for a in pipe.alerts.list(active_only=True):
                cur = alerts_by_dev.get(a["device"])
                if a["device"] and (cur is None or rank[a["severity"]] < rank[cur]):
                    alerts_by_dev[a["device"]] = a["severity"]
            now_ts = now.timestamp()
            devices = []
            for dv in st.devices.values():
                if dv.cls == "other":
                    continue
                s = stats.get(dv.id, {})
                quiet = (now - dv.last_seen).total_seconds() if dv.last_seen else None
                sev = alerts_by_dev.get(dv.id)
                status = {"critical": "critical", "warning": "warning"}.get(sev, "ok")
                devices.append({
                    "id": dv.id, "cls": dv.cls, "name": dv.name or dv.id, "location": dv.location,
                    "ip": dv.ip, "last_seen": dv.last_seen.isoformat() if dv.last_seen else None,
                    "quiet_s": quiet, "events": s.get("n", 0), "warnings": s.get("e", 0),
                    "errors": s.get("err", 0), "status": status,
                    "clients_now": sum(1 for t in dv.clients.values() if t > now_ts - 900),
                    "clients": s.get("clients", 0), "reboots": dv.reboots,
                    "uptime_h": round(dv.uptime / 3600, 1) if dv.uptime else None,
                    "mem_mb": round(dv.mem_avail_kb / 1024) if dv.mem_avail_kb else None,
                    "ports_down": [p_ for p_, v in dv.link_state.items() if v[0] == "down"],
                })
            devices.sort(key=lambda d: (d["cls"], d["location"] or "~", d["name"]))
            for i in issues:
                t = st.templates.get(i["template_id"], {})
                i["text"], i["program"] = t.get("text", "?"), t.get("program", "")
                i["sev_name"] = SEV_NAMES.get(i["sev"], "")
                i["template_id"] = str(i["template_id"])
            for l in links:
                dv = st.devices.get(l["device"])
                l["name"] = dv.name if dv else l["device"]
                l["state"] = (dv.link_state.get(l["port"], ["?"])[0]) if dv else "?"
            servers = {d.id: {"id": d.id, "programs": [], "events": 0, "warnings": 0}
                       for d in st.devices.values() if d.cls == "server"}
            for r in srv:
                d = servers.setdefault(r["device"], {"id": r["device"], "programs": [], "events": 0, "warnings": 0})
                d["events"] += r["n"]
                d["warnings"] += r["e"]
                d["programs"].append({"program": r["program"], "events": r["n"], "warnings": r["e"]})
            for d in servers.values():
                hw = st.hw_status.get(d["id"])
                d["hardware"] = hw
                dv = st.devices.get(d["id"])
                d["name"] = dv.name if dv else d["id"]
                d["last_seen"] = dv.last_seen.isoformat() if dv and dv.last_seen else None
                d["status"] = next((x["status"] for x in devices if x["id"] == d["id"]), "ok")
                d["programs"] = sorted(d["programs"], key=lambda x: (-x["warnings"], -x["events"]))[:6]
            return {"window": window, "bucket_min": b, "start": start.isoformat(), "end": now.isoformat(),
                    "timeseries": ts, "devices": devices,
                    "issues": issues, "links": links, "servers": list(servers.values()),
                    "wifi_clients": wifi_os[0]["n"] if wifi_os else 0}
        return await pipe.cached(("infra", window, frm, to), build)

    # ---- internet & security view -----------------------------------------------
    @app.get("/api/security")
    async def security(window: str = "1h", frm: str = Query("", alias="from"), to: str = ""):
        async def build():
            start, now, mins = pipe.span(window, frm, to)
            b = bucket_minutes(mins)
            p = [start, now]
            fw = "dev_class='firewall' AND ts > ? AND ts <= ?"
            ts = await pipe.q(f"""
                SELECT time_bucket(INTERVAL '{b} minutes', ts) AS t,
                       count(*) FILTER (WHERE fw_action='blocked') AS blocked,
                       count(*) FILTER (WHERE fw_action='allowed') AS allowed
                FROM events WHERE {fw} GROUP BY ALL ORDER BY t""", p)
            apps = await pipe.q(f"""
                SELECT fw_app AS app, any_value(fw_cat) AS cat,
                       count(*) FILTER (WHERE fw_action='blocked') AS blocked,
                       count(*) FILTER (WHERE fw_action='allowed') AS allowed
                FROM events WHERE {fw} AND fw_app <> ''
                GROUP BY fw_app ORDER BY blocked + allowed DESC LIMIT 12""", p)
            cats = await pipe.q(f"""
                SELECT fw_cat AS cat, count(*) FILTER (WHERE fw_action='blocked') AS blocked,
                       count(*) FILTER (WHERE fw_action='allowed') AS allowed
                FROM events WHERE {fw} AND kind IN ('app_block','app_seen','proxy_access')
                GROUP BY fw_cat ORDER BY blocked + allowed DESC LIMIT 10""", p)
            clients = await pipe.q(f"""
                SELECT coalesce(nullif(client_mac, ''), client_ip) AS c, any_value(client_mac) AS mac,
                       any_value(client_ip) AS ip, count(*) AS n,
                       count(*) FILTER (WHERE fw_action='blocked') AS blocked,
                       mode(fw_app) FILTER (WHERE fw_app <> '') AS top_app,
                       count(*) FILTER (WHERE kind='proxy_access') AS proxy
                FROM events WHERE {fw} AND client_ip <> '' GROUP BY 1 ORDER BY blocked DESC""", p)
            kinds = await pipe.q(f"""
                SELECT kind, count(*) AS n FROM events WHERE {fw} GROUP BY kind""", p)
            sec = await pipe.q(f"""
                SELECT ts, kind, template_id, client_mac, client_ip, dst_ip, dst_port, fw_action, raw
                FROM events WHERE {fw} AND kind IN {SECURITY_KINDS}
                  AND NOT (kind='ips' AND severity > 4)
                ORDER BY ts DESC LIMIT 150""", p)

            st = pipe.state
            k = {r["kind"]: r["n"] for r in kinds}
            total = sum(k.values())
            blocked = sum(r["blocked"] for r in ts)
            decks: dict[str, dict] = {}
            top_clients = []
            for r in clients:
                lab = st.client_label(r["mac"], r["ip"], pipe.mask)
                deck = lab.get("deck") or "Unknown / wired"
                d = decks.setdefault(deck, {"deck": deck, "clients": 0, "blocked": 0, "events": 0})
                d["clients"] += 1
                d["blocked"] += r["blocked"]
                d["events"] += r["n"]
                if len(top_clients) < 12:
                    top_clients.append({**lab, "events": r["n"], "blocked": r["blocked"],
                                        "top_app": r["top_app"] or "", "proxy": r["proxy"]})
            events = []
            for r in sec:
                lab = st.client_label(r["client_mac"], r["client_ip"], pipe.mask)
                t = st.templates.get(r["template_id"], {})
                remote = r["dst_ip"] + (f":{r['dst_port']}" if r["dst_port"] else "")
                events.append({"ts": r["ts"], "kind": r["kind"], "what": t.get("text", r["kind"]),
                               "client": lab["id"], "deck": lab.get("deck", ""),
                               "remote": remote, "action": r["fw_action"]})
            return {
                "window": window, "bucket_min": b, "timeseries": ts,
                "start": start.isoformat(), "end": now.isoformat(),
                "kpis": {"total": total, "blocked": blocked, "allowed": total - blocked,
                         "clients": len(clients),
                         "security": sum(k.get(x, 0) for x in SECURITY_KINDS if x != "web_denied"),
                         "proxy": k.get("proxy_access", 0)},
                "kinds": k, "apps": apps, "categories": cats, "clients": top_clients,
                "decks": sorted(decks.values(), key=lambda d: -d["blocked"]),
                "events": events,
            }
        return await pipe.cached(("sec", window, frm, to), build)

    # ---- one device -----------------------------------------------------------------
    @app.get("/api/device")
    async def device(id: str, window: str = "1h", frm: str = Query("", alias="from"), to: str = ""):
        st = pipe.state
        dv = st.devices.get(id)
        if not dv:
            raise HTTPException(404, "Unknown device")
        start, now, mins = pipe.span(window, frm, to)
        b = bucket_minutes(mins)
        p = [id, start, now]
        ts = await pipe.q(f"""
            SELECT time_bucket(INTERVAL '{b} minutes', ts) AS t, count(*) AS n,
                   count(*) FILTER (WHERE {sev_err}) AS e
            FROM events WHERE device = ? AND ts > ? AND ts <= ? GROUP BY ALL ORDER BY t""", p)
        tpls = await pipe.q("""
            SELECT template_id, count(*) AS n, min(severity) AS sev, bool_or(noise) AS noise
            FROM events WHERE device = ? AND ts > ? AND ts <= ?
            GROUP BY template_id ORDER BY n DESC LIMIT 15""", p)
        lines = await pipe.q("""
            SELECT ts, severity, program, kind, noise, raw FROM events
            WHERE device = ? AND ts > ? AND ts <= ? ORDER BY ts DESC LIMIT 100""", p)
        for t in tpls:
            info = st.templates.get(t["template_id"], {})
            t["text"], t["program"] = info.get("text", "?"), info.get("program", "")
            t["template_id"] = str(t["template_id"])
            t["sev_name"] = SEV_NAMES.get(t["sev"], "")
        for l in lines:
            l["raw"] = pipe.mask_raw(l["raw"])
            l["sev_name"] = SEV_NAMES.get(l["severity"], "")
        now_ts = now.timestamp()
        clients = []
        for mac, t in sorted(dv.clients.items(), key=lambda x: -x[1]):
            if t > now_ts - 900:
                info = st.clients.get(mac, {})
                clients.append({"id": mask_mac(mac) if pipe.mask else mac, "os": info.get("os", ""),
                                "last_seen": datetime.fromtimestamp(t, timezone.utc).isoformat()})
        return {"id": dv.id, "name": dv.name, "cls": dv.cls, "location": dv.location, "ip": dv.ip,
                "first_seen": dv.first_seen.isoformat() if dv.first_seen else None,
                "last_seen": dv.last_seen.isoformat() if dv.last_seen else None,
                "uptime_h": round(dv.uptime / 3600, 1) if dv.uptime else None, "reboots": dv.reboots,
                "hardware": st.hw_status.get(dv.id), "link_state": dv.link_state,
                "bucket_min": b, "start": start.isoformat(), "end": now.isoformat(),
                "timeseries": ts, "templates": tpls, "lines": lines,
                "clients": clients[:100],
                "alerts": [a for a in pipe.alerts.list(active_only=False, limit=1000)
                           if a["device"] == dv.id][:20]}

    # ---- event explorer ------------------------------------------------------------
    @app.get("/api/events")
    async def events(window: str = "1h", q: str = "", cls: str = "", device: str = "",
                     min_sev: int = Query(7, ge=0, le=7), hide_noise: bool = True,
                     limit: int = Query(300, le=2000), frm: str = Query("", alias="from"), to: str = ""):
        start, now, _ = pipe.span(window, frm, to)
        where, params = ["ts > ?", "ts <= ?"], [start, now]
        if q:
            where.append("raw ILIKE ?")
            params.append(f"%{q}%")
        if cls:
            where.append("dev_class = ?")
            params.append(cls)
        if device:
            where.append("(device = ? OR device_name ILIKE ?)")
            params += [device, f"%{device}%"]
        if min_sev < 7:
            where.append("severity <= ?")
            params.append(min_sev)
        if hide_noise:
            where.append("NOT noise")
        rows = await pipe.q(f"""
            SELECT ts, dev_class, device, device_name, severity, program, kind, noise, template_id, raw
            FROM events WHERE {' AND '.join(where)} ORDER BY ts DESC LIMIT {int(limit)}""", params)
        names = {d.id: d.name for d in pipe.state.devices.values()}
        for r in rows:
            r["raw"] = pipe.mask_raw(r["raw"])
            r["sev_name"] = SEV_NAMES.get(r["severity"], "")
            r["device_name"] = names.get(r["device"], r["device_name"])
            r["template_id"] = str(r["template_id"])
        return rows

    # ---- while you were away ------------------------------------------------------------
    @app.get("/api/away")
    async def away():
        a = pipe.away
        if not a:
            return {"pending": False}
        st = pipe.state
        frm = datetime.fromisoformat(a["from_data"])
        to = datetime.fromisoformat(a["to_data"]) if a.get("to_data") else (st.clock or frm)
        if to < frm:
            to = frm
        mins = max(1, int((to - frm).total_seconds() // 60))
        b = bucket_minutes(mins)
        p = [frm, to]
        by_cls = await pipe.q(f"""
            SELECT dev_class, count(*) AS n, count(*) FILTER (WHERE {sev_err}) AS e,
                   count(*) FILTER (WHERE severity <= 3 AND NOT noise) AS err
            FROM events WHERE ts > ? AND ts <= ? GROUP BY dev_class""", p)
        ts = await pipe.q(f"""
            SELECT time_bucket(INTERVAL '{b} minutes', ts) AS t, dev_class,
                   count(*) FILTER (WHERE {sev_err}) AS e
            FROM events WHERE ts > ? AND ts <= ? GROUP BY ALL ORDER BY t""", p)
        fw = await pipe.q("""
            SELECT count(*) FILTER (WHERE fw_action='blocked') AS blocked, count(*) AS n,
                   count(*) FILTER (WHERE kind IN ('port_scan','ip_spoof','flood')) AS attacks,
                   count(*) FILTER (WHERE kind='proxy_access') AS proxy
            FROM events WHERE dev_class='firewall' AND ts > ? AND ts <= ?""", p)
        apps = await pipe.q("""
            SELECT fw_app AS app, count(*) AS n FROM events
            WHERE dev_class='firewall' AND fw_action='blocked' AND fw_app <> '' AND ts > ? AND ts <= ?
            GROUP BY fw_app ORDER BY n DESC LIMIT 3""", p)

        def in_range(iso):
            return iso and frm <= datetime.fromisoformat(iso) <= to + timedelta(minutes=1)
        alerts = [x for x in pipe.alerts.list(active_only=False, limit=2000) if in_range(x["first_seen"])]
        alerts.sort(key=lambda x: ({"critical": 0, "warning": 1, "info": 2}[x["severity"]], x["first_seen"]))
        new_types = [{"text": t["text"], "cls": t["cls"], "severity": SEV_NAMES.get(t["severity"], ""),
                      "first_seen": t["first_seen"], "count": t["count"],
                      "device": (st.devices.get(t.get("device", "")).name
                                 if st.devices.get(t.get("device", "")) else "")}
                     for t in st.templates.values()
                     if t["severity"] <= 4 and not t.get("noise") and in_range(t["first_seen"])]
        new_types.sort(key=lambda t: t["first_seen"])
        rules = {}
        for x in alerts:
            rules[x["rule"]] = rules.get(x["rule"], 0) + 1
        return {"pending": True, "reason": a["reason"], "from": frm.isoformat(), "to": to.isoformat(),
                "minutes": mins, "bucket_min": b, "caught_up": a.get("caught_up", False),
                "progress": pipe.catchup_progress(), "note": a.get("note", ""),
                "closed_from": a.get("closed_from"), "closed_to": a.get("closed_to"),
                "mode": "live" if pipe.live else "replay", "source": pipe.kind,
                "by_class": by_cls, "timeseries": ts, "firewall": fw[0] if fw else {},
                "top_blocked": apps, "alerts": alerts[:200], "alert_rules": rules,
                "alerts_total": len(alerts),
                "still_active": sum(1 for x in alerts if x["active"]),
                "new_types": new_types[:30]}

    @app.post("/api/away/seen")
    async def away_seen():
        pipe.away_seen()
        return {"ok": True}

    # ---- noise management --------------------------------------------------------------
    @app.post("/api/templates/{tid}/noise")
    async def set_noise(tid: str, on: bool = True):
        t = int(tid)
        if on and t not in pipe.user_noise:
            pipe.user_noise.append(t)
        if not on and t in pipe.user_noise:
            pipe.user_noise.remove(t)
        if t in pipe.state.templates:
            pipe.state.templates[t]["noise"] = on

        def persist():
            pipe.store.save_kv("user_noise", pipe.user_noise)
            pipe.store.execute("UPDATE events SET noise = ? WHERE template_id = ?", [on, t])
        await asyncio.get_running_loop().run_in_executor(None, persist)
        pipe._cache.clear()
        return {"ok": True}

    @app.get("/api/settings")
    async def settings():
        safe = {k: v for k, v in cfg.items() if k != "graylog"}
        g = dict(cfg["graylog"])
        g["token"] = "set" if g.get("token") else "not set"
        return {**safe, "graylog": g, "user_noise": [str(x) for x in pipe.user_noise]}

    # ---- web page ---------------------------------------------------------------------------
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    return app
