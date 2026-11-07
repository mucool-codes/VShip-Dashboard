"""Alert rules.

Two kinds of rule:
* event rules fire the moment a specific line arrives (hardware sensor not
  green, proxy bypass, AP reboot ...);
* periodic rules run every 15 seconds and look at recent behaviour (device gone
  silent, error spike, noisy client, flapping switch port ...).

An alert stays active while its rule keeps firing and resolves itself once the
rule has been quiet for the rule's `resolve_after` minutes.
"""
from __future__ import annotations

import re
import statistics
from collections import Counter, deque
from datetime import datetime, timedelta, timezone

from .parser import Event
from .state import Device, State, minute_of

SEV_RANK = {"critical": 0, "warning": 1, "info": 2}
AREA_OF = {"wifi": "wifi", "server": "server", "switch": "switch", "firewall": "firewall",
           "other": "other"}

# rule -> minutes of quiet before the alert resolves itself
RESOLVE_AFTER = {
    "hw_sensor": 30, "device_silent": 0, "error_spike": 15, "link_flap": 30,
    "link_down": 0, "ap_reboot": 60, "radio_reset": 30, "conntrack_full": 30,
    "dns_unreachable": 30, "low_memory": 30, "new_message_type": 120,
    "proxy_access": 60, "noisy_client": 15, "port_scan": 30, "flood": 30,
    "vpn_error": 30, "admin_login": 60, "admin_login_failed": 60, "feed_stalled": 0,
}


class AlertEngine:
    def __init__(self, cfg: dict, state: State, mask_clients: bool):
        self.cfg = cfg
        self.state = state
        self.mask = mask_clients
        self.alerts: dict[int, dict] = {}     # id -> alert
        self.active: dict[str, int] = {}      # key -> id of active alert
        self.next_id = 1
        self.last_tick: datetime | None = None
        self.enabled = True
        self.catchup = False                  # True while loading data missed while closed

    # ---- core ---------------------------------------------------------------
    def raise_(self, now: datetime, rule: str, key: str, severity: str, area: str,
               title: str, detail: str = "", device: str = "", device_name: str = ""):
        if not self.enabled:
            return
        aid = self.active.get(key)
        if aid is not None:
            a = self.alerts[aid]
            a["last_seen"] = now.isoformat()
            a["count"] += 1
            a["title"], a["detail"] = title, detail or a["detail"]
            if SEV_RANK[severity] < SEV_RANK[a["severity"]]:
                a["severity"], a["acked"] = severity, False
            return a
        a = {"id": self.next_id, "key": key, "rule": rule, "severity": severity,
             "area": area, "title": title, "detail": detail, "device": device,
             "device_name": device_name, "first_seen": now.isoformat(),
             "last_seen": now.isoformat(), "count": 1, "active": True,
             "acked": False, "resolved_at": None, "catchup": self.catchup}
        self.alerts[a["id"]] = a
        self.active[key] = a["id"]
        self.next_id += 1
        self._trim()
        return a

    def resolve(self, key: str, now: datetime):
        aid = self.active.pop(key, None)
        if aid is not None:
            self.alerts[aid]["active"] = False
            self.alerts[aid]["resolved_at"] = now.isoformat()

    def ack(self, aid: int) -> bool:
        a = self.alerts.get(aid)
        if a:
            a["acked"] = True
        return bool(a)

    def _trim(self, keep: int = 2000):
        if len(self.alerts) > keep:
            for aid in sorted(self.alerts)[: len(self.alerts) - keep]:
                if not self.alerts[aid]["active"]:
                    del self.alerts[aid]

    # ---- event rules --------------------------------------------------------
    def on_event(self, ev: Event, dv: Device, new_template: bool):
        # (raise_ is a no-op while alerts are disabled, but state such as
        # link status, uptime and sensor status is still tracked)
        c, now, k = self.cfg, ev.ts, ev.kind
        name = dv.name or ev.device

        if k == "hw_sensors":
            bad = ev.extra.get("bad_sensors") or {}
            self.state.hw_status[ev.device] = {"ts": now.isoformat(), "bad": bad}
            key = f"hw:{ev.device}"
            if bad:
                sev = "critical" if "Red" in bad.values() else "warning"
                self.raise_(now, "hw_sensor", key, sev, "server",
                            f"Hardware sensor not green on {name}",
                            ", ".join(f"{s}: {v}" for s, v in bad.items()), ev.device, name)
            else:
                self.resolve(key, now)

        elif k in ("link_down", "link_up") and ev.port:
            ls = dv.link_state.setdefault(ev.port, ["up", now.isoformat(), []])
            if k == "link_down":
                ls[0], ls[1] = "down", now.isoformat()
                ls[2].append(now.timestamp())
                ls[2][:] = [t for t in ls[2] if t > now.timestamp() - 3600]
            else:
                ls[0], ls[1] = "up", now.isoformat()
                self.resolve(f"linkdown:{ev.device}:{ev.port}", now)

        elif k == "admin_login":
            who = ev.extra.get("user", "?")
            src = ev.extra.get("from_ip", "?")
            self.raise_(now, "admin_login", f"login:{ev.device}:{who}:{src}", "info", "security",
                        f"Admin login to {name}", f"User {who} from {src} (web UI)", ev.device, name)
        elif k == "admin_login_failed":
            self.raise_(now, "admin_login_failed", f"loginfail:{ev.device}", "warning", "security",
                        f"Failed admin login on {name}", ev.raw[-160:], ev.device, name)

        elif k == "proxy_access":
            # One rolling alert for the whole ship; per-device detail is on the
            # Internet & Security page.
            who = self.state.client_label(ev.client_mac, ev.client_ip, self.mask)
            dq = self.state.proxy_events
            dq.append((now.timestamp(), who["id"], ev.fw_app))
            while dq and dq[0][0] < now.timestamp() - 3600:
                dq.popleft()
            devs = Counter(d for _, d, _ in dq)
            kinds = Counter(a for _, _, a in dq)
            self.raise_(now, "proxy_access", "proxy", "warning", "security",
                        f"VPN / proxy-bypass traffic from {len(devs)} device{'s' if len(devs) != 1 else ''} (last hour)",
                        ", ".join(f"{a}: {n}" for a, n in kinds.most_common(3))
                        + f". Most active: {devs.most_common(1)[0][0]}")
        elif k == "flood":
            msg = re.search(r'msg="([^"]+)"', ev.raw)
            text = msg.group(1) if msg else ev.template
            if "ceased" not in text:
                self.raise_(now, "flood", "flood", "critical", "security",
                            "Possible TCP flood against the firewall", text, ev.device, name)
        elif k == "vpn_error":
            self.raise_(now, "vpn_error", "vpn", "warning", "firewall",
                        "Site-to-site VPN (IKEv2) errors", ev.template, ev.device, name)
        elif k in ("port_scan", "ip_spoof") or (k == "ips" and ev.severity <= 4):
            self.state.sec_events.append((now.timestamp(), k))

        elif k == "radio_reset":
            dq = self.state.radio_resets.setdefault(ev.device, deque())
            dq.append(now.timestamp())
            while dq and dq[0] < now.timestamp() - 900:
                dq.popleft()
            if len(dq) >= c["radio_reset_count"]:
                self.raise_(now, "radio_reset", f"radio:{ev.device}", "warning", "wifi",
                            f"Wi-Fi radio resetting repeatedly on {name}",
                            f"{len(dq)} radio firmware resets in 15 min", ev.device, name)
        elif k == "conntrack_full":
            self.raise_(now, "conntrack_full", f"conntrack:{ev.device}", "warning", "wifi",
                        f"{name} is dropping packets (connection table full)", "", ev.device, name)
        elif k == "dns_unreachable":
            # Usually ship-wide (DNS server or uplink down), so one alert for all APs.
            seen = self.state.dns_fail
            seen[name] = now.timestamp()
            for n_ in [n_ for n_, t in seen.items() if t < now.timestamp() - 900]:
                del seen[n_]
            names = sorted(seen)
            self.raise_(now, "dns_unreachable", "dns", "warning" if len(names) < 5 else "critical",
                        "wifi", f"{len(names)} access point{'s' if len(names) != 1 else ''} cannot reach DNS",
                        ", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else "")
                        + ". Check the DNS server and ship uplink.")
        elif k == "mem_stats":
            kb = ev.extra.get("mem_avail_kb")
            dv.mem_avail_kb = kb
            if kb is not None and kb < c["low_mem_kb"]:
                self.raise_(now, "low_memory", f"mem:{ev.device}", "warning", "wifi",
                            f"Low memory on {name}", f"{kb // 1024} MB available", ev.device, name)

        # AP reboot: the kernel uptime counter went backwards
        up = ev.extra.get("uptime") if ev.dev_class == "wifi" else None
        if up is not None:
            if dv.uptime is not None and up + 60 < dv.uptime:
                dv.reboots += 1
                self.raise_(now, "ap_reboot", f"reboot:{ev.device}", "warning", "wifi",
                            f"{name} restarted", f"Uptime reset from {dv.uptime // 3600} h to {up // 60} min",
                            ev.device, name)
            dv.uptime = up

        # New kind of warning/error never seen before (after the learning period)
        if new_template and ev.severity <= 4 and not ev.noise and self.state.first_clock:
            learned = now - self.state.first_clock >= timedelta(minutes=c["learning_minutes"])
            if learned:
                self.raise_(now, "new_message_type", f"newtpl:{ev.template_id}", "info",
                            AREA_OF.get(ev.dev_class, "other"),
                            f"New {('error' if ev.severity <= 3 else 'warning')} type on {name}",
                            ev.template[:160], ev.device, name)

    # ---- periodic rules ------------------------------------------------------
    def tick(self, now: datetime):
        if not self.enabled:
            return
        if self.last_tick and now - self.last_tick < timedelta(seconds=15):
            return
        self.last_tick = now
        c, st = self.cfg, self.state
        now_min = minute_of(now)

        for dv in list(st.devices.values()):
            name = dv.name or dv.id
            # 1. device silent
            limit = c["silent_minutes"].get(dv.cls)
            key = f"silent:{dv.id}"
            if limit and dv.last_seen and dv.first_seen:
                quiet = (now - dv.last_seen).total_seconds() / 60
                known_for = (dv.last_seen - dv.first_seen).total_seconds() / 60
                end = minute_of(dv.last_seen)
                regular = (known_for >= 30 and dv.regularity(end) >= 0.8
                           and dv.rate(end) >= c["silent_min_rate_per_min"])
                if regular and quiet >= limit:
                    sev = "critical" if dv.cls in ("firewall", "server") else "warning"
                    self.raise_(now, "device_silent", key, sev, AREA_OF.get(dv.cls, "other"),
                                f"{name} has gone silent",
                                f"No messages for {int(quiet)} min (normally ~{dv.rate(minute_of(dv.last_seen)):.0f}/min)",
                                dv.id, name)
                elif key in self.active:
                    self.resolve(key, now)

            # 2. error spike vs this device's own normal level
            cur = dv.window(now_min, 5, 1)
            key = f"spike:{dv.id}"
            if cur >= c["spike_min_errors"]:
                past = [sum(dv.minutes.get(m, [0, 0])[1] for m in range(end - 5, end))
                        for end in range(now_min - 5, now_min - 120, -5)
                        if end - 5 >= minute_of(dv.first_seen)]
                if len(past) >= 6:
                    base = statistics.median(past)
                    if cur >= c["spike_factor"] * max(base, 1):
                        self.raise_(now, "error_spike", key, "warning", AREA_OF.get(dv.cls, "other"),
                                    f"Error spike on {name}",
                                    f"{cur} warnings/errors in 5 min (usual ~{base:.0f})", dv.id, name)

            # 3. switch ports: flapping or staying down
            for port, (state_, since, downs) in dv.link_state.items():
                recent = [t for t in downs if t > now.timestamp() - 900]
                if len(recent) >= c["link_flap_count"]:
                    self.raise_(now, "link_flap", f"flap:{dv.id}:{port}", "warning", "switch",
                                f"Port {port} on {name} is flapping",
                                f"Went down {len(recent)} times in 15 min", dv.id, name)
                key = f"linkdown:{dv.id}:{port}"
                if state_ == "down":
                    mins = (now - datetime.fromisoformat(since)).total_seconds() / 60
                    if mins >= c["link_down_minutes"]:
                        self.raise_(now, "link_down", key, "warning", "switch",
                                    f"Port {port} on {name} is down",
                                    f"Down for {int(mins)} min", dv.id, name)

        # 4. one client hammering the firewall
        totals = Counter()
        for m, cnt in st.fw_client_minutes:
            if m > now_min - 5:
                totals.update(cnt)
        for client, n in totals.most_common(5):
            if n >= c["noisy_client_drops"]:
                lab = st.client_label(client if ":" in client else "", client if ":" not in client else "", self.mask)
                self.raise_(now, "noisy_client", f"noisy:{client}", "info", "firewall",
                            f"{lab['id']} is generating heavy blocked traffic",
                            f"{n} blocked connections in 5 min"
                            + (f" - near {lab['ap']}" if lab.get("ap") else ""))

        # 5. scans / spoofing against the ship
        while st.sec_events and st.sec_events[0][0] < now.timestamp() - 600:
            st.sec_events.popleft()
        if len(st.sec_events) >= c["port_scan_threshold"]:
            kinds = Counter(k for _, k in st.sec_events)
            self.raise_(now, "port_scan", "scans", "warning", "security",
                        "Repeated scanning / spoofing detected by the firewall",
                        ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in kinds.most_common()) + " in 10 min")

        # 6. the feed itself
        if st.live and st.last_rx_wall:
            gap = (datetime.now(timezone.utc) - st.last_rx_wall).total_seconds()
            if gap >= c["feed_stall_seconds"]:
                self.raise_(now, "feed_stalled", "feed", "critical", "feed",
                            "No log data is arriving", f"Nothing received for {int(gap // 60)} min")
            else:
                self.resolve("feed", now)

        # 7. auto-resolve quiet alerts
        for key, aid in list(self.active.items()):
            a = self.alerts[aid]
            after = RESOLVE_AFTER.get(a["rule"], 30)
            if after and now - datetime.fromisoformat(a["last_seen"]) > timedelta(minutes=after):
                self.resolve(key, now)

    # ---- views --------------------------------------------------------------------
    def list(self, active_only=True, limit=300):
        rows = [a for a in self.alerts.values() if a["active"] or not active_only]
        rows.sort(key=lambda a: (not a["active"], SEV_RANK[a["severity"]], a["last_seen"]), reverse=False)
        if not active_only:
            rows.sort(key=lambda a: a["last_seen"], reverse=True)
        return rows[:limit]

    def area_status(self) -> dict:
        out = {k: "ok" for k in ("wifi", "server", "switch", "firewall", "security", "feed")}
        for aid in self.active.values():
            a = self.alerts[aid]
            area = a["area"] if a["area"] in out else None
            if area and a["severity"] != "info":
                cur = out[area]
                if cur == "ok" or SEV_RANK[a["severity"]] < SEV_RANK[cur]:
                    out[area] = a["severity"]
        return out

    def to_dict(self):
        return {"next_id": self.next_id,
                "alerts": [a for a in self.list(active_only=False, limit=1000)]}

    def load(self, d):
        if not d:
            return
        self.next_id = d.get("next_id", 1)
        for a in d.get("alerts", []):
            self.alerts[a["id"]] = a
            if a["active"]:
                self.active[a["key"]] = a["id"]
