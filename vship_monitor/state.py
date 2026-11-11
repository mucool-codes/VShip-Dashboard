"""In-memory picture of the vessel: devices, Wi-Fi clients and message types.

The database holds the full history; this module holds the "what is true right
now" view that alerting needs (last seen times, recent rates, baselines). It is
saved to the database every minute so a restart doesn't lose it.
"""
from __future__ import annotations

import hashlib
from collections import Counter, deque
from datetime import datetime, timezone

from .parser import Event

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def minute_of(ts: datetime) -> int:
    return int(ts.timestamp() // 60)


def mask_mac(mac: str) -> str:
    if not mac:
        return ""
    return "Device-" + hashlib.sha1(mac.lower().encode()).hexdigest()[:6].upper()


def mask_ip(ip: str) -> str:
    """A device we only know by IP address still gets its own code."""
    if not ip:
        return "Unknown device"
    return "Device-" + hashlib.sha1(("ip:" + ip).encode()).hexdigest()[:6].upper()


SHARED_MAC_IPS = 20    # a hardware address seen with more IPs than this is a router, not a device


class Device:
    __slots__ = ("id", "cls", "name", "location", "ip", "first_seen", "last_seen",
                 "total", "errors", "minutes", "uptime", "uptime_ts", "boot", "last_rx", "reboots", "mem_avail_kb",
                 "clients", "link_state", "recent_err")

    def __init__(self, id, cls):
        self.id, self.cls = id, cls
        self.name = self.location = self.ip = ""
        self.first_seen = self.last_seen = None
        self.total = self.errors = 0
        self.minutes: dict[int, list[int]] = {}   # minute -> [events, errors]
        self.uptime = None
        self.uptime_ts: float | None = None     # message time of the uptime sample
        self.boot: float | None = None          # estimated boot time (epoch)
        self.last_rx: float | None = None       # wall time the newest message from it arrived (live only)
        self.recent_err: deque = deque()        # times of warnings/errors in the last 10 min (exact counts)
        self.reboots = 0
        self.mem_avail_kb = None
        self.clients: dict[str, float] = {}        # client mac -> last seen (epoch s)
        self.link_state: dict[str, list] = {}      # switch port -> [state, since_iso, downs(list of epoch s)]

    # events per minute over the last hour (or since first seen)
    def rate(self, now_min: int) -> float:
        if not self.first_seen:
            return 0.0
        span = max(1, min(60, now_min - minute_of(self.first_seen) + 1))
        return sum(v[0] for m, v in self.minutes.items() if m > now_min - span) / span

    def regularity(self, end_min: int, span: int = 60) -> float:
        """Share of the `span` minutes before end_min in which the device sent anything.
        Steady talkers (APs, servers) score ~1; bursty ones (switches) score low."""
        if not self.first_seen:
            return 0.0
        span = max(1, min(span, end_min - minute_of(self.first_seen) + 1))
        return sum(1 for m in self.minutes if end_min - span < m <= end_min) / span

    def window(self, now_min: int, n: int, idx: int = 0) -> int:
        return sum(v[idx] for m, v in self.minutes.items() if now_min - n < m <= now_min)

    def to_dict(self):
        return {"id": self.id, "cls": self.cls, "name": self.name, "location": self.location,
                "ip": self.ip, "first_seen": self.first_seen.isoformat() if self.first_seen else None,
                "last_seen": self.last_seen.isoformat() if self.last_seen else None,
                "total": self.total, "errors": self.errors, "uptime": self.uptime,
                "uptime_ts": self.uptime_ts, "boot": self.boot, "last_rx": self.last_rx,
                "reboots": self.reboots, "mem_avail_kb": self.mem_avail_kb,
                "minutes": {str(k): v for k, v in self.minutes.items()},
                "clients": self.clients, "link_state": self.link_state}

    @classmethod
    def from_dict(cls, d):
        dv = cls(d["id"], d["cls"])
        for k in ("name", "location", "ip", "total", "errors", "uptime", "uptime_ts", "boot", "last_rx", "reboots",
                  "mem_avail_kb", "clients", "link_state"):
            if d.get(k) is not None:
                setattr(dv, k, d[k])
        dv.first_seen = datetime.fromisoformat(d["first_seen"]) if d.get("first_seen") else None
        dv.last_seen = datetime.fromisoformat(d["last_seen"]) if d.get("last_seen") else None
        dv.minutes = {int(k): v for k, v in (d.get("minutes") or {}).items()}
        return dv


class State:
    def __init__(self, live: bool):
        self.live = live
        self.catching_up = False
        self.horizon: datetime | None = None        # Graylog: data is complete up to here
        self.rx_grace = 0.0     # seconds: Graylog <6 delivers late messages once per check, allow for that
        self.rx_floor = 0.0     # wall time the feed last became healthy (start-up or after an outage)
        self.clock: datetime | None = None          # latest event time seen
        self.first_clock: datetime | None = None    # first event ever (learning period)
        self.last_rx_wall: datetime | None = None   # wall time of last event received
        self.devices: dict[str, Device] = {}
        self.clients: dict[str, dict] = {}          # wifi/firewall client mac -> info
        self.ip_to_mac: dict[str, str] = {}
        self.mac_ips: dict[str, set] = {}          # firewall: hardware address -> IPs seen with it
        self.templates: dict[int, dict] = {}
        self.fw_client_minutes: deque = deque()     # (minute, Counter(client -> blocked))
        self.fw_blocked: deque = deque()            # (time, client) of blocked connections, last 5 min
        self.sec_events: deque = deque()            # (epoch s, kind)
        self.proxy_events: deque = deque()          # (epoch s, client label, app)
        self.dns_fail: dict[str, float] = {}        # AP name -> last DNS failure (epoch s)
        self.radio_resets: dict[str, deque] = {}
        self.rate_window: deque = deque()           # wall epoch secs of recent events (for events/sec)
        self.hw_status: dict[str, dict] = {}        # server -> latest hardware sensor report
        self.total = 0

    # ---- time ----------------------------------------------------------------
    def now(self) -> datetime:
        # While loading missed data after a restart, "now" follows the data so
        # time-based rules (e.g. device silent) judge it as it happened.
        if self.live and not self.catching_up:
            wall = datetime.now(timezone.utc)
            # Graylog: only judge up to the time we *know* we have all data for.
            # If Graylog is unreachable, devices must not look "silent".
            return min(wall, self.horizon) if self.horizon else wall
        return self.clock or datetime.now(timezone.utc)

    # ---- ingest ---------------------------------------------------------------
    def ingest(self, ev: Event) -> tuple[Device, bool]:
        """Update state with one event. Returns (device, is_new_template)."""
        self.total += 1
        if self.clock is None or ev.ts > self.clock:
            self.clock = ev.ts
        if self.first_clock is None:
            self.first_clock = ev.ts
        wall = datetime.now(timezone.utc)
        self.last_rx_wall = wall
        self.rate_window.append(wall.timestamp())
        while self.rate_window and self.rate_window[0] < wall.timestamp() - 10:
            self.rate_window.popleft()

        dv = self.devices.get(ev.device)
        if dv is None:
            dv = self.devices[ev.device] = Device(ev.device, ev.dev_class)
            dv.first_seen = ev.ts
        if ev.device_name:
            dv.name = ev.device_name
        elif not dv.name:
            # APs that only send debug lines have no name; borrow it from the
            # device registry once a named line arrives.
            dv.name = ev.device.split(":", 1)[-1]
        if ev.location:
            dv.location = ev.location
        if ev.ip:
            dv.ip = ev.ip
        if dv.last_seen is None or ev.ts > dv.last_seen:
            dv.last_seen = ev.ts
        if self.live and not self.catching_up:
            dv.last_rx = wall.timestamp()
        if ev.ts < dv.first_seen:
            dv.first_seen = ev.ts
        dv.total += 1
        m = minute_of(ev.ts)
        slot = dv.minutes.get(m)
        if slot is None:
            slot = dv.minutes[m] = [0, 0]
            if len(dv.minutes) > 150:
                for k in sorted(dv.minutes)[:-130]:
                    del dv.minutes[k]
        slot[0] += 1
        if ev.severity <= 4 and not ev.noise:
            slot[1] += 1
            dv.errors += 1
            t = ev.ts.timestamp()
            dv.recent_err.append(t)
            while dv.recent_err and dv.recent_err[0] < t - 600:
                dv.recent_err.popleft()

        # Wi-Fi client tracking. Only association/auth lines tie a client to an
        # AP; DHCP lines are snooped broadcasts that every AP on the VLAN sees,
        # so they only give us the client's IP and OS.
        if ev.dev_class == "wifi" and ev.client_mac:
            c = self.clients.setdefault(ev.client_mac, {})
            if ev.kind == "client_disassoc":
                dv.clients.pop(ev.client_mac, None)
            elif ev.kind in ("client_assoc", "client_low_snr"):
                dv.clients[ev.client_mac] = ev.ts.timestamp()
                c.update(ap=ev.device, ap_name=dv.name, deck=dv.location)
            c["last_seen"] = ev.ts.isoformat()
            if ev.client_ip:
                c["ip"] = ev.client_ip
                self.ip_to_mac[ev.client_ip] = ev.client_mac
            if ev.extra.get("os"):
                c["os"] = ev.extra["os"]

        # Firewall: learn which addresses belong together
        if ev.dev_class == "firewall":
            for mac_, ip_ in ev.extra.get("pairs", ()):
                if mac_ and ip_:
                    ips = self.mac_ips.setdefault(mac_, set())
                    if len(ips) <= SHARED_MAC_IPS:
                        ips.add(ip_)

        # Firewall: per-client blocked counts for the "noisy client" rule
        if ev.dev_class == "firewall" and ev.fw_action == "blocked":
            key = self.client_key(ev.client_mac, ev.client_ip)
            if not self.fw_client_minutes or self.fw_client_minutes[-1][0] != m:
                self.fw_client_minutes.append((m, Counter()))
                while self.fw_client_minutes and self.fw_client_minutes[0][0] < m - 15:
                    self.fw_client_minutes.popleft()
            self.fw_client_minutes[-1][1][key] += 1
            t = ev.ts.timestamp()
            self.fw_blocked.append((t, key))
            while self.fw_blocked and self.fw_blocked[0][0] <= t - 300:
                self.fw_blocked.popleft()

        # Message types
        is_new = False
        t = self.templates.get(ev.template_id)
        if t is None:
            is_new = True
            t = self.templates[ev.template_id] = {
                "id": ev.template_id, "cls": ev.dev_class, "program": ev.program,
                "text": ev.template, "severity": ev.severity, "noise": ev.noise,
                "first_seen": ev.ts.isoformat(), "count": 0, "example": ev.raw[:400],
                "device": ev.device}
        t["count"] += 1
        t["last_seen"] = ev.ts.isoformat()
        if ev.severity < t["severity"]:
            t["severity"] = ev.severity
        return dv, is_new

    # ---- helpers for the API --------------------------------------------------
    def events_per_sec(self) -> float:
        wall = datetime.now(timezone.utc).timestamp()
        return round(sum(1 for t in self.rate_window if t > wall - 10) / 10, 1)

    def resolve_mac(self, mac: str, ip: str) -> str:
        """The crew device's hardware address, if we know it. A firewall line names a
        device by IP and usually MAC; Wi-Fi lines tell us which MAC has which IP. A
        MAC seen with many IPs is a router/gateway, not a device."""
        mac = (mac or "").lower()
        if mac and len(self.mac_ips.get(mac, ())) > SHARED_MAC_IPS:
            mac = ""
        return mac or self.ip_to_mac.get(ip, "").lower()

    def client_key(self, mac: str, ip: str) -> str:
        """One stable key per device, whether a line gives its MAC, its IP, or both."""
        m = self.resolve_mac(mac, ip)
        return m or (f"ip:{ip}" if ip else "")

    def client_label(self, mac: str, ip: str, mask: bool) -> dict:
        if mac.startswith("ip:"):                  # a client_key for a device known only by IP
            mac, ip = "", mac[3:]
        mac = self.resolve_mac(mac, ip)
        info = self.clients.get(mac, {})
        return {"id": mask_mac(mac) if mac else (mask_ip(ip) if mask else (ip or "Unknown device")),
                "mac": "" if mask else mac, "ip": "" if mask else (ip or info.get("ip", "")),
                "os": info.get("os", ""), "deck": info.get("deck", ""),
                "ap": info.get("ap_name", "")}

    # ---- persistence ------------------------------------------------------------
    def to_dict(self):
        return {"clock": self.clock.isoformat() if self.clock else None,
                "first_clock": self.first_clock.isoformat() if self.first_clock else None,
                "devices": [d.to_dict() for d in self.devices.values()],
                "clients": self.clients, "templates": list(self.templates.values()),
                "mac_ips": {m: sorted(ips) for m, ips in self.mac_ips.items()},
                "ip_to_mac": self.ip_to_mac,
                "hw_status": self.hw_status}

    def load(self, d):
        if not d:
            return
        self.clock = datetime.fromisoformat(d["clock"]) if d.get("clock") else None
        self.first_clock = datetime.fromisoformat(d["first_clock"]) if d.get("first_clock") else None
        self.devices = {x["id"]: Device.from_dict(x) for x in d.get("devices", [])}
        self.clients = d.get("clients", {})
        self.ip_to_mac = d.get("ip_to_mac") or {v["ip"]: k for k, v in self.clients.items() if v.get("ip")}
        self.mac_ips = {m: set(ips) for m, ips in (d.get("mac_ips") or {}).items()}
        self.templates = {int(t["id"]): t for t in d.get("templates", [])}
        self.hw_status = d.get("hw_status", {})
