"""Turn one raw syslog line into a structured Event.

The ship's feed mixes five very different log formats. Each has its own parse
function; `parse()` tries them in order. Every regex is unanchored where it can
be, because the same device line looks slightly different depending on whether
it arrives via Graylog (header already stripped) or as a raw syslog packet.
"""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# --- severity -----------------------------------------------------------------
# Standard syslog numbering: lower = worse.
SEV_NAMES = {0: "emerg", 1: "alert", 2: "crit", 3: "error", 4: "warning",
             5: "notice", 6: "info", 7: "debug"}
_SEV_WORDS = {
    "EMERG": 0, "EMERGENCY": 0, "ALERT": 1, "CRIT": 2, "CRITICAL": 2,
    "ERR": 3, "ERROR": 3, "WARN": 4, "WARNING": 4, "NOTICE": 5, "EVENT": 5,
    "INFO": 6, "VERBOSE": 7, "DEBUG": 7,
}

DEV_CLASSES = ("wifi", "server", "firewall", "switch", "other")


@dataclass(slots=True)
class Event:
    ts: datetime
    dev_class: str                 # wifi | server | firewall | switch | other
    device: str                    # stable id, e.g. ap:DC:08:56:A6:8D:C0
    device_name: str = ""          # human name, e.g. Deck5_Lounge
    location: str = ""             # deck, e.g. Deck5
    ip: str = ""
    severity: int = 6
    program: str = ""
    kind: str = ""                 # semantic event type (link_down, app_block ...)
    template: str = ""             # message with variables masked
    template_id: int = 0
    noise: bool = False
    raw: str = ""
    # optional detail
    client_mac: str = ""
    client_ip: str = ""
    fw_action: str = ""            # blocked | allowed
    fw_app: str = ""
    fw_cat: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    port: str = ""                 # switch port
    extra: dict = field(default_factory=dict)


# --- helpers ------------------------------------------------------------------
_MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
_RE_MAC = re.compile(_MAC)
_RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_RE_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")
_RE_NUM = re.compile(r"\d+")
_RE_QUOTED = re.compile(r"'[^']*'")


def make_template(text: str) -> str:
    """Mask the variable parts so identical message *types* collapse together."""
    t = _RE_MAC.sub("<MAC>", text)
    t = _RE_IP.sub("<IP>", t)
    t = _RE_HEX.sub("<HEX>", t)
    t = _RE_NUM.sub("#", t)
    return t[:200]


def template_id(dev_class: str, program: str, template: str) -> int:
    return zlib.crc32(f"{dev_class}|{program}|{template}".encode())


def is_internal(ip: str) -> bool:
    if ip.startswith(("10.", "192.168.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def _deck(name: str) -> str:
    m = re.match(r"(Deck\s*\d+)", name, re.I)
    return m.group(1).replace(" ", "").capitalize() if m else ""


# --- firewall (SonicWall key=value) -------------------------------------------
_RE_KV = re.compile(r'(\w+)=("([^"]*)"|\S*)')


def _split_addr(v: str):
    # "10.199.16.217:53182:X4-V16"  ->  ip, port, interface
    parts = v.split(":")
    ip = parts[0] if parts else ""
    port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    iface = parts[2] if len(parts) > 2 else ""
    return ip, port, iface


def _parse_firewall(ts, raw):
    kv = {k: (q if q is not None and v.startswith('"') else v)
          for k, v, q in _RE_KV.findall(raw)}
    msg = kv.get("msg", "")
    sn = kv.get("sn", "firewall")
    ev = Event(ts=ts, dev_class="firewall", device=f"fw:{sn}",
               device_name=f"Firewall {sn[-4:]}", ip=kv.get("fw", ""),
               program="firewall", raw=raw)

    src_ip, src_port, _ = _split_addr(kv.get("src", ""))
    dst_ip, dst_port, _ = _split_addr(kv.get("dst", ""))
    if is_internal(src_ip) or not is_internal(dst_ip):
        ev.client_ip, ev.client_mac = src_ip, kv.get("srcMac", "")
        ev.dst_ip, ev.dst_port = dst_ip, dst_port
    else:  # inbound: the ship-side device is the destination
        ev.client_ip, ev.client_mac = dst_ip, kv.get("dstMac", "")
        ev.dst_ip, ev.dst_port = src_ip, src_port
    ev.extra = {"rule": kv.get("rule", ""), "proto": kv.get("proto", ""),
                "remote_ip": src_ip if ev.client_ip == dst_ip else dst_ip}

    action = kv.get("fw_action", "").lower()
    head = msg.split(":")[0].strip()
    if msg.startswith("Application Control"):
        appcat = kv.get("appcat", "") or msg.split(":", 1)[-1].strip()
        # "MULTIMEDIA TikTok -- HTTPS Activity 1"
        cat, _, rest = appcat.partition(" ")
        app = rest.split(" -- ")[0].strip() or appcat
        ev.fw_cat, ev.fw_app = cat, app
        ev.kind = "app_block" if "Prevention" in msg or action == "drop" else "app_seen"
        ev.severity = 6
        ev.template = f"{head}: {cat} {app}"
        if cat == "PROXY-ACCESS":
            ev.kind, ev.severity = "proxy_access", 4
    elif msg.startswith("IPS"):
        ev.kind, ev.severity = "ips", 5 if kv.get("ipspri", "3") == "3" else 4
        ev.fw_cat = kv.get("ipscat", "")
        ev.template = f"IPS: {ev.fw_cat}"
    elif "port scan" in msg.lower() or "FIN scan" in msg:
        ev.kind, ev.severity, ev.template = "port_scan", 4, head
    elif "Flood" in msg:
        ev.kind, ev.severity, ev.template = "flood", 3, "TCP flood detected"
    elif "spoof" in msg.lower():
        ev.kind, ev.severity, ev.template = "ip_spoof", 4, head
    elif msg.startswith("Web site access denied"):
        ev.kind, ev.severity, ev.template = "web_denied", 6, head
        ev.fw_app = kv.get("dstname", "")
    elif msg.startswith("IKE"):
        ev.kind, ev.severity, ev.template = "vpn_error", 4, make_template(msg)
    else:
        ev.kind, ev.severity, ev.template = "fw_other", 6, make_template(msg)
    ev.fw_action = "blocked" if action == "drop" or ev.kind == "app_block" else "allowed"
    ev.template_id = template_id("firewall", ev.kind, ev.template)
    return ev


# --- Wi-Fi access points --------------------------------------------------------
_RE_AP = re.compile(rf"\[AP ({_MAC})@([\d.]+)\]\s?(.*)$")
_RE_AP_NAME = re.compile(r"(?:^|\s)([A-Za-z][\w\-]*) : (System|User|Wireless|Security) (\S+?)(?:\[\d+\])? ")
_RE_AP_DEBUG = re.compile(r"Ap-Debug (\S+?)(?:\[\w+\])? ")
_RE_LVL = re.compile(r"<([A-Z]+)>")
_RE_UPTIME = re.compile(r"^\[\s*(\d+)\.\d+\]\s*")
_RE_WLAN_LVL = re.compile(r"wlan: \[\d+:([IWED]):")
_RE_PROG = re.compile(r"^([A-Za-z_][\w\-]*)(?:\[\d+\])?:")
_RE_CLIENT_DHCP = re.compile(rf"ip:\[([\d.]*)\], mac:\[({_MAC})\](?:, (?:host|hostname):\[([^\]]*)\])?(?:.*?os ?type:\[([^\]]*)\])?")
_RE_CLIENT_80211 = re.compile(rf"\[ath\d+\({_MAC}\)\] \[({_MAC})")


def _parse_ap(ts, raw, m):
    mac, ip, body = m.group(1).upper(), m.group(2), m.group(3)
    ev = Event(ts=ts, dev_class="wifi", device=f"ap:{mac}", ip=ip, raw=raw)
    nm = _RE_AP_NAME.search(raw[: m.start()] + " ")
    if nm:
        ev.device_name, ev.extra = nm.group(1), {"facility": nm.group(2)}
        ev.program = nm.group(3)
        ev.location = _deck(ev.device_name)
    else:
        dm = _RE_AP_DEBUG.search(raw)
        ev.program = dm.group(1) if dm else "ap"
    lvl = _RE_LVL.search(raw[: m.start()])
    ev.severity = _SEV_WORDS.get(lvl.group(1), 6) if lvl else 6

    # Kernel lines carry the AP's uptime in seconds -> lets us detect reboots.
    up = _RE_UPTIME.match(body)
    if up:
        ev.extra["uptime"] = int(up.group(1))
        body = body[up.end():]
    pm = _RE_PROG.match(body)
    if pm and ev.program in ("syslog", "ap", ""):
        ev.program = pm.group(1)
    # The wlan driver tags its own level ("[0:I:ANY]" = info) inside lines the
    # AP labels <ERR>; trust the driver's tag.
    wl = _RE_WLAN_LVL.search(body)
    if wl:
        ev.severity = {"I": 6, "W": 4, "E": 3, "D": 7}.get(wl.group(1), ev.severity)

    if "Login successfully" in body or "Login failed" in body or "login fail" in body.lower():
        ev.kind = "admin_login" if "successfully" in body else "admin_login_failed"
        ev.severity = 5 if ev.kind == "admin_login" else 4
        um = re.search(r"\[([^@\]]+)@(?:::ffff:)?([\d.]+)\]", body)
        if um:
            ev.extra.update(user=um.group(1), from_ip=um.group(2))
    elif "TID_DHCP_PROTOCOL" in body or "TID_HTTP_PROTOCOL" in body:
        cm = _RE_CLIENT_DHCP.search(body)
        if cm:
            ev.kind = "client_seen"
            ev.client_ip, ev.client_mac = cm.group(1), cm.group(2).lower()
            if cm.group(4):
                ev.extra["os"] = cm.group(4)
    elif "[ASSOC]" in body or "[AUTH]" in body:
        cm = _RE_CLIENT_80211.search(body)
        if cm:
            ev.kind, ev.client_mac = "client_assoc", cm.group(1).lower()
    elif "disassoc" in body:
        cm = _RE_CLIENT_80211.search(body)
        ev.kind = "client_disassoc"
        if cm:
            ev.client_mac = cm.group(1).lower()
    elif "channel utilization exceeded" in body:
        ev.kind, ev.severity = "chan_util_high", 4
    elif "neighbor ap wireless lost" in body:
        ev.kind = "neighbor_lost"
    elif "WDOG_TRIGGERED" in body or "WHAL_ERROR_RESET" in body:
        ev.kind, ev.severity = "radio_reset", 4
    elif "nf_conntrack: table full" in body:
        ev.kind, ev.severity = "conntrack_full", 4
    elif "NS servers are unreachable" in body:
        ev.kind, ev.severity = "dns_unreachable", 4
    elif "disallowed by DCM" in body:          # band steering, normal behaviour
        ev.kind, ev.severity = "band_steer", 6
    elif "SNR(" in body and "lower than" in body:
        ev.kind = "client_low_snr"
        cm = _RE_MAC.search(body)
        if cm:
            ev.client_mac = cm.group(0).lower()
    elif "MemAvailable:" in body:
        mm = re.search(r"MemAvailable:\s*(\d+)\s*kB", body)
        if mm:
            ev.kind, ev.extra["mem_avail_kb"] = "mem_stats", int(mm.group(1))

    ev.template = make_template(body) or "(empty message)"
    ev.template_id = template_id("wifi", ev.program, ev.template)
    return ev


# --- servers (ESXi / HPE iLO) ---------------------------------------------------
_RE_HOSTLINE = re.compile(r"^(?:\S+ )?(?P<host>[\w\-]+\.[\w\-.]+|esx[\w\-]*) (?P<prog>[A-Za-z][\w\-.]*)(?:\[\d+\])?: ?(?P<body>.*)$")
_RE_BRACKET_LVL = re.compile(r"\[(ERROR|WARNING|WARN|INFO|DEBUG|CRITICAL)\]")
_RE_WORD_LVL = re.compile(r"^(error|warning|info|verbose|crit|critical)\b", re.I)
_RE_SENSORS = re.compile(r"Hardware Sensor Status: (.*)")


def _parse_server(ts, raw, m):
    host = m.group("host")
    short = host.split(".")[0]
    prog, body = m.group("prog"), m.group("body")
    ev = Event(ts=ts, dev_class="server", device=f"srv:{short}", device_name=short,
               program=prog, raw=raw)
    sev = 6
    bm = _RE_BRACKET_LVL.search(body)
    if bm:
        sev = _SEV_WORDS[bm.group(1)]
    else:
        wm = _RE_WORD_LVL.match(body)
        if wm:
            sev = _SEV_WORDS.get(wm.group(1).upper(), 6)
        elif prog == "vmkernel" and "Failed" in body:
            sev = 4
    ev.severity = sev
    if prog == "sut":
        ev.extra["subsystem"] = "iLO"

    sm = _RE_SENSORS.search(body)
    if sm:
        ev.kind = "hw_sensors"
        bad = {}
        for part in sm.group(1).split(","):
            bits = part.strip().rsplit(" ", 1)
            if len(bits) == 2 and bits[1].rstrip(".") not in ("Green", "Ot...", "Unknown") \
                    and bits[1].rstrip(".") in ("Yellow", "Red", "Orange"):
                bad[bits[0]] = bits[1].rstrip(".")
        ev.extra["bad_sensors"] = bad
        ev.severity = 2 if "Red" in bad.values() else (4 if bad else 6)
    ev.template = make_template(body)
    ev.template_id = template_id("server", prog, ev.template)
    return ev


# --- switches (Alcatel-Lucent OmniSwitch style) ---------------------------------
_RE_SWLOG = re.compile(r"(?P<sw>[\w\-]+) swlogd (?P<body>.*)$")
_RE_SWLVL = re.compile(r"\b(INFO|EVENT|WARNING|WARN|ERROR|ERR|ALARM|CRIT|DEBUG\d?):")
_RE_LINK = re.compile(r"Link (\S+) operationally (up|down)", re.I)
_RE_SW_OTHER = re.compile(r"^(?:\S+ )?(?P<sw>stack\d+|LocalSwitch\d+|[\w\-]*[Ss]witch[\w\-]*) (?P<prog>[\w\-]+)(?:\[\d+\])? ?(?P<body>.*)$")


def _parse_switch(ts, sw, prog, body, raw):
    ev = Event(ts=ts, dev_class="switch", device=f"sw:{sw}", device_name=sw,
               program=prog, raw=raw)
    lm = _RE_SWLVL.search(body)
    ev.severity = _SEV_WORDS.get(lm.group(1).rstrip("0123456789"), 6) if lm else 6
    lk = _RE_LINK.search(body)
    if lk:
        ev.port, ev.kind = lk.group(1), f"link_{lk.group(2).lower()}"
        ev.severity = 4 if ev.kind == "link_down" else 5
    elif "^^ repeated" in body:
        ev.kind = "repeat"
    ev.template = make_template(body)
    ev.template_id = template_id("switch", prog, ev.template)
    return ev


# --- entry point --------------------------------------------------------------------
def parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return datetime.now(timezone.utc)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def parse(ts, source: str, message: str, pri: Optional[int] = None) -> Event:
    """Parse one log line. `source` is the sender (hostname/IP) if known."""
    raw = (message or "").strip()
    if "\n" in raw or "\r" in raw:  # some APs send multi-line messages
        raw = re.sub(r"\s*[\r\n]+\s*", " | ", raw)
    ts = parse_ts(ts)

    if "id=firewall" in raw[:40]:
        return _parse_firewall(ts, raw)

    m = _RE_AP.search(raw)
    if m:
        return _parse_ap(ts, raw, m)

    m = _RE_SWLOG.search(raw)
    if m:
        return _parse_switch(ts, m.group("sw"), "swlogd", m.group("body"), raw)
    m = _RE_SW_OTHER.match(raw)
    if m:
        return _parse_switch(ts, m.group("sw"), m.group("prog"), m.group("body"), raw)

    m = _RE_HOSTLINE.match(raw)
    if m:
        return _parse_server(ts, raw, m)

    # Unknown format: keep it, attributed to whoever sent it.
    src = (source or "unknown").strip(": ") or "unknown"
    ev = Event(ts=ts, dev_class="other", device=f"other:{src}", device_name=src,
               program="", raw=raw)
    ev.severity = pri & 7 if pri is not None else 6
    ev.template = make_template(raw)
    ev.template_id = template_id("other", "", ev.template)
    return ev
