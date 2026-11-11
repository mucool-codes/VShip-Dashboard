"""Regression tests for problems found in the end-to-end verification."""
from datetime import datetime, timedelta, timezone

from vship_monitor.alerts import AlertEngine
from vship_monitor.config import DEFAULTS
from vship_monitor.graylog import parse_ts
from vship_monitor.parser import parse
from vship_monitor.state import State, mask_ip

T = datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc)


# ---- Graylog timestamps: every form it can send, never "now" ----------------------------
def test_graylog_timestamps_in_any_time_zone():
    utc = datetime(2026, 5, 28, 6, 51, 15, 123000, tzinfo=timezone.utc)
    for s in ["2026-05-28T06:51:15.123Z", "2026-05-28T12:21:15.123+05:30", "2026-05-28T12:21:15.123+0530",
              "2026-05-28 06:51:15.123", "2026-05-28T01:51:15.123-05:00"]:
        assert parse_ts(s) == utc, s
    assert parse_ts("2026-05-28T06:51:15Z") == utc.replace(microsecond=0)
    assert parse_ts("2026-05-28T06:51:15.123456789Z") == utc.replace(microsecond=123456)
    assert parse_ts("garbage") is None and parse_ts("-") is None and parse_ts(None) is None


# ---- firewall: only real decisions are blocked/allowed ------------------------------------
def fw(msg, extra=""):
    return parse(T, "10.199.38.1", f'id=firewall sn=18C2412BF964 time="x" fw=10.10.10.10 pri=1 c=0 m=1 msg="{msg}" {extra}')


def test_firewall_decisions():
    assert fw("Application Control Prevention Alert: MULTIMEDIA TikTok -- HTTPS",
              'appcat="MULTIMEDIA TikTok -- HTTPS" fw_action="drop" src=10.199.42.5:1:X5 dst=1.2.3.4:443:X1').fw_action == "blocked"
    assert fw("Application Control Detection Alert: PROTOCOLS DNS -- query",
              'appcat="PROTOCOLS DNS -- query" fw_action="NA" src=10.199.42.5:1:X5 dst=1.2.3.4:53:X1').fw_action == "allowed"
    assert fw("Web site access denied", 'fw_action="drop" src=10.199.42.5:1:X5 dst=1.2.3.4:80:X1').fw_action == "blocked"
    for notice in ["Possible port scan detected", "IKEv2 VPN Policy not found", "DPI-SSL Connection",
                   "Possible TCP Flood on IF X2 - src"]:
        assert fw(notice, 'fw_action="NA" src=1.2.3.4:1:X1 dst=10.10.10.10:443:X1').fw_action == "", notice


# ---- SSH bad password = security alert -----------------------------------------------------
def test_ssh_bad_password_is_a_failed_login():
    ev = parse(T, "", "900 Deck7_Gym : Ap-Debug syslog[null] <WARNING> [AP DC:08:56:A6:85:00@10.199.38.116] "
                      "dropbear[32150]: [SSH] Bad password attempt for 'support' from 10.199.38.251:51234")
    assert ev.kind == "admin_login_failed" and ev.extra["user"] == "support" and ev.extra["from_ip"] == "10.199.38.251"


def engine():
    st = State(live=False)
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS["alerts"].items()}
    return st, AlertEngine(cfg, st, True)


def feed(st, al, ev):
    dv, new = st.ingest(ev)
    al.on_event(ev, dv, new)


def ap_kernel(t, uptime):
    return parse(t, "", f"257 Deck7_Outside_PS kernel: Ap-Debug syslog[null] <NOTICE> "
                        f"[AP DC:08:56:E3:BB:60@10.199.38.121] [{uptime}.123456] something")


# ---- late (out-of-order) messages must not look like a reboot ------------------------------
def test_late_message_is_not_a_reboot():
    st, al = engine()
    feed(st, al, ap_kernel(T, 50_000))
    feed(st, al, ap_kernel(T + timedelta(seconds=60), 50_060))
    feed(st, al, ap_kernel(T - timedelta(seconds=300), 49_700))      # arrives late: older
    assert not [a for a in al.alerts.values() if a["rule"] == "ap_reboot"]
    feed(st, al, ap_kernel(T + timedelta(seconds=120), 30))          # a real restart
    assert [a for a in al.alerts.values() if a["rule"] == "ap_reboot"]


def sw(t, state):
    return parse(t, "", f"LocalSwitch20 swlogd intfCmm Mgr EVENT: CUSTLOG CMM Link 1/1/6 operationally {state}")


def test_late_link_down_does_not_flip_the_port():
    st, al = engine()
    feed(st, al, sw(T, "down"))
    feed(st, al, sw(T + timedelta(seconds=30), "up"))
    feed(st, al, sw(T - timedelta(seconds=10), "down"))             # late copy of an older event
    assert st.devices["sw:LocalSwitch20"].link_state["1/1/6"][0] == "up"


# ---- one device = one identity -------------------------------------------------------------
def test_device_identity_merges_mac_and_ip_and_ignores_routers():
    st, _ = engine()
    st.ip_to_mac["10.199.42.7"] = "aa:bb:cc:dd:ee:01"
    assert st.client_key("", "10.199.42.7") == st.client_key("aa:bb:cc:dd:ee:01", "10.199.42.7")
    # unknown devices get distinct codes, not one shared "Unknown device"
    assert st.client_label("", "10.199.42.8", True)["id"] != st.client_label("", "10.199.42.9", True)["id"]
    assert st.client_label("", "10.199.42.8", True)["id"] == mask_ip("10.199.42.8")
    # a hardware address seen with many IPs is a router: never a crew device
    for i in range(30):
        ev = fw("Application Control Detection Alert: X Y -- z",
                f'appcat="X Y -- z" srcMac=bc:24:11:cc:7a:74 src=203.0.113.{i}:1:X1 dstMac=aa:bb:cc:dd:ee:02 dst=10.199.42.10:2:X5')
        st.ingest(ev)
    assert st.resolve_mac("bc:24:11:cc:7a:74", "10.10.10.1") == ""


def test_router_detection_survives_a_restart():
    st, _ = engine()
    for i in range(30):
        st.ingest(fw("Application Control Detection Alert: X Y -- z",
                     f'appcat="X Y -- z" srcMac=bc:24:11:cc:7a:74 src=203.0.113.{i}:1:X1 dstMac=aa:bb:cc:dd:ee:02 dst=10.199.42.10:2:X5'))
    st2 = State(live=False)
    st2.load(st.to_dict())
    assert st2.resolve_mac("bc:24:11:cc:7a:74", "10.10.10.1") == ""
