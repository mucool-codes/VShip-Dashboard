"""Parser tests built from real lines in the ship's Graylog export."""
from vship_monitor.noise import NoiseFilter
from vship_monitor.parser import parse
from vship_monitor.sources import parse_syslog_packet

TS = "2026-05-28T05:51:15.000Z"


def test_firewall_app_block():
    e = parse(TS, "10.199.38.1", 'id=firewall sn=18C2412BF964 time="2026-05-28 05:51:17 UTC" fw=10.10.10.10 pri=1 c=0 m=1155 msg="Application Control Prevention Alert: MULTIMEDIA YouTube -- HTTPS Activity 1" sid=10253 appcat="MULTIMEDIA YouTube -- HTTPS Activity 1" appid=1 catid=17 n=12501846 src=10.199.42.84:36870:X6-V42 dst=142.250.1.1:443:X2 srcMac=aa:bb:cc:dd:ee:ff dstMac=18:c2:41:2b:f9:68 proto=tcp/443 fw_action="drop"')
    assert (e.dev_class, e.kind, e.fw_action, e.fw_app, e.fw_cat) == ("firewall", "app_block", "blocked", "YouTube", "MULTIMEDIA")
    assert e.client_ip == "10.199.42.84" and e.client_mac == "aa:bb:cc:dd:ee:ff"


def test_firewall_port_scan_inbound():
    e = parse(TS, "", 'id=firewall sn=18C2412BF964 fw=10.10.10.10 pri=1 c=32 m=82 msg="Possible port scan detected" n=1 src=142.250.151.102:443:X2 dst=10.10.10.10:10667:X2 srcMac=bc:24:11:cc:7a:74 dstMac=18:c2:41:2b:f9:66 proto=tcp/https')
    assert e.kind == "port_scan" and e.severity == 4
    assert e.client_ip == "10.10.10.10" and e.dst_ip == "142.250.151.102"


def test_ap_named_line():
    e = parse(TS, "646", "646 Deck5_Lounge : System core-mon[12843] <NOTICE> [AP DC:08:56:A6:8D:C0@10.199.38.100] rtnetlink err cnt: 0")
    assert e.dev_class == "wifi" and e.device == "ap:DC:08:56:A6:8D:C0"
    assert e.device_name == "Deck5_Lounge" and e.location == "Deck5" and e.severity == 5
    assert NoiseFilter().is_noise(e.raw)
    e2 = parse(TS, "646", "646 Deck5_Lounge : System core-mon[12843] <NOTICE> [AP DC:08:56:A6:8D:C0@10.199.38.100] rtnetlink err cnt: 4")
    assert not NoiseFilter().is_noise(e2.raw)


def test_ap_wlan_level_overrides_err_tag():
    e = parse(TS, "kernel:", "kernel: Ap-Debug syslog[null] <ERR> [AP DC:08:56:E3:AB:E0@10.199.38.126] [268560.684735] wlan: [0:I:ANY] ieee80211_ucfg_getparam: Run-time average NF_dBr = -95")
    assert e.severity == 6 and e.extra["uptime"] == 268560


def test_ap_radio_reset_and_dns():
    e = parse(TS, "", "kernel: Ap-Debug syslog[null] <ERR> [AP DC:08:56:E3:AB:E0@10.199.38.126] [1.0] wlan: [0:E:ANY] [soc0] FWLOG: [123] WAL_DBGID_BB_WDOG_TRIGGERED ( 0x1, 0x2, 0x3, 0x4)")
    assert e.kind == "radio_reset"
    e = parse(TS, "", "123 Deck4_Corridor : System acv_client[1] <WARNING> [AP DC:08:56:A6:91:20@10.199.38.143] DNS servers are unreachable!")
    assert e.kind == "dns_unreachable"


def test_ap_multiline_memory():
    e = parse(TS, "", "743 Deck4_Corridor_3 : System syslog[null] <NOTICE> [AP DC:08:56:A6:A5:60@10.199.38.145]  MemTop: \nMemFree:   135824 kB\nMemAvailable:     163000 kB")
    assert e.dev_class == "wifi" and e.kind == "mem_stats" and e.extra["mem_avail_kb"] == 163000


def test_server_lines():
    e = parse(TS, "esx1.dmawson.local", "esx1.dmawson.local sut[2099301]: [ERROR] :: [risadapter.cpp:1406] :: REST call failed, wait 2 seconds before retrying 1 time")
    assert (e.dev_class, e.device, e.program, e.severity) == ("server", "srv:esx1", "sut", 3)
    e = parse(TS, "", "esx2.dmawson.local Hostd[2098480]: [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 1 : Hardware Sensor Status: Processor Green, Memory Green, Fan Red, Voltage Green")
    assert e.kind == "hw_sensors" and e.extra["bad_sensors"] == {"Fan": "Red"} and e.severity == 2


def test_switch_link_down():
    e = parse(TS, "stack2", "LocalSwitch28 swlogd intfCmm Mgr EVENT: CUSTLOG CMM Link 1/1/1 operationally down")
    assert (e.dev_class, e.device, e.kind, e.port) == ("switch", "sw:LocalSwitch28", "link_down", "1/1/1")


def test_unknown_line_is_kept():
    e = parse(TS, "mystery", "something completely different")
    assert e.dev_class == "other" and e.device == "other:mystery"


def test_syslog_rfc5424_rebuilds_graylog_style_message():
    ts, host, msg, pri = parse_syslog_packet("<166>1 2026-05-28T05:51:15.000Z esx1.dmawson.local sut 2099301 - - [INFO] :: hello")
    assert host == "esx1.dmawson.local" and msg == "esx1.dmawson.local sut[2099301]: [INFO] :: hello" and pri == 166
    e = parse(ts, host, msg, pri)
    assert e.dev_class == "server" and e.program == "sut"


def test_syslog_rfc3164():
    _, host, msg, _ = parse_syslog_packet("<30>May 28 05:51:15 stack1 swlogd intfCmm Mgr EVENT: CUSTLOG CMM Link 1/1/2 operationally up")
    e = parse(TS, host, msg)
    assert e.dev_class == "switch" and e.kind == "link_up"
