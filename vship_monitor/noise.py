"""Known-harmless chatter.

Noise events are still stored and searchable; they are only left out of error
rates, spike detection and "new message type" alerts. Users can add patterns in
config.toml under [noise] patterns = [...].
"""
import re

DEFAULT_NOISE = [
    # Wi-Fi APs
    r"iot_radio_manage running",
    r"can't open '/dev/ttyUSB",
    r"Run-time average NF",
    r"The trap is not exist or trapswitch is not open",
    r"err cnt: 0\b",
    r"func: Check",
    r"lldpd\] is alive|do_check_lldp",
    r"policy: the user dose not exist",
    r"wam_handle_sync: recvive message len",
    r"wam_iotEnforcement_get failed",
    r"channel bit enum \d+ is out of range",
    r"is not HAN AP bssid",
    r"WAL_DBGID_TX_AC_BUF",
    r"didn't find the sta .* in sync table",
    r"There is no hostname in this DHCP",
    r"requestURI is:\[generate_\d+\], drop the packet",
    r"get_chassis",
    r"Unable to find peer object",
    r"\] \[\d+\.\d+\]\s*$",          # empty kernel line from an AP
    r"ap_manage.*(strlen ifname|get_ap_bytes|config file donnot exist)|\[apmanage\]:The \w+ config file donnot exist",
    r"eag_time_gettimeofday get time litter",
    r"acv_clientd.*type = \d+,process_ret",
    r"is HAN AP bssid, fill in neighbor response",
    r"dcm_roming_rssi_threshold",
    # Servers
    r"iLO is in Production mode",
    r"Return value from validateOutput\(\) is 0",
    r"Unknown feature '.*'\. ASSUMING DISABLED",
    r"Glibc malloc guards disabled",
    # Switches
    r"process_remove:\d+ /flash/switch/dhcpBindV3\.db",
    r"\^\^ repeated \d+ times",
]


class NoiseFilter:
    def __init__(self, extra_patterns=()):
        pats = list(DEFAULT_NOISE) + list(extra_patterns)
        self._re = re.compile("|".join(f"(?:{p})" for p in pats))

    def is_noise(self, text: str) -> bool:
        # Checked against the raw line (not the template) because some rules
        # depend on a number, e.g. "err cnt: 0" is healthy, "err cnt: 5" is not.
        return bool(self._re.search(text))
