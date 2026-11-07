"""Settings, loaded from config.toml (see config.example.toml). Every value has a default."""
from __future__ import annotations

import copy
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

DEFAULTS = {
    "vessel": {"name": "Vessel"},
    "server": {"host": "127.0.0.1", "port": 8080},
    "storage": {"path": "data/vship.duckdb", "retention_days": 14},
    "source": {
        # "graylog" | "syslog" | "replay"
        "type": "replay",
    },
    "graylog": {
        "url": "http://graylog.local:9000",
        "token": "",
        "query": "*",
        "streams": [],
        "poll_seconds": 5,
        "lag_seconds": 5,          # Graylog indexes with a small delay
        "api": "scripting",        # "scripting" (Graylog 5+) or "export" (Graylog 4.x)
        "verify_tls": True,
        "backfill_minutes": 60,    # on first start, fetch this much history
        "max_catchup_hours": 168,  # after the app was closed, load at most this much missed data
    },
    "syslog": {"host": "0.0.0.0", "udp_port": 5514, "tcp_port": 5514},
    "replay": {"csv": "", "speed": 60.0, "loop": False},
    "privacy": {"mask_clients": True},
    "away": {"min_minutes": 10},
    # phone access through Tailscale (see PHONE_ACCESS.md)
    "phone": {"tailscale": True, "auto_serve": True},   # show "While you were away" after this long away
    "noise": {"patterns": []},
    "alerts": {
        "learning_minutes": 120,         # no "new message type" alerts before this
        "silent_minutes": {"wifi": 10, "server": 10, "firewall": 5, "switch": 30},
        "silent_min_rate_per_min": 0.5,  # only alert silence for devices that normally talk this much
        "spike_factor": 3.0,
        "spike_min_errors": 50,          # per 5 minutes
        "noisy_client_drops": 500,       # per 5 minutes
        "port_scan_threshold": 20,       # scan / spoof events per 10 minutes
        "link_flap_count": 3,            # downs per port in 15 minutes
        "link_down_minutes": 5,
        "radio_reset_count": 3,          # per AP in 15 minutes
        "low_mem_kb": 30000,
        "feed_stall_seconds": 120,
        "desktop_notify_min": "warning",  # critical | warning | info
    },
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: str | None) -> dict:
    data = {}
    if path and Path(path).exists():
        with open(path, "rb") as f:
            data = tomllib.load(f)
    return _merge(DEFAULTS, data)
