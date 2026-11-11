"""Command line entry point.

    python -m vship_monitor                         # uses config.toml
    python -m vship_monitor --replay data.csv       # demo with a CSV export
    python -m vship_monitor --config other.toml
"""
import argparse
import json
import logging
import os
import socket
import sys
import threading
import urllib.request
import webbrowser
from pathlib import Path

import uvicorn

from . import config as config_mod
from .app import create_app


def main():
    ap = argparse.ArgumentParser(prog="vship_monitor", description="Vessel network log monitor")
    ap.add_argument("--config", default="config.toml", help="settings file (default: config.toml)")
    ap.add_argument("--replay", metavar="CSV", help="play a Graylog CSV export instead of the live feed")
    ap.add_argument("--speed", type=float, help="replay speed multiplier (0 = as fast as possible)")
    ap.add_argument("--loop", action="store_true", help="restart the replay when it reaches the end")
    ap.add_argument("--db", help="database file (overrides config)")
    ap.add_argument("--port", type=int, help="web port (default 8080)")
    ap.add_argument("--no-browser", action="store_true", help="don't open the browser")
    ap.add_argument("--fresh", action="store_true",
                    help="delete the stored data first (e.g. to restart a replay from the beginning)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)   # one line per Graylog request is just noise
    cfg = config_mod.load(args.config)
    if args.replay:
        cfg["source"]["type"] = "replay"
        cfg["replay"]["csv"] = args.replay
        # keep demo data out of the real database unless told otherwise
        if not args.db and cfg["storage"]["path"] == config_mod.DEFAULTS["storage"]["path"]:
            cfg["storage"]["path"] = "data/replay.duckdb"
    if args.speed is not None:
        cfg["replay"]["speed"] = args.speed
    if args.loop:
        cfg["replay"]["loop"] = True
    if args.db:
        cfg["storage"]["path"] = args.db
    if args.port:
        cfg["server"]["port"] = args.port

    host, port = cfg["server"]["host"], cfg["server"]["port"]
    url = f"http://{'localhost' if host in ('0.0.0.0', '127.0.0.1') else host}:{port}"

    # Already running (e.g. the window was left open and the .bat double-clicked
    # again)? Then just open the dashboard instead of starting a second copy.
    if already_running(port):
        print(f"\n  The monitor is already running - opening {url}\n")
        if not args.no_browser:
            webbrowser.open(url)
        return
    if port_busy(host, port):
        sys.exit(f"Port {port} is used by another program. Set a different [server] port in "
                 f"config.toml or pass --port.")

    if args.fresh:
        db = Path(cfg["storage"]["path"])
        for f in (db, db.with_name(db.name + ".wal")):
            if f.exists():
                f.unlink()
        print("  Stored data cleared.")

    app = create_app(cfg)
    print(f"\n  Vessel monitor running at {url}  (Ctrl+C to stop)\n")
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    if cfg["phone"].get("tailscale", True):
        # look for Tailscale in the background and print the phone address + QR code
        threading.Timer(2.0, app.state.phone.announce).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")


def already_running(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=2) as r:
            return "events_total" in json.loads(r.read().decode())
    except Exception:
        return False


def port_busy(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if os.name != "nt":   # match the web server; ignores ports still closing after a crash
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


if __name__ == "__main__":
    main()
