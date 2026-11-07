"""Send lines from a Graylog CSV export to the monitor as live syslog (UDP).

Lets you test "syslog" mode on one laptop before connecting the ship:

    python -m vship_monitor --config config.toml          (with [source] type = "syslog")
    python tools/send_test_syslog.py export.csv --rate 50

Timestamps are replaced with "now", so the dashboard sees it as live traffic.
"""
import argparse
import csv
import socket
import time
from datetime import datetime, timezone


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--rate", type=float, default=50, help="messages per second")
    ap.add_argument("--limit", type=int, default=0, help="stop after N messages (0 = all)")
    a = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    with open(a.csv, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            msg = row["message"].replace("\n", " ")
            # RFC 5424 with no app-name: the message keeps the shape Graylog stored.
            pkt = f"<134>1 {ts} {row['source'].strip(': ') or '-'} - - - - {msg}"
            sock.sendto(pkt.encode("utf-8")[:65000], (a.host, a.port))
            sent += 1
            if a.limit and sent >= a.limit:
                break
            time.sleep(1 / a.rate)
    print(f"sent {sent} messages")


if __name__ == "__main__":
    main()
