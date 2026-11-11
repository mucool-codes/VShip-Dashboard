"""Where log lines come from. Each source is an async generator of
(timestamp, source, message, syslog_pri) tuples.

* (GraylogSource lives in graylog.py)
* SyslogSource    - listens for syslog forwarded straight to this laptop
* ReplaySource    - plays a Graylog CSV export back as if it were live
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

log = logging.getLogger("vship.sources")


# ---------------------------------------------------------------------------------
class ReplaySource:
    """Play a CSV export (timestamp, source, message) at `speed` x real time.
    speed=0 means as fast as possible."""

    def __init__(self, path: str, speed: float = 60.0, loop: bool = False,
                 resume_after: datetime | None = None, catchup_until: datetime | None = None):
        self.path, self.speed, self.loop = path, float(speed), loop
        self.resume_after = resume_after      # skip rows already stored last time
        self.catchup_until = catchup_until    # play rows up to here instantly (time the app was closed)
        self.status = {"type": "replay", "file": path, "speed": speed, "state": "starting",
                       "caught_up": not (resume_after and catchup_until),
                       "catchup_target": catchup_until.isoformat() if catchup_until else None}

    def _is_descending(self) -> bool:
        with open(self.path, newline="", encoding="utf-8", errors="replace") as f:
            r = csv.DictReader(f)
            first = [row.get("timestamp", "") for _, row in zip(range(200), r)]
        return len(first) > 1 and first[0] > first[-1]

    def _iter_rows(self):
        """Yield rows oldest-first. Exports sorted oldest-first are streamed
        without loading the whole file; newest-first exports are loaded and reversed."""
        if self._is_descending():
            with open(self.path, newline="", encoding="utf-8", errors="replace") as f:
                rows = list(csv.DictReader(f))
            rows.sort(key=lambda r: r.get("timestamp", ""))
            yield from rows
            return
        with open(self.path, newline="", encoding="utf-8", errors="replace") as f:
            yield from csv.DictReader(f)

    async def stream(self):
        loop = asyncio.get_running_loop()
        self.status["state"] = "playing"
        cycle, span = 0, timedelta(0)
        while True:
            offset = span * cycle      # shift timestamps forward so a loop looks continuous
            start_wall, start_ts, first_ts, ts = loop.time(), None, None, None
            for i, r in enumerate(self._iter_rows()):
                try:
                    ts = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00")) + offset
                except (KeyError, ValueError):
                    continue
                first_ts = first_ts or ts
                if self.resume_after and ts <= self.resume_after:
                    if i % 5000 == 0:
                        await asyncio.sleep(0)
                    continue
                if self.catchup_until:
                    if ts <= self.catchup_until:          # fast-forward
                        if i % 2000 == 0:
                            await asyncio.sleep(0)
                        self.status["position"] = i + 1
                        yield ts, r.get("source", ""), r.get("message", ""), None
                        continue
                    self.catchup_until = None
                    self.status["caught_up"] = True
                    start_wall, start_ts = loop.time(), None
                if self.speed > 0:
                    if start_ts is None:
                        start_ts, start_wall = ts, loop.time()
                    due = (ts - start_ts).total_seconds() / self.speed
                    wait = due - (loop.time() - start_wall)
                    if wait > 0.02:
                        await asyncio.sleep(wait)
                elif i % 2000 == 0:
                    await asyncio.sleep(0)
                self.status["position"] = i + 1
                yield ts, r.get("source", ""), r.get("message", ""), None
            self.resume_after = None
            if not self.loop or ts is None:
                self.status["state"] = "finished"
                self.status["caught_up"] = True
                return
            span = (ts - first_ts) + timedelta(seconds=1) if cycle == 0 else span
            cycle += 1


# ---------------------------------------------------------------------------------
_RE_5424 = re.compile(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|(?:\[.*?\])+) ?(.*)$", re.S)
_RE_3164 = re.compile(r"^<(\d{1,3})>(?:([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) )?(\S+) (.*)$", re.S)


def parse_syslog_packet(data: str):
    """Return (ts, host, message, pri) for an RFC 5424 or RFC 3164 packet."""
    data = data.strip("\x00\r\n ")
    now = datetime.now(timezone.utc)
    m = _RE_5424.match(data)
    if m:
        pri, ts, host, app, procid, _msgid, msg = m.groups()
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            t = now
        tag = app if procid in ("-", "") else f"{app}[{procid}]"
        if app in ("-", ""):
            return t, host, f"{host} {msg}", int(pri)
        return t, host, f"{host} {tag}: {msg}", int(pri)
    m = _RE_3164.match(data)
    if m:
        pri, _ts, host, rest = m.groups()
        # RFC 3164 timestamps have no year or zone, so use the arrival time.
        return now, host, f"{host} {rest}", int(pri)
    return now, "", data, None


class SyslogSource:
    """UDP + TCP syslog listener. Use a port above 1024 (default 5514) so it
    runs without admin rights; point the ship's syslog forwarder at it."""

    def __init__(self, host="0.0.0.0", udp_port=5514, tcp_port=5514):
        self.host, self.udp_port, self.tcp_port = host, udp_port, tcp_port
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=100_000)
        self.status = {"type": "syslog", "listen": f"{host} udp/{udp_port} tcp/{tcp_port}",
                       "state": "starting", "packets": 0}

    def _put(self, text: str, peer: str):
        self.status["packets"] += 1
        ts, host, msg, pri = parse_syslog_packet(text)
        try:
            self.queue.put_nowait((ts, host or peer, msg, pri))
        except asyncio.QueueFull:
            self.status["dropped"] = self.status.get("dropped", 0) + 1

    async def _start(self):
        loop = asyncio.get_running_loop()
        outer = self

        class UDP(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                outer._put(data.decode("utf-8", "replace"), addr[0])

        if self.udp_port:
            await loop.create_datagram_endpoint(UDP, local_addr=(self.host, self.udp_port))

        async def handle(reader: asyncio.StreamReader, writer):
            peer = (writer.get_extra_info("peername") or ("?",))[0]
            try:
                while True:
                    first = await reader.read(1)
                    if not first:
                        break
                    if first.isdigit():   # RFC 6587 octet counting: "123 <34>1 ..."
                        num = first + await reader.readuntil(b" ")
                        frame = await reader.readexactly(int(num.strip()))
                    else:                 # newline-delimited
                        frame = first + await reader.readuntil(b"\n")
                    self._put(frame.decode("utf-8", "replace"), peer)
            except (asyncio.IncompleteReadError, ConnectionError, ValueError):
                pass
            finally:
                writer.close()

        if self.tcp_port:
            await asyncio.start_server(handle, self.host, self.tcp_port)
        self.status["state"] = "listening"

    async def stream(self):
        await self._start()
        while True:
            yield await self.queue.get()


# ---------------------------------------------------------------------------------
