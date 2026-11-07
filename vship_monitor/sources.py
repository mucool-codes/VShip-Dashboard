"""Where log lines come from. Each source is an async generator of
(timestamp, source, message, syslog_pri) tuples.

* GraylogSource   - polls the ship's Graylog server over its REST API
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
class GraylogSource:
    """Poll Graylog for new messages.

    api="scripting": POST /api/search/messages (Graylog 5.0 and later)
    api="export":    POST /api/views/search/messages, CSV (Graylog 4.x)
    Authentication: an access token, sent as username=<token>, password="token".
    """

    def __init__(self, url, token, query="*", streams=None, poll_seconds=5, lag_seconds=5,
                 api="scripting", verify_tls=True, backfill_minutes=60, resume_from=None):
        self.url = url.rstrip("/")
        self.token, self.query, self.streams = token, query, list(streams or [])
        self.poll, self.lag, self.api = poll_seconds, lag_seconds, api
        self.verify = verify_tls
        start = resume_from or datetime.now(timezone.utc) - timedelta(minutes=backfill_minutes)
        self.cursor: datetime = start
        # After a restart, everything up to the last stored message is already saved.
        self.skip_until: datetime | None = resume_from
        self.overlap_counts: Counter = Counter()   # rows already delivered inside the overlap window
        self.status = {"type": "graylog", "url": self.url, "api": api, "state": "starting",
                       "last_poll": None, "last_error": None, "caught_up": False}

    def _fmt(self, t: datetime) -> str:
        return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    async def _fetch(self, client, frm, to, size):
        headers = {"X-Requested-By": "vship-monitor"}
        if self.api == "export":
            body = {"timerange": {"type": "absolute", "from": self._fmt(frm), "to": self._fmt(to)},
                    "query_string": {"type": "elasticsearch", "query_string": self.query},
                    "fields_in_order": ["timestamp", "source", "message"], "limit": size}
            if self.streams:
                body["streams"] = self.streams
            r = await client.post(f"{self.url}/api/views/search/messages", json=body,
                                  headers={**headers, "Accept": "text/csv"})
            r.raise_for_status()
            rows = list(csv.reader(io.StringIO(r.text)))
            return [(x[0], x[1], x[2]) for x in rows[1:] if len(x) >= 3]
        body = {"query": self.query, "fields": ["timestamp", "source", "message"],
                "timerange": {"type": "absolute", "from": self._fmt(frm), "to": self._fmt(to)},
                "size": size, "sort": "timestamp", "sort_order": "asc"}
        if self.streams:
            body["streams"] = self.streams
        r = await client.post(f"{self.url}/api/search/messages", json=body,
                              headers={**headers, "Accept": "application/json"})
        r.raise_for_status()
        data = r.json()
        names = [s.get("field") or s.get("name", "").replace("field: ", "") for s in data.get("schema", [])]
        idx = {n: i for i, n in enumerate(names)}
        out = []
        for row in data.get("datarows", []):
            out.append((row[idx.get("timestamp", 0)], row[idx.get("source", 1)], row[idx.get("message", 2)]))
        return out

    async def stream(self):
        import httpx  # imported here so replay/syslog modes don't need it
        size = 10_000
        async with httpx.AsyncClient(auth=(self.token, "token"), verify=self.verify,
                                     timeout=60) as client:
            while True:
                to = datetime.now(timezone.utc) - timedelta(seconds=self.lag)
                frm = self.cursor - timedelta(seconds=self.lag)   # overlap; duplicates are skipped
                try:
                    rows = await self._fetch(client, frm, to, size)
                    self.status.update(state="connected", last_poll=self._fmt(datetime.now(timezone.utc)),
                                       last_error=None, last_batch=len(rows))
                except Exception as e:  # keep running; show the problem in the UI
                    self.status.update(state="error", last_error=f"{type(e).__name__}: {e}"[:300])
                    log.warning("Graylog poll failed: %s", e)
                    await asyncio.sleep(max(self.poll, 10))
                    continue
                # Each poll re-reads the last few seconds (Graylog indexes with a
                # small delay). Rows in that overlap that were already delivered
                # are skipped by count, so genuinely repeated log lines survive.
                newest = self.cursor
                used: Counter = Counter()
                parsed = []
                for ts, src, msg in rows:
                    try:
                        t = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                    except ValueError:
                        t = datetime.now(timezone.utc)
                    h = hashlib.blake2b(f"{ts}|{src}|{msg}".encode(), digest_size=12).digest()
                    parsed.append((t, h))
                    used[h] += 1
                    if used[h] <= self.overlap_counts.get(h, 0):
                        continue
                    if self.skip_until and t <= self.skip_until:
                        continue
                    newest = max(newest, t)
                    yield t, src or "", msg or "", None
                # A full page means there is more waiting: go again straight away.
                full = len(rows) >= size and newest > self.cursor
                self.cursor = newest if full else max(self.cursor, min(to, newest) if rows else to)
                self.skip_until = None
                edge = self.cursor - timedelta(seconds=self.lag)
                self.overlap_counts = Counter(h for t, h in parsed if t >= edge)
                if not full:
                    self.status["caught_up"] = True     # everything up to "now" is loaded
                    await asyncio.sleep(self.poll)
