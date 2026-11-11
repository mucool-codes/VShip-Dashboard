"""Reading messages from Graylog - built so that nothing is missed or counted twice.

How it works (checked against Graylog's own source code, graylog2-server):

* Graylog 5.0+ ("scripting" API): POST /api/search/messages. Graylog 4.x:
  POST /api/views/search/messages (CSV export). Both take an absolute time
  range that includes its start and excludes its end, and return messages
  oldest-first. Authentication: the access token as user name, "token" as
  password.
* Every message has a unique Graylog id (`_id`). Messages are de-duplicated on
  that id, so re-reading a time window never counts a message twice. (If a
  Graylog version doesn't return ids, a content key is used instead.)
* Each poll re-reads the last `rescan_seconds` too, which picks up messages
  Graylog indexed a little late.
* Every `verify_seconds` the app asks Graylog how many messages it has per
  minute for the last `verify_minutes` and compares that with what it stored.
  Any minute that doesn't match is fetched again and the missing messages are
  added. This catches messages Graylog indexed very late, and it is how the
  app *knows* its data is complete. The result is shown in the status bar.
* If Graylog records the time it *received* each message
  (`gl2_receive_timestamp`, Graylog 5+), the app reads by that time. Then a
  device whose own clock is wrong cannot slip through the gaps.
* A time window is never paged with offsets (Graylog's sort order among
  messages with the same timestamp isn't stable between requests). If a window
  has more than one page of messages it is split at a timestamp instead.
* Timestamps come back in the Graylog user's own time zone (e.g. +05:30); they
  are converted to UTC. A timestamp that can't be read is never replaced by
  "now" silently: it is counted and reported.
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
from typing import Awaitable, Callable

log = logging.getLogger("vship.graylog")

MAX_WINDOW = 10_000          # OpenSearch's default max_result_window: one request can return at most this many
RECV = "gl2_receive_timestamp"

_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?$")


def parse_ts(value) -> datetime | None:
    """Read a Graylog timestamp in any of the forms it uses; None if unreadable.
    No time zone given = UTC (that's what Graylog stores)."""
    if value is None:
        return None
    if isinstance(value, (int, float)):           # epoch millis
        return datetime.fromtimestamp(value / 1000, timezone.utc)
    m = _TS.match(str(value).strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    us = int((frac or "0").ljust(6, "0")[:6])
    try:
        t = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), us, tzinfo=timezone.utc)
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        t -= sign * timedelta(hours=hh, minutes=mm)
    return t


def fmt(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def es_time(t: datetime) -> str:
    """Graylog's date format for range queries on date fields (UTC)."""
    return t.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def content_key(ts: str, src: str, msg: str) -> str:
    return hashlib.blake2b(f"{ts}|{src}|{msg}".encode(), digest_size=10).hexdigest()


class Row:
    __slots__ = ("key", "ts", "recv", "src", "msg", "t")

    def __init__(self, key, ts, recv, src, msg, t):
        self.key, self.ts, self.recv, self.src, self.msg, self.t = key, ts, recv, src, msg, t


class GraylogSource:
    """Poll Graylog; yields (ts, source, message, pri, gid, recv)."""

    def __init__(self, url, token, query="*", streams=None, poll_seconds=5, lag_seconds=5,
                 api="scripting", verify_tls=True, backfill_minutes=60, resume_from=None,
                 rescan_seconds=15, verify_seconds=60, verify_minutes=120, timeout=60,
                 export_verify_seconds=300, settle_minutes=10,
                 local_counts: Callable[[str, datetime, datetime], Awaitable[dict]] | None = None,
                 known_keys: Callable[[str, datetime, datetime], Awaitable[set]] | None = None):
        self.url = url.rstrip("/")
        self.token, self.query = token, (query or "*").strip() or "*"
        self.streams = list(streams or [])
        self.poll, self.lag, self.api = float(poll_seconds), float(lag_seconds), api
        self.verify_tls, self.timeout = verify_tls, timeout
        self.rescan = timedelta(seconds=rescan_seconds)
        self.verify_every, self.verify_span = verify_seconds, timedelta(minutes=verify_minutes)
        self.settle = timedelta(minutes=settle_minutes)
        if api == "export":     # Graylog 4.x: counting means listing timestamps - do it less often
            self.verify_every = export_verify_seconds
            self.verify_span = timedelta(minutes=min(verify_minutes, 60))
        self.local_counts, self.known_keys = local_counts, known_keys
        now = datetime.now(timezone.utc)
        self.resumed = resume_from is not None
        self.cursor: datetime = min(resume_from or now - timedelta(minutes=backfill_minutes), now)
        self.start = self.cursor
        self.field = "timestamp"          # time field we page on; becomes RECV if Graylog has it
        self.ids = True                   # Graylog returns message ids
        self.seen: dict[str, datetime] = {}
        self.progress = self.cursor
        self.resume_recv: datetime | None = None   # set by the app: latest stored receive time
        # Oldest data in the local database (set by the app). Verification after a
        # restart reaches back to here, so messages Graylog indexed late - while
        # the app was closed - are still found.
        self.floor_ts: datetime | None = None
        self.future: list | None = None   # Graylog <6: latest look at future-stamped messages (seconds ahead, source, message)
        self._prev_hi: datetime | None = None    # end of the previous normal read
        self._prev_fhi: datetime | None = None   # end of the previous "future" read
        self.floor_recv: datetime | None = None
        self.status = {"type": "graylog", "url": self.url, "api": api, "state": "starting",
                       "last_poll": None, "last_error": None, "caught_up": False,
                       "horizon": None, "time_field": None, "ids": None,
                       "verified_until": None, "verified_from": None, "last_verify": None,
                       "verify_ok": None, "recovered": 0, "mismatch_minutes": [],
                       "bad_timestamps": 0, "over_limit": 0, "requests": 0}

    # ------------------------------------------------------------------ http
    def _q(self, extra: str = "") -> str:
        base = self.query if self.query != "*" else ""
        parts = [f"({base})" if base else "", extra]
        q = " AND ".join(p for p in parts if p)
        return q or "*"

    def _range_q(self, lo: datetime, hi: datetime) -> tuple[dict, str]:
        """Time range + query for messages with time-field in [lo, hi)."""
        if self.field == "timestamp":
            return {"type": "absolute", "from": fmt(lo), "to": fmt(hi)}, self._q()
        # Receive-time mode: Graylog picks indices by message timestamp, so give a
        # generous timestamp range and filter on the receive time in the query.
        tr = {"type": "absolute", "from": fmt(lo - timedelta(days=2)), "to": fmt(hi + timedelta(days=2))}
        return tr, self._q(f'{RECV}:["{es_time(lo)}" TO "{es_time(hi)}"}}')

    async def _post(self, client, path, body, accept):
        self.status["requests"] += 1
        r = await client.post(f"{self.url}{path}", json=body,
                              headers={"X-Requested-By": "vship-monitor", "Accept": accept})
        if r.status_code >= 400:
            text = r.text[:300].replace("\n", " ")
            raise RuntimeError(f"HTTP {r.status_code} from Graylog {path}: {text}")
        return r

    async def _fetch(self, client, lo, hi, size, fields=None, newest_first=False) -> list[Row]:
        """Messages with time-field in [lo, hi), oldest first, at most `size`."""
        tr, q = self._range_q(lo, hi)
        want = fields or (["_id", "timestamp", "source", "message"] + ([RECV] if self.field == RECV else []))
        if self.api == "export":
            body = {"timerange": tr, "query_string": {"type": "elasticsearch", "query_string": q},
                    "fields_in_order": want, "limit": size, "chunk_size": min(size, 1000)}
            if self.streams:
                body["streams"] = self.streams
            r = await self._post(client, "/api/views/search/messages", body, "text/csv")
            rows = list(csv.reader(io.StringIO(r.text)))
            if not rows:
                return []
            head, data = rows[0], rows[1:]
            idx = {n: i for i, n in enumerate(head)}
            get = lambda row, f: row[idx[f]] if f in idx and idx[f] < len(row) else None   # noqa: E731
        else:
            body = {"query": q, "fields": want, "timerange": tr, "size": size,
                    "sort": self.field, "sort_order": "Descending" if newest_first else "Ascending"}
            if self.streams:
                body["streams"] = self.streams
            r = await self._post(client, "/api/search/messages", body, "application/json")
            js = r.json()
            names = [s.get("field") or str(s.get("name", "")).replace("field: ", "") for s in js.get("schema", [])]
            idx = {n: i for i, n in enumerate(names)}
            data = js.get("datarows", [])
            get = lambda row, f: row[idx[f]] if f in idx and idx[f] < len(row) else None   # noqa: E731
        out, occ = [], Counter()
        for row in data:
            ts_raw = get(row, "timestamp")
            src = get(row, "source")
            msg = get(row, "message")
            src = "" if src in (None, "-") else str(src)
            msg = "" if msg is None else str(msg)
            gid = get(row, "_id")
            recv = parse_ts(get(row, RECV)) if self.field == RECV else None
            ts = parse_ts(ts_raw)
            if ts is None:
                self.status["bad_timestamps"] += 1
                log.warning("Unreadable Graylog timestamp %r", ts_raw)
            if gid in (None, "", "-"):
                if "_id" in want:
                    self.ids = False
                ck = content_key(str(ts_raw), src, msg)
                occ[ck] += 1
                gid = f"c:{ck}:{occ[ck]}"
            t = (recv if self.field == RECV else ts) or ts or recv
            out.append(Row(str(gid), ts, recv, src, msg, t))
        return out

    async def _counts(self, client, lo, hi) -> dict[datetime, int] | None:
        """Graylog's own message count per minute in [lo, hi)."""
        if self.api == "export":
            # Graylog 4.x has no count API here: list just the timestamps (small)
            # and count them. Same splitting rule as for messages.
            out: dict[datetime, int] = {}
            cur = lo
            while cur < hi:
                rows = await self._fetch(client, cur, hi, MAX_WINDOW, fields=["timestamp"])
                full = len(rows) >= MAX_WINDOW
                last = rows[-1].t if rows else None
                for r in rows:
                    if r.t is None or (full and last is not None and last > cur and r.t >= last):
                        continue
                    m = r.t.replace(second=0, microsecond=0)
                    out[m] = out.get(m, 0) + 1
                if not full:
                    break
                cur = last if last and last > cur else cur + timedelta(milliseconds=1)
            return out
        tr, q = self._range_q(lo, hi)
        body = {"query": q, "timerange": tr,
                "group_by": [{"field": self.field, "timeunit": "1m"}],
                "metrics": [{"function": "count"}]}
        if self.streams:
            body["streams"] = self.streams
        r = await self._post(client, "/api/search/aggregate", body, "application/json")
        js = r.json()
        out = {}
        for row in js.get("datarows", []):
            t = parse_ts(row[0])
            if t is None:
                continue
            t = t.replace(second=0, microsecond=0)
            try:
                out[t] = out.get(t, 0) + int(float(row[-1]))
            except (TypeError, ValueError):
                continue
        return out

    # ------------------------------------------------------------------ setup
    async def _detect(self, client):
        """Does this Graylog return message ids and receive times? Looks at a few
        recent messages."""
        now = datetime.now(timezone.utc)
        tr = {"type": "absolute", "from": fmt(now - timedelta(hours=2)), "to": fmt(now)}
        if self.api == "export":
            body = {"timerange": tr, "query_string": {"type": "elasticsearch", "query_string": self._q()},
                    "fields_in_order": ["timestamp", "_id"], "limit": 20}
            if self.streams:
                body["streams"] = self.streams
            rows = list(csv.reader(io.StringIO((await self._post(
                client, "/api/views/search/messages", body, "text/csv")).text)))[1:]
            ids = [r[1] if len(r) > 1 else "" for r in rows]
        else:
            body = {"query": self._q(), "fields": ["_id", RECV], "timerange": tr, "size": 20,
                    "sort": "timestamp", "sort_order": "Descending"}
            if self.streams:
                body["streams"] = self.streams
            js = (await self._post(client, "/api/search/messages", body, "application/json")).json()
            names = [x.get("field") for x in js.get("schema", [])]
            rows = js.get("datarows", [])
            ids = [r[names.index("_id")] if "_id" in names else "" for r in rows]
            if rows and RECV in names and all(parse_ts(r[names.index(RECV)]) is not None for r in rows):
                self.field = RECV
        self.ids = all(i not in (None, "", "-") for i in ids) if ids else True
        if self.field == RECV and self.resumed:
            # Carry on from the last stored *receive* time (older databases have none:
            # then the message time is the best we have).
            self.cursor = self.resume_recv or self.cursor
        if self.resumed:
            floor = self.floor_recv if self.field == RECV else self.floor_ts
            self.start = min(self.cursor, floor) if floor else self.cursor
        self.status["time_field"] = "received" if self.field == RECV else "timestamp"
        self.status["ids"] = "graylog" if self.ids else "content"
        log.info("Graylog: paging on %s, message ids: %s", self.field, self.status["ids"])

    # ------------------------------------------------------------------ main loop
    async def _read_range(self, client, lo, hi):
        """All messages in [lo, hi) not yet delivered, splitting the range when a
        page is full. Yields rows; returns when the whole range is done."""
        while lo < hi:
            self.progress = lo
            rows = await self._fetch(client, lo, hi, MAX_WINDOW)
            if len(rows) < MAX_WINDOW:
                for r in rows:
                    yield r
                return
            # Full page: everything before the last row's time is complete.
            last = rows[-1].t
            if last is None or last <= lo:
                # >10,000 messages share one timestamp: Graylog can't page past
                # that. Take what we have and report it (verification shows it).
                self.status["over_limit"] += 1
                log.warning("More than %s messages at %s - Graylog can't return them all", MAX_WINDOW, lo)
                for r in rows:
                    yield r
                lo = lo + timedelta(milliseconds=1)
                continue
            for r in rows:
                if r.t is not None and r.t < last:
                    yield r
            lo = last

    def _new(self, r: Row) -> bool:
        if r.key in self.seen:
            return False
        self.seen[r.key] = r.t or datetime.now(timezone.utc)
        return True

    def _prune(self, upto: datetime):
        """Forget ids older than anything a later read can return again."""
        edge = min(upto, datetime.now(timezone.utc)) - self.rescan - timedelta(seconds=30)
        self.seen = {k: t for k, t in self.seen.items() if t >= edge}

    def _out(self, r: Row, arrived: datetime | None = None):
        ts = r.ts
        if ts is None:                      # unreadable timestamp: use the receive time if we have it
            ts = r.recv or r.t
        # (A device whose clock is wrong is handled by the app, which knows the device's name.)
        # `arrived`: when the message reached Graylog, if we know it to within a poll
        # (it appeared since our previous read of its time range); else None.
        return ts, r.src, r.msg, None, r.key, r.recv, arrived

    async def _probe_future(self, client):
        """Graylog before 6.0: are there messages stamped in the future? Only a device
        whose clock is ahead produces those (they are read when that time comes, so
        that device shows up late on the dashboard). Reported, never altered."""
        if self.field != "timestamp":
            return
        now = datetime.now(timezone.utc)
        # newest first, so the offset is measured from the device's latest message
        # (the export API can only sort oldest first: take everything and keep the newest)
        rows = await self._fetch(client, now + timedelta(seconds=120), now + timedelta(days=3),
                                 500 if self.api != "export" else MAX_WINDOW, newest_first=True)
        if self.api == "export":
            rows = rows[-500:]
        self.future = [((r.t - now).total_seconds(), r.src, r.msg) for r in rows if r.t]
        self.status["future_messages"] = len(rows)

    async def _verify(self, client):
        """Compare Graylog's per-minute counts with what we stored; fetch what's missing."""
        if not (self.local_counts and self.known_keys):
            return
        hi = (self.cursor - self.rescan).replace(second=0, microsecond=0)
        lo = max(self.start, hi - self.verify_span)
        if lo.second or lo.microsecond:            # only whole minutes we were meant to have
            lo = lo.replace(second=0, microsecond=0) + timedelta(minutes=1)
        if hi <= lo:
            return
        started = datetime.now(timezone.utc)      # Graylog's counts are as of this moment
        theirs = await self._counts(client, lo, hi)
        if theirs is None:
            self.status["verify_ok"] = None
            return
        ours = await self.local_counts(self.field, lo, hi)
        fixed, found = 0, {}
        for _round in range(3):
            # Minutes where Graylog has more than we stored: read them again and add
            # whatever we don't have yet (matched on Graylog's message id).
            short = sorted(m for m in theirs if theirs[m] > ours.get(m, 0))
            if not short:
                break
            for m in short:
                have = await self.known_keys(self.field, m, m + timedelta(minutes=1))
                n = 0
                async for r in self._read_range(client, m, m + timedelta(minutes=1)):
                    if r.key not in have:
                        have.add(r.key)
                        n += 1
                        # arrived since the previous check, if checks are frequent
                        yield self._out(r, datetime.now(timezone.utc) if self.verify_every <= 90 else None)
                found[m] = n
                fixed += n
            if not any(found[m] for m in short):
                break                       # re-reading found nothing new: no point repeating
            # Count both sides again: Graylog may have indexed more messages meanwhile.
            theirs = await self._counts(client, lo, hi) or theirs
            ours = await self.local_counts(self.field, lo, hi)
        if fixed:
            self.status["recovered"] += fixed
            log.info("Verification: fetched %s late messages", fixed)
        diff = [m for m in sorted(set(theirs) | set(ours)) if theirs.get(m, 0) != ours.get(m, 0)]
        # Graylog may still be indexing the last few minutes (under load, messages can
        # arrive minutes late). Those are fetched at every check; only minutes older
        # than `settle` that still don't match count as a real problem.
        settled = hi - self.settle
        # A real problem: Graylog has more than we stored and re-reading the minute
        # found nothing new (we can't get them), or we have more than Graylog. A minute
        # whose re-read just found new messages is still filling up (pending).
        still = [m for m in diff if m < settled and
                 (ours.get(m, 0) > theirs.get(m, 0) or found.get(m) == 0)]
        self.status["pending_minutes"] = len(diff) - len(still)
        self.status["settled_until"] = fmt(settled)
        self.status.update(last_verify=fmt(datetime.now(timezone.utc)), verify_started=fmt(started), verified_from=fmt(lo),
                           verified_until=fmt(hi), verify_ok=not still,
                           mismatch_minutes=[{"minute": fmt(m), "graylog": theirs.get(m, 0),
                                              "stored": ours.get(m, 0)} for m in still[:20]])
        if still:
            log.warning("Verification: %s minute(s) still differ from Graylog: %s", len(still),
                        self.status["mismatch_minutes"][:3])

    async def stream(self):
        import httpx
        async with httpx.AsyncClient(auth=(self.token, "token"), verify=self.verify_tls,
                                     timeout=self.timeout) as client:
            detected = False
            last_verify = 0.0
            loop = asyncio.get_running_loop()
            while True:
                try:
                    if not detected:
                        await self._detect(client)
                        detected = True
                        if self.resumed and self.known_keys:
                            # what's already stored around the resume point
                            for k in await self.known_keys(self.field, self.cursor - self.rescan,
                                                           self.cursor + timedelta(days=3)):
                                self.seen[k] = self.cursor
                    now = datetime.now(timezone.utc)
                    hi = now - timedelta(seconds=self.lag)
                    lo = min(self.cursor, hi) - self.rescan
                    n = 0
                    normal = self._prev_hi is not None and (hi - self._prev_hi).total_seconds() <= self.poll * 3 + 10
                    async for r in self._read_range(client, lo, hi):
                        if self._new(r):
                            n += 1
                            known = r.t is not None and self._prev_hi is not None and (r.t < self._prev_hi or normal)
                            yield self._out(r, now if known else None)
                            if n % 20_000 == 0:          # long catch-up: keep memory small
                                self._prune(self.progress)
                    self._prev_hi = hi
                    self.cursor = max(self.cursor, hi)
                    self._prune(self.cursor)
                    self.status.update(state="connected", last_error=None, last_batch=n,
                                       last_poll=fmt(datetime.now(timezone.utc)), horizon=fmt(self.cursor))
                    self.status["caught_up"] = True
                    if loop.time() - last_verify >= self.verify_every:
                        last_verify = loop.time()
                        await self._probe_future(client)
                        async for item in self._verify(client):
                            yield item
                except asyncio.CancelledError:
                    raise
                except Exception as e:   # keep running; show the problem in the dashboard
                    self.status.update(state="error", last_error=f"{type(e).__name__}: {e}"[:300])
                    log.warning("Graylog poll failed: %s", e)
                    await asyncio.sleep(max(self.poll, 10))
                    continue
                await asyncio.sleep(self.poll)
