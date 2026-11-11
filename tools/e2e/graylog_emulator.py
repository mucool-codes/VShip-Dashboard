"""A Graylog stand-in that behaves like graylog2-server's REST API (checked
against its source) and can be made to misbehave on purpose.

Data: real lines from the sample export, re-timed so the first part is already
in Graylog ("history") and the rest arrives live, compressed in time.

Run:  python emulator.py --port 9900 --csv export.csv --history-min 60 --live-min 60 --speed 6
"""
import argparse, asyncio, csv, hashlib, json, random, re, time, uuid
from datetime import datetime, timedelta, timezone

import numpy as np
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=9900)
ap.add_argument("--csv", required=True)
ap.add_argument("--history-min", type=float, default=60)
ap.add_argument("--live-min", type=float, default=60, help="minutes of source data streamed live")
ap.add_argument("--speed", type=float, default=6)
ap.add_argument("--t0", type=float, default=None, help="wall epoch for 'now' at start (to restart identically)")
ap.add_argument("--tz", default="+05:30", help="time zone of the token user (Graylog formats dates in it)")
ap.add_argument("--late-frac", type=float, default=0.0, help="fraction of messages indexed late")
ap.add_argument("--late-max", type=float, default=300, help="max indexing delay (s) for late messages")
ap.add_argument("--very-late", type=int, default=0, help="number of messages indexed very late")
ap.add_argument("--very-late-min", type=float, default=20)
ap.add_argument("--skew-ap", default="", help="AP name whose clock is wrong")
ap.add_argument("--skew-min", type=float, default=-25)
ap.add_argument("--ahead-ap", default="", help="AP name whose clock is ahead")
ap.add_argument("--ahead-min", type=float, default=20)
ap.add_argument("--burst-at", type=float, default=-1, help="seconds after start: inject a burst")
ap.add_argument("--burst-n", type=int, default=15000)
ap.add_argument("--no-recv", action="store_true", help="old Graylog: no gl2_receive_timestamp")
ap.add_argument("--export-ids", action="store_true", help="CSV export returns _id")
ap.add_argument("--token", default="testtoken")
ap.add_argument("--seed", type=int, default=7)
args = ap.parse_args()

rng = random.Random(args.seed)
T0 = args.t0 or time.time()
sign = 1 if args.tz[0] == "+" else -1
TZ = timezone(sign * timedelta(hours=int(args.tz[1:3]), minutes=int(args.tz[-2:])))

# ------------------------------------------------------------------ data
def load():
    rows = []
    with open(args.csv, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        first = None
        limit = (args.history_min + args.live_min) * 60
        for x in r:
            t = datetime.fromisoformat(x["timestamp"].replace("Z", "+00:00")).timestamp()
            if first is None:
                first = t
            off = t - first
            if off >= limit:
                break
            rows.append((off, x["source"], x["message"]))
    return rows

src_rows = load()
hist = args.history_min * 60
N = len(src_rows)
recv = np.empty(N); ts = np.empty(N); vis = np.empty(N)
ids, sources, messages = [], [], []
for i, (off, s, m) in enumerate(src_rows):
    # history: placed at the same spacing ending at T0; live: compressed by `speed` after T0
    r_ = T0 - hist + off if off < hist else T0 + (off - hist) / args.speed
    r_ = round(r_, 3)
    recv[i] = r_
    t_ = r_
    if args.skew_ap and f" {args.skew_ap} " in m:
        t_ = r_ + args.skew_min * 60
    if args.ahead_ap and f" {args.ahead_ap} " in m:
        t_ = r_ + args.ahead_min * 60
    ts[i] = round(t_, 3)
    h = int(hashlib.md5(f"{args.seed}:{i}".encode()).hexdigest()[:8], 16)
    delay = 0.3 + (h % 1000) / 1000 * 1.5               # normal indexing: 0.3-1.8 s
    if args.late_frac and (h >> 10) % 10000 < args.late_frac * 10000:
        delay = 5 + (h >> 4) % int(args.late_max)       # late: 5 s .. late_max
    vis[i] = r_ + delay
    ids.append(str(uuid.UUID(int=h << 96 | i)))         # unique, stable across restarts
    sources.append(s); messages.append(m)
# a few very late messages (e.g. Graylog's journal backed up)
if args.very_late:
    live_idx = [i for i in range(N) if recv[i] > T0 + 60]
    for i in random.Random(args.seed + 1).sample(live_idx, args.very_late):
        vis[i] = recv[i] + args.very_late_min * 60
# a burst of messages (flood) within 2 seconds
if args.burst_at >= 0:
    base = T0 + args.burst_at
    extra_r, extra_t, extra_v = [], [], []
    for k in range(args.burst_n):
        r_ = round(base + (k % 2000) / 1000, 3)          # 2,000 distinct ms -> many share a timestamp
        extra_r.append(r_); extra_t.append(r_); extra_v.append(r_ + 1.0)
        ids.append(str(uuid.UUID(int=(0xB0B << 100) | k)))
        sources.append("10.199.38.1")
        messages.append(f'id=firewall sn=18C2412BF964 time="burst" fw=10.10.10.10 pri=1 c=32 m=82 '
                        f'msg="Possible port scan detected" n={k} src=203.0.113.{k % 250}:{1000 + k}:X1 dst=10.10.10.10:443:X1')
    recv = np.concatenate([recv, extra_r]); ts = np.concatenate([ts, extra_t]); vis = np.concatenate([vis, extra_v])
N = len(ids)
by_ts = np.argsort(ts, kind="stable"); ts_sorted = ts[by_ts]
by_recv = np.argsort(recv, kind="stable"); recv_sorted = recv[by_recv]
print(f"emulator: {N} messages, {int((recv <= T0).sum())} history, live until +{(recv.max() - T0) / 60:.1f} min", flush=True)

faults = {"auth_fail": False, "error_rate": 0.0, "down": False, "slow": 0.0, "max_window": 10000}
stats = {"requests": 0, "errors": 0, "by_path": {}}

# ------------------------------------------------------------------ helpers
def out_ts(epoch):            # how Graylog's Jackson/Joda mapper writes a date in the user's time zone
    d = datetime.fromtimestamp(epoch, timezone.utc).astimezone(TZ)
    s = d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}"
    off = d.strftime("%z")
    return s + ("Z" if off == "+0000" else off[:3] + ":" + off[3:])

def parse_abs(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()

RANGE = re.compile(r'gl2_receive_timestamp:([\[{])"([^"]+)" TO "([^"]+)"([\]}])')
def es_parse(s):              # "yyyy-MM-dd HH:mm:ss.SSS" UTC
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()

def select(tr, query, sort_field="timestamp"):
    now = time.time()
    lo, hi = parse_abs(tr["from"]), parse_abs(tr["to"])
    a, b = np.searchsorted(ts_sorted, lo, "left"), np.searchsorted(ts_sorted, hi, "left")   # gte from, lt to
    idx = by_ts[a:b]
    idx = idx[vis[idx] <= now]
    m = RANGE.search(query or "")
    if m:
        if args.no_recv:
            return np.array([], dtype=int)
        l_inc, rlo, rhi, r_inc = m.groups()
        rlo, rhi = es_parse(rlo), es_parse(rhi)
        sel = (recv[idx] >= rlo) if l_inc == "[" else (recv[idx] > rlo)
        sel &= (recv[idx] <= rhi) if r_inc == "]" else (recv[idx] < rhi)
        idx = idx[sel]
    key = recv if sort_field == "gl2_receive_timestamp" else ts
    # OpenSearch sorts on the field only: ties come back in no particular order
    tieb = np.array([rng.random() for _ in range(len(idx))])
    order = np.lexsort((tieb, key[idx]))
    return idx[order]

def check(request):
    stats["requests"] += 1
    p = request.url.path
    stats["by_path"][p] = stats["by_path"].get(p, 0) + 1
    if faults["down"]:
        return Response(status_code=502, content="Bad Gateway (Graylog down)")
    auth = request.headers.get("authorization", "")
    import base64
    try:
        user, pw = base64.b64decode(auth.split()[1]).decode().split(":", 1)
    except Exception:
        user, pw = "", ""
    if faults["auth_fail"] or user != args.token or pw != "token":
        return Response(status_code=401, content="")
    if faults["error_rate"] and rng.random() < faults["error_rate"]:
        stats["errors"] += 1
        return JSONResponse({"type": "ApiError", "message": "Search failed: OpenSearch timeout"}, status_code=500)
    return None

def value(i, f):
    if f == "_id": return ids[i]
    if f == "timestamp": return out_ts(ts[i])
    if f == "source": return sources[i] or "-"
    if f == "message": return messages[i]
    if f == "gl2_receive_timestamp": return "-" if args.no_recv else out_ts(recv[i])
    return "-"

app = FastAPI()

@app.get("/api/")
async def hello():      # HelloWorldResource: no permission check
    return {"cluster_id": "test", "node_id": "node", "version": "6.1.4+abc123", "tagline": "Manage your logs in the dark"}

@app.post("/api/search/messages")
async def messages_api(request: Request):
    if faults["slow"]: await asyncio.sleep(faults["slow"])
    bad = check(request)
    if bad: return bad
    b = await request.json()
    so = (b.get("sort_order") or "Descending").strip().lower()
    if so not in ("asc", "ascending", "desc", "descending"):
        return JSONResponse({"message": f"Failed to parse sort direction:{so}"}, status_code=400)
    size, frm = int(b.get("size") or 10), int(b.get("from") or 0)
    if frm + size > faults["max_window"]:
        return JSONResponse({"message": "Result window is too large, from + size must be less than or equal to: [10000]"}, status_code=500)
    sort = b.get("sort") or "timestamp"
    idx = select(b["timerange"], b.get("query", "*"), sort)
    if so.startswith("desc"):
        idx = idx[::-1]
    idx = idx[frm:frm + size]
    fields = b.get("fields") or ["timestamp", "source", "message"]
    schema = [{"column_type": "field", "type": "date" if "timestamp" in f else "string", "field": f, "name": f"field: {f}"} for f in fields]
    return {"schema": schema, "datarows": [[value(int(i), f) for f in fields] for i in idx],
            "metadata": {"effective_timerange": {"type": "absolute", "from": b["timerange"]["from"], "to": b["timerange"]["to"]}}}

@app.post("/api/search/aggregate")
async def aggregate_api(request: Request):
    bad = check(request)
    if bad: return bad
    b = await request.json()
    g = b["group_by"][0]
    field = g["field"]
    if g.get("timeunit") != "1m":
        return JSONResponse({"message": "only 1m supported by emulator"}, status_code=400)
    idx = select(b["timerange"], b.get("query", "*"))
    key = recv if field == "gl2_receive_timestamp" else ts
    mins = np.floor(key[idx] / 60) * 60
    u, c = np.unique(mins, return_counts=True)
    return {"schema": [{"column_type": "grouping", "type": "date", "field": field, "name": f"grouping: {field}"},
                       {"column_type": "metric", "type": "numeric", "function": "count", "name": "metric: count()"}],
            "datarows": [[out_ts(float(m)), int(n)] for m, n in zip(u, c)],
            "metadata": {"effective_timerange": b["timerange"]}}

@app.post("/api/views/search/messages")
async def export_api(request: Request):
    bad = check(request)
    if bad: return bad
    b = await request.json()
    fields = b.get("fields_in_order") or ["timestamp", "source", "message"]
    q = (b.get("query_string") or {}).get("query_string", "*")
    idx = select(b["timerange"], q)
    # export sorts by timestamp then a tiebreaker: stable
    idx = idx[np.lexsort((np.array(idx), ts[idx]))]
    if b.get("limit"):
        idx = idx[: int(b["limit"])]
    import io
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(fields)
    for i in idx:
        i = int(i)
        row = []
        for f in fields:
            if f == "timestamp":   # Joda DateTime.toString() in the request time zone (default UTC)
                d = datetime.fromtimestamp(ts[i], timezone.utc)
                row.append(d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z")
            elif f == "_id":
                row.append(ids[i] if args.export_ids else "")
            else:
                v = value(i, f)
                row.append("" if v == "-" else v)
        w.writerow(row)
    return PlainTextResponse(buf.getvalue(), media_type="text/csv")

# ------------------------------------------------------------------ test control
@app.post("/admin/faults")
async def set_faults(request: Request):
    faults.update(await request.json()); return faults

@app.get("/admin/stats")
async def get_stats():
    return {**stats, "faults": faults, "now": time.time(), "T0": T0}

@app.get("/admin/truth")
async def truth(until: float, field: str = "recv", vis_before: float = 0):
    """Every message Graylog had indexed by `vis_before` (default now) with its time field < until."""
    now = vis_before or time.time()
    key = recv if field == "recv" else ts
    sel = np.where((vis <= now) & (key < until))[0]
    return {"n": len(sel), "rows": [[ids[i], float(ts[i]), float(recv[i]), sources[i], messages[i]] for i in sel]}

uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
