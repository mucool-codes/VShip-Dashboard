"""Check the connection to Graylog and how well the monitor understands your data.

Run it with check_graylog.bat (or: python tools/check_graylog.py). It only READS
from Graylog. It checks:

  1. the Graylog address, the version, and that the token can read the logs
  2. which API setting to use ("scripting" or "export")
  3. whether Graylog gives message ids and receive times (used to prove completeness)
  4. device clocks that are wrong (their messages' times would be misleading)
  5. a sample of your real recent messages: how many the monitor recognises,
     and examples of any it doesn't
  6. if the monitor is running: whether its stored data matches Graylog
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vship_monitor import config as config_mod          # noqa: E402
from vship_monitor.graylog import RECV, fmt, parse_ts   # noqa: E402
from vship_monitor.parser import parse                  # noqa: E402

OK, WARN, BAD = "  OK    ", "  CHECK ", "  PROBLEM"
problems = 0


def say(mark, text):
    global problems
    if mark == BAD:
        problems += 1
    print(f"{mark} {text}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.toml")
    ap.add_argument("--sample", type=int, default=5000, help="recent messages to test the parser on")
    a = ap.parse_args()
    import httpx

    if not Path(a.config).exists():
        say(BAD, f"{a.config} not found. Double-click start.bat once to create it, then fill in Graylog.")
        return
    cfg = config_mod.load(a.config)
    g = cfg["graylog"]
    url = g["url"].rstrip("/")
    print(f"\nChecking Graylog at {url}\n")
    if not g["token"]:
        say(BAD, "No token in config.toml ([graylog] token = \"...\"). See HOW_TO_USE.md section 2.2.")
        return
    client = httpx.Client(auth=(g["token"], "token"), verify=g["verify_tls"], timeout=60,
                          headers={"X-Requested-By": "vship-monitor-check", "Accept": "application/json"})

    # 1. reach + version (GET /api/ needs no special permission)
    try:
        r = client.get(f"{url}/api/")
    except Exception as e:
        say(BAD, f"Can't reach Graylog: {type(e).__name__}: {e}")
        print("         Check the address and port, and that this laptop is on the ship network or VPN.")
        return
    if r.status_code == 401:
        say(BAD, "Graylog refused the token (401). Check the token, or create a new one (HOW_TO_USE.md 2.2).")
        return
    if r.status_code >= 400 or "version" not in r.text:
        say(BAD, f"That address doesn't look like Graylog's API (HTTP {r.status_code}). "
                 "Use the address you open Graylog with, e.g. http://192.168.1.10:9000")
        return
    version = str(r.json().get("version", "?"))
    say(OK, f"Reached Graylog, version {version}.")
    try:
        major = int(version.split(".")[0])
    except ValueError:
        major = 0
    want_api = "scripting" if major >= 5 else "export"
    if major and g["api"] != want_api:
        say(BAD, f'config.toml has api = "{g["api"]}" but Graylog {version} needs api = "{want_api}".')
    elif major:
        say(OK, f'The API setting (api = "{g["api"]}") suits this version.')

    # 2. read a sample of recent messages
    now = datetime.now(timezone.utc)
    tr = {"type": "absolute", "from": fmt(now - timedelta(hours=1)), "to": fmt(now)}
    fields = ["_id", "timestamp", "source", "message", RECV]
    try:
        if g["api"] == "export":
            body = {"timerange": tr, "query_string": {"type": "elasticsearch", "query_string": g["query"] or "*"},
                    "fields_in_order": fields, "limit": a.sample}
            if g["streams"]:
                body["streams"] = g["streams"]
            r = client.post(f"{url}/api/views/search/messages", json=body, headers={"Accept": "text/csv"})
            r.raise_for_status()
            import csv, io
            rows = list(csv.reader(io.StringIO(r.text)))
            head, data = rows[0], rows[1:]
        else:
            def search(query, timerange, sort, size):
                body = {"query": query, "fields": fields, "timerange": timerange, "size": size,
                        "sort": sort, "sort_order": "Descending"}
                if g["streams"]:
                    body["streams"] = g["streams"]
                r = client.post(f"{url}/api/search/messages", json=body)
                r.raise_for_status()
                return r.json()
            js = search(g["query"] or "*", tr, "timestamp", 5)
            names = [s.get("field") for s in js["schema"]]
            recv_ok = js["datarows"] and RECV in names and all(
                parse_ts(x[names.index(RECV)]) is not None for x in js["datarows"])
            if recv_ok:
                # Sample by *receive* time, so a device whose clock is behind is included.
                q = f'({g["query"] or "*"}) AND {RECV}:["{(now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S.000")}" TO "{now.strftime("%Y-%m-%d %H:%M:%S.000")}"]'
                wide = {"type": "absolute", "from": fmt(now - timedelta(days=2)), "to": fmt(now + timedelta(days=2))}
                js = search(q, wide, RECV, a.sample)
            else:
                js = search(g["query"] or "*", tr, "timestamp", a.sample)
            head = [s.get("field") for s in js["schema"]]
            data = js["datarows"]
    except Exception as e:
        code = getattr(getattr(e, "response", None), "status_code", None)
        if code == 401:
            say(BAD, "Graylog refused the token (401). Check the token, or create a new one (HOW_TO_USE.md 2.2).")
        elif code == 403:
            say(BAD, "The token works, but its Graylog user isn't allowed to search these logs (403). "
                     "Ask the Graylog admin to give the user read access to the streams.")
        else:
            say(BAD, f"Searching Graylog failed: {e}")
        return
    say(OK, "The token works and can read the logs.")
    idx = {n: i for i, n in enumerate(head)}
    get = lambda row, f: row[idx[f]] if f in idx and idx[f] < len(row) else None   # noqa: E731
    if not data:
        say(BAD, "Graylog returned no messages for the last hour (check [graylog] query / streams, and that logs arrive).")
        return
    say(OK, f"Read {len(data)} messages from the last hour.")

    ids = [get(x, "_id") for x in data]
    if all(i not in (None, "", "-") for i in ids):
        say(OK, "Graylog gives message ids: duplicates are impossible and completeness can be proven.")
    else:
        say(WARN, "Graylog doesn't return message ids: the monitor uses message contents instead (still checked).")
    recvs = [parse_ts(get(x, RECV)) for x in data]
    has_recv = all(t is not None for t in recvs)
    say(OK if has_recv else WARN,
        "Graylog records when it received each message (Graylog 6+): a device with a wrong clock is shown "
        "at the right time anyway."
        if has_recv else "Graylog doesn't record receive times (that started in Graylog 6.0). Times are shown as "
                         "Graylog has them, so a device with a wrong clock shows wrong times; the monitor "
                         "alerts you about clocks that are clearly ahead or behind.")

    # 3. timestamps + clocks
    bad_ts = sum(1 for x in data if parse_ts(get(x, "timestamp")) is None)
    if bad_ts:
        say(BAD, f"{bad_ts} messages have a timestamp the monitor can't read. Example: {get(data[0], 'timestamp')!r}")
    else:
        say(OK, f"All timestamps readable (Graylog sends them like {get(data[0], 'timestamp')}).")
    if has_recv:
        skew, names = defaultdict(list), {}
        for x, rt in zip(data, recvs):
            t = parse_ts(get(x, "timestamp"))
            ev = parse(t, get(x, "source") or "", get(x, "message") or "")
            if ev.device_name:
                names[ev.device] = ev.device_name
            if t and rt:
                skew[ev.device].append((t - rt).total_seconds())
        off = {names.get(d, d): sorted(v)[len(v) // 2] for d, v in skew.items() if abs(sorted(v)[len(v) // 2]) > 120}
        if off:
            say(WARN, f"{len(off)} device(s) have a clock that is off by more than 2 minutes "
                      "(the monitor places their messages at Graylog's receive time):")
            for d, s in sorted(off.items(), key=lambda x: -abs(x[1]))[:10]:
                print(f"           {d}: {'ahead' if s > 0 else 'behind'} by {abs(s) / 60:.0f} min")
        else:
            say(OK, "Device clocks agree with Graylog (within 2 minutes).")

    future_tr = {"type": "absolute", "from": fmt(now + timedelta(minutes=2)), "to": fmt(now + timedelta(days=3))}
    try:
        if g["api"] == "export":
            body = {"timerange": future_tr, "query_string": {"type": "elasticsearch", "query_string": g["query"] or "*"},
                    "fields_in_order": ["timestamp", "source", "message"], "limit": 500}
            import csv, io
            fr = list(csv.reader(io.StringIO(client.post(f"{url}/api/views/search/messages", json=body,
                                                         headers={"Accept": "text/csv"}).text)))[1:]
        else:
            body = {"query": g["query"] or "*", "fields": ["timestamp", "source", "message"],
                    "timerange": future_tr, "size": 500, "sort": "timestamp", "sort_order": "Descending"}
            fr = client.post(f"{url}/api/search/messages", json=body).json().get("datarows", [])
        ahead = {}
        for row in fr:
            t = parse_ts(row[0])
            if t:
                ev = parse(t, row[1] or "", row[2] or "")
                ahead[ev.device_name or ev.device] = max(ahead.get(ev.device_name or ev.device, 0), (t - now).total_seconds())
        if ahead:
            say(WARN, f"{len(ahead)} device(s) stamp their messages in the future (clock ahead):")
            for d, sec in sorted(ahead.items(), key=lambda x: -x[1])[:10]:
                print(f"           {d}: ahead by about {sec / 60:.0f} min")
        else:
            say(OK, "No messages stamped in the future (no device clock is ahead).")
    except Exception as e:
        say(WARN, f"Couldn't look for future-stamped messages: {e}")

    # 4. does the monitor understand these messages?
    cls = Counter(); unknown = Counter(); examples = {}
    for x in data:
        ev = parse(parse_ts(get(x, "timestamp")) or now, get(x, "source") or "", get(x, "message") or "")
        cls[ev.dev_class] += 1
        if ev.dev_class == "other":
            key = (ev.device_name, ev.template[:60])
            unknown[key] += 1
            examples.setdefault(key, (get(x, "message") or "")[:150])
    total = sum(cls.values())
    print(f"\n  Message types in the sample: " + ", ".join(f"{k} {v}" for k, v in cls.most_common()))
    share = cls.get("other", 0) / total
    if share > 0.02:
        say(WARN, f"{share:.0%} of messages are from devices/formats the monitor doesn't know yet. They are "
                  "still stored and searchable, but not counted per device type. Most common:")
        for (src, _), n in unknown.most_common(8):
            print(f"           {n:>5}x  {examples[(src, _)]}")
        print("           Send these examples to whoever maintains the monitor so they can be added.")
    else:
        say(OK, f"The monitor recognises {1 - share:.1%} of these messages.")

    # 5. is the monitor running? then report its completeness check
    port = cfg["server"]["port"]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=5) as r:
            st = json.loads(r.read())
        src = st.get("source", {})
        print()
        if src.get("verify_ok") is True:
            say(OK, f"The running monitor's data matches Graylog, minute by minute, from {src.get('verified_from')} "
                    f"to {src.get('verified_until')} (UTC). Late messages fetched: {src.get('recovered', 0)}.")
        elif src.get("verify_ok") is False:
            say(BAD, "The running monitor's data does NOT fully match Graylog for these minutes (UTC):")
            for m in src.get("mismatch_minutes", [])[:10]:
                print(f"           {m['minute']}: Graylog {m['graylog']}, monitor {m['stored']}")
        else:
            say(WARN, "The running monitor hasn't finished its first check against Graylog yet - run this again in a minute.")
    except Exception:
        print("\n  (The monitor isn't running, so its stored data wasn't compared. Start it and run this again.)")

    print("\nResult:", "everything looks right." if not problems else f"{problems} problem(s) - see PROBLEM lines above.")


if __name__ == "__main__":
    main()
