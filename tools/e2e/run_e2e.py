"""End-to-end test: Graylog stand-in -> monitor -> stored data, with faults.

Compares, message by message, what the monitor stored with what "Graylog" had,
and fails on any missing / duplicated / wrong message, a false alert, or a red
self-check. Needs a Graylog CSV export of real traffic.

  python tools/e2e/run_e2e.py --name test1 --csv export.csv            # Graylog 6+
  python tools/e2e/run_e2e.py --name test2 --csv export.csv --device-time --emu "--no-recv"   # Graylog 5.x
  python tools/e2e/run_e2e.py --name test3 --csv export.csv --api export --device-time --emu "--no-recv --export-ids"  # 4.x
Extra faults go in --emu, e.g. "--late-frac 0.03 --late-max 300 --burst-at 150 --skew-ap Deck5_Lounge --skew-min -25".
"""
import re, argparse, json, os, signal, subprocess, sys, time, urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--name", required=True)
ap.add_argument("--csv", required=True, help="Graylog CSV export (timestamp, source, message)")
ap.add_argument("--workdir", default=None, help="where to keep the run (default: a temp folder)")
ap.add_argument("--api", default="scripting")
ap.add_argument("--emu", default="", help="extra emulator args")
ap.add_argument("--live-sec", type=int, default=420)
ap.add_argument("--faults", default="1", help="1 = run the fault schedule")
ap.add_argument("--restart-at", type=int, default=240, help="kill -9 the monitor at this second (0 = never)")
ap.add_argument("--down-for", type=int, default=60)
ap.add_argument("--app-extra", default="")
ap.add_argument("--rescan", type=int, default=15)
ap.add_argument("--verify", type=int, default=20)
ap.add_argument("--device-time", action="store_true", help="no receive times: expect the device's own time")
ap.add_argument("--settle", type=int, default=55, help="seconds to wait after the live phase")
args = ap.parse_args()

import tempfile
W = Path(args.workdir or tempfile.gettempdir()) / f"vship_e2e_{args.name}"; W.mkdir(parents=True, exist_ok=True)
for f in W.glob("*"): f.unlink()
CSV = args.csv
EPORT, APORT = int(os.environ.get("EPORT", 9900)), int(os.environ.get("APORT", 8097))
APPDIR = str(Path(__file__).resolve().parents[2])
T0 = time.time()

def log(*a):
    line = f"[{time.time() - T0:6.1f}s] " + " ".join(str(x) for x in a)
    print(line, flush=True)
    with open(W / "harness.log", "a") as f: f.write(line + "\n")

def http(url, data=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())

def faults(**kw):
    log("FAULT", kw); http(f"http://127.0.0.1:{EPORT}/admin/faults", kw)

emu = subprocess.Popen([sys.executable, str(Path(__file__).with_name("graylog_emulator.py")), "--port", str(EPORT), "--csv", CSV,
                        "--t0", str(T0), "--history-min", "60", "--live-min", str(args.live_sec * 6 / 60 + 1),
                        "--speed", "6"] + args.emu.split(), stdout=open(W / "emu.log", "w"), stderr=subprocess.STDOUT)
for _ in range(120):
    time.sleep(1)
    try: http(f"http://127.0.0.1:{EPORT}/admin/stats"); break
    except Exception: pass
log("emulator up:", open(W / "emu.log").read().strip().splitlines()[-1])

cfg = W / "config.toml"
cfg.write_text(f'''
[source]
type = "graylog"
[graylog]
url = "http://127.0.0.1:{EPORT}"
token = "testtoken"
api = "{args.api}"
poll_seconds = 2
lag_seconds = 3
backfill_minutes = 70
rescan_seconds = {args.rescan}
verify_seconds = {args.verify}
verify_minutes = 120
export_verify_seconds = {args.verify}
[phone]
tailscale = false
{args.app_extra}
''')
DB = W / "monitor.duckdb"
def start_app():
    p = subprocess.Popen([sys.executable, "-m", "vship_monitor", "--config", str(cfg), "--db", str(DB),
                          "--port", str(APORT), "--no-browser"], cwd=APPDIR,
                         stdout=open(W / "app.log", "a"), stderr=subprocess.STDOUT, env={**os.environ, "PYTHONPATH": APPDIR})
    for _ in range(60):
        time.sleep(1)
        try: http(f"http://127.0.0.1:{APORT}/api/status"); return p
        except Exception: pass
    raise SystemExit("app did not start")
app = start_app(); log("monitor started")

def status():
    try:
        return http(f"http://127.0.0.1:{APORT}/api/status")
    except Exception as e:
        return {"error": str(e)}

schedule = []
if args.faults == "1":
    schedule = [(60, dict(auth_fail=True)), (90, dict(auth_fail=False)),
                (120, dict(error_rate=0.35)), (180, dict(error_rate=0.0)),
                (200, dict(slow=4.0)), (225, dict(slow=0.0)),
                (300, dict(down=True)), (300 + args.down_for, dict(down=False))]
restarted = False
next_print = 0
while time.time() - T0 < args.live_sec:
    el = time.time() - T0
    while schedule and el >= schedule[0][0]:
        faults(**schedule.pop(0)[1])
    if args.restart_at and not restarted and el >= args.restart_at:
        log("KILL -9 the monitor (abrupt crash)"); app.send_signal(signal.SIGKILL); app.wait()
        time.sleep(20)
        app = start_app(); restarted = True; log("monitor restarted")
    if el >= next_print:
        s = status(); src = s.get("source", {})
        log(f"status: {s.get('events_total')} stored, state={src.get('state')} err={str(src.get('last_error'))[:60]} "
            f"verified={src.get('verify_ok')} recovered={src.get('recovered')} field={src.get('time_field')} ids={src.get('ids')}")
        next_print = el + 30
    time.sleep(1)

# let the monitor finish: two verification rounds after the last message became visible
log("live phase over; waiting for final verification rounds")
time.sleep(args.settle)
s = status(); log("final status:", json.dumps(s.get("source"))[:600])
alerts_end = http(f"http://127.0.0.1:{APORT}/api/alerts?state=all")
alerts_end = alerts_end if isinstance(alerts_end, list) else alerts_end.get("alerts", [])
json.dump(alerts_end, open(W / "alerts.json", "w"), indent=1)
by_rule = Counter(a["rule"] for a in alerts_end)
log("alerts raised during the run:", dict(by_rule))
silent = [a for a in alerts_end if a["rule"] == "device_silent"]
def rel(iso): return round(datetime.fromisoformat(iso).timestamp() - T0)
log(f"device_silent alerts: {len(silent)}", [(a['device_name'], rel(a['first_seen'])) for a in silent[:12]])
log(f"ap_reboot alerts: {by_rule.get('ap_reboot', 0)}")
for a in alerts_end:
    if a["rule"] in ("clock_skew", "data_incomplete", "feed_stalled", "admin_login_failed"):
        log("  alert:", a["rule"], "|", a["title"], "|", a["detail"][:100], "| active" if a["active"] else "| resolved")
stop_wall = time.time()
app.send_signal(signal.SIGINT); app.wait(timeout=60)

# ------------------------------------------------------------------ compare
import duckdb
con = duckdb.connect(str(DB), read_only=True)
rows = con.execute("SELECT gid, epoch(ts), epoch(recv), raw FROM events WHERE gid IS NOT NULL").fetchall()
con.close()
src_ = s.get("source") or {}
def ep(x): return datetime.fromisoformat(x.replace("Z", "+00:00")).timestamp() if x else None
lv, vu = ep(src_.get("verify_started") or src_.get("last_verify")), ep(src_.get("verified_until"))
until = min(stop_wall - 60, vu or stop_wall)
vis_before = (lv - 1) if lv else stop_wall
log(f"truth = messages Graylog had indexed by the app's last check ({vis_before - T0:.0f}s), received before {until - T0:.0f}s")
truth = http(f"http://127.0.0.1:{EPORT}/admin/truth?until={until}&field=recv&vis_before={vis_before}")
emu_stats = http(f"http://127.0.0.1:{EPORT}/admin/stats")
truth_all = http(f"http://127.0.0.1:{EPORT}/admin/truth?until={stop_wall + 3600}&field=recv")
emu.terminate()

if rows and all(str(r[0]).startswith("c:") for r in rows[:1000]):
    # No Graylog ids: compare by (time, text) as multisets
    norm = lambda m: re.sub(r"\s*[\r\n]+\s*", " | ", m.strip())
    want = Counter((round(t, 3), norm(m)) for _, t, rc, _, m in truth["rows"])
    have = Counter((round(t, 3), r) for _, t, _, r in rows if t < until)
    everything = Counter((round(t, 3), norm(m)) for _, t, rc, _, m in truth_all["rows"])
    have_all = Counter((round(t, 3), r) for _, t, _, r in rows)
    miss = want - have
    dup = have_all - everything          # stored but NOT in Graylog at all (or stored more often than Graylog has it)
    res = {"name": args.name, "mode": "content", "graylog_messages": sum(want.values()), "stored_in_window": sum(have.values()),
           "missing": sum(miss.values()), "duplicates_or_extra": sum(dup.values())}
    ok = not miss and not dup
    log("RESULT", "PASS" if ok else "FAIL", json.dumps(res))
    if miss: log("missing examples:", [(round(k[0] - T0, 1), k[1][:60], n) for k, n in list(miss.items())[:5]])
    if dup: log("extra examples:", [(round(k[0] - T0, 1), k[1][:60], n) for k, n in list(dup.items())[:5]])
    sys.exit(0)
by_gid = Counter(r[0] for r in rows)
dups = {g: n for g, n in by_gid.items() if n > 1}
stored = {r[0]: r for r in rows}
T = {r[0]: r for r in truth["rows"]}
# Without receive times the app loads history by the message's own timestamp: anything
# stamped before the backfill start (T0 - 70 min) is correctly outside what it was asked for.
before_backfill = {g for g, r in T.items() if args.device_time and (r[1] < T0 - 70 * 60 or r[1] > until - 5)}
missing = [g for g in T if g not in stored and g not in before_backfill]
if before_backfill:
    log(f"{len(before_backfill)} messages are stamped before the backfill start (device clock behind) - not expected;",
        f"{sum(1 for g in before_backfill if g in stored)} of them were stored anyway")
extra = [g for g in stored if g not in T]
bad_ts, bad_txt = [], []
for g, (gid, ts, rc, src, msg) in T.items():
    s_ = stored.get(g)
    if not s_: continue
    exp = ts if (args.device_time or abs(ts - rc) <= 120) else rc            # wrong-clock device: placed at receive time
    if abs(s_[1] - exp) > 0.0015: bad_ts.append((g, s_[1], exp))
    if s_[3] != re.sub(r"\s*[\r\n]+\s*", " | ", msg.strip()) and s_[3] != msg: bad_txt.append(g)
res = {"name": args.name, "graylog_messages": truth["n"], "stored": len(rows),
       "missing": len(missing), "duplicates": len(dups), "extra_not_in_graylog_window": len(extra),
       "wrong_time": len(bad_ts), "wrong_text": len(bad_txt), "emulator_requests": emu_stats["requests"],
       "emulator_errors_injected": emu_stats["errors"], "final_source_status": s.get("source")}
json.dump({**res, "missing_examples": missing[:10], "bad_ts_examples": bad_ts[:5]}, open(W / "result.json", "w"), indent=1, default=str)
false_alarms = [a for a in alerts_end if a["rule"] in ("data_incomplete", "ap_reboot")
                or (a["rule"] == "device_silent" and a["severity"] != "info" and T0 + 30 < datetime.fromisoformat(a["first_seen"]).timestamp() < T0 + args.live_sec - 30)]
if false_alarms:
    log("UNEXPECTED ALERTS:", [(a["rule"], a["title"], a["detail"][:80]) for a in false_alarms])
res["final_self_check_ok"] = (s.get("source") or {}).get("verify_ok")
ok = not missing and not dups and not bad_ts and not bad_txt and not false_alarms and res["final_self_check_ok"] is True
log("RESULT", "PASS" if ok else "FAIL", json.dumps({k: v for k, v in res.items() if k != "final_source_status"}))
if missing:
    log("missing examples:", [(round(T[g][2] - T0, 1), T[g][4][:60]) for g in missing[:5]])
    hist = Counter(int((T[g][2] - T0) // 30) * 30 for g in missing)
    log("missing by receive time (s after start):", sorted(hist.items()))
if bad_ts:
    log("wrong time examples:", bad_ts[:5])
