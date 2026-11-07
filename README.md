# VShip Dashboard - vessel network monitor

> **Using the dashboard?** Read [HOW_TO_USE.md](HOW_TO_USE.md), the step-by-step guide for day-to-day users. **On a phone?** See [PHONE_ACCESS.md](PHONE_ACCESS.md). This README is the technical reference.

A real-time monitor for one vessel's network logs. It runs on a single laptop and shows the results in the browser at `http://localhost:8080`.

It reads the ship's syslog feed (Wi-Fi access points, ESXi/HPE iLO servers, the SonicWall firewall and the switches). It turns each line into structured data, raises alerts and shows two views:

| View | For | Answers |
|---|---|---|
| **Infrastructure health** | IT / network superintendent | Are all access points, servers and switches reporting? Which deck has problems? Is any hardware failing? Which errors are new or spiking? |
| **Internet & security** | Crew-internet policy / cybersecurity | What is being blocked or allowed, and on which deck? Which devices generate the most traffic? Are there scans, floods or VPN/proxy-bypass attempts? |

When you come back after closing the app (or after leaving the dashboard tab unattended), a **While you were away** summary shows everything that happened in between. After that the dashboard carries on in real time. See [below](#while-you-were-away).

There is also an **Alerts** page (acknowledge, history, desktop notifications) and an **Event explorer** to search the raw messages. Clicking any device opens its detail panel: activity chart, message types, connected clients and latest lines.

Everything works offline: no internet, CDN or cloud service is needed on board.

The dashboard is responsive. Below 700 px wide it switches to a phone layout with a bottom tab bar, stacked cards, sideways-scrolling tables and tap-to-read charts. It can be added to the home screen (web app manifest and service worker). See [Phone access](#phone-access).

---

## Quick start (Windows)

You need **Python 3.10 or newer** ([python.org](https://www.python.org/downloads/), tick "Add python.exe to PATH").

**Demo with a CSV export** (no ship connection needed):

```bat
start_demo.bat "C:\path\to\All-Messages-search-result.csv"
```

The first run creates a virtual environment and installs the packages, which takes about a minute. The browser then opens and the 8-hour export plays back at 60× speed, so one hour of data plays in one minute.

**Live mode:**

```bat
start.bat
```

On the first run this creates `config.toml` and opens it in Notepad. Fill in the Graylog address and token (see below), save, then run `start.bat` again.

### Manual setup (any OS)

```bash
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp config.example.toml config.toml   # then edit it
python -m vship_monitor                                   # live, using config.toml
python -m vship_monitor --replay export.csv --speed 60    # demo
python -m vship_monitor --replay export.csv --speed 0     # load a whole file as fast as possible
```

Useful flags: `--port 8081`, `--no-browser`, `--loop` (repeat the replay), `--db path\to\file.duckdb`, `--config other.toml`, `--fresh` (delete stored data and start over, e.g. to replay a file from the beginning).

If you double-click the `.bat` while the app is already running, it just opens the dashboard again instead of starting a second copy.

---

## Connecting to the live feed

### Option 1 - Graylog (recommended)

The sample export is a Graylog "All messages" search, so the ship most likely already runs Graylog. With this option the laptop simply asks Graylog for new messages every 5 seconds. No ship configuration changes are needed, and if the laptop is off nothing is lost: on restart it continues from the last message it stored.

1. Ask the Graylog admin for a **dedicated read-only user**, e.g. `vessel-dashboard`, with read access to the streams holding these logs.
2. Log in as that user, then go to **profile → Edit tokens → Create token**. Copy the token.
3. In `config.toml`:
   ```toml
   [source]
   type = "graylog"
   [graylog]
   url = "http://<graylog-address>:9000"
   token = "<the token>"
   api = "scripting"      # Graylog 5.0 or newer; use "export" for Graylog 4.x
   ```

Tokens are free; they are a built-in Graylog feature. The status bar shows `Graylog connected`, or the error message if something is wrong (wrong URL, token or API version).

### Option 2 - syslog sent straight to the laptop

Use this if there is no Graylog, or as a second copy of the feed. Configure the ship's syslog server (or the devices) to forward to the laptop's IP on **UDP or TCP port 5514**:

```toml
[source]
type = "syslog"
[syslog]
udp_port = 5514
tcp_port = 5514
```

Windows Firewall will ask to allow Python on first start; allow it on the ship network. The port is above 1024, so no admin rights are needed. Messages sent while the laptop is off are lost, which is why Graylog is preferred.

To test syslog mode on one laptop, run the monitor in syslog mode and feed it an export:

```bash
python tools/send_test_syslog.py export.csv --rate 50
```

---

## While you were away

The app remembers when you last had the dashboard open. It saves this every few seconds, so it also works if the window is closed abruptly.

**When you close the black window and start the app again later:**
1. The app first loads the messages it missed:
   - **Graylog:** it fetches everything Graylog received while the app was closed, up to `max_catchup_hours`, default 7 days. Those messages go through the alert rules with their original timestamps, so for example "esx2 went silent at 02:10" is reported with the right time.
   - **Syslog:** messages sent while the app was closed were never received. The summary says so and shows the gap.
   - **Demo replay:** it continues from where it stopped and fast-forwards through the part of the file that would have played while you were away.
2. A **While you were away** panel opens, with:
   - the period, for example "Fri 18:40 → Sat 09:15 · 14 h 35 min"
   - the alerts raised, most serious first, marked still active or resolved
   - warnings and errors over time, by device type
   - what happened in short form, for example "3 flapping switch ports", "2 DNS outages", "1 hardware sensor warning"
   - new kinds of warning or error seen for the first time
   - firewall totals and attack or bypass attempts

   While the missed messages load, a progress bar shows and the summary fills in.
3. Click **Got it - go live** and the dashboard continues in real time.

From the panel you can also:
- open the warnings and errors from that period in the Event explorer
- open the Alerts page
- show the period on the dashboards

The **Since last visit** button in the time-range bar returns to that period later.

**If you leave the app running but stop looking at it** (browser tab closed or hidden for more than 10 minutes, set by `[away] min_minutes`), the same panel appears when you come back.

Alerts found while catching up don't trigger one desktop notification each. You get a single "While you were away: N alerts" notification instead.

## What it alerts on

| Alert | Rule (defaults, all editable in `config.toml`) |
|---|---|
| Device gone silent | An AP or server that normally reports steadily sends nothing for 10 min (firewall 5 min). Bursty devices like switches are excluded. |
| Error spike | A device logs more than 3× its own usual rate of warnings/errors in 5 minutes. |
| New message type | A warning or error never seen before, once 2 hours of data have been learned. |
| Hardware sensor | ESXi/iLO reports any sensor that is not Green. |
| Switch port | A port flaps (3 downs in 15 min) or stays down more than 5 min. |
| Wi-Fi | AP restart (uptime reset), radio firmware resets, connection table full, low memory, APs unable to reach DNS (grouped into one ship-wide alert). |
| Firewall / security | VPN or proxy-bypass traffic, TCP flood, repeated port scans or spoofing, IKEv2 VPN errors, one device generating heavy blocked traffic, admin logins to APs. |
| Feed | Live mode only: no data received for 2 minutes. |

Alerts resolve themselves when the condition clears. **Acknowledge** hides an alert from the top strip but keeps it on the Alerts page. Click **Notify** in the top bar to get Windows desktop notifications; by default this covers warnings and criticals.

### Noise

About 300k of the ~950k sample messages are known-harmless chatter, such as the access points' `iot_radio_manage` heartbeat, `/dev/ttyUSB` errors, `err cnt: 0` and iLO "Production mode". These are still stored and searchable, but excluded from error counts and alerts. The built-in list is in `vship_monitor/noise.py`. Add your own patterns in `config.toml` under `[noise]`, or click **Hide** next to a message type on the Infrastructure page.

### Privacy

The firewall and Wi-Fi logs identify individual crew devices. By default, device MAC/IP addresses are replaced with stable pseudonyms (`Device-3FA2C1`) on screen and in the explorer. Set `mask_clients = false` only if your policy allows it. The raw data stays on the laptop.

---

## How it works

```
Graylog API ─┐
syslog 5514 ─┼─► parser ─► noise filter ─► state + alert rules ─► DuckDB file
CSV replay ──┘                                                     │
                       browser ◄── local web server (FastAPI) ◄────┘
```

| File | Purpose |
|---|---|
| `vship_monitor/parser.py` | Turns each log format (SonicWall key=value, AP syslog, ESXi/iLO, OmniSwitch) into one structured event: device, deck, severity, event type, client, app, etc. |
| `vship_monitor/noise.py` | Known-harmless message patterns |
| `vship_monitor/state.py` | Live picture: devices, last seen, rates, Wi-Fi clients, message types |
| `vship_monitor/alerts.py` | Alert rules |
| `vship_monitor/sources.py` | Graylog poller, syslog listener, CSV replay |
| `vship_monitor/store.py` | DuckDB storage (`data/vship.duckdb`) |
| `vship_monitor/app.py` | Pipeline, catch-up / "while you were away", and the web API |
| `vship_monitor/phone.py` | Tailscale detection, `tailscale serve` setup, QR codes for phone access |
| `vship_monitor/static/` | The dashboard (plain HTML/CSS/JS, no build step), home-screen icons and service worker |
| `tests/` | Parser tests from real sample lines (`python -m pytest`) |

Sizing from the sample: about 105k messages/hour, roughly 30 per second, with peaks near 750/s. Parsing runs at about 30k lines/s, and dashboard queries take around 0.1 s on 24 hours of data.

## Phone access

The web server stays bound to `127.0.0.1`. Phones reach it through **Tailscale**: `tailscale serve --bg <port>` publishes the dashboard at `https://<laptop>.<tailnet>.ts.net`, with a real TLS certificate, and only to devices in the same tailnet. No firewall rule, port forward or `0.0.0.0` binding is needed.

- On start-up (`[phone] tailscale = true`), `vship_monitor/phone.py` finds the Tailscale CLI, reads `tailscale status --json` and `tailscale serve status --json`, and prints the phone URL with a QR code in the console. With `auto_serve = true` it runs `tailscale serve --bg <port>` the first time. If HTTPS is not yet enabled for the tailnet, it captures and shows the enable link. It never replaces an existing serve config on `/` that points at another port.
- The **Phone** button (desktop only) calls `GET /api/phone[?refresh=1]` and shows the same URL and QR code as SVG, or a hint saying what is missing.
- `GET /manifest.webmanifest`, `/sw.js` and `static/icons/` provide home-screen install. The service worker doesn't cache anything (live data). It exists so Android can show alert notifications and to focus the app when one is tapped.
- Responses are gzip-compressed: about 6 KB per 5-second refresh instead of about 45 KB.
- The `.bat` launchers reinstall packages when `requirements.txt` changes (`qrcode` was added). If `qrcode` is missing, the URL is still shown, just without the QR code.

User steps for Android and iPhone are in [PHONE_ACCESS.md](PHONE_ACCESS.md).

## Known limitations

- **Parsing rules come from one 8-hour sample.** New device types or firmware may log lines that land in "other" or lack an event type. They are still stored, searchable and counted, and new warning/error types raise an alert. Add rules in `parser.py` as you meet them.
- **The Graylog connection was tested against a stand-in server, not V.Ships' Graylog.** The first connection is the thing to check: the status bar shows any error message. If you're on Graylog 4.x, set `api = "export"`.
- "Clients now" per access point counts devices seen associating in the last 15 minutes. It is an estimate, not the controller's exact client table.
- **Phone access needs the laptop running.** The phone only views the laptop's dashboard. Notifications on the phone arrive only while the dashboard is open there; there is no push service. Phone access was tested with phone emulation and a stand-in for the Tailscale command, not yet on a real phone and tailnet.
- The dashboard is for one vessel on one laptop. A fleet view would need a central server.
