# How to use the Vessel Network Monitor

This guide is for the person who uses the dashboard day to day. (Technical details are in `README.md`.)

The monitor watches the ship's network logs (Wi-Fi access points, servers, switches and the firewall) and shows on one screen what is working, what is not, and what changed. It runs on your laptop and opens in your web browser. It does not need an internet connection.

---

## 1. One-time setup

You need Windows and about 10 minutes.

1. **Install Python.**
   - Go to <https://www.python.org/downloads/>, download the latest version and run the installer.
   - On the first screen, **tick "Add python.exe to PATH"**, then click *Install Now*.
2. **Copy the `VShip-Dashboard` folder** to your laptop, for example to `D:\VShip-Dashboard`.
3. **Connect it to the ship's log server (Graylog).**
   - Double-click **`start.bat`**. The first time, it creates a settings file called `config.toml` and opens it in Notepad.
   - Fill in these lines. Your IT / Graylog administrator can give you both values:
     ```
     [vessel]
     name = "MV Your Ship Name"

     [graylog]
     url = "http://<Graylog address>:9000"
     token = "<your Graylog access token>"
     ```
   - Save the file (Ctrl+S) and close Notepad.
4. **Double-click `start.bat` again.**
   - The first start installs what it needs, which takes about a minute.
   - Then the dashboard opens in your browser at **http://localhost:8080**.

> **Asking IT for a token:** ask the Graylog administrator for "a read-only Graylog user and access token for the vessel network dashboard". It is a standard Graylog feature and costs nothing.

> **If Windows Firewall asks** whether to allow Python, click *Allow* on private networks.

---

## 2. Every day

| To… | Do this |
|---|---|
| **Start the monitor** | Double-click `start.bat`. A black window opens, then the dashboard opens in your browser. |
| **Stop the monitor** | Close the black window. |
| **Reopen the dashboard** if you closed the browser | Double-click `start.bat` again, or go to http://localhost:8080. If the monitor is already running, it just reopens the page. |

**Keep the black window open** while you want the monitor to watch the ship. You can minimise it.

### Coming back after a break

When you start the monitor again after it was closed, it first **catches up on everything that happened while it was off**. A progress bar shows while it loads. You then see a **"While you were away"** summary:

- the period you were away, for example *Fri 18:40 → Sat 09:15 · 14 h 35 min*
- every alert raised in that time, most serious first, marked **still active** or **resolved**
- a chart of warnings and errors over that period
- a short "what happened" list, for example *2 DNS outages · 3 flapping switch ports*
- any new kinds of error the system had never seen before
- firewall totals and any attack or bypass attempts

Buttons at the bottom of the summary:

| Button | What it does |
|---|---|
| **Show warnings & errors in explorer** | Lists every warning and error from that period |
| **Open alerts page** | Goes to the full list of alerts |
| **Show this period on the dashboards** | Switches the charts to just that period |
| **Got it - go live** | Closes the summary; the dashboard continues in real time |

The same summary also appears if the monitor was left running but you didn't look at the dashboard for more than 10 minutes. Later, the **Since last visit** button (top right, next to *15 min / 1 hour / …*) shows that period again.

---

## 3. Reading the screen

### Top bar

- **LIVE** (green) means data is arriving. **FEED ERROR** (red) means the monitor can't reach the log server; the message next to it says why.
- **Status chips: Wi-Fi · Servers · Switches · Firewall · Security · Feed.** Each one shows the worst current problem in that area:
  - ● **OK** - nothing wrong
  - ▲ **Warning** - something needs a look
  - ■ **Critical** - act now
- **Notify** turns on Windows pop-up notifications for new warnings and critical alerts. Click it once and allow notifications when the browser asks.
- The **moon icon** switches between dark and light mode.

### Time range (top right)

**15 min · 1 hour · 6 hours · 24 hours · 7 days · Since last visit** - changes the period for all charts and tables. The screen refreshes itself every 5 seconds.

### Tab 1 - Infrastructure health

For keeping the ship's network running.

- **Summary tiles** - how many access points and servers are reporting, switch ports down, Wi-Fi devices and total warnings.
- **Warnings and errors chart** - one line per device type. Hover to see exact numbers. A sudden spike means something changed.
- **Wi-Fi access points by deck** - one tile per access point, grouped by deck:
  - ● green = fine
  - ▲ amber = warning
  - ■ red = critical
  - ○ dashed = **silent**, meaning it has stopped sending anything (possibly powered off or disconnected)

  Each tile shows the number of connected devices. **Click a tile** to see that access point's details.
- **Servers** - the two ESXi servers. It shows whether each is reporting and whether its hardware sensors (fans, power, temperature, disks) are all green.
- **Switches** - ports that are down or keep going up and down ("flapping").
- **Top warning and error types** - the most frequent problems. If one is known to be harmless, click **Hide** so it stops counting as a warning. It is still kept and searchable.

### Tab 2 - Internet & security

For crew internet use and cyber security.

- **Summary tiles** - firewall events, the share blocked, security events and VPN/proxy-bypass attempts.
- **Firewall decisions over time** - blocked (orange) versus allowed (blue).
- **Top applications** - which apps are being blocked or allowed, for example TikTok and YouTube.
- **Blocked traffic by deck** - where on the ship the blocked traffic comes from. The location is taken from the Wi-Fi access point the device last connected to.
- **Most active devices** - devices generating the most traffic. They are shown as codes like `Device-3FA2C1` to protect crew privacy.
- **Security events** - port scans, spoofing, floods, intrusion-prevention hits, VPN tunnel errors and attempts to get around the filter.

### Tab 3 - Alerts

All current alerts. Switch to **History** to see older ones.

- **Acknowledge** hides an alert from the banner at the top of the dashboards. It stays on this page until the problem clears.
- Alerts **resolve themselves** when the problem stops.
- **Device** opens the affected device.

### Tab 4 - Event explorer

Search the raw log messages, for example to find out what happened on one access point at 03:00.

- Type a word (a deck name, an app name, "link", "error"…).
- Choose the device type, a device name and the severity.
- Keep **Hide noise** ticked to leave out known harmless chatter.
- Click **Search**. The newest messages are shown first.

### Device details

Clicking any device name or access point tile opens a panel on the right with:
- when it was last heard from, uptime and restarts
- an activity chart
- its alerts
- the kinds of messages it sends
- connected devices (for access points)
- its latest log lines

Press **Esc** to close it.

---

## 4. What the alerts mean

| Alert | What it means | Typical first step |
|---|---|---|
| **… has gone silent** | A device that normally reports constantly has sent nothing for 10 minutes (firewall: 5 minutes). | Check that it has power and a network connection. If a whole deck goes silent, check that deck's switch. |
| **Error spike on …** | A device is logging at least 3 times more errors than usual. | Open the device and look at its latest messages. |
| **Hardware sensor not green** | A server reports a fan, power, temperature or disk problem. | Check the server's iLO / hardware status and inform IT. |
| **Port … is flapping / is down** | A switch port keeps dropping, or has been down for over 5 minutes. | Check the cable and the device on that port. |
| **… restarted / radio resetting repeatedly** | An access point rebooted, or its Wi-Fi radio keeps resetting. | If it repeats, the AP may be faulty or overheating. |
| **N access points cannot reach DNS** | Access points can't resolve web addresses. This is usually ship-wide. | Check the DNS server and the ship's internet uplink. |
| **VPN / proxy-bypass traffic** | Devices are trying to get around the internet filter. | Review against crew internet policy. |
| **Repeated scanning / spoofing** | Something outside (or inside) is probing the network. | Inform IT / security. |
| **Possible TCP flood** | The firewall sees a flood of connection attempts. | Inform IT / security immediately. |
| **New warning / error type** | A kind of problem never seen before on this ship. | Read it, and click *Hide* if it is harmless. |
| **No log data is arriving** | The monitor isn't receiving anything at all. | Check the laptop is on the ship network and the log server is up. |

---

## 5. If something goes wrong

| Problem | Fix |
|---|---|
| Double-clicking `start.bat` closes straight away, or says Python is missing | Install Python (step 1) and make sure "Add python.exe to PATH" was ticked. |
| The top bar says **FEED ERROR** | Read the message next to it. Usually the Graylog address or token in `config.toml` is wrong, or the laptop isn't on the ship network. |
| "Port 8080 is used by another program" | Open `config.toml`, change `port = 8080` under `[server]` to `8081`, then restart. |
| The page says **OFFLINE** | The black window was closed. Double-click `start.bat`. |
| Notifications don't appear | Click **Notify** in the top bar, allow notifications in the browser, and check Windows "Focus assist / Do not disturb" is off. |
| The "While you were away" summary didn't appear | It only appears after being away for at least 10 minutes. |

---

## 6. Trying it without the ship connection (demo)

To see how it works using a saved log file (a Graylog CSV export):

1. Put the `.csv` file in the `VShip-Dashboard` folder.
2. Double-click **`start_demo.bat`**.

The file plays back at 60× speed, so one hour of data plays in one minute. If you close it and start it again later, it carries on from where it stopped and shows a "While you were away" summary. To play the file from the beginning, delete the `data` folder first.

---

## 7. Good to know

- **Privacy:** crew devices are shown as codes (`Device-3FA2C1`), not by their real addresses. Check your company policy before changing this (`mask_clients` in `config.toml`).
- **Storage:** everything stays on this laptop, in the `data` folder. Messages older than 14 days are deleted automatically. You can change this with `retention_days` in `config.toml`.
- **Settings:** alert thresholds such as how many minutes before a device counts as silent are in `config.toml`, with a comment on each line. Restart the monitor after changing them.
