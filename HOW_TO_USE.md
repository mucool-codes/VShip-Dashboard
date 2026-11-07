# How to use the Vessel Network Monitor

This guide is for the person who uses the dashboard day to day. (Technical details are in `README.md`.)

The monitor watches the ship's network logs (Wi-Fi access points, servers, switches and the firewall) and shows on one screen what is working, what is not, and what changed. It runs on your laptop and opens in your web browser. It doesn't need an internet connection.

You can also open the same dashboard **on your phone** (Android or iPhone), laid out for a small screen. It updates live, together with the laptop.

---

## Quick start

**First time only:**
1. Install Python (section 1, step 1).
2. Double-click `start.bat`, fill in the Graylog address and token, save, then double-click `start.bat` again (section 1).
3. *(Optional, for the phone)* Set up Tailscale on the laptop and phone (section 3).

**Every day:**
1. Double-click **`start.bat`**. The dashboard opens in your browser.
2. If you were away, read the **"While you were away"** summary, then click **Got it - go live**.
3. Look at the status chips at the top. Anything ▲ amber or ■ red needs a look. Open the **Alerts** tab for details.
4. *(Phone)* Tap the **Vessel Net** icon on your phone to see the same dashboard while you're away from the laptop.
5. Leave the black window open (you can minimise it). Close it when you want to stop monitoring.

---

## 1. One-time setup (laptop)

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
   - The first start installs what it needs, which takes about a minute. It does the same automatically after an update.
   - Then the dashboard opens in your browser at **http://localhost:8080**.

> **Asking IT for a token:** ask the Graylog administrator for "a read-only Graylog user and access token for the vessel network dashboard". It is a standard Graylog feature and costs nothing.

> **If Windows Firewall asks** whether to allow Python, click *Allow* on private networks.

---

## 2. Every day

| To… | Do this |
|---|---|
| **Start the monitor** | Double-click `start.bat`. A black window opens, then the dashboard opens in your browser. |
| **Stop the monitor** | Close the black window. (The phone then shows **OFFLINE** too.) |
| **Reopen the dashboard** if you closed the browser | Double-click `start.bat` again, or go to http://localhost:8080. If the monitor is already running, it just reopens the page. |
| **Open it on your phone** | Tap the **Vessel Net** icon (after the phone setup in section 3). |
| **Show the phone address / QR code again** | Click **Phone** at the top of the dashboard on the laptop. |

**Keep the black window open** while you want the monitor to watch the ship. You can minimise it. It checks Graylog for new messages every 5 seconds, so a new problem shows up on the dashboard within about 5 to 15 seconds.

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
| **Got it - go live** | Closes the summary; the dashboard continues in real time |
| **Show warnings & errors in explorer** | Lists every warning and error from that period |
| **Open alerts page** | Goes to the full list of alerts |
| **Show this period on the dashboards** | Switches the charts to just that period |

The same summary also appears if the monitor was left running but nobody looked at the dashboard (on the laptop **or** the phone) for more than 10 minutes. Later, the **Since last visit** button (next to *15 min / 1 hour / …*) shows that period again.

---

## 3. Using it on your phone

### Setting up the phone (once, about 10 minutes)

The phone connects to the laptop privately through a free app called **Tailscale**. Only phones and computers signed in to **your** Tailscale account can open the dashboard. It is never on the public internet.

1. **Laptop:** install Tailscale from **tailscale.com/download** and sign in (Google, Microsoft or Apple account).
2. **Phone:** install **Tailscale** from the Play Store (Android) or App Store (iPhone). Sign in with the **same account** and switch it **on**.
3. **Once, in the Tailscale admin page** (login.tailscale.com/admin/dns): turn on **MagicDNS** and **HTTPS Certificates**.
4. **Start the monitor** (`start.bat` or `start_demo.bat`). The black window shows the phone address and a **QR code**. You can also click **Phone** at the top of the dashboard on the laptop.
5. **Scan the QR code** with the phone's camera and tap the link.
6. **Add it to your home screen:**
   - **Android (Chrome):** ⋮ menu → **Add to Home screen** → **Add**
   - **iPhone (Safari):** Share button → **Add to Home Screen** → **Add**. On iPhone this has to be done in Safari.

A ship icon called **Vessel Net** appears. Tap it to open the dashboard full screen, like an app.

Step-by-step help and fixes is in **[PHONE_ACCESS.md](PHONE_ACCESS.md)**.

### Finding your way around on the phone

The phone shows the same four tabs, re-arranged for a small screen:

- **Top:** ship name, the status chips (swipe sideways to see them all), the bell and the moon icon.
- **Just below:** the time range (*15 min · 1 hour · …*). It stays at the top while you scroll. Swipe it sideways if it doesn't fit.
- **Bottom bar:** the four tabs: **Health**, **Security**, **Alerts** (with the number of active alerts) and **Explorer**.
- **Cards** are stacked in one column. Scroll down to see everything.
- **Charts:** tap anywhere on a chart to see the exact numbers for that time. Drag your finger sideways to move along the chart. Tap elsewhere to hide the numbers.
- **Wide tables** scroll sideways: swipe left on the table.
- **Devices:** tap an access-point tile or a device name to open its details full screen. Tap **✕** to close.
- The top of the dashboard shows at most two alerts; tap **"… more alerts"** to see the rest.

### What the laptop and phone share

The phone and the laptop are two windows onto the **same** monitor on the laptop. New data, alerts and changes appear on both within about 5 seconds.

| Shared (a change shows on both) | Separate on each device |
|---|---|
| All the data, charts and alerts | Which tab is open |
| **Acknowledge** on an alert | The time range you picked |
| **Hide** a message type as noise | Dark / light theme |
| The **"While you were away"** summary. Checking on one counts as a visit; dismissing it clears it on both. | The bell (notifications) setting |

So the laptop can show *Infrastructure health* for 7 days while the phone shows *Alerts* for 15 minutes, and both stay live.

### Alerts on the phone

Tap the **bell** at the top and allow notifications. You get a notification for each new warning or critical alert.
- **Android:** works in Chrome and from the home-screen icon.
- **iPhone:** works only from the home-screen icon (iOS 16.4 or newer). The bell is hidden in normal Safari.

Notifications only arrive **while the dashboard is open on the phone**. A locked phone or a closed app doesn't get them.

### Things to remember

- The phone works only while the **laptop is awake** and the **black window is open**. Set Windows not to sleep when plugged in (Settings → System → Power).
- Tailscale must be **on** on the phone.
- On mobile data it uses about **5 MB per hour** while the dashboard is open on screen, and nothing when the screen is off.

---

## 4. Reading the screen

### Top bar

- **LIVE** (green) means data is arriving. **FEED ERROR** (red) means the monitor can't reach the log server; the message next to it says why. **OFFLINE** means the page can't reach the monitor (the black window was closed or the laptop is asleep).
- **Status chips: Wi-Fi · Servers · Switches · Firewall · Security · Feed.** Each one shows the worst current problem in that area:
  - ● **OK** - nothing wrong
  - ▲ **Warning** - something needs a look
  - ■ **Critical** - act now
- **Phone** (laptop only) shows the phone address and QR code.
- **Notify / bell** turns on pop-up notifications for new warnings and critical alerts. Click it once and allow notifications when the browser asks.
- The **moon icon** switches between dark and light mode.

### Time range

**15 min · 1 hour · 6 hours · 24 hours · 7 days · Since last visit** - changes the period for all charts and tables. The screen refreshes itself every 5 seconds.

### Tab 1 - Infrastructure health ("Health" on the phone)

For keeping the ship's network running.

- **Summary tiles** - how many access points and servers are reporting, switch ports down, Wi-Fi devices and total warnings.
- **Warnings and errors chart** - one line per device type. Hover (or tap on the phone) to see exact numbers. A sudden spike means something changed.
- **Wi-Fi access points by deck** - one tile per access point, grouped by deck:
  - ● green = fine
  - ▲ amber = warning
  - ■ red = critical
  - ○ dashed = **silent**, meaning it has stopped sending anything (possibly powered off or disconnected)

  Each tile shows the number of connected devices. **Click a tile** to see that access point's details.
- **Servers** - the two ESXi servers. It shows whether each is reporting and whether its hardware sensors (fans, power, temperature, disks) are all green.
- **Switches** - ports that are down or keep going up and down ("flapping").
- **Top warning and error types** - the most frequent problems. If one is known to be harmless, click **Hide** so it stops counting as a warning. It is still kept and searchable.

### Tab 2 - Internet & security ("Security" on the phone)

For crew internet use and cyber security.

- **Summary tiles** - firewall events, the share blocked, security events and VPN/proxy-bypass attempts.
- **Firewall decisions over time** - blocked (orange) versus allowed (blue).
- **Top applications** - which apps are being blocked or allowed, for example TikTok and YouTube.
- **Blocked traffic by deck** - where on the ship the blocked traffic comes from. The location is taken from the Wi-Fi access point the device last connected to.
- **Most active devices** - devices generating the most traffic. They are shown as codes like `Device-3FA2C1` to protect crew privacy.
- **Security events** - port scans, spoofing, floods, intrusion-prevention hits, VPN tunnel errors and attempts to get around the filter.

### Tab 3 - Alerts

All current alerts. Switch to **History** to see older ones.

- **Acknowledge** hides an alert from the banner at the top of the dashboards, on the laptop and the phone. It stays on this page until the problem clears.
- Alerts **resolve themselves** when the problem stops.
- **Device** opens the affected device.

### Tab 4 - Event explorer ("Explorer" on the phone)

Search the raw log messages, for example to find out what happened on one access point at 03:00.

- Type a word (a deck name, an app name, "link", "error"…).
- Choose the device type, a device name and the severity.
- Keep **Hide noise** ticked to leave out known harmless chatter.
- Click **Search**. The newest messages are shown first.

### Device details

Clicking any device name or access point tile opens a panel (full screen on the phone) with:
- when it was last heard from, uptime and restarts
- an activity chart
- its alerts
- the kinds of messages it sends
- connected devices (for access points)
- its latest log lines

Press **Esc** or **✕** to close it.

---

## 5. What the alerts mean

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

## 6. If something goes wrong

| Problem | Fix |
|---|---|
| Double-clicking `start.bat` closes straight away, or says Python is missing | Install Python (section 1) and make sure "Add python.exe to PATH" was ticked. |
| The top bar says **FEED ERROR** | Read the message next to it. Usually the Graylog address or token in `config.toml` is wrong, or the laptop isn't on the ship network. |
| "Port 8080 is used by another program" | Open `config.toml`, change `port = 8080` under `[server]` to `8081`, then restart. |
| The page says **OFFLINE** | The black window was closed or the laptop went to sleep. Double-click `start.bat`. The phone reconnects by itself. |
| Notifications don't appear | Click **Notify** / the bell, allow notifications in the browser, and check Windows "Focus assist / Do not disturb" is off. On the phone, the dashboard must be open on screen. |
| The "While you were away" summary didn't appear | It only appears after being away for at least 10 minutes, on both the laptop and the phone. If you checked on the phone, the laptop won't show it again. |
| The black window says Tailscale is not installed / not connected | Install Tailscale on the laptop or sign in to it (section 3). |
| It says **HTTPS is turned off** for Tailscale | Open the link it shows, or turn on HTTPS Certificates in the Tailscale admin page. Then click **Check again** in the **Phone** pop-up. |
| The phone says "This site can't be reached" | Check: Tailscale is **on** on the phone; the laptop is awake with the black window open; the phone uses the **same** Tailscale account. Some ship or office Wi-Fi blocks Tailscale; try mobile data. |

More phone fixes are in [PHONE_ACCESS.md](PHONE_ACCESS.md).

---

## 7. Trying it without the ship connection (demo)

To see how it works using a saved log file (a Graylog CSV export):

1. Put the `.csv` file in the `VShip-Dashboard` folder.
2. Double-click **`start_demo.bat`**.
3. *(Optional)* Open it on your phone the same way as the live version: scan the QR code in the black window.

The file plays back at 60× speed, so one hour of data plays in one minute. If you close it and start it again later, it carries on from where it stopped and shows a "While you were away" summary. To play the file from the beginning, delete the `data` folder first.

---

## 8. Good to know

- **Phone:** the phone shows the laptop's dashboard, so it works only while the laptop is awake and the monitor window is open. Only devices signed in to your Tailscale account can open it. To switch phone access off, set `tailscale = false` under `[phone]` in `config.toml`.
- **Privacy:** crew devices are shown as codes (`Device-3FA2C1`), not by their real addresses. Check your company policy before changing this (`mask_clients` in `config.toml`).
- **Storage:** everything stays on this laptop, in the `data` folder. Messages older than 14 days are deleted automatically. You can change this with `retention_days` in `config.toml`.
- **Settings:** alert thresholds such as how many minutes before a device counts as silent are in `config.toml`, with a comment on each line. Restart the monitor after changing them.
