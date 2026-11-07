# Seeing the dashboard on your phone

The monitor runs on your laptop. With **Tailscale** (free for personal use) you can open the same dashboard on your phone, on Wi-Fi or mobile data, from anywhere. Only phones and computers signed in to **your** Tailscale account can open it. It is never put on the public internet.

On the phone it has its own layout: the tabs move to a bottom bar, the cards stack in one column, wide tables scroll sideways, and you tap a chart to read its values. You can put it on your home screen, where it opens like an app.

> **Remember:** the phone shows the dashboard only while the laptop is on and the monitor window is open. The phone is a window onto the laptop.

---

## One-time setup (about 10 minutes)

### Step 1. Install Tailscale on the laptop

1. Go to **tailscale.com/download**, download the Windows version and install it.
2. Click **Log in** and sign in with a Google, Microsoft or Apple account. Use one you also have on your phone.
3. A small Tailscale icon appears near the clock. That means the laptop is connected.

### Step 2. Install Tailscale on the phone

- **Android:** install **Tailscale** from the Google Play Store.
- **iPhone:** install **Tailscale** from the App Store.

Open the app and sign in with **the same account** as on the laptop. Allow it to add a VPN configuration when asked. This is how the phone reaches the laptop privately. Then switch it **on**. Your laptop should appear in the app's list of devices.

### Step 3. Turn on two switches in the Tailscale admin page (once)

1. On the laptop, open **login.tailscale.com/admin/dns** and sign in.
2. Under **MagicDNS**, make sure it says *Enabled*. If not, click **Enable MagicDNS**.
3. Under **HTTPS Certificates**, click **Enable HTTPS**.

This gives the laptop a private web address like `https://your-laptop.tail1234.ts.net`.

### Step 4. Start the monitor and scan the code

1. Double-click `start_demo.bat` (or `start.bat` for the live feed) as usual.
2. The first time, the monitor sets up the private address by itself and prints it in the black window, with a **QR code**:

   ```
   On your phone (Tailscale):  https://your-laptop.tail1234.ts.net
   Scan this with the phone's camera:
   ```

   You can also click the **Phone** button at the top of the dashboard on the laptop to see the same code.
3. Point the phone's camera at the code and tap the link that appears.

The first time the page opens, it may take a few seconds while the secure connection is set up.

### Step 5. Put it on your home screen

- **Android (Chrome):** tap the **⋮** menu (top right), then **Add to Home screen**, then **Add**.
- **iPhone (Safari):** tap the **Share** button (square with an arrow), scroll down, tap **Add to Home Screen**, then **Add**.
  On iPhone this only works in **Safari**, not in Chrome or other browsers.

A ship icon called **Vessel Net** appears. From now on, tap it to open the dashboard.

---

## Every day

1. Start the monitor on the laptop (double-click the .bat file).
2. Make sure Tailscale is **on** on the phone.
3. Tap **Vessel Net** on the phone.

The phone shows the same live data as the laptop and refreshes by itself every few seconds. The **"While you were away"** summary also appears on the phone, on whichever screen you open first after a break.

**Alerts on the phone (optional):** tap the bell at the top to get a notification for new alerts. This works:
- on **Android**, in Chrome or from the home-screen icon;
- on **iPhone**, only from the home-screen icon (iOS 16.4 or newer). The bell is hidden in normal Safari.

Notifications arrive only while the dashboard is open on the phone. A locked phone or a closed app doesn't receive them.

**Mobile data:** each refresh is about 6 KB, so roughly 5 MB per hour while the dashboard is open on screen. When the phone screen is off, it uses nothing.

---

## If something doesn't work

| What you see | What to do |
|---|---|
| The black window says *"Tailscale is not installed"* | Do Step 1, then close and reopen the monitor. |
| *"Tailscale is installed but not connected"* | Click the Tailscale icon near the clock and **Log in** / **Connect**. |
| *"HTTPS is turned off for your Tailscale network"* (with a link) | Open the link, or do Step 3. Then click **Check again** in the dashboard's **Phone** pop-up. |
| *"…already used by another 'tailscale serve' setting"* | Something else on the laptop already uses the private address. Ask IT, or if nothing else needs it, run `tailscale serve reset` in a Command Prompt and restart the monitor. |
| *"Tailscale refused the setup command"* | Open **Command Prompt as administrator** and run `tailscale serve --bg 8080` once. |
| The phone says *"This site can't be reached"* / *"Safari cannot open the page"* | (1) Is Tailscale **on** on the phone? (2) Is the laptop awake, with the monitor window open? (3) Is the phone signed in to the **same** Tailscale account? |
| The page opens but says **OFFLINE** at the top | The laptop's monitor window was closed or the laptop went to sleep. Start it again. The phone reconnects by itself. |
| Ship WiFi blocks Tailscale | Some ship or office networks block VPNs. Try on mobile data, or ask IT to allow Tailscale. |

**Keep the laptop awake:** in Windows Settings → System → Power, set "When plugged in, put my device to sleep after" to **Never** while you rely on the phone.

---

## Good to know

- **Who can see it:** only devices signed in to your Tailscale account, plus anyone you deliberately share the laptop with in Tailscale. Don't turn on Tailscale **Funnel** for this, because that would make the dashboard public.
- **Nothing changes on the laptop's firewall or router.** The dashboard still listens only on the laptop itself. Tailscale carries it to your phone over an encrypted connection.
- **Turning phone access off:** in `config.toml`, under `[phone]`, set `tailscale = false`. To remove the private address, run `tailscale serve reset`.
- **Several people:** each person installs Tailscale and signs in to the same account. Or the account owner invites them in the Tailscale admin page. Everyone sees the same dashboard.
