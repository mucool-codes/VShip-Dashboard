"""Open the dashboard on a phone, through Tailscale.

The dashboard itself only listens on this laptop (127.0.0.1). `tailscale serve`
makes it reachable as https://<laptop>.<tailnet>.ts.net - but only from devices
signed in to the same Tailscale account, never from the open internet.

This module finds that address, sets up `tailscale serve` if it isn't yet
(when [phone] auto_serve is on), and draws a QR code for the phone to scan.
Everything here is best-effort: if Tailscale is missing, the monitor runs
exactly as before and just prints a hint.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

log = logging.getLogger("vship.phone")

GUIDE = "PHONE_ACCESS.md"
_CANDIDATES = [
    r"C:\Program Files\Tailscale\tailscale.exe",
    r"C:\Program Files (x86)\Tailscale\tailscale.exe",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
]


def tailscale_exe() -> str | None:
    exe = shutil.which("tailscale")
    if exe:
        return exe
    for p in _CANDIDATES:
        if Path(p).exists():
            return p
    return None


def _run(args: list[str], timeout: float = 8) -> tuple[int, str]:
    """Run a command, hide its console window on Windows, return (code, output)."""
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL, **kw)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        out = e.stdout or b""
        err = e.stderr or b""
        out = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
        err = err.decode("utf-8", "replace") if isinstance(err, bytes) else err
        return -1, out + err
    except OSError as e:
        return -2, str(e)


def _json(text: str) -> dict:
    try:
        i = text.index("{")
        return json.loads(text[i:])
    except (ValueError, json.JSONDecodeError):
        return {}


def _serving(serve_cfg: dict, dns: str, port: int) -> str | None:
    """Return the https URL if `tailscale serve` already forwards to our port."""
    for hostport, web in (serve_cfg.get("Web") or {}).items():
        host, _, hport = hostport.rpartition(":")
        if host.rstrip(".").lower() != dns.lower():
            continue
        for path, handler in (web.get("Handlers") or {}).items():
            proxy = str(handler.get("Proxy") or "")
            if path == "/" and re.search(rf"(^|:){port}/?$", proxy):
                return f"https://{dns}" + ("" if hport == "443" else f":{hport}")
    return None


def _root_taken(serve_cfg: dict, dns: str) -> bool:
    """Is https://<dns>/ already used by something else? Then we leave it alone."""
    for hostport, web in (serve_cfg.get("Web") or {}).items():
        host, _, hport = hostport.rpartition(":")
        if host.rstrip(".").lower() == dns.lower() and hport == "443" and "/" in (web.get("Handlers") or {}):
            return True
    return False


def check(port: int, auto_serve: bool = False) -> dict:
    """Work out how (and whether) a phone can open the dashboard right now."""
    info = {"installed": False, "running": False, "https": False, "serving": False,
            "url": None, "hint": None, "enable_url": None, "command": f"tailscale serve --bg {port}"}
    exe = tailscale_exe()
    if not exe:
        info["hint"] = (f"Tailscale is not installed on this laptop, so your phone can't reach the dashboard yet. "
                        f"Install it from tailscale.com/download - see {GUIDE}.")
        return info
    info["installed"] = True

    code, out = _run([exe, "status", "--json"])
    st = _json(out)
    if st.get("BackendState") != "Running" or not st.get("Self"):
        info["hint"] = "Tailscale is installed but not connected. Open Tailscale on this laptop and sign in."
        return info
    info["running"] = True
    dns = (st["Self"].get("DNSName") or "").rstrip(".")
    if not dns:
        info["hint"] = ("Tailscale has no name for this laptop. In the Tailscale admin page, open DNS and "
                        "turn on MagicDNS, then click Check again.")
        return info
    info["dns"] = dns
    info["https"] = bool(st.get("CertDomains"))

    code, out = _run([exe, "serve", "status", "--json"])
    cfg = _json(out)
    url = _serving(cfg, dns, port)
    if not url and auto_serve and not _root_taken(cfg, dns):
        # First time: point https://<laptop>.ts.net at the dashboard. If HTTPS isn't
        # enabled for the tailnet yet, Tailscale prints a link to turn it on and waits.
        log.info("setting up 'tailscale serve' for port %s", port)
        code, out = _run([exe, "serve", "--bg", str(port)], timeout=20)
        m = re.search(r"https://login\.tailscale\.com/\S+", out)
        if m:
            info["enable_url"] = m.group(0).rstrip(".,)")
        code2, out2 = _run([exe, "serve", "status", "--json"])
        url = _serving(_json(out2), dns, port)
        if not url and code not in (0, -1):
            log.warning("tailscale serve failed: %s", out.strip()[:300])
            if re.search(r"access denied|permission|operator", out, re.I):
                info["hint"] = ("Tailscale refused the setup command. Open a Command Prompt as administrator "
                                f"and run:  {info['command']}")
    if url:
        info.update(serving=True, url=url)
        return info
    if info["hint"]:
        return info
    if info["enable_url"] or not info["https"]:
        info["hint"] = ("One switch left: HTTPS is turned off for your Tailscale network. Open the link below "
                        "(or the Tailscale admin page → DNS → HTTPS Certificates → Enable), then click Check again.")
    elif _root_taken(cfg, dns):
        info["hint"] = (f"https://{dns}/ is already used by another 'tailscale serve' setting on this laptop. "
                        f"Free it with 'tailscale serve reset', or see {GUIDE}.")
    else:
        info["hint"] = f"Tailscale is connected, but the dashboard isn't shared to your phone yet. Run this once:  {info['command']}"
    return info


# ---------------------------------------------------------------- QR code
def _matrix(text: str, border: int = 2):
    try:
        import qrcode
    except ImportError:
        return None
    qr = qrcode.QRCode(border=border, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(text)
    qr.make(fit=True)
    return qr.get_matrix()          # True = dark module, includes the quiet zone


def qr_svg(text: str) -> str | None:
    m = _matrix(text)
    if m is None:
        return None
    n = len(m)
    d = "".join(f"M{x},{y}h1v1h-1z" for y, row in enumerate(m) for x, v in enumerate(row) if v)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" shape-rendering="crispEdges" '
            f'role="img" aria-label="QR code for {text}"><rect width="{n}" height="{n}" fill="#fff"/>'
            f'<path d="{d}" fill="#000"/></svg>')


def qr_text(text: str) -> str | None:
    """QR code drawn with block characters, two rows per line, for the console
    window. Dark modules print as spaces and light ones as blocks, so it reads
    correctly on the usual black console background."""
    m = _matrix(text, border=3)
    if m is None:
        return None
    if len(m) % 2:
        m = m + [[False] * len(m[0])]
    lines = []
    for y in range(0, len(m), 2):
        top, bot = m[y], m[y + 1]
        lines.append("  " + "".join(
            " " if t and b else "▄" if t else "▀" if b else "█" for t, b in zip(top, bot)))
    return "\n".join(lines)


# ---------------------------------------------------------------- cached state
class Phone:
    def __init__(self, port: int, auto_serve: bool = True):
        self.port, self.auto_serve = port, auto_serve
        self._info: dict | None = None
        self._at = 0.0
        self._lock = threading.Lock()

    def info(self, refresh: bool = False) -> dict:
        with self._lock:
            if refresh or self._info is None or time.time() - self._at > 60:
                try:
                    # only try to set things up on startup / "Check again", not on every cache refresh
                    self._info = check(self.port, self.auto_serve and refresh)
                except Exception as e:      # never let this break the dashboard
                    log.warning("phone check failed: %s", e)
                    self._info = {"hint": f"Couldn't check Tailscale: {e}"}
                self._at = time.time()
            out = dict(self._info)
        if out.get("url"):
            out["qr_svg"] = qr_svg(out["url"])
        return out

    def announce(self) -> None:
        """Print the phone address (and a QR code) in the console window."""
        try:
            self._announce()
        except Exception as e:          # e.g. a console that can't show the QR characters
            log.warning("couldn't print phone address: %s", e)

    def _announce(self) -> None:
        info = self.info(refresh=True)
        if info.get("url"):
            print(f"\n  On your phone (Tailscale):  {info['url']}")
            q = qr_text(info["url"])
            if q:
                try:
                    print("  Scan this with the phone's camera:\n")
                    print(q)
                except UnicodeEncodeError:
                    pass
            print("  (or click the Phone button at the top of the dashboard)\n")
        else:
            print(f"\n  Phone access: {info.get('hint')}".replace("→", ">"))
            if info.get("enable_url"):
                print(f"  Turn on HTTPS here: {info['enable_url']}")
            print()
