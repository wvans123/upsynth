"""Does a page really stream? Prints MB received per 5 s on an interface while the page is open.

Usage: probe.py <url> [seconds] [chromium|firefox] [mobile|desktop] [iface]
"""

import sys
import time

from playwright.sync_api import sync_playwright

url = sys.argv[1]
secs = float(sys.argv[2]) if len(sys.argv) > 2 else 40
engine = sys.argv[3] if len(sys.argv) > 3 else "firefox"
mobile = (sys.argv[4] if len(sys.argv) > 4 else "desktop") == "mobile"
iface = sys.argv[5] if len(sys.argv) > 5 else "eth0"


def rx() -> int:
    for line in open("/proc/net/dev"):
        if line.strip().startswith(iface + ":"):
            return int(line.split(":")[1].split()[0])
    return 0


with sync_playwright() as p:
    bt = getattr(p, engine)
    opts = {"args": ["--no-sandbox", "--autoplay-policy=no-user-gesture-required"]} if engine == "chromium" else {
        "firefox_user_prefs": {"media.autoplay.default": 0, "media.autoplay.blocking_policy": 0}}
    b = bt.launch(**opts)
    ctx = b.new_context(**(p.devices["Pixel 7"] if mobile and engine == "chromium" else {}), locale="zh-CN")
    page = ctx.new_page()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
    except Exception as e:
        print("goto:", str(e).splitlines()[0])
    page.evaluate("() => document.querySelectorAll('video').forEach(v => { v.muted = true; v.play(); })")
    last, t0 = rx(), time.time()
    marks = []
    while time.time() - t0 < secs:
        time.sleep(5)
        now = rx()
        marks.append(round((now - last) / 1e6, 2))
        last = now
    state = page.evaluate("() => [...document.querySelectorAll('video')].map(v => [v.paused, Math.round(v.currentTime), v.readyState])")
    print(engine, url[:60], "| MB per 5 s:", marks, "| video [paused, t, ready]:", state, "| title:", page.title()[:30])
    b.close()
