"""Does a video / live page really stream in this browser? Prints downlink bytes per 5 s from media hosts.

Usage: probe_play.py firefox|chromium vod|live [seconds]
"""

import re
import sys
import time
from collections import Counter
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

browser_name, kind = sys.argv[1], sys.argv[2]
secs = float(sys.argv[3]) if len(sys.argv) > 3 else 40
MEDIA = re.compile(r"bilivideo|smtcdns|akamaized|mcdn|szbdyd")
got = Counter()

with sync_playwright() as p:
    bt = getattr(p, browser_name)
    b = bt.launch(args=["--no-sandbox", "--autoplay-policy=no-user-gesture-required"] if browser_name == "chromium" else [],
                  firefox_user_prefs={"media.autoplay.default": 0, "media.autoplay.blocking_policy": 0} if browser_name == "firefox" else None)
    page = b.new_context(locale="zh-CN", viewport={"width": 1280, "height": 800}).new_page()
    t0 = time.time()

    def on_resp(r):
        host = urlparse(r.url).hostname or ""
        if MEDIA.search(host):
            try:
                got[int((time.time() - t0) // 5)] += len(r.body())
            except Exception:
                pass

    page.on("response", on_resp)
    if kind == "vod":
        page.goto("https://www.bilibili.com/v/popular/all", wait_until="domcontentloaded", timeout=30000)
        time.sleep(4)
        links = [l for l in page.eval_on_selector_all("a[href*='/video/BV']", "els => els.map(e => e.href)")]
        url = links[0] if links else "https://www.bilibili.com/"
    else:
        url = "https://live.bilibili.com/"
    t0 = time.time()
    page.goto(url, wait_until="domcontentloaded", timeout=30000)
    page.evaluate("() => document.querySelectorAll('video').forEach(v => { v.muted = true; v.play(); })")
    def rx():
        return int(open("/sys/class/net/eth0/statistics/rx_bytes").read())

    per5 = []
    last = rx()
    for _ in range(int(secs // 5)):
        time.sleep(5)
        now = rx()
        per5.append(round((now - last) / 1e3))
        last = now
    state = page.evaluate("() => [...document.querySelectorAll('video')].map(v => [v.paused, Math.round(v.currentTime), v.error && v.error.code])")
    print(browser_name, kind, url[:60])
    print("video elements [paused, currentTime, error]:", state)
    print("eth0 KB received per 5 s:", per5)
    b.close()
