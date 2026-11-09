"""Operate Bilibili's mobile site like a person and log every action with its time and service.

Runs inside the UE network namespace (run.sh), so the traffic crosses N3. Writes actions.csv:
t_start,t_end,app,action,service,detail where service is vod, live, short_video or other.

A session moves between three modes, as people do:
- vod: browse the feed, open a video, watch it for a while, read comments, go back, search
- live: enter a live room and stay
- short_video: swipe through videos, a few seconds each (a behavioural stand-in until real phones
  run Douyin / Kuaishou; their web players refuse automation)

Without --script it follows that policy; with --script it plays an action script (the format upsynth
synth --script reads), e.g. one an LLM wrote from a persona.

Usage: python human_bilibili.py --out actions.csv --duration 600 [--script session.json] [--seed 1]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import re
import time

from playwright.sync_api import Error as PwError
from playwright.sync_api import TimeoutError as PwTimeout
from playwright.sync_api import sync_playwright

HOME = "https://m.bilibili.com/"
LIVE_HOME = "https://live.bilibili.com/"
LIVE_AREAS = ["https://live.bilibili.com/p/eden/area-tags?parentAreaId=2&areaId=86",
              "https://live.bilibili.com/p/eden/area-tags?parentAreaId=3&areaId=0",
              "https://live.bilibili.com/p/eden/area-tags?parentAreaId=6&areaId=0"]
QUERIES = ["火锅", "原神", "猫", "科技", "数码测评", "美食", "旅行vlog", "篮球", "钢琴", "健身"]
SERVICE = {"open_video": "vod", "watch": "vod", "live_enter": "live", "live_watch": "live",
           "swipe": "short_video"}
ACTIONS = ("launch", "scroll_feed", "open_video", "watch", "scroll_comments", "back", "search",
           "live_enter", "live_watch", "swipe")


class Driver:
    def __init__(self, page, writer, rnd: random.Random):
        self.page = page
        self.w = writer
        self.r = rnd
        self.video_links: list[str] = []

    def log(self, action: str, t0: float, detail: str = "") -> None:
        self.w.writerow([f"{t0:.3f}", f"{time.time():.3f}", "bilibili", action, SERVICE.get(action, "other"), detail])

    def pause(self, lo: float, hi: float) -> None:
        time.sleep(self.r.uniform(lo, hi))

    def goto(self, url: str) -> None:
        for _ in range(3):  # a fresh tunnel can report ERR_NETWORK_CHANGED for the first request
            try:
                self.page.goto(url, wait_until="domcontentloaded", timeout=20000)
                return
            except PwTimeout:
                return
            except PwError:
                time.sleep(1.0)

    def links(self, pattern: str) -> list[str]:
        try:
            hrefs = self.page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        except PwError:
            return []
        return list(dict.fromkeys(h for h in hrefs if re.search(pattern, h)))

    def collect_videos(self) -> None:
        found = self.links(r"/video/(BV\w+|av\d+)")
        if found:
            self.video_links = found

    def play(self) -> None:
        try:  # mobile autoplay needs a muted start
            self.page.evaluate("() => document.querySelectorAll('video').forEach(v => { v.muted = true; v.play(); })")
        except PwError:
            pass

    def _video(self) -> str:
        if not self.video_links:
            self.collect_videos()
        if not self.video_links:
            self.goto(HOME)
            self.collect_videos()
        return self.r.choice(self.video_links) if self.video_links else HOME

    # ---------------------------------------------------------------- vod

    def launch(self, dwell=None, **_):
        t0 = time.time()
        self.goto(HOME)
        time.sleep(dwell) if dwell else self.pause(1.5, 3.0)
        self.collect_videos()
        self.log("launch", t0)

    def scroll_feed(self, dwell=None, **_):
        t0 = time.time()
        n = self.r.randint(2, 5)
        for _ in range(n):
            self.page.mouse.wheel(0, self.r.randint(500, 1400))
            self.pause(0.6, 2.0)
        if dwell:
            time.sleep(dwell)
        self.collect_videos()
        self.log("scroll_feed", t0, str(n))

    def open_video(self, dwell=None, **_):
        t0 = time.time()
        url = self._video()
        self.goto(url)
        self.play()
        time.sleep(dwell) if dwell else self.pause(1.0, 2.5)
        self.log("open_video", t0, url.split("?")[0].rsplit("/", 1)[-1])

    def watch(self, dwell=None, **_):
        t0 = time.time()
        d = dwell if dwell is not None else min(150.0, math.exp(self.r.gauss(math.log(40), 0.7)))
        time.sleep(d)
        self.log("watch", t0, f"{d:.1f}")

    def scroll_comments(self, dwell=None, **_):
        t0 = time.time()
        n = self.r.randint(2, 6)
        for _ in range(n):
            self.page.mouse.wheel(0, self.r.randint(400, 1000))
            self.pause(0.8, 2.5)
        if dwell:
            time.sleep(dwell)
        self.log("scroll_comments", t0, str(n))

    def back(self, dwell=None, **_):
        t0 = time.time()
        try:
            self.page.go_back(wait_until="domcontentloaded", timeout=15000)
        except PwError:
            self.goto(HOME)
        time.sleep(dwell) if dwell else self.pause(0.8, 2.0)
        self.collect_videos()
        self.log("back", t0)

    def search(self, dwell=None, query=None, **_):
        t0 = time.time()
        q = query or self.r.choice(QUERIES)
        self.goto(f"https://m.bilibili.com/search?keyword={q}")
        time.sleep(dwell) if dwell else self.pause(1.5, 3.5)
        self.collect_videos()
        self.log("search", t0, q)

    # ---------------------------------------------------------------- live

    def live_enter(self, dwell=None, **_):
        t0 = time.time()
        if self.r.random() < 0.5:
            self.goto(LIVE_HOME)  # the live home page plays a featured room
            detail = "home"
        else:
            self.goto(self.r.choice(LIVE_AREAS))
            time.sleep(2)
            rooms = self.links(r"live\.bilibili\.com/(h5/)?\d+")
            detail = rooms[0].rsplit("/", 1)[-1].split("?")[0] if rooms else "area"
            if rooms:
                self.goto(self.r.choice(rooms[:10]))
        self.play()
        time.sleep(dwell) if dwell else self.pause(2.0, 4.0)
        self.log("live_enter", t0, detail)

    def live_watch(self, dwell=None, **_):
        t0 = time.time()
        d = dwell if dwell is not None else min(240.0, math.exp(self.r.gauss(math.log(70), 0.6)))
        time.sleep(d)
        self.log("live_watch", t0, f"{d:.1f}")

    # ---------------------------------------------------------------- short video

    def swipe(self, dwell=None, **_):
        t0 = time.time()
        url = self._video()
        self.goto(url)
        self.play()
        d = dwell if dwell is not None else min(30.0, math.exp(self.r.gauss(math.log(6), 0.6)))
        time.sleep(d)
        self.collect_videos()
        self.log("swipe", t0, f"{d:.1f}")


POLICY = {
    "launch": [("scroll_feed", 0.5), ("open_video", 0.4), ("search", 0.1)],
    "scroll_feed": [("open_video", 0.6), ("scroll_feed", 0.25), ("search", 0.15)],
    "open_video": [("watch", 1.0)],
    "watch": [("back", 0.55), ("scroll_comments", 0.25), ("open_video", 0.2)],
    "scroll_comments": [("back", 0.7), ("open_video", 0.3)],
    "back": [("scroll_feed", 0.45), ("open_video", 0.45), ("search", 0.1)],
    "search": [("open_video", 0.8), ("scroll_feed", 0.2)],
    "live_enter": [("live_watch", 1.0)],
    "live_watch": [("live_enter", 0.3), ("live_watch", 0.2), ("back", 0.5)],
    "swipe": [("swipe", 0.9), ("back", 0.1)],
}
MODE_START = {"vod": "launch", "live": "live_enter", "short_video": "swipe"}


def run_action(d: Driver, name: str, **kw) -> None:
    t0 = time.time()
    try:
        getattr(d, name)(**kw)
    except PwError as e:  # one failed step does not end the session
        d.log(name, t0, f"error: {str(e).splitlines()[0][:80]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=float, default=600)
    ap.add_argument("--script")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--mode-minutes", type=float, default=2.0, help="average time in one mode before switching")
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    with sync_playwright() as p, open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["t_start", "t_end", "app", "action", "service", "detail"])
        browser = p.chromium.launch(args=["--no-sandbox", "--disable-quic", "--autoplay-policy=no-user-gesture-required"])
        ctx = browser.new_context(**p.devices["Pixel 7"], locale="zh-CN")
        d = Driver(ctx.new_page(), w, rnd)
        end = time.time() + a.duration
        if a.script:
            doc = json.load(open(a.script, encoding="utf-8"))
            session = doc["sessions"][0] if "sessions" in doc else doc
            for s in session["steps"]:
                name = s["action"].split("/")[-1]
                if time.time() > end:
                    break
                if name in ACTIONS:
                    run_action(d, name, dwell=s.get("dwell"), query=s.get("query"))
                    f.flush()
        else:
            modes = ["vod", "live", "short_video"]
            rnd.shuffle(modes)
            i = 0
            while time.time() < end:
                mode = modes[i % len(modes)]
                i += 1
                mode_end = min(end, time.time() + rnd.expovariate(1 / (a.mode_minutes * 60)) + 30)
                action = MODE_START[mode]
                while time.time() < mode_end:
                    run_action(d, action)
                    f.flush()
                    choices, weights = zip(*POLICY[action])
                    action = rnd.choices(choices, weights)[0]
                    if action == "back" and mode != "vod":
                        break
        browser.close()


if __name__ == "__main__":
    main()
