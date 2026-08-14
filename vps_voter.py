#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vps_voter.py: IPv6ソース回転投票器 (HAX /112 サブネット用)

HAX VPS 上で実行。割り当てられた /112 (65,536アドレス) から
1票=1アドレスで投票を回す。サイトの重複排除がIP単位か/64単位かを
まず test モードで判定し、OKなら run モードで10票/秒を目指す。

使用法:
  python3 vps_voter.py test                 # 同一/64内2アドレスで重複排除判定
  python3 vps_voter.py run --rate 10        # 全/112を回転して投票
  python3 vps_voter.py run --rate 10 --limit 1000
"""
import argparse
import hashlib
import ipaddress
import itertools
import queue
import random
import re
import sys
import threading
import time
import json

from curl_cffi import Curl, CurlOpt

BASE = "https://suki-kira.com"
VOTE_URL = BASE + "/people/vote/oe%20(%E3%83%9C%E3%82%AB%E3%83%ADP)"
POST_URL = BASE + "/people/result/oe (ボカロP)"
PID = "102032"
IMPS = ["safari180_ios", "safari170", "chrome136", "firefox135"]
AUTH_RE = re.compile(r'name="auth1"[^>]*value="([^"]*)"')
COUNT_RE = re.compile(r"嫌い派[:\s]*([\d.]+)%\s*\((\d+)票\)")


class RateLimiter:
    def __init__(self, rate):
        self.interval = 1.0 / rate
        self.lock = threading.Lock()
        self.next_t = time.monotonic()

    def wait(self):
        with self.lock:
            t = time.monotonic()
            self.next_t = max(self.next_t, t)
            wait = self.next_t - t
            self.next_t += self.interval
        if wait > 0:
            time.sleep(wait)


class Voter:
    def __init__(self, src, imp, rate):
        self.src = src
        self.imp = imp
        self.rate = rate

    def _request(self, url, data=None, cookies=None):
        c = Curl()
        c.setopt(CurlOpt.URL, url)
        c.setopt(CurlOpt.INTERFACE, self.src)
        c.setopt(CurlOpt.IMPERSONATE, self.imp)
        c.setopt(CurlOpt.FOLLOWLOCATION, 1)
        c.setopt(CurlOpt.TIMEOUT, 15)
        c.setopt(CurlOpt.HTTPHEADER, [b"Accept: text/html", b"Accept-Language: ja,en;q=0.8"])
        body = []
        resp_headers = []
        c.setopt(CurlOpt.WRITEFUNCTION, body.append)
        c.setopt(CurlOpt.HEADERFUNCTION, resp_headers.append)
        if cookies:
            c.setopt(CurlOpt.COOKIELIST, cookies)
        if data:
            c.setopt(CurlOpt.POSTFIELDS, data)
        try:
            c.perform()
            status = c.getinfo(CurlOpt.RESPONSE_CODE)
        except Exception:
            status = 0
        raw = b"".join(body)
        c.close()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        return status, raw, resp_headers

    def vote(self):
        status, html, _ = self._request(VOTE_URL)
        if status == 0:
            return "net_err"
        if "Just a moment" in html[:3000] or status == 403:
            return "challenge"
        m = AUTH_RE.search(html)
        if not m:
            return "noform"
        a1 = m.group(1)
        a2 = hashlib.sha256(a1.encode()).hexdigest()[:32]
        data = "vote=0&ok=ng&id=%s&auth1=%s&auth2=%s" % (PID, a1, a2)
        _, _, hdrs = self._request(POST_URL, data=data)
        joined = "\n".join(hdrs)
        if "sk_vote=deleted" in joined:
            return "landed"
        return "rejected"


def current_count(src=None):
    try:
        c = Curl()
        c.setopt(CurlOpt.URL, POST_URL)
        if src:
            c.setopt(CurlOpt.INTERFACE, src)
        c.setopt(CurlOpt.IMPERSONATE, random.choice(IMPS))
        c.setopt(CurlOpt.TIMEOUT, 15)
        buf = []
        c.setopt(CurlOpt.WRITEFUNCTION, buf.append)
        c.perform()
        c.close()
        html = b"".join(buf).decode("utf-8", "replace")
        m = COUNT_RE.search(html)
        if m:
            return int(m.group(2))
        return None
    except Exception:
        return None


def detect_prefix():
    out = ""
    for line in open("/proc/net/if_inet6").readlines():
        addr = ":".join(line.split()[0][i:i + 4] for i in range(0, 32, 4))
        if line.split()[5] == "wlan0" or True:
            if addr.startswith("fe8") or addr.startswith("fe9") or addr.startswith("fea"):
                continue
            out = addr
    if not out:
        import socket
        for f in [socket.AF_INET6]:
            for info in socket.getaddrinfo("suki-kira.com", 443, f):
                ip = info[4][0]
                if not ip.startswith("fe8"):
                    out = ip
                    break
    net = ipaddress.IPv6Network(out + "/112", strict=False)
    return net


def counter_thread(delay, stop):
    last = None
    while not stop.is_set():
        n = current_count()
        if n is not None and n != last:
            print(json.dumps({"event": "counter", "votes": n}, ensure_ascii=False), flush=True)
            last = n
        time.sleep(delay)


def run(prefix, rate, limit, threads):
    addrs = list(ipaddress.IPv6Network(prefix).hosts())
    if not addrs:
        return
    start_ip = int(addrs[0])
    counter = itertools.count(start_ip)
    q = queue.Queue(maxsize=threads * 4)
    stop = threading.Event()
    stats = {"landed": 0, "rejected": 0, "challenge": 0, "net_err": 0, "noform": 0}
    stats_lock = threading.Lock()

    def producer():
        for i in range(limit):
            idx = int(next(counter))
            q.put(idx)
        for _ in range(threads):
            q.put(None)

    def worker():
        rl = RateLimiter(rate)
        imp = random.choice(IMPS)
        while True:
            item = q.get()
            if item is None:
                return
            v = Voter(str(ipaddress.IPv6Address(item)), imp, rate)
            rl.wait()
            st = v.vote()
            with stats_lock:
                stats[st] += 1
                landed = stats["landed"]
            if landed and landed % 25 == 0:
                print(json.dumps({"event": "progress", "stats": stats, "addr": str(item)}, ensure_ascii=False), flush=True)

    procs = [threading.Thread(target=producer), threading.Thread(target=counter_thread, args=(30, stop))]
    for t in procs:
        t.start()
    for _ in range(threads):
        threading.Thread(target=worker).start()
    time.sleep(limit / rate * 1.2)
    stop.set()
    print(json.dumps({"event": "done", "stats": stats}, ensure_ascii=False), flush=True)


def self_test(prefix):
    addrs = list(ipaddress.IPv6Network(prefix).hosts())
    if len(addrs) < 3:
        print(json.dumps({"event": "prefix_too_small"}, ensure_ascii=False))
        return
    a, b = str(addrs[1]), str(addrs[2])
    print(json.dumps({"event": "test_start", "same_64": ipaddress.IPv6Network(a + "/64", strict=False) == ipaddress.IPv6Network(b + "/64", strict=False)}, ensure_ascii=False))
    before = current_count()
    print(json.dumps({"event": "counter_before", "votes": before}, ensure_ascii=False))
    v1 = Voter(a, random.choice(IMPS), 10).vote()
    print(json.dumps({"event": "vote1", "src": a, "status": v1}, ensure_ascii=False))
    time.sleep(2)
    mid = current_count()
    print(json.dumps({"event": "counter_mid", "votes": mid}, ensure_ascii=False))
    v2 = Voter(b, random.choice(IMPS), 10).vote()
    print(json.dumps({"event": "vote2", "src": b, "status": v2}, ensure_ascii=False))
    time.sleep(2)
    after = current_count()
    print(json.dumps({"event": "counter_after", "votes": after}, ensure_ascii=False))
    if before is None or after is None:
        print(json.dumps({"event": "verdict", "dedup": "unknown", "note": "カウンター取得失敗、要調査"}, ensure_ascii=False))
    elif after - before >= 2:
        print(json.dumps({"event": "verdict", "dedup": "per_ip", "note": "同一/64内で複数票可 → HAXフル活用可"}, ensure_ascii=False))
    elif after - before == 1:
        print(json.dumps({"event": "verdict", "dedup": "per_64", "note": "/64単位で重複排除 → HAXは1票のみ、WebHorizon /48 が必要"}, ensure_ascii=False))
    else:
        print(json.dumps({"event": "verdict", "dedup": "unknown", "note": "カウンターが動いていない、要調査"}, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["test", "run"])
    ap.add_argument("--rate", type=float, default=10.0)
    ap.add_argument("--limit", type=int, default=65000)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--prefix", default=None)
    args = ap.parse_args()
    prefix = ipaddress.IPv6Network(args.prefix, strict=False) if args.prefix else detect_prefix()
    print(json.dumps({"event": "prefix", "network": str(prefix)}, ensure_ascii=False))
    if args.mode == "test":
        self_test(prefix)
    else:
        run(prefix, args.rate, args.limit, args.threads)


if __name__ == "__main__":
    main()
