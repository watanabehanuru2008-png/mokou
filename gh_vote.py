# -*- coding: utf-8 -*-
"""gh_vote.py: GitHub Actions ランナーで1票投じる (バースト用)

各ランナーは固有のエグレスIP。1ジョブ=1票。結果はJSONで出力し、
ワークフローが集計。curl_cffi でTLSフィンガープリント偽装。
"""
import hashlib, io, json, os, random, re, sys, time, urllib.parse

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
from curl_cffi import requests as cr

BASE = "https://suki-kira.com"
VOTE_URL = BASE + "/people/vote/oe%20(%E3%83%9C%E3%82%AB%E3%83%ADP)"
POST_URL = BASE + "/people/result/oe (ボカロP)"
PID = "102032"
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
IMPS = ["safari180_ios", "safari170", "chrome136", "firefox135"]


def public_ip():
    try:
        r = cr.get("https://api.ipify.org", timeout=15, impersonate="chrome")
        return r.text.strip()
    except Exception:
        return "?"


def get_retry(s, url):
    for imp in random.sample(IMPS, 4):
        try:
            r = s.get(url, timeout=20, impersonate=imp)
            if r.status_code != 403 and "Just a moment" not in r.text[:3000]:
                return r
        except Exception:
            pass
    return None


def main():
    time.sleep(random.uniform(0.5, 8.0))
    ip = public_ip()
    result = {"status": "unknown", "ip": ip}
    with cr.Session(impersonate="safari180_ios") as s:
        r = get_retry(s, VOTE_URL)
        if r is None:
            result = {"status": "challenge", "note": "all profiles blocked"}
            print(json.dumps(result, ensure_ascii=False)); return
        html = r.text
        if 'name="vote"' not in html:
            result = {"status": "noform"}
            print(json.dumps(result, ensure_ascii=False)); return
        m = re.search(r'name="auth1"[^>]*value="([^"]*)"', html)
        a1 = m.group(1) if m else os.urandom(16).hex()
        a2 = hashlib.sha256(a1.encode()).hexdigest()[:32]
        data = {"vote": "0", "ok": "ng", "id": PID, "auth1": a1, "auth2": a2}
        r = get_retry(s, POST_URL)
        if r is None:
            result = {"status": "challenge", "note": "post blocked"}
            print(json.dumps(result, ensure_ascii=False)); return
        sc = r.headers.get("set-cookie", "")
        if "sk_vote=deleted" not in sc:
            result = {"status": "rejected", "set_cookie": sc[:120]}
            print(json.dumps(result, ensure_ascii=False)); return
        r2 = get_retry(s, VOTE_URL)
        if r2 is not None and 'name="vote"' not in r2.text:
            result = {"status": "landed"}
        else:
            result = {"status": "verify_fail"}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()