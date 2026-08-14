# -*- coding: utf-8 -*-
"""he_ga.py: HE登録をGitHub Actionsランナーで完結させる
   1secmail(ランナーからAPI到達可)でメール生成 -> HE登録(ddddocrでCAPTCHA) ->
   アクティベーション -> ログイン -> トンネル作成(クライアント=LOの公開IP) -> 値を出力
"""
import base64, io, json, os, random, re, string, sys, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
from curl_cffi import requests as cr

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
CLIENT_IP = os.environ.get("HE_CLIENT_IP", "")
S1_API = ["https://www.1secmail.com/api/v1", "https://www.1secmail.org/api/v1",
          "https://www.1secmail.net/api/v1", "https://api.1secmail.com/api/v1",
          "https://api.1secmail.org/api/v1", "https://api.1secmail.net/api/v1",
          "https://1secmail.com/api/v1", "https://1secmail.org/api/v1",
          "https://1secmail.net/api/v1", "http://www.1secmail.com/api/v1"]


def s1(action, **params):
    q = "?action=" + action + "&" + "&".join("%s=%s" % (k, urllib_quote(str(v))) for k, v in params.items())
    errs = []
    for base in S1_API:
        try:
            r = cr.get(base + q, impersonate="chrome", timeout=20, verify=False)
            if r.status_code == 200:
                return r.json()
            errs.append("%s:%d" % (base.replace("https://", "").replace("http://", ""), r.status_code))
        except Exception as e:
            errs.append("%s:%s" % (base.replace("https://", "").replace("http://", ""), repr(e)[:40]))
    print("s1 all failed:", "; ".join(errs[:6]), flush=True)
    return None


def urllib_quote(v):
    return v.replace("%", "%25").replace("&", "%26").replace("=", "%3D").replace("+", "%2B").replace("@", "%40")


def get_mailbox():
    for _ in range(3):
        r = s1("genRandomMailbox", count=1)
        if r and isinstance(r, list) and r:
            return r[0].split("@")[0], r[0].split("@")[1]
    return None, None


def wait_activation(login, domain, timeout=240):
    t0 = time.time()
    while time.time() - t0 < timeout:
        msgs = s1("getMessages", login=login, domain=domain)
        if msgs:
            for m in msgs:
                full = s1("getMessage", login=login, domain=domain, id=m.get("id"))
                if full:
                    body = json.dumps(full, ensure_ascii=False)
                    hit = re.search(r"https?://[^\s\"'<>]+", body)
                    if hit and "tunnelbroker" in hit.group(0):
                        return hit.group(0)
        time.sleep(5)
    return None


def captcha_solve(png_bytes):
    try:
        import ddddocr
        return ddddocr.DdddOcr(show_ad=False).classification(png_bytes)
    except Exception:
        pass
    try:
        import numpy as np
        import cv2
        from rapidocr_onnxruntime import RapidOCR
        arr = np.frombuffer(png_bytes, np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        img = cv2.resize(img, None, fx=6, fy=6, interpolation=cv2.INTER_CUBIC)
        ok, buf = cv2.imencode(".png", img)
        r, _ = RapidOCR()(buf.tobytes())
        return "".join(x[1] for x in r) if r else None
    except Exception:
        return None


def main():
    if not CLIENT_IP:
        print("FATAL: HE_CLIENT_IP env missing")
        return 1
    login, domain = get_mailbox()
    if not login:
        print("FATAL: 1secmail unreachable")
        return 1
    email = login + "@" + domain
    print("mailbox:", email, flush=True)

    user = "skrvote" + "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    password = "SkrV0te!" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(8)) + "xQ7"
    print("user:", user, flush=True)

    s = cr.Session(impersonate="chrome", timeout=30)
    s.get("https://tunnelbroker.net/register.php")
    registered = False
    for attempt in range(1, 9):
        r = s.get("https://tunnelbroker.net/register.php")
        html = r.text
        img_m = re.search(r'<img src="data:image/png;base64,([^"]+)"', html)
        if not img_m:
            print("! no captcha", flush=True)
            break
        cap = captcha_solve(base64.b64decode(img_m.group(1)))
        print("attempt %d captcha=%r" % (attempt, cap), flush=True)
        if not cap:
            continue
        data = {
            "user_name": user, "password": password, "password2": password,
            "email": email, "first_name": "Taro", "last_name": "Suzuki", "company_name": "",
            "country": "JP", "street": "1-1-1 Chiyoda", "city": "Tokyo", "state": "Tokyo",
            "postal_code": "100-0001", "phone": "03-1234-5678",
            "captcha_code": cap, "tos": "on", "register": "Register",
        }
        r = s.post("https://tunnelbroker.net/register.php", data=data)
        low = r.text.lower()
        if "activate" in low:
            registered = True
            break
        if "email is not permitted" in low or "invalid email address" in low:
            print("FATAL: email domain rejected:", email, flush=True)
            return 1
        print("! register rejected (attempt %d)" % attempt, flush=True)
        time.sleep(1)
    if not registered:
        print("FATAL: registration failed", flush=True)
        return 1
    print("+ registered, waiting activation...", flush=True)
    link = wait_activation(login, domain)
    if not link:
        print("FATAL: no activation email", flush=True)
        return 1
    print("activation:", link, flush=True)
    s.get(link)

    r = s.post("https://tunnelbroker.net/login.php", data={"f_user": user, "f_pass": password, "Login": "Login"})
    if "logout" not in r.text.lower():
        print("FATAL: login failed", flush=True)
        return 1
    print("+ logged in", flush=True)

    r = s.get("https://tunnelbroker.net/tunnel.php")
    radios = re.findall(r'<input[^>]*type="radio"[^>]*name="server_id"[^>]*value="(\d+)"[^>]*>', r.text)
    if not radios:
        print("FATAL: no server radios", flush=True)
        return 1
    rows = re.findall(r'value="(\d+)"[^>]*>.*?<td[^>]*>.*?([A-Za-z ,]+?)\s*</td>.*?(\d+) ms', r.text, re.S)
    sid = None
    if rows:
        pick = min(rows, key=lambda x: int(x[2]))
        sid = pick[0]
        print("servers:", [(x[1].strip(), x[2]) for x in rows], "pick:", pick[1].strip(), flush=True)
    if not sid:
        sid = radios[0]
    r = s.post("https://tunnelbroker.net/tunnel.php",
               data={"tunnel_type": "6in4", "client_ipv4": CLIENT_IP, "server_id": sid, "submit": "Create Tunnel"})
    print("create status:", r.status_code, flush=True)

    r = s.get("https://tunnelbroker.net/tunnel.php")
    m = re.search(r"tunnel\.php\?tid=(\d+)", r.text)
    if not m:
        print("FATAL: tid not found", flush=True)
        return 1
    tid = m.group(1)
    r = s.get("https://tunnelbroker.net/tunnel.php?tid=" + tid)
    html = r.text

    def grab(label):
        g = re.search(re.escape(label) + r"\s*</td>\s*<td[^>]*>([0-9a-fA-F:\./]+)", html)
        return g.group(1).strip() if g else None

    vals = {
        "server_v4": grab("Server IPv4 Address"),
        "client_v4": grab("Client IPv4 Address"),
        "server_v6": grab("Server IPv6 Address"),
        "client_v6": grab("Client IPv6 Address"),
        "routed48": grab("Routed /48"),
    }
    print("TUNNEL_VALUES_BEGIN", flush=True)
    for k, v in vals.items():
        print("%s=%s" % (k, v or "MISSING"), flush=True)
    print("TUNNEL_VALUES_END", flush=True)
    with open("he_tunnel_values.txt", "w") as f:
        for k, v in vals.items():
            f.write("%s=%s\n" % (k, v or "MISSING"))
    if not all(vals.values()):
        print("WARN: incomplete parse", flush=True)
    print("DONE tid=" + tid, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())