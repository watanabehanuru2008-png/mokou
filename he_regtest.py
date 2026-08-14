# -*- coding: utf-8 -*-
"""he_regtest.py: GH runner (datacenter IP) からHE登録テスト"""
import base64, io, random, re, string, sys, urllib.request, urllib.error, urllib.parse
import http.cookiejar as cookiejar

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)


def http(method, url, opener, data=None, timeout=30):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/136.0.0.0")
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.data = urllib.parse.urlencode(data).encode()
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    email = sys.argv[1] if len(sys.argv) > 1 else "skrvote1@yahoo.co.jp"
    jar = cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    st, html = http("GET", "https://tunnelbroker.net/register.php", opener)
    img_m = re.search(r'<img src="data:image/png;base64,([^"]+)"', html)
    if not img_m:
        import json
        print("NO CAPTCHA IMG, status=%d, len=%d, head=%s" % (st, len(html), json.dumps(html[:1200])))
        return
    import ddddocr
    cap = ddddocr.DdddOcr(show_ad=False).classification(base64.b64decode(img_m.group(1)))
    data = {
        "user_name": "skrvote" + "".join(random.choice(string.ascii_lowercase) for _ in range(6)),
        "password": "SkrV0te!xQ7aBcDe", "password2": "SkrV0te!xQ7aBcDe",
        "email": email, "first_name": "Taro", "last_name": "Suzuki", "company_name": "",
        "country": "JP", "street": "1-1-1 Chiyoda", "city": "Tokyo", "state": "Tokyo",
        "postal_code": "100-0001", "phone": "03-1234-5678",
        "captcha_code": cap, "tos": "on", "register": "Register",
    }
    st, resp = http("POST", "https://tunnelbroker.net/register.php", opener, data)
    low = resp.lower()
    m = re.search(r'<div class="errorMessageBox">([\s\S]*?)</div>', resp)
    errs = re.sub(r"<br\s*/?>", " | ", m.group(1)).strip() if m else "(none)"
    if "captcha code does not match" in low:
        print("CAPTCHA_FAIL")
    elif "activate" in low:
        print("ACCEPTED")
    else:
        print("RESULT: %s" % errs)


if __name__ == "__main__":
    main()