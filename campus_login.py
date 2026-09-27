#!/usr/bin/env python3
"""兰州大学校园网账号认证快捷脚本。"""

import base64
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

PORTAL = "http://10.10.0.166"
AC_ID = "2"
CALLBACK = "campusLogin"
BASE64_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
CONFIG_FILE = Path(__file__).with_name("campus_login.txt")


def load_credentials() -> tuple[str, str]:
    values = {}
    for line in CONFIG_FILE.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    username = values.get("username", "")
    password = values.get("password", "")
    domain = values.get("domain", "")
    if not username or not password:
        raise ValueError("campus_login.txt 中必须填写 username 和 password")
    return username + domain, password


def jsonp_or_json(payload: str) -> dict:
    payload = payload.strip()
    match = re.match(r"^[^(]+\((.*)\)\s*;?\s*$", payload, re.DOTALL)
    return json.loads(match.group(1) if match else payload)


def request_json(url: str, params: dict | None = None) -> dict:
    separator = "&" if "?" in url else "?"
    query = {"callback": CALLBACK, "_": str(int(time.time() * 1000))}
    if params:
        query.update(params)
    request = Request(
        url + separator + urlencode(query),
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    )
    with urlopen(request, timeout=12) as response:
        return jsonp_or_json(response.read().decode("utf-8"))


def get_ip() -> str:
    status = request_json(PORTAL + "/cgi-bin/rad_user_info")
    ip = status.get("online_ip") or status.get("client_ip")
    if ip:
        return ip

    page_url = PORTAL + "/srun_portal_pc?" + urlencode(
        {"ac_id": AC_ID, "theme": "pro"}
    )
    request = Request(page_url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(request, timeout=12) as response:
        page = response.read().decode("utf-8", errors="replace")
    match = re.search(r'\bip\s*:\s*"([^"]+)"', page)
    if not match:
        raise RuntimeError("无法从校园网页面取得本机 IP 地址。")
    return match.group(1)


def already_online(base: str) -> str | None:
    result = request_json(base + "/cgi-bin/rad_user_info")
    if result.get("error") == "ok":
        return result.get("user_name", "未知账号")
    return None


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def sencode(value: str, include_length: bool) -> list[int]:
    encoded = value.encode("utf-16le", errors="surrogatepass")
    chars = [int.from_bytes(encoded[index:index + 2], "little") for index in range(0, len(encoded), 2)]
    result = []
    for index in range(0, len(chars), 4):
        word = 0
        for offset in range(4):
            if index + offset < len(chars):
                word |= chars[index + offset] << (offset * 8)
        result.append(_u32(word))
    if include_length:
        result.append(len(chars))
    return result


def lencode(values: list[int], include_length: bool) -> bytes:
    raw = bytearray()
    for value in values:
        raw.extend(_u32(value).to_bytes(4, "little"))
    return bytes(raw[: values[-1]] if include_length else raw)


def portal_base64(value: bytes) -> str:
    standard = base64.b64encode(value).decode("ascii")
    source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return standard.translate(str.maketrans(source, BASE64_ALPHABET))


def xencode(message: str, key: str) -> bytes:
    if not message:
        return b""
    values = sencode(message, True)
    keys = sencode(key, False)
    keys.extend([0] * (4 - len(keys)))
    count = len(values) - 1
    z = values[count]
    total = 0
    delta = 0x9E3779B9
    rounds = 6 + 52 // (count + 1)
    while rounds:
        total = _u32(total + delta)
        e = (total >> 2) & 3
        for position in range(count):
            y = values[position + 1]
            mix = _u32((z >> 5) ^ _u32(y << 2))
            mix = _u32(mix + ((y >> 3) ^ _u32(z << 4) ^ (total ^ y)))
            mix = _u32(mix + (keys[(position & 3) ^ e] ^ z))
            values[position] = _u32(values[position] + mix)
            z = values[position]
        y = values[0]
        mix = _u32((z >> 5) ^ _u32(y << 2))
        mix = _u32(mix + ((y >> 3) ^ _u32(z << 4) ^ (total ^ y)))
        mix = _u32(mix + (keys[(count & 3) ^ e] ^ z))
        values[count] = _u32(values[count] + mix)
        z = values[count]
        rounds -= 1
    return lencode(values, False)


def login(username: str, password: str) -> dict:
    online_user = already_online(PORTAL)
    if online_user:
        print(f"已在线，无需重复登录：{online_user}")
        return {"error": "ok"}

    ip = get_ip()
    challenge_response = request_json(
        PORTAL + "/cgi-bin/get_challenge", {"username": username, "ip": ip}
    )
    token = challenge_response.get("challenge")
    if not token:
        raise RuntimeError("获取登录挑战码失败：" + challenge_response.get("error", "未知错误"))

    info_source = json.dumps(
        {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": AC_ID,
            "enc_ver": "srun_bx1",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    info = "{SRBX1}" + portal_base64(xencode(info_source, token))
    password_hash = hmac.new(token.encode("utf-8"), password.encode("utf-8"), hashlib.md5).hexdigest()
    checksum = hashlib.sha1(
        (token + username + token + password_hash + token + AC_ID
         + token + ip + token + "200" + token + "1" + token + info).encode("utf-8")
    ).hexdigest()
    return request_json(
        PORTAL + "/cgi-bin/srun_portal",
        {
            "action": "login",
            "username": username,
            "password": "{MD5}" + password_hash,
            "os": "Windows",
            "name": "Windows 10",
            "double_stack": "0",
            "chksum": checksum,
            "info": info,
            "ac_id": AC_ID,
            "ip": ip,
            "n": "200",
            "type": "1",
        },
    )


def main() -> int:
    username, password = load_credentials()
    result = login(username, password)
    if result.get("error") == "ok":
        print("校园网登录成功。")
        return 0
    message = result.get("error_msg") or result.get("error") or "未知错误"
    print("登录失败：" + message)
    print("门户响应：" + json.dumps(result, ensure_ascii=False))
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, URLError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print("操作失败：" + str(error))
        raise SystemExit(1)
