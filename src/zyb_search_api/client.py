#!/usr/bin/env python3
"""作业帮 14.53.0 单题搜题协议客户端（单次请求，无批量/并发功能）。"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .protocol import accept_sign_b, create_sign_a, request_sign, response_key


APP_TOKEN = "1_XPXQH3c5HRPtFHkSwi3sCCURmT25QfxM"
APP_VERSION_CODE = "2810"
APP_VERSION_NAME = "14.53.0"
ANTISPAM_URL = "https://pluto.zuoyebang.com/pluto/app/antispam"
SEARCH_URL = "https://aisearch.zuoyebang.com/search/submit/single"
USER_AGENT = "Mozilla/5.0 (Linux; Android 12; Pixel 6) zyb/14.53.0"


class ClientError(RuntimeError):
    pass


def http_post_form(url: str, fields: dict[str, str], timeout: int = 45) -> dict[str, Any]:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent": USER_AGENT,
            "X-Wap-Proxy-Cookie": "none",
        },
        method="POST",
    )
    return read_json_response(request, timeout)


def http_post_multipart(
    url: str,
    fields: dict[str, str],
    file_field: str,
    filename: str,
    file_bytes: bytes,
    timeout: int = 90,
) -> dict[str, Any]:
    boundary = "----zyb-client-" + uuid.uuid4().hex
    marker = boundary.encode("ascii")
    body = bytearray()
    for key, value in fields.items():
        body.extend(b"--" + marker + b"\r\n")
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n'.encode("utf-8"))
        body.extend(b"Content-Type: text/plain; charset=UTF-8\r\n\r\n")
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")
    body.extend(b"--" + marker + b"\r\n")
    body.extend(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode("utf-8")
    )
    body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
    body.extend(file_bytes)
    body.extend(b"\r\n--" + marker + b"--\r\n")
    request = urllib.request.Request(
        url,
        data=bytes(body),
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": USER_AGENT,
            "X-Wap-Proxy-Cookie": "none",
        },
        method="POST",
    )
    return read_json_response(request, timeout)


def read_json_response(request: urllib.request.Request, timeout: int) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise ClientError(f"HTTP {exc.code}: {raw[:500]!r}") from exc
    except urllib.error.URLError as exc:
        raise ClientError(f"网络请求失败：{exc}") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientError(f"服务端返回的不是 JSON：{raw[:500]!r}") from exc
    if not isinstance(value, dict):
        raise ClientError("服务端返回了非对象 JSON")
    return value


def rc4(key: bytes, data: bytes) -> bytes:
    if not key:
        raise ClientError("RC4 密钥为空")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def parse_json_layers(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                return parse_json_layers(json.loads(stripped))
            except json.JSONDecodeError:
                return value
        return value
    if isinstance(value, list):
        return [parse_json_layers(item) for item in value]
    if isinstance(value, dict):
        return {key: parse_json_layers(item) for key, item in value.items()}
    return value


def decrypt_answers(response: dict[str, Any], base_key: str) -> dict[str, Any]:
    answers = response.get("data", {}).get("answers", {})
    if answers.get("encryption") != 1:
        return {
            "mainPageInfo": parse_json_layers(answers.get("mainPageInfo", [])),
            "commonPageInfo": parse_json_layers(answers.get("commonPageInfo", "")),
        }
    gzip_enabled = answers.get("gzip") == 1
    key_bytes = base_key.encode("utf-8")
    try:
        subkeys = [
            rc4(key_bytes, base64.b64decode(value)).decode("utf-8")
            for value in answers.get("tids", [])
        ]
        pages: list[Any] = []
        for subkey, encrypted_page in zip(subkeys, answers.get("mainPageInfo", [])):
            inner_b64 = rc4(subkey.encode("utf-8"), base64.b64decode(encrypted_page))
            clear = rc4(key_bytes, base64.b64decode(inner_b64))
            if gzip_enabled:
                clear = gzip.decompress(clear)
            pages.append(parse_json_layers(clear.decode("utf-8")))
        common_clear = rc4(key_bytes, base64.b64decode(answers.get("commonPageInfo", "")))
        if gzip_enabled:
            common_clear = gzip.decompress(common_clear)
        common = parse_json_layers(common_clear.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, OSError) as exc:
        raise ClientError(f"响应解密失败：{exc}") from exc
    return {"mainPageInfo": pages, "commonPageInfo": common}


def collect_answer_texts(value: Any) -> list[str]:
    texts: list[str] = []

    def walk(node: Any, inside_answer: bool = False) -> None:
        if isinstance(node, dict):
            now_inside = inside_answer or "answer_list" in node
            if inside_answer and isinstance(node.get("text"), str):
                texts.append(node["text"])
            for key, item in node.items():
                walk(item, now_inside or key == "answer_list")
        elif isinstance(node, list):
            for item in node:
                walk(item, inside_answer)

    walk(value)
    return list(dict.fromkeys(texts))


def build_common(cuid: str) -> dict[str, str]:
    return {
        "cuid": cuid,
        "channel": "official",
        "token": APP_TOKEN,
        "vc": APP_VERSION_CODE,
        "vcname": APP_VERSION_NAME,
        "os": "android",
        "sdk": "31",
        "device": "Pixel 6",
        "pkgName": "com.baidu.homework",
        "appId": "homework",
        "androidVersion": "12",
    }


def search_bytes(image_bytes: bytes, cuid: str) -> dict[str, Any]:
    sign_a, _ = create_sign_a(cuid)
    common = build_common(cuid)
    handshake = http_post_form(ANTISPAM_URL, {**common, "data": sign_a})
    if handshake.get("errNo") != 0:
        raise ClientError(f"反垃圾握手失败：{json.dumps(handshake, ensure_ascii=False)}")
    try:
        sign_b = handshake["data"]["data"]
        session_token = accept_sign_b(cuid, sign_a, sign_b)
    except (KeyError, TypeError, ValueError) as exc:
        raise ClientError(f"反垃圾握手响应无效：{exc}") from exc

    now_ms = int(time.time() * 1000)
    params = {
        **common,
        "ref": "2",
        "logid": "-1",
        "bookId": "0",
        "isFirst": "0",
        "picMD5": hashlib.md5(image_bytes).hexdigest(),
        "thirdChannel": "",
        "wholeExtraInfo": "",
        "userType": "0",
        "shouldDetectMulti": "0",
        "referer": "0",
        "isNewFePage": "0",
        "ext": "",
        "extraMsg": "",
        "college": "",
        "gradeId": "0",
        "sessionID": uuid.uuid4().hex,
        "feSkin": "1",
        "aiTabStatus": "",
        "upspeed": "",
        "dwspeed": "",
        "etid": "",
        "abtest": "",
        "refererSid": "",
        "firstActTime": str(now_ms),
        "isMultiImage": "0",
        "_t_": str(int(time.time())),
        "kakorrhaphiophobia": str(int(time.monotonic() * 1000)),
    }
    canonical = "".join(sorted(f"{key}={value}" for key, value in params.items()))
    payload = base64.b64encode(canonical.encode("utf-8")).decode("ascii")
    params["sign"] = request_sign(payload, session_token)
    base_key = response_key(APP_VERSION_CODE, session_token)

    response = http_post_multipart(SEARCH_URL, params, "image", "image", image_bytes)
    if response.get("errNo") != 0:
        raise ClientError(f"搜题请求失败：{json.dumps(response, ensure_ascii=False)}")
    decoded = decrypt_answers(response, base_key)

    data = response.get("data", {})
    answer_texts = collect_answer_texts(decoded.get("mainPageInfo"))
    return {
        "metadata": {
            "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "endpoint": SEARCH_URL,
            "imageSha256": hashlib.sha256(image_bytes).hexdigest(),
            "protocolVersion": APP_VERSION_NAME,
        },
        "summary": {
            "sid": data.get("sid"),
            "subject": data.get("searchInfo", {}).get("subjectName"),
            "matchCount": data.get("answers", {}).get("count"),
            "pictureUrl": data.get("picture", {}).get("url"),
            "answerTexts": answer_texts,
        },
        "decoded": decoded,
        "rawResponse": response,
    }


def search(image: Path, cuid: str) -> dict[str, Any]:
    return search_bytes(image.read_bytes(), cuid)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="作业帮 14.53.0 单题图片搜题客户端")
    parser.add_argument("--image", type=Path, required=True, help="待搜索的 JPG/PNG 图片")
    parser.add_argument("-o", "--output", type=Path, default=Path("zyb-result.json"), help="输出 JSON")
    parser.add_argument("--cuid", help="可选；默认每次随机生成，不包含手机号或账号")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.image.is_file():
        print(f"错误：图片不存在：{args.image}", file=sys.stderr)
        return 2
    cuid = args.cuid or (uuid.uuid4().hex.upper() + "|0")
    try:
        result = search(args.image.resolve(), cuid)
    except (ClientError, OSError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = result["summary"]
    print(f"成功：{summary['subject'] or '未知学科'}，匹配 {summary['matchCount']} 条")
    for index, text in enumerate(summary["answerTexts"][:10], 1):
        print(f"  {index}. {text}")
    print(f"完整结果：{args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
