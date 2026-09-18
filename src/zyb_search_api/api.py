#!/usr/bin/env python3
"""Small HTTP API around the pure-Python Zyb search client."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import uuid
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .client import APP_VERSION_NAME, ClientError, search_bytes


MAX_BODY_BYTES = 15 * 1024 * 1024
MAX_IMAGE_BYTES = 12 * 1024 * 1024


def _openapi(host: str) -> dict[str, Any]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "Zyb Search API", "version": "1.0.0"},
        "servers": [{"url": host}],
        "paths": {
            "/healthz": {
                "get": {
                    "summary": "Health check",
                    "responses": {"200": {"description": "Service is ready"}},
                }
            },
            "/v1/search": {
                "post": {
                    "summary": "Search one question image",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "required": ["image"],
                                    "properties": {
                                        "image": {"type": "string", "format": "binary"},
                                        "cuid": {"type": "string"},
                                    },
                                }
                            },
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["imageBase64"],
                                    "properties": {
                                        "imageBase64": {"type": "string", "format": "byte"},
                                        "cuid": {"type": "string"},
                                    },
                                }
                            },
                        },
                    },
                    "responses": {
                        "200": {"description": "Decoded search result"},
                        "400": {"description": "Invalid request"},
                        "413": {"description": "Request or image is too large"},
                        "502": {"description": "Upstream request failed"},
                    },
                }
            },
        },
    }


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str):
        super().__init__(message)
        self.status = status


class ZybApiHandler(BaseHTTPRequestHandler):
    server_version = "ZybSearchAPI/1.0"

    def _json(self, status: HTTPStatus, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok", "protocolVersion": APP_VERSION_NAME})
            return
        if self.path == "/openapi.json":
            self._json(HTTPStatus.OK, _openapi(f"http://{self.headers.get('Host', '127.0.0.1')}"))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found", "message": "接口不存在"})

    def do_POST(self) -> None:
        if self.path != "/v1/search":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found", "message": "接口不存在"})
            return
        try:
            image, cuid = self._read_search_request()
            result = search_bytes(image, cuid or (uuid.uuid4().hex.upper() + "|0"))
        except ApiError as exc:
            self._json(exc.status, {"error": "invalid_request", "message": str(exc)})
            return
        except ClientError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"error": "upstream_error", "message": str(exc)})
            return
        except Exception:
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal_error", "message": "服务内部错误"},
            )
            return
        self._json(HTTPStatus.OK, result)

    def _read_search_request(self) -> tuple[bytes, str | None]:
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header or "")
        except ValueError as exc:
            raise ApiError(HTTPStatus.LENGTH_REQUIRED, "必须提供有效的 Content-Length") from exc
        if length <= 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "请求体不能为空")
        if length > MAX_BODY_BYTES:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "请求体超过 15 MiB")
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() == "application/json":
            image, cuid = self._read_json_body(body)
        elif content_type.split(";", 1)[0].strip().lower() == "multipart/form-data":
            image, cuid = self._read_multipart_body(content_type, body)
        else:
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "仅支持 multipart/form-data 或 application/json")
        if not image:
            raise ApiError(HTTPStatus.BAD_REQUEST, "图片不能为空")
        if len(image) > MAX_IMAGE_BYTES:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "图片超过 12 MiB")
        return image, cuid

    @staticmethod
    def _read_json_body(body: bytes) -> tuple[bytes, str | None]:
        try:
            value = json.loads(body.decode("utf-8"))
            encoded = value["imageBase64"]
            cuid = value.get("cuid")
            if not isinstance(encoded, str) or (cuid is not None and not isinstance(cuid, str)):
                raise TypeError
            return base64.b64decode(encoded, validate=True), cuid
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, binascii.Error) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "JSON 必须包含有效的 imageBase64，可选 cuid") from exc

    @staticmethod
    def _read_multipart_body(content_type: str, body: bytes) -> tuple[bytes, str | None]:
        message = BytesParser(policy=default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii") + body
        )
        if not message.is_multipart():
            raise ApiError(HTTPStatus.BAD_REQUEST, "multipart 请求缺少有效 boundary")
        image: bytes | None = None
        cuid: str | None = None
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            content = part.get_payload(decode=True) or b""
            if name == "image":
                image = content
            elif name == "cuid":
                try:
                    cuid = content.decode(part.get_content_charset() or "utf-8")
                except UnicodeDecodeError as exc:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "cuid 必须是 UTF-8 文本") from exc
        if image is None:
            raise ApiError(HTTPStatus.BAD_REQUEST, "multipart 请求缺少 image 字段")
        return image, cuid

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")


class ZybApiServer(ThreadingHTTPServer):
    daemon_threads = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="作业帮图片搜题 HTTP API")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址，默认 127.0.0.1")
    parser.add_argument("--port", type=int, default=8080, help="监听端口，默认 8080")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = ZybApiServer((args.host, args.port), ZybApiHandler)
    print(f"Zyb Search API listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
