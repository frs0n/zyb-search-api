# Zyb Search API

独立的作业帮 14.53.0 单题图片搜索 API。握手、签名、动态密钥和响应解密均使用纯 Python 实现。

## 本地启动

需要 Python 3.10 或更高版本。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
zyb-search-api --host 127.0.0.1 --port 8080
```

服务提供三个接口：

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/healthz` | 健康检查与协议版本 |
| `GET` | `/openapi.json` | OpenAPI 3.0 描述 |
| `POST` | `/v1/search` | 上传单张题目图片并返回解密结果 |

### multipart 上传

```bash
curl -X POST http://127.0.0.1:8080/v1/search \
  -F 'image=@samples/test-question.jpg'
```

可以附带自定义客户端标识：

```bash
curl -X POST http://127.0.0.1:8080/v1/search \
  -F 'image=@question.jpg' \
  -F 'cuid=MY-CLIENT-ID|0'
```

### JSON 上传

```bash
base64 < question.jpg | tr -d '\n' > /tmp/question.b64
python3 - <<'PY' >/tmp/request.json
import json
from pathlib import Path
print(json.dumps({"imageBase64": Path("/tmp/question.b64").read_text()}))
PY
curl -X POST http://127.0.0.1:8080/v1/search \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/request.json
```

成功响应结构：

```json
{
  "metadata": {
    "generatedAt": "2026-09-18T12:07:28Z",
    "imageSha256": "...",
    "protocolVersion": "14.53.0"
  },
  "summary": {
    "sid": "...",
    "subject": "数学",
    "matchCount": 5,
    "pictureUrl": "https://...",
    "answerTexts": ["1. $1+1=2$"]
  },
  "decoded": {},
  "rawResponse": {}
}
```

请求体上限为 15 MiB，解码后的图片上限为 12 MiB。无效输入返回 4xx；上游握手或搜索失败返回 `502 upstream_error`。实现没有自动重试或旧协议回退。

## Docker

```bash
docker build -t zyb-search-api .
docker run --rm -p 8080:8080 zyb-search-api
```

## Python 调用

```python
from pathlib import Path
from zyb_search_api import search_bytes

result = search_bytes(
    Path("question.jpg").read_bytes(),
    cuid="MY-CLIENT-ID|0",
)
print(result["summary"])
```

## 命令行客户端

```bash
zyb-search --image samples/test-question.jpg -o result.json
```

## 测试

```bash
make test
```

测试覆盖定制 DES、wire 编解码、握手、请求签名和响应密钥的原生差分向量。仓库内测试图也已完成真实接口验证：返回数学、5 条匹配，解密答案包含 `1+1=2`。

完整算法说明见 [docs/reverse-engineering-report.md](docs/reverse-engineering-report.md)，脱敏验证记录见 [docs/validation.json](docs/validation.json)。

这是第三方未公开移动端协议的互操作实现，服务端升级后可能变化。请仅上传你有权处理的图片。
