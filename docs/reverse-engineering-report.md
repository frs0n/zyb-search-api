# 作业帮 14.53.0 搜题接口完整分析

## 结论

样本 APK 的单题搜题链路已完整还原。交付实现直接执行等价的 Python 算法，不加载或模拟 ARM `.so`。2026-09-18 的在线验证中，测试图片 `1 + 1 = ?` 完成握手、签名、上传及多层响应解密，返回 `errNo=0`、数学、5 条匹配，答案包含 `1+1=2`。

## 样本

| 项目 | 值 |
|---|---|
| 包名 | `com.baidu.homework` |
| versionName / versionCode | `14.53.0 / 2810` |
| minSdk / targetSdk | `21 / 31` |
| APK SHA-256 | `a22a5bab20855278c1ab92f0ea5c8d775c3b59b9790ce32dca8f4e9ed87f32a2` |
| 签名证书 DER SHA-256 | `065a135e573f6287ed63e8b9ddfd8164c6ecc8a0d9f3d1888381af4923e29a64` |
| 分析库 | `lib/armeabi-v7a/libbaseutil.so` |
| SO SHA-256 | `6558c123c13170617fdb327ea013b7f56d37d45ca8296508e03eaf13de5cbb23` |

该 ARM32 ELF 保留了符号和源文件信息。关键 JNI 导出为 `nativeInitBaseUtil`、`nativeSetToken`、`nativeGetSign`、`nativeGetKey`、`nativeGetRandom`。

## 接口

| Host | 路径 | 编码 | 用途 |
|---|---|---|---|
| `pluto.zuoyebang.com` | `/pluto/app/antispam` | POST form | 协商 10 字符会话 token |
| `aisearch.zuoyebang.com` | `/search/submit/single` | POST multipart | 单题图片搜索 |

当前 Activity 使用第二个接口，文件字段名和文件名均为 `image`。

## 原生算法还原

### 1. `nativeInitBaseUtil`

生成 10 个 ASCII 字母或数字作为 `challenge`。APK 签名通过 Android `Signature.toCharsString()` 得到小写十六进制文本，再取 MD5；本样本的结果为：

```text
0f3c509eef614432e414ce9d37f00c80
```

拼接明文：

```text
8&%d*##{challenge}##{certificateCharsMd5}##{cuid}
```

明文用 8 字节密钥 `@fG2SuLA` 加密，再转为 wire 字符串形成 `signA`。

加密器源自 DES，但有三处必须严格复现：

1. 字节展开为 bit 时按低位到高位；
2. PC2 表索引 35 的值为 `46`，标准 DES 对应位置为 `47`；
3. 填充为若干 `00` 加最后一个填充长度字节。例如补 3 字节时为 `00 00 03`。

wire 编码先反转每个密文字节的 8 个 bit，再把高、低半字节分别格式化为两位十六进制，因此每个输入字节输出 4 个字符。解码执行逆过程。

### 2. `nativeSetToken`

客户端用 `@fG2SuLA` 解密自身的 `signA`，检查固定前缀、challenge、证书摘要和 cuid。服务端的 `signB` 使用同一 wire 编码，其 DES 密钥为：

```text
{challenge 前 5 字符}#G4
```

解密明文为：

```text
{challenge}##{sessionToken}
```

两边 challenge 必须相同，session token 长度必须为 10。通过后 token 成为当前请求会话状态。

### 3. `nativeGetSign`

业务参数先逐项转成 `key=value`，按整个字符串字典序排序，无分隔符拼接，再做标准 Base64。签名为下列 UTF-8 文本的小写 MD5：

```text
8&%d*[{MD5(sessionToken)}]@{base64Payload}
```

固定差分向量：session token `rsbV4048PW`、payload `YWJj` 的结果为：

```text
12ca66351c37c5fe0e0314c7e4689d33
```

### 4. `nativeGetKey`

设：

```text
A = MD5("@#AIjd83#@6B")
B = MD5(versionCode)
C = MD5("[" + sessionToken + "]@")
```

原生循环仅交换 `C[0..14]` 与对应尾部字符，所以 32 字符串中间的 `C[15]`、`C[16]` 保持原顺序。令该结果为 `C'`：

```text
X = A + B + C'
交换 X 的首尾各 3 个字符（0↔95、1↔94、2↔93）
Y = X + MD5(X)
交换 Y 的前后 60 对字符
```

最终 `Y` 长 128 字符，直接作为响应 RC4 基础 key。固定差分向量 `versionCode=2810`、token=`rsbV4048PW` 的结果为：

```text
70d9aac75172a49edb6063a473c01bb16a55a8e808bc17c8ab697e8cc07341befe888bff7cd3cab59f063880ae27736631cd22941af1d9898bc5ba70303e7918
```

Python 的签名与 key 均通过同一输入下的原生函数逐字节差分验证。

## 搜题参数

公共字段为 `cuid`、`channel=official`、APK 内 token、`vc=2810`、`vcname=14.53.0`、`os=android`、`sdk=31`、`device=Pixel 6`、`pkgName=com.baidu.homework`、`appId=homework`、`androidVersion=12`。

业务字段包括图片 MD5、随机 `sessionID`、`firstActTime`、秒级 `_t_`、单调时钟毫秒 `kakorrhaphiophobia` 以及 Activity 设置的空值和开关。完整集合以 `src/zyb_search_api/client.py` 的 `params` 为准。`sign` 在其他参数完成排序和 Base64 后生成，不参与自身签名。

省略 `_t_` 时上游返回 `errNo=5110 / lack time param: _t_`；有时间但无签名时返回 `errNo=5103 / user params lack sign key words`。

## 响应解密

当 `answers.encryption=1`：

1. `tids[i]` 做 Base64 解码，再以 128 字符基础 key 做 RC4，得到第 i 条子 key；
2. `mainPageInfo[i]` 做 Base64 解码，以子 key 做 RC4，结果作为另一层 Base64；
3. 再 Base64 解码，以基础 key 做 RC4；
4. 若 `answers.gzip=1`，执行 Gzip 解压，再解析 JSON；
5. `commonPageInfo` 直接执行“Base64 → 基础 key RC4 → 可选 Gzip → JSON”。

解密后的 JSON 仍可能嵌套 JSON 字符串，客户端会递归解析。

## 交付结构与边界

`src/zyb_search_api/protocol.py` 是纯算法层，`src/zyb_search_api/client.py` 是上游客户端，`src/zyb_search_api/api.py` 暴露本地 HTTP API。运行期只依赖 Python 3.10+ 标准库，没有 APK、SO、Java 或模拟器路径。

实现面向此固定版本，不包含协议猜测、旧接口回退、自动重试、登录或验证码处理。服务端协议变更时会明确返回错误。
