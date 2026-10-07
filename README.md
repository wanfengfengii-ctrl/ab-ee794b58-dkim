# DKIM Forensic Audit Gateway

归档外部来信**之前**对邮件进行 DKIM (RFC 6376) 独立复核的服务。即使转发组件折叠了首部、改写了正文或在多个同名字段中选错了实例，本服务也不会把被篡改的邮件标记为可信。

- 纯 Python 标准库实现（RSA-PKCS#1 v1.5 验证、规范化、DER 解析均自带），构建期**无需网络**
- `POST /api/dkim/audit`，接收 `application/rfc822`，上限 2 MiB，强制 CRLF 行边界，仅处理**单个** `DKIM-Signature`
- 正文摘要 (`bh`) 与密码学签名 (`b=`) 给出**相互独立**的裁决
- 严格策略：仅 `rsa-sha256`；首部/正文规范化仅接受 `simple`/`relaxed`；禁止 `l=`；`h=` 必须覆盖 `From`
- 折行 (folding)、尾随空行、重复首部的**自底向上选取**均按 RFC 6376 处理
- Dockerfile + 可配置宿主端口的 Compose + 健康检查
- 一次性 `verify` 服务：等待 API 健康后执行构建检查、单元测试与 HTTP 冒烟，以退出码汇总

## 目录结构

```
app/dkim_core.py        DKIM 核心：解析/规范化/策略/正文摘要/RSA 验证
app/server.py           http.server 实现的 REST 前端
config/keyring.json     按域 -> 选择器登记的 RSA 公钥 (DNS p= 标签格式)
tests/test_dkim_core.py 34 个单元测试
tests/fixtures/*.eml    冻结的签名样例（见下）
tests/tools/            离线签名器与 fixture 生成器
smoke/smoke_http.py     HTTP 端到端冒烟（11 项）
verify/entrypoint.sh    一次性验证编排（构建/等待/单测/冒烟）
Dockerfile, docker-compose.yml
```

## 运行

```sh
# 默认发布到宿主 8080
docker compose up --build api

# 自定义宿主端口
DKIM_HOST_PORT=18080 docker compose up --build api
```

一次性验证作业（会先等 API 健康，再跑全部检查；非零退出码表示失败）：

```sh
docker compose build
docker compose up verify          # 或: docker compose up --build
```

## API

`POST /api/dkim/audit` — 请求体为原始 RFC 822 邮件，`Content-Type: application/rfc822`。

合法邮件响应（HTTP 200）：

```json
{
  "decision": "accept",
  "reason_code": "OK",
  "domain": "example.com",
  "selector": "default",
  "algorithm": "rsa-sha256",
  "canonicalization": {"headers": "relaxed", "body": "relaxed"},
  "signed_headers": ["from", "to", "subject", "date", "message-id"],
  "body_verdict": {"verdict": "pass", "algorithm": "sha256", "...": "..."},
  "signature_verdict": "pass"
}
```

正文被改写时（HTTP 422），正文摘要失败但首部签名仍独立显示 `pass`，两类问题可区分：

```json
{
  "decision": "reject",
  "reason_code": "BODY_HASH_MISMATCH",
  "body_verdict": {"verdict": "fail", "declared_bh": "…", "computed": "…"},
  "signature_verdict": "pass"
}
```

### 稳定原因码

| reason_code | 含义 |
| --- | --- |
| `OK` | 正文摘要与签名均通过，允许归档 |
| `NO_SIGNATURE` / `MULTIPLE_SIGNATURES` | 无签名 / 签名不唯一 |
| `MALFORMED_MESSAGE` / `MALFORMED_SIGNATURE` | 非 CRLF 框架、结构损坏、base64 非法等 |
| `NONCOMPLIANT_TAG` | 标签不合规（重复标签、`v≠1`、`q≠dns/txt`、d/s 非法等） |
| `L_TAG_FORBIDDEN` | 出现 `l=`（长度）标签 |
| `UNSUPPORTED_ALGORITHM` | 非 `rsa-sha256` |
| `UNSUPPORTED_CANONICALIZATION` | 非 `simple`/`relaxed` |
| `FROM_NOT_SIGNED` | `h=` 未覆盖 `From` |
| `UNKNOWN_KEY` | keyring 中无该域/选择器登记 |
| `KEY_UNAVAILABLE` | 公钥数据损坏 |
| `BODY_HASH_MISMATCH` | 规范化正文 SHA-256 与 `bh=` 不符（正文被改写/折行处理错误） |
| `SIGNATURE_MISMATCH` | 首部签名数据 RSA 验证失败（首部被折叠/改写/选错重复字段） |
| `MESSAGE_TOO_LARGE` | 超过 2 MiB |

归档组件应只信任 `decision == "accept"`（等价于 `reason_code == "OK"` 且两个独立裁决均为 `pass`）。

`signature_verdict` 有三种取值：`pass` / `fail`（有登记公钥且 RSA 验证成功/失败）、`indeterminate`（`UNKNOWN_KEY`/`KEY_UNAVAILABLE`，无法进行密码学判定；`signature_detail` 给出细节）。

## 密钥登记

`config/keyring.json`：

```json
{
  "example.com": {
    "default": {"kty": "rsa", "p": "<base64 DER 公钥>"}
  }
}
```

`p` 接受 RFC 3110 裸 `RSAPublicKey`（DNS TXT 实际发布格式）或 SubjectPublicKeyInfo。从 PEM 生成：

```sh
openssl rsa -in key.pem -RSAPublicKey_out  # 取出 DER 段 base64 拼为 p
```

## 测试与样例

冻结的 `.eml` fixture 由 `tests/tools/generate_fixtures.py` 离线生成；生成时每个签名都会用 **OpenSSL CLI 独立交叉验证**（`pkeyutl -verifyrecover`），避免“自证”。

- `valid_relaxed.eml` / `valid_simple.eml` — 合法签名（relaxed/relaxed 含折行 b=；simple/simple 含尾随空行）
- `body_rewritten.eml` — 首部原样、正文改写 → `BODY_HASH_MISMATCH`，签名裁决仍 `pass`
- `duplicate_headers_valid.eml` — 两个 `X-Trace`，`h=` 只签一次 → 取自底向上的最后一个
- `duplicate_headers_top_mutated.eml` — 改写未签的上方实例 → 仍通过
- `duplicate_headers_bottom_mutated.eml` — 改写被签的底部实例 → `SIGNATURE_MISMATCH`
- `duplicate_headers_both_signed.eml` — `h=` 列出两次，两个实例均被签

本地重新生成（需要 openssl 二进制，仅维护时使用，运行镜像不需要）：

```sh
python3 tests/tools/generate_fixtures.py
```
