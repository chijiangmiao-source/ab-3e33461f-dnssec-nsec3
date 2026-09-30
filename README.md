# NSEC3 不存在证明离线审计服务

面向卫星任务离线控制网的值班审计工具：核对收到的 NSEC3 记录组是否**确实**
证明某主机名不存在（NXDOMAIN），防止把截断证据、错误环绕区间或伪造的通配符
排除证据误判为 NXDOMAIN。

- 仅处理 **SHA-1（算法号 1）** 且 **flags=0（无 Opt-Out）** 的 NSEC3；
- 对目标名称及全部祖先**精确复算迭代哈希**：
  `H0 = SHA1(wire(name) ‖ salt)`，`H(k) = SHA1(H(k−1) ‖ salt)`，
  输出为无填充大写 Base32hex（字母表 `0-9A-V`）；
- 判定 RFC 7129「最近存在祖先证明（Closest Encloser Proof）」三要素；
- 结论按**稳定审计标识冻结**，可凭标识重新打开逐项证据；
- 仅依赖 Python 3.11 标准库，离线构建、离线运行。

## 判定规则

设目标名称为 Q，其祖先链从区域顶点逐标签上升到 Q：

1. **最近存在祖先 CE**：祖先链上哈希命中某条 NSEC3 `owner` 的**最深**名称；
2. **下一层名称 NC**：CE 之下通往 Q 的第一层名称，必须被某条 NSEC3 的
   半开环形区间 `(owner, next]` **覆盖**（哈希不得等于任一 owner——
   命中先于覆盖，命中即名称存在，绝不按覆盖处理）；
3. **通配符排除 WC**：`*.CE` 必须同样被某条区间覆盖。

三项事实全部成立，且记录组自身一致，才给出 `PASS / NXDOMAIN_PROVEN`。
环形区间语义（模 2^160）：

- 正向 `FORWARD`（owner < next）：`owner < hash ≤ next`；
- 环绕 `WRAP_AROUND`（owner > next，跨零）：`hash > owner` 或 `hash ≤ next`。

以下情形一律拒绝（`REJECTED`，绝不给出通过结论）：

| 情形 | 拒绝码 |
|---|---|
| 重复 owner | `DUPLICATE_OWNER` |
| 区间内部严格包含另一条 owner（错误环绕/伪造链） | `ASSERTION_CONFLICT` |
| NC/WC 哈希命中 owner（名称或通配符实际存在） | `ASSERTION_CONFLICT` |
| 非法 Base32hex（非法字符、填充、非零尾部位） | `ILLEGAL_BASE32HEX`（400） |
| 哈希长度不是 20 字节（截断/补齐证据） | `TRUNCATED_HASH`（400） |
| 非 SHA-1 或 Opt-Out | `UNSUPPORTED_ALGORITHM` / `OPT_OUT_UNSUPPORTED`（400） |
| 审计标识复用但归一化载荷改变 | `AUDIT_ID_REUSED`（409） |
| 无 CE / NC 或 WC 未被覆盖 / 目标自身存在 | `INSUFFICIENT_EVIDENCE`、`MISSING_NEXT_CLOSER_COVER`、`MISSING_WILDCARD_COVER`、`TARGET_NAME_EXISTS` |

哈希实现以 RFC 5155 附录 A 向量校验，并以附录 I.5 的真实 NXDOMAIN 响应
（`x.w.c.example`，盐 `aabbccdd`，12 轮）作为端到端验收基线。

## 目录结构

```
app/nsec3.py      原语：线型名称、SHA-1 迭代哈希、Base32hex
app/verifier.py   最近存在祖先证明判定（CE/NC/WC、区间、一致性）
app/storage.py    冻结结论持久化（JSON + fcntl 锁，幂等/复用检测）
app/server.py     HTTP 服务与审计页面（标准库 http.server）
tests/            45 个单元/HTTP 测试（RFC 官方向量 + 全拒绝类别）
verify_pkg/       一次性验收包（构建检查、测试、API/HTTP 冒烟穿插执行）
verify            可执行入口：./verify
Dockerfile        零三方依赖镜像
docker-compose.yml web（常驻）+ verify（一次性）
```

## 运行

### Docker Compose

```bash
# 宿主机端口由 .env 的 WEB_HOST_PORT 决定（默认 8080）
cp .env.example .env
docker compose up -d web

# 健康地址与审计页面（宿主机端口）
curl -s http://localhost:8080/healthz
open http://localhost:8080/
```

### 一次性验收服务 verify

verify 会穿插执行字节码构建检查、全部代码测试与 API/HTTP 冒烟
（合法证明通过与环绕覆盖确认、遗漏通配符覆盖拒绝、非法记录拒绝、
标识复用拒绝、页面并列证据检查），**完成后退出并以退出码报告结果**：

```bash
# 方式一：随栈启动，以 verify 容器退出码为整个编排的退出码
docker compose up --abort-on-container-exit --exit-code-from verify

# 方式二：web 已在运行，单独跑一次性验收
docker compose run --rm verify
# 容器内等价命令
verify --base-url http://web:8080

# 方式三：不依赖 Docker，本地直接执行（进程内临时端口自启真实服务）
./verify
python3 -m verify_pkg --base-url http://localhost:8080
```

### 本地直接运行服务

```bash
AUDIT_PORT=8080 AUDIT_DATA_DIR=./data python3 -m app.server
python3 -m unittest discover -s tests -v
```

## HTTP API

| 方法 路径 | 说明 |
|---|---|
| `GET /healthz` | 健康检查 `{ "status": "ok" }` |
| `GET /` | 审计提交页 |
| `POST /api/audits` | 提交载荷（JSON），冻结并返回结论；重复同载荷 200 幂等，载荷冲突 409 |
| `GET /api/audits` | 列出全部审计标识 |
| `GET /api/audits/<audit_id>` | 读取冻结结论（JSON，含逐项证据与数值排序） |
| `GET /audits/<audit_id>` | 按标识重新打开冻结结论页面 |

提交载荷示例（RFC 5155 I.5）：

```json
{
  "audit_id": "SAT-MISSION-20260930-01",
  "zone": "example",
  "qname": "x.w.c.example",
  "salt": "aabbccdd",
  "iterations": 12,
  "records": [
    {"owner_hash": "4G6P9U5GVFSHP30PQECJ98B3MAQBN1CK",
     "next_hash": "B76EQLMTQ7S6IULHLPOQGM1COPU2PCA6",
     "types": ["NS", "DS", "RRSIG"]},
    {"owner_hash": "U5KHQI4917VS9CA7IRC0TOT78AM6208L",
     "next_hash": "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM",
     "types": ["RRSIG"]}
  ]
}
```

冻结页面与 JSON 结论并列展示：最近存在祖先、两项被覆盖名称（NC/WC）、
各自迭代哈希、承担事实的所用记录及环绕方向（FORWARD / WRAP_AROUND）、
逐祖先哈希复算表，供审查员独立复算。

## 审计标识与冻结语义

- 标识限定 `[A-Za-z0-9_-]{1,64}`；
- 同标识 + 同归一化载荷（忽略大小写、记录顺序、类型位图顺序）→ 幂等返回；
- 同标识但参数或记录内容改变 → `409 AUDIT_ID_REUSED`，原结论**永不被覆盖**；
- 证据不足的提交同样冻结为 `REJECTED`，保留完整审计轨迹。
