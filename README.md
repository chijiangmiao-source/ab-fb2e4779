# 隔离维护站 · 设备指令委托包核验系统

值班员在页面粘贴外部签发的委托包与待执行命令，系统在提交前逐级核验 Ed25519
委托链（每一级权限只会收窄），核验通过后在**一次持久化裁决**中完成恰好一次
设备执行并返回稳定回执；被篡改、越权、过期或被有效撤销的委托不会留下任何
执行记录。零第三方依赖（纯 Python 标准库实现 RFC 8032 Ed25519、HTTP 服务与
SQLite 持久化）。

## 快速开始

```bash
# 启动维护站（宿主端口可用 HOST_PORT 覆盖，默认 8080）
HOST_PORT=8080 docker compose up --build app
# 打开 http://localhost:8080 进入核验台

# 运行验收（构建 + 单元测试 + HTTP/API 冒烟 + 三大场景），退出码即结果
docker compose up --build --exit-code-from verify
echo $?   # 0 = 全部通过
```

本地无 Docker 时：

```bash
DATA_DIR=/tmp/data PORT=8000 python3 -m app.server          # 启动服务
APP_URL=http://127.0.0.1:8000 APP_ROOT=$PWD python3 -m verify.verify   # 验收
python3 -m unittest discover -s tests -v                    # 仅单元测试
```

## 委托包格式（规范 UTF-8 JSON）

```json
{
  "chain": [
    {
      "payload": {
        "issuer": "root-authority", "delegate": "ops-team",
        "delegate_key": "<下级公钥 hex>",
        "devices": ["pump-01", "valve-07"], "commands": ["restart", "status"],
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
        "item_id": "唯一标识", "parent_digest": null
      },
      "public_key": "<本级签发者 Ed25519 公钥 hex>",
      "signature": "<对 payload 规范 JSON 字节的签名 hex>"
    }
  ],
  "revocations": [
    {"payload": {"type": "revocation", "target_digest": "<链项摘要>",
                 "issued_at": "...", "reason": "..."},
     "public_key": "<根或链上任一签发者公钥>", "signature": "..."}
  ]
}
```

裁决规则：

- 仅接受严格 UTF-8 JSON（拒绝重复键、NaN、非法字节），所有摘要/签名输入
  均为规范序列化（键排序、无空白、UTF-8）。
- 根项公钥必须在受信集合内；每个子项 `parent_digest` 必须等于父项整体摘要，
  且设备集合、命令集合、有效窗口只能收窄；签发者/公钥须与上级委托衔接。
- 撤销声明须由根或链上任一签发者签名，且 `target_digest` 命中本链某项；
  无效撤销声明被忽略并如实展示。
- **裁决键** = SHA-256(根公钥, 链摘要, 叶项标识, 请求载荷)；**叶键** =
  SHA-256(根公钥, 链摘要, 叶项标识)。
- 末级凭据单次有效：同一裁决键的并发提交/重试收敛为一次执行与同一回执；
  同一叶键携带不同请求再次提交将被拒绝（409），且不产生新执行记录。
- 被拒绝（篡改/越权/过期/撤销）的请求不写入任何持久化记录。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康响应（含已持久化裁决数） |
| GET | `/` | 值班员核验台页面 |
| GET | `/api/demo` | 内置演练包（valid/tampered/out_of_scope/expired/revoked） |
| POST | `/api/inspect` | 干跑核验：逐级签名、主体、范围、窗口、首个拒因 |
| POST | `/api/execute` | 裁决并幂等执行，返回稳定回执或拒因 |
| GET | `/api/verdicts` | 已持久化裁决复核（重启后仍在） |

## 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `HOST_PORT` | `8080` | Compose 宿主端口映射 |
| `PORT` | `8000` | 容器内监听端口 |
| `DATA_DIR` | `/data` | SQLite 持久化目录（Compose 卷 `station-data`） |
| `TRUSTED_ROOTS` | 空 | 追加受信根公钥（逗号分隔 hex） |
| `DEMO_ROOT_ENABLED` | `1` | 置 `0` 停用内置演练根密钥与演练包接口 |

## 验收容器 `verify`

`verify` 与 `app` 共用镜像，待 `app` 健康后依次执行并以退出码报告：

1. 单元测试（RFC 8032 测试向量、链收窄/绑定规则、存储幂等）；
2. HTTP 冒烟（`/healthz`、操作员页面）与 API 冒烟（`/api/demo`、`/api/inspect`）；
3. **有效执行**：返回回执、重试返回同一回执、裁决可复核；
4. **并发重传**：8 路并发相同提交收敛为一次执行、同一回执，叶凭据单次有效；
5. **篡改拒绝**：篡改已签字段、越权命令、过期、有效撤销声明均被拒（400），
   且不留下执行记录。
