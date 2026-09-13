# cache-node —— zerostack 节点网格

内容寻址 (sha256) KV 缓存节点 + 节点间同步 + WebRTC 数据通道 P2P + mpkg Rust 验证器。

一个静态单文件二进制（musl 构建 1-1.3MB），零运行时依赖，Linux/Windows/Android 全平台。

## 快速开始

```bash
# 启动节点 (默认 0.0.0.0:9910, blob 目录 ./blobs)
CACHE_NODE_ADDR=0.0.0.0:9910 ./cache-node

# 三平台产物: GitHub Releases (aarch64/x86_64 musl 静态 + windows MSVC)
```

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| PUT | `/cache/{64hex}` | body=bytes；校验 sha256(body)=={hash} 后落盘（幂等/原子）。不符 → 400 |
| GET | `/cache/{64hex}` | 200 + bytes \| 404 |
| GET | `/manifest` | 本节点全部 blob 清单 `[{hash,size}]`（对账/同步用） |
| POST | `/sync` | `{"peer":"host:port"}` —— 对账并拉取缺失 blob（落地前逐个 hash 校验） |
| GET | `/healthz` | `{blobs, bytes, root, version}` |

设计：git/attic 式两级 fanout、临时文件+rename 原子落盘、content-addressed 天然防篡改（改一字节 = 另一个 key）。

## WebRTC mesh（P2P 同步）

```bash
# 被拉方 (持有产物)
cache-node mesh --role answer --signal https://lain42.top/signal --session s1 --root blobs/
# 拉取方
cache-node mesh --role offer  --signal https://lain42.top/signal --session s1 --root my-blobs/
```

信令经 `/signal` 中继交换 SDP（非 trickle，候选内嵌），数据走 WebRTC 数据通道直连；
ICE 配置读 `ice-servers.json`（exe 同目录优先）。传输协议：文本控制（PULL/MANIFEST/GET/DONE）
+ 二进制块（16KB 分块），接收端聚合后 sha256 验证。跨机实测：1.3MB 产物字节级一致。

## mpkg 验证器（Rust 原生）

```bash
cache-node verify <file.mpkg> [--out att.json]
```

读取记忆包（zip），校验清单，逐 step 以 POSIX shell 回放（`{{pkg}}`/`{{work}}` 替换、
expect.exit 校验、120s 单步超时），产出 attestation。content-id 计算与 Python 实现
（mpkg.py）逐字节一致——双实现互证。

## 构建

```bash
cargo build --release                                    # 本机
cargo build --release --target aarch64-unknown-linux-musl  # 交叉 (需 zigbuild 或 musl 工具链)
```

CI：推 tag `v*` 自动构建三平台并发布 Release（zigbuild + sccache）。
验收：`bash smoke.sh`（BASE=http://host:9910）。

## 许可

MIT OR Apache-2.0
