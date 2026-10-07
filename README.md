# cache-node —�?zerostack 节点网格

内容寻址 (sha256) KV 缓存节点 + 节点间同�?+ WebRTC 数据通道 P2P + mpkg Rust 验证器�?

默认构建 = �?KV 单文件二进制（musl 构建�?1MB 量级），零运行时依赖�?
`--features mesh` 追加 WebRTC P2P 网格能力（webrtc 0.13 仅在�?feature 下编译）�?
Linux/Windows/Android 全平台�?

> 本拆分属 lilyco 生态路线图 P2（结构重组）：把"KV 原子"�?P2P 网格"在构建层解耦，
> 默认产物回归 README 宣称的单文件体积�?

## 快速开�?

```bash
# 启动节点 (默认 0.0.0.0:9910, blob 目录 ./blobs)
CACHE_NODE_ADDR=0.0.0.0:9910 ./cache-node

# 三平台产�? GitHub Releases (aarch64/x86_64 musl 静�?+ windows MSVC)
```

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| PUT | `/cache/{64hex}` | body=bytes；校�?sha256(body)=={hash} 后落盘（幂等/原子）。不�?�?400 |
| GET | `/cache/{64hex}` | 200 + bytes \| 404 |
| GET | `/manifest` | 本节点全�?blob 清单 `[{hash,size}]`（对�?同步用） |
| POST | `/sync` | `{"peer":"host:port"}` —�?对账并拉取缺�?blob（落地前逐个 hash 校验�?|
| GET | `/healthz` | `{blobs, bytes, root, version}` |

设计：git/attic 式两�?fanout、临时文�?rename 原子落盘、content-addressed 天然防篡改（改一字节 = 另一�?key）�?

## WebRTC mesh（P2P 同步, 需 `--features mesh`�?

```bash
# 被拉�?(持有产物)
cache-node mesh --role answer --signal https://lain42.top/signal --session s1 --root blobs/
# 拉取�?
cache-node mesh --role offer  --signal https://lain42.top/signal --session s1 --root my-blobs/
```

默认构建不含 mesh：运�?`cache-node mesh` 会提示用 `--features mesh` 重编�?

信令�?`/signal` 中继交换 SDP（非 trickle，候选内嵌），数据走 WebRTC 数据通道直连�?
ICE 配置�?`ice-servers.json`（exe 同目录优先）。传输协议：文本控制（PULL/MANIFEST/GET/DONE�?
+ 二进制块�?6KB 分块），接收端聚合后 sha256 验证。跨机实测：1.3MB 产物字节级一致�?

## mpkg 验证器（Rust 原生�?

```bash
cache-node verify <file.mpkg> [--out att.json]
```

读取记忆包（zip），校验清单，�?step �?POSIX shell 回放（`{{pkg}}`/`{{work}}` 替换�?
expect.exit 校验�?20s 单步超时），产出 attestation。content-id 计算�?Python 实现
（mpkg.py）逐字节一致——双实现互证�?

## 构建

```bash
cargo build --release                                    # 默认: KV 单文�?(�?webrtc)
cargo build --release --features mesh                    # �?WebRTC P2P 网格
cargo build --release --target aarch64-unknown-linux-musl  # 交叉 (需 zigbuild �?musl 工具�?
```

构建矩阵�?

| 构建 | 依赖�?| 产物 |
|---|---|---|
| 默认 | axum + tokio(最�?features) + sha2/hex/serde_json + zip | KV HTTP 节点 + mpkg 验证�?|
| `--features mesh` | 上述 + webrtc 0.13 + ureq + bytes + tokio(time,sync) | 追加 `cache-node mesh` 子命�?|

CI：PR/push main �?fmt + clippy(默认�?mesh 两档) + test（`.github/workflows/ci.yml`）；
�?tag `v*` 自动构建三平台并发布 Release（zigbuild + sccache）�?
验收：`bash smoke.sh`（BASE=http://host:9910）�?

## 许可

MIT OR Apache-2.0
