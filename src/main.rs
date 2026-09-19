//! cache-node v0 —— zerostack 节点网格第一原子：内容寻址 (sha256) KV。
//!
//! API:
//!   PUT /cache/{64hex}   body = bytes；校验 sha256(body)=={hash} 后落盘（幂等/原子）
//!   GET /cache/{64hex}   200 + bytes | 404
//!   GET /healthz         {blobs, bytes, root, version}
//!
//! 设计（信条：验证在门口 / 原子化构建）：
//! - git/attic 式两级 fanout：blobs/ab/cdef…，避免巨型目录
//! - 临时文件 + rename：blob 原子可见，断电不留半截
//! - content-addressed：写入时校验 hash，天然幂等 + 防篡改；改一字节 = 另一个 key

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// mesh 模块仅在有 `mesh` feature 时编译（WebRTC 依赖不进默认 KV 单文件构建）。
#[cfg(feature = "mesh")]
mod mesh;
mod mpkg_verify;

#[derive(Clone)]
struct Node {
    root: PathBuf,
    blobs: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

fn hex_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
}

impl Node {
    fn path(&self, hex: &str) -> PathBuf {
        self.root.join(&hex[..2]).join(&hex[2..])
    }

    /// 返回 true=新写入, false=已存在（幂等）
    fn store(&self, hex: &str, data: &[u8]) -> std::io::Result<bool> {
        let p = self.path(hex);
        if p.exists() {
            return Ok(false);
        }
        fs::create_dir_all(p.parent().expect("fanout parent"))?;
        let tmp = p.with_extension("part");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, &p)?;
        self.blobs.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(true)
    }
}

async fn put_cache(State(n): State<Node>, Path(h): Path<String>, body: Bytes) -> impl IntoResponse {
    if !hex_ok(&h) {
        return (
            StatusCode::BAD_REQUEST,
            "hash: need 64 hex chars\n".to_string(),
        );
    }
    let want = h.to_lowercase();
    let got = hex::encode(Sha256::digest(&body));
    if want != got {
        return (
            StatusCode::BAD_REQUEST,
            format!("hash mismatch: sha256(body)={got}\n"),
        );
    }
    match n.store(&want, &body) {
        Ok(true) => (
            StatusCode::CREATED,
            format!("stored {} bytes\n", body.len()),
        ),
        Ok(false) => (StatusCode::OK, "dedup (already exists)\n".to_string()),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("io: {e}\n")),
    }
}

async fn get_cache(State(n): State<Node>, Path(h): Path<String>) -> impl IntoResponse {
    if !hex_ok(&h) {
        return (
            StatusCode::BAD_REQUEST,
            Bytes::from_static(b"hash: need 64 hex chars\n"),
        )
            .into_response();
    }
    match fs::read(n.path(&h.to_lowercase())) {
        Ok(data) => (StatusCode::OK, data).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Bytes::from_static(b"not found\n")).into_response(),
    }
}

async fn healthz(State(n): State<Node>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "cache-node",
        "version": VERSION,
        "blobs": n.blobs.load(Ordering::Relaxed),
        "bytes": n.bytes.load(Ordering::Relaxed),
        "root": n.root,
    }))
}

/// GET /manifest —— 本节点全部 blob 的 hash 清单（对账/同步用）
async fn manifest(State(n): State<Node>) -> Json<serde_json::Value> {
    let mut items = Vec::new();
    if let Ok(l1) = fs::read_dir(&n.root) {
        for d in l1.flatten() {
            let prefix = d.file_name().to_string_lossy().to_string();
            if let Ok(l2) = fs::read_dir(d.path()) {
                for f in l2.flatten() {
                    let name = f.file_name().to_string_lossy().to_string();
                    if name.ends_with(".part") {
                        continue;
                    }
                    if let Ok(md) = f.metadata() {
                        if md.is_file() {
                            items.push(serde_json::json!({
                                "hash": format!("{prefix}{name}"),
                                "size": md.len(),
                            }));
                        }
                    }
                }
            }
        }
    }
    items.sort_by(|a, b| a["hash"].as_str().cmp(&b["hash"].as_str()));
    Json(serde_json::json!({ "count": items.len(), "blobs": items }))
}

/// 零依赖 HTTP GET 客户端（仅对本节点/受信对端使用；MVP 不跟随重定向）
fn http_get(hostport: &str, path: &str) -> Result<Vec<u8>, String> {
    let mut s = TcpStream::connect(hostport).map_err(|e| format!("connect {hostport}: {e}"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .ok();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("bad http: no header terminator")?;
    let head = String::from_utf8_lossy(&raw[..sep]).to_lowercase();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .ok_or("bad http: status line")?;
    if status != 200 {
        return Err(format!("peer http {status}"));
    }
    let body = &raw[sep + 4..];
    if head.contains("transfer-encoding: chunked") {
        Ok(dechunk(body))
    } else {
        Ok(body.to_vec())
    }
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(nl) = body.windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let len_str = std::str::from_utf8(&body[..nl]).unwrap_or("0");
        let Ok(len) = usize::from_str_radix(len_str.split(';').next().unwrap_or("0").trim(), 16)
        else {
            break;
        };
        if len == 0 || nl + 2 + len > body.len() {
            break;
        }
        out.extend_from_slice(&body[nl + 2..nl + 2 + len]);
        body = &body[(nl + 2 + len + 2).min(body.len())..];
    }
    out
}

/// POST /sync {"peer":"host:port"} —— 对账并拉取本节点缺失的 blob（落地前逐个 hash 校验）
async fn sync(
    State(n): State<Node>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let Some(peer) = req.get("peer").and_then(|v| v.as_str()) else {
        return Json(serde_json::json!({ "error": "body must be {\"peer\":\"host:port\"}" }));
    };
    let peer = peer.trim_start_matches("http://").trim_end_matches('/');
    let manifest: serde_json::Value = match http_get(peer, "/manifest") {
        Ok(v) => serde_json::from_slice(&v).unwrap_or(serde_json::json!({})),
        Err(e) => return Json(serde_json::json!({ "error": e })),
    };
    let mut pulled = 0u64;
    let mut skipped = 0u64;
    let mut bytes = 0u64;
    let mut errors: Vec<String> = Vec::new();
    for b in manifest["blobs"].as_array().map_or([].as_slice(), |a| a) {
        let Some(hash) = b["hash"].as_str() else {
            continue;
        };
        if !hex_ok(hash) {
            continue;
        }
        if n.path(hash).exists() {
            skipped += 1;
            continue;
        }
        match http_get(peer, &format!("/cache/{hash}")) {
            Ok(data) => {
                let got = hex::encode(Sha256::digest(&data));
                if got != hash {
                    errors.push(format!("{hash}: digest mismatch on pull"));
                    continue;
                }
                match n.store(hash, &data) {
                    Ok(_) => {
                        pulled += 1;
                        bytes += data.len() as u64;
                    }
                    Err(e) => errors.push(format!("{hash}: {e}")),
                }
            }
            Err(e) => errors.push(format!("{hash}: {e}")),
        }
    }
    Json(serde_json::json!({
        "peer": peer, "pulled": pulled, "skipped": skipped, "bytes": bytes, "errors": errors,
    }))
}

fn count_existing(root: &str) -> (u64, u64) {
    let (mut blobs, mut bytes) = (0u64, 0u64);
    if let Ok(l1) = fs::read_dir(root) {
        for d in l1.flatten() {
            if let Ok(l2) = fs::read_dir(d.path()) {
                for f in l2.flatten() {
                    if let Ok(md) = f.metadata() {
                        if md.is_file() && !f.path().extension().is_some_and(|e| e == "part") {
                            blobs += 1;
                            bytes += md.len();
                        }
                    }
                }
            }
        }
    }
    (blobs, bytes)
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map_or(false, |a| a == "verify") {
        mpkg_verify::handle(&argv[1..]);
        return;
    }
    #[cfg(feature = "mesh")]
    if argv.first().map_or(false, |a| a == "mesh") {
        let get = |k: &str| {
            argv.iter()
                .position(|a| a == k)
                .and_then(|i| argv.get(i + 1))
                .cloned()
                .unwrap_or_default()
        };
        let args = mesh::MeshArgs {
            role: get("--role"),
            signal: get("--signal"),
            session: get("--session"),
            root: PathBuf::from(if get("--root").is_empty() {
                "blobs".to_string()
            } else {
                get("--root")
            }),
        };
        if let Err(e) = mesh::run(args).await {
            eprintln!("mesh: {e}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(not(feature = "mesh"))]
    if argv.first().map_or(false, |a| a == "mesh") {
        eprintln!("cache-node: 本二进制未内置 mesh 模块 (WebRTC P2P 同步)");
        eprintln!("请带 mesh feature 重新编译: cargo build --release --features mesh");
        std::process::exit(2);
    }
    let root = std::env::var("CACHE_NODE_ROOT").unwrap_or_else(|_| "blobs".into());
    let addr = std::env::var("CACHE_NODE_ADDR").unwrap_or_else(|_| "0.0.0.0:9910".into());
    fs::create_dir_all(&root).expect("create blob root");

    let (blobs, bytes) = count_existing(&root);
    let node = Node {
        root: root.clone().into(),
        blobs: Arc::new(AtomicU64::new(blobs)),
        bytes: Arc::new(AtomicU64::new(bytes)),
    };

    let app = Router::new()
        .route("/cache/{hash}", put(put_cache).get(get_cache))
        .route("/manifest", get(manifest))
        .route("/sync", post(sync))
        .route("/healthz", get(healthz))
        .with_state(node);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    eprintln!("cache-node v{VERSION} on http://{addr}  root={root}  blobs={blobs} bytes={bytes}");
    axum::serve(listener, app).await.expect("serve");
}
