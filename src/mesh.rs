//! mesh —— WebRTC 数据通道 P2P 同步（Phase 2）。
//!
//! 信令: /signal 中继（非 trickle ICE, SDP 内嵌候选）；ICE: ice-servers.json。
//! 传输协议（数据通道上）:
//!   文本: `PULL` / `MANIFEST <json>` / `GET <hash>` / `MISS <hash>` / `DONE`
//!   二进制块: [u32 seq][u32 total][payload ≤16KB]，接收端聚合后 sha256 验证落盘。
//!
//! 用法:
//!   cache-node mesh --role offer  --signal https://lain42.top/signal --session s1 --root blobs/
//!   cache-node mesh --role answer --signal https://lain42.top/signal --session s1 --root blobs/

use bytes::Bytes;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_gathering_state::RTCIceGatheringState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use bytes::Bytes as BBytes;
use webrtc::peer_connection::RTCPeerConnection;

const CHUNK: usize = 16 * 1024;
const SIGNAL_TIMEOUT: u64 = 180;

pub struct MeshArgs {
    pub role: String,
    pub signal: String,
    pub session: String,
    pub root: PathBuf,
}

#[derive(Clone)]
pub struct BlobStore {
    pub root: PathBuf,
}

impl BlobStore {
    fn path(&self, hex: &str) -> PathBuf {
        self.root.join(&hex[..2]).join(&hex[2..])
    }

    pub fn manifest(&self) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        if let Ok(l1) = std::fs::read_dir(&self.root) {
            for d in l1.flatten() {
                if let Ok(l2) = std::fs::read_dir(d.path()) {
                    for f in l2.flatten() {
                        let name = f.file_name().to_string_lossy().to_string();
                        if name.ends_with(".part") {
                            continue;
                        }
                        if let Ok(md) = f.metadata() {
                            if md.is_file() {
                                out.push((format!("{}{}", d.file_name().to_string_lossy(), name), md.len()));
                            }
                        }
                    }
                }
            }
        }
        out.sort();
        out
    }

    fn store(&self, hex: &str, data: &[u8]) -> std::io::Result<bool> {
        let p = self.path(hex);
        if p.exists() {
            return Ok(false);
        }
        std::fs::create_dir_all(p.parent().expect("fanout parent"))?;
        let tmp = p.with_extension("part");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &p)?;
        Ok(true)
    }
}

// ── 信令 HTTP 客户端（ureq, rustls, 零 C 依赖）────────────────────────────

fn sig_post(base: &str, path: &str, body: serde_json::Value) -> Result<(), String> {
    let url = format!("{}/{}", base.trim_end_matches('/'), path);
    let mut err = String::new();
    for attempt in 1..=10 {
        match ureq::post(&url).timeout(Duration::from_secs(15)).send_json(body.clone()) {
            Ok(_) => return Ok(()),
            Err(e) => {
                err = format!("signal POST {path} (try {attempt}): {e}");
                eprintln!("mesh: {err}");
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
    Err(err)
}

fn sig_get(base: &str, path: &str) -> Result<Option<serde_json::Value>, String> {
    let url = format!("{}/{}", base.trim_end_matches('/'), path);
    match ureq::get(&url).timeout(Duration::from_secs(15)).call() {
        Ok(mut r) => {
            let body = r.into_string().map_err(|e| e.to_string())?;
            Ok(serde_json::from_str(&body).ok())
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(e) => Err(format!("signal GET {path}: {e}")),
    }
}

async fn sig_wait_msg(
    base: &str,
    path: &str,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(v) = sig_get(base, path).map_err(|e| e.to_string())? {
            if v.get("msg").and_then(|m| m.as_str()).is_some() {
                return Ok(v);
            }
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("signal timeout waiting {path}"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

// ── ICE / PeerConnection ────────────────────────────────────────────────────

fn ice_servers() -> Vec<RTCIceServer> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("ice-servers.json")));
    let mut cands = vec!["ice-servers.json".to_string(), "/home/radxa/ice-servers.json".to_string()];
    if let Some(e) = exe_dir {
        cands.push(e.to_string_lossy().to_string());
    }
    for cand in &cands {
        let cand = cand.as_str();
        if let Ok(s) = std::fs::read_to_string(cand) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                let mut out = Vec::new();
                if let Some(list) = v["primary"].as_array() {
                    for e in list {
                        if let Some(urls) = e["urls"].as_str() {
                            out.push(RTCIceServer {
                                urls: vec![urls.to_string()],
                                username: e["username"].as_str().unwrap_or("").to_string(),
                                credential: e["credential"].as_str().unwrap_or("").to_string(),
                                ..Default::default()
                            });
                        }
                    }
                }
                if !out.is_empty() {
                    eprintln!("mesh: ICE from {cand} ({} servers)", out.len());
                    return out;
                }
            }
        }
    }
    eprintln!("mesh: ICE default (google stun)");
    vec![RTCIceServer {
        urls: vec!["stun:stun.l.google.com:19302".to_string()],
        ..Default::default()
    }]
}

async fn new_peer() -> Result<Arc<RTCPeerConnection>, String> {
    let m = MediaEngine::default();
    let api = APIBuilder::new().with_media_engine(m).build();
    let config = RTCConfiguration {
        ice_servers: ice_servers(),
        ..Default::default()
    };
    let pc = api.new_peer_connection(config).await.map_err(|e| e.to_string())?;
    Ok(Arc::new(pc))
}

// 非 trickle: set_local 后轮询 gathering 状态 (gatherer 回调类型私有, PC 层公开 API 等效)
async fn gathered_local_sdp(pc: &Arc<RTCPeerConnection>) -> Result<String, String> {
    for _ in 0..100 {
        if pc.ice_gathering_state() == RTCIceGatheringState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if let Some(local) = pc.local_description().await {
        return Ok(local.sdp);
    }
    Err("no local description".into())
}

fn parse_sdp(msg: &str) -> Result<RTCSessionDescription, String> {
    let v: serde_json::Value = serde_json::from_str(msg).map_err(|e| e.to_string())?;
    let sdp = v["sdp"].as_str().ok_or("sdp body missing")?.to_string();
    match v["type"].as_str() {
        Some("offer") => RTCSessionDescription::offer(sdp).map_err(|e| e.to_string()),
        Some("answer") => RTCSessionDescription::answer(sdp).map_err(|e| e.to_string()),
        other => Err(format!("unknown sdp type: {other:?}")),
    }
}

// ── 数据通道角色流程 ────────────────────────────────────────────────────────

async fn pull_flow(
    dc: Arc<RTCDataChannel>,
    mut msg_rx: tokio::sync::mpsc::UnboundedReceiver<DataChannelMessage>,
    store: BlobStore,
) -> Result<(), String> {
    eprintln!("mesh: pull_flow started, ready={:?}", dc.ready_state());
    let first = tokio::time::timeout(Duration::from_secs(60), msg_rx.recv())
        .await
        .map_err(|_| "timeout waiting MANIFEST")?
        .ok_or("channel closed")?;
    let text = String::from_utf8_lossy(&first.data).to_string();
    if !text.starts_with("MANIFEST ") {
        return Err(format!(
            "unexpected first message: {}",
            &text[..text.len().min(40)]
        ));
    }
    let manifest: serde_json::Value =
        serde_json::from_str(text["MANIFEST ".len()..].trim()).map_err(|e| e.to_string())?;
    let blobs = manifest["blobs"].as_array().cloned().unwrap_or_default();

    let mut pulled = 0u64;
    let mut skipped = 0u64;
    for b in &blobs {
        let hash = b["hash"].as_str().unwrap_or("").to_string();
        let size = b["size"].as_u64().unwrap_or(0);
        if hash.len() != 64 || store.path(&hash).exists() {
            skipped += 1;
            continue;
        }
        eprintln!("mesh: pulling {hash} ({size}B)…");
        dc.send(&BBytes::from(format!("GET {hash}")))
            .await
            .map_err(|e| e.to_string())?;

        let total = size as usize / CHUNK + 1;
        let mut buf: Vec<u8> = Vec::with_capacity(size as usize);
        while buf.len() < size as usize {
            let m = tokio::time::timeout(Duration::from_secs(60), msg_rx.recv())
                .await
                .map_err(|_| "timeout waiting chunk")?
                .ok_or("channel closed")?;
            if m.is_string {
                let t = String::from_utf8_lossy(&m.data).to_string();
                if t.starts_with("MISS") {
                    eprintln!("mesh: peer missing {hash}, skip");
                    buf.clear();
                    break;
                }
                return Err(format!("control msg mid-transfer: {}", &t[..t.len().min(40)]));
            }
            let d = &m.data[..];
            if d.len() < 8 {
                return Err("short chunk header".into());
            }
            buf.extend_from_slice(&d[8..]);
            let _ = (d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]); // seq/total 记录用
        }
        if buf.is_empty() {
            skipped += 1;
            continue;
        }
        let got = hex::encode(Sha256::digest(&buf));
        if got != hash {
            return Err(format!("integrity FAIL: got {got}"));
        }
        store.store(&hash, &buf).map_err(|e| e.to_string())?;
        pulled += 1;
        let _ = total;
    }
    dc.send(&BBytes::from("DONE")).await.ok();
    eprintln!("mesh: pull complete pulled={pulled} skipped={skipped}");
    Ok(())
}

async fn serve_flow(
    mut dc_rx: tokio::sync::mpsc::UnboundedReceiver<Arc<RTCDataChannel>>,
    mut msg_rx: tokio::sync::mpsc::UnboundedReceiver<(bool, Vec<u8>)>,
    store: BlobStore,
) -> Result<(), String> {
    let dc = tokio::time::timeout(Duration::from_secs(SIGNAL_TIMEOUT), dc_rx.recv())
        .await
        .map_err(|_| "timeout waiting data channel")?
        .ok_or("no data channel")?;

    // 等 PULL
    let first = tokio::time::timeout(Duration::from_secs(SIGNAL_TIMEOUT), msg_rx.recv())
        .await
        .map_err(|_| "timeout waiting PULL")?
        .ok_or("channel closed")?;
    eprintln!("mesh: [ANS] serve_flow first msg: {:?}", String::from_utf8_lossy(&first.1[..first.1.len().min(16)]));
    // 注意: 控制消息按内容判断 (offerer 用二进制 send 发送, is_string=false)
    let first_text = String::from_utf8_lossy(&first.1).to_string();
    if first_text == "PULL" {
        let manifest = json!({
            "blobs": store
                .manifest()
                .into_iter()
                .map(|(h, s)| json!({"hash": h, "size": s}))
                .collect::<Vec<_>>()
        });
        eprintln!("mesh: [ANS] about to send MANIFEST ({} bytes)", manifest.to_string().len());
        match tokio::time::timeout(Duration::from_secs(5), dc.send(&BBytes::from(format!("MANIFEST {}", manifest)))).await {
            Ok(Ok(_)) => eprintln!("mesh: [ANS] MANIFEST sent OK"),
            Ok(Err(e)) => eprintln!("mesh: [ANS] MANIFEST send ERR: {e}"),
            Err(_) => eprintln!("mesh: [ANS] MANIFEST send TIMEOUT (hang confirmed)"),
        }
    }

    // 处理 GET，直到 DONE (控制消息按内容判断)
    while let Some((_is_string, data)) = msg_rx.recv().await {
        {
            let t = String::from_utf8_lossy(&data).to_string();
            if t == "DONE" {
                eprintln!("mesh: puller done");
                return Ok(());
            }
            if let Some(hash) = t.strip_prefix("GET ") {
                let hash = hash.trim().to_string();
                if hash.len() != 64 {
                    continue;
                }
                let data = std::fs::read(store.path(&hash)).unwrap_or_default();
                if data.is_empty() {
                    dc.send(&BBytes::from(format!("MISS {hash}"))).await.ok();
                    continue;
                }
                let total = data.len() / CHUNK + 1;
                eprintln!("mesh: [{:?}] serving {hash}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()%1000).unwrap_or(0));
                for (seq, chunk) in data.chunks(CHUNK).enumerate() {
                    let mut frame = Vec::with_capacity(8 + chunk.len());
                    frame.extend_from_slice(&(seq as u32).to_be_bytes());
                    frame.extend_from_slice(&(total as u32).to_be_bytes());
                    frame.extend_from_slice(chunk);
                    dc.send(&Bytes::from(frame))
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
        }
    }
    Ok(())
}

pub async fn run(args: MeshArgs) -> Result<(), String> {
    let store = BlobStore { root: args.root.clone() };
    std::fs::create_dir_all(&args.root).map_err(|e| e.to_string())?;
    let base = args.signal.trim_end_matches('/').to_string();
    let offer_path = format!("s/mesh-{}-offer", args.session);
    let answer_path = format!("s/mesh-{}-answer", args.session);

    let pc = new_peer().await?;
    pc.on_peer_connection_state_change(Box::new(|s: RTCPeerConnectionState| {
        Box::pin(async move { eprintln!("mesh: [{:?}] pc state {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()%1000).unwrap_or(0), s); })
    }));

    match args.role.as_str() {
        "offer" => {
            let (msg_tx, msg_rx) = tokio::sync::mpsc::unbounded_channel::<DataChannelMessage>();
            let (open_tx, mut open_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
            let dc = pc
                .create_data_channel("blobs", None)
                .await
                .map_err(|e| e.to_string())?;
            // on_message 必须先于 on_open 注册: open 即发 PULL, 消息不能有丢失窗口
            {
                let mt = msg_tx.clone();
                dc.on_message(Box::new(move |m: DataChannelMessage| {
                    eprintln!("mesh: [OFF] on_message fired: {:?}", String::from_utf8_lossy(&m.data[..m.data.len().min(16)]));
                    let _ = mt.send(m);
                    Box::pin(async {})
                }));
            }
            let offer = pc.create_offer(None).await.map_err(|e| e.to_string())?;
            pc.set_local_description(offer).await.map_err(|e| e.to_string())?;
            let sdp = gathered_local_sdp(&pc).await?;
            eprintln!("mesh: offer sdp len={} m=application={} candidates={}", sdp.len(), sdp.contains("m=application"), sdp.matches("a=candidate").count());
            sig_post(&base, &offer_path, json!({ "type": "offer", "sdp": sdp }))?;
            eprintln!("mesh: [{:?}] offer posted", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()%1000).unwrap_or(0));
            let answer = sig_wait_msg(&base, &answer_path, Duration::from_secs(SIGNAL_TIMEOUT)).await?;
            let msg = answer["msg"].as_str().ok_or("answer msg missing")?;
            let remote = parse_sdp(msg)?;
            pc.set_remote_description(remote).await.map_err(|e| e.to_string())?;
            for _ in 0..120 {
                let rs = dc.ready_state();
                if matches!(rs, webrtc::data_channel::data_channel_state::RTCDataChannelState::Open) {
                    eprintln!("mesh: [{:?}] dc OPEN", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()%1000).unwrap_or(0));
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            dc.send(&BBytes::from("PULL")).await.map_err(|e| e.to_string())?;
    eprintln!("mesh: PULL sent");
            pull_flow(dc, msg_rx, store).await?;
            let _ = pc.close().await;
            Ok(())
        }
        "answer" => {
            let (dc_tx, dc_rx) = tokio::sync::mpsc::unbounded_channel::<Arc<RTCDataChannel>>();
            let (msg_tx, msg_rx) =
                tokio::sync::mpsc::unbounded_channel::<(bool, Vec<u8>)>();
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                eprintln!("mesh: [{:?}] dc arrived", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()%1000).unwrap_or(0));
                let mt = msg_tx.clone();
                dc.on_message(Box::new(move |m: DataChannelMessage| {
                    eprintln!("mesh: [ANS] on_message fired: {:?}", String::from_utf8_lossy(&m.data[..m.data.len().min(16)]));
                    let _ = mt.send((m.is_string, m.data.to_vec()));
                    Box::pin(async {})
                }));
                // 通道 open 后才交给 serve_flow ( Connecting 时 send 会失败 )
                let ot = dc_tx.clone();
                let d2 = dc.clone();
                dc.on_open(Box::new(move || {
                    eprintln!("mesh: answerer channel OPEN");
                    let _ = ot.send(d2.clone());
                    Box::pin(async {})
                }));
                Box::pin(async {})
            }));
            eprintln!("mesh: waiting offer…");
            let offer = sig_wait_msg(&base, &offer_path, Duration::from_secs(SIGNAL_TIMEOUT)).await?;
            let msg = offer["msg"].as_str().ok_or("offer msg missing")?;
            let remote = parse_sdp(msg)?;
            pc.set_remote_description(remote).await.map_err(|e| e.to_string())?;
            let answer = pc.create_answer(None).await.map_err(|e| e.to_string())?;
            pc.set_local_description(answer).await.map_err(|e| e.to_string())?;
            let sdp = gathered_local_sdp(&pc).await?;
            eprintln!("mesh: answer sdp len={} m=application={} candidates={}", sdp.len(), sdp.contains("m=application"), sdp.matches("a=candidate").count());
            sig_post(&base, &answer_path, json!({ "type": "answer", "sdp": sdp }))?;
            eprintln!("mesh: [{:?}] answer posted", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()%1000).unwrap_or(0));
            serve_flow(dc_rx, msg_rx, store).await?;
            let _ = pc.close().await;
            Ok(())
        }
        other => Err(format!("unknown role: {other} (offer|answer)")),
    }
}
