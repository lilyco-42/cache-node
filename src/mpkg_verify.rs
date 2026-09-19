//! mpkg_verify —— 记忆包 Rust 原生验证器（与 Python 实现交叉验证，双实现一致 = 信任增强）。
//!
//! 用法: cache-node verify <file.mpkg> [--out att.json] [--root workdir]
//!
//! 算法与 Python mpkg.py 严格对齐:
//!   id = sha256( canon_json({"manifest": <清单>, "files": {<相对路径>: <sha256>}}) )
//!   canon_json = 键排序 + 紧凑分隔符 + UTF-8 原样 (serde_json 默认即满足)
//! 回放: 解包 → 逐 step 以 POSIX shell 执行 → expect.exit 校验 → verify 命令 → attestation。

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const STEP_TIMEOUT: u64 = 120;

pub fn canon(v: &Value) -> String {
    // serde_json Map 默认 BTreeMap (键有序) + 紧凑分隔符 + UTF-8 原样 —— 与 Python
    // json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False) 逐字节一致
    serde_json::to_string(v).expect("canon serialize")
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

struct ZipEntry {
    name: String,
    data: Vec<u8>,
}

fn read_zip(path: &Path) -> Result<(Value, Vec<ZipEntry>), String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open {path:?}: {e}"))?;
    let mut zip = zip::ZipArchive::new(f).map_err(|e| format!("zip: {e}"))?;
    let mut entries = Vec::new();
    let mut manifest = None;
    for i in 0..zip.len() {
        let mut e = zip.by_index(i).map_err(|e| format!("zip entry {i}: {e}"))?;
        let name = e.name().to_string();
        let mut data = Vec::with_capacity(e.size() as usize);
        e.read_to_end(&mut data)
            .map_err(|e| format!("read {name}: {e}"))?;
        if name == "mpkg.json" {
            manifest = Some(
                serde_json::from_slice::<Value>(&data)
                    .map_err(|e| format!("manifest parse: {e}"))?,
            );
        }
        entries.push(ZipEntry { name, data });
    }
    let manifest = manifest.ok_or("zip missing mpkg.json")?;
    Ok((manifest, entries))
}

fn validate(m: &Value) -> Result<(), String> {
    for k in ["mpkg", "name", "version", "intent", "steps", "verify"] {
        if m.get(k).is_none() {
            return Err(format!("manifest missing: {k}"));
        }
    }
    if m["mpkg"] != "0.1" {
        return Err(format!("unsupported mpkg version: {}", m["mpkg"]));
    }
    if m["steps"].as_array().map_or(true, |a| a.is_empty())
        || m["steps"]
            .as_array()
            .map_or(false, |a| a.iter().any(|s| s.get("run").is_none()))
    {
        return Err("steps must be non-empty list of {run}".into());
    }
    if m["verify"].as_array().map_or(true, |a| a.is_empty()) {
        return Err("verify must be non-empty".into());
    }
    Ok(())
}

fn package_id(manifest: &Value, files: &[(String, String)]) -> String {
    // files 需与 Python 一致: 按 relpath 排序后构造 {rel: hash} 对象 (BTreeMap 自动排序)
    let mut map = serde_json::Map::new();
    for (rel, hash) in files {
        map.insert(rel.clone(), Value::String(hash.clone()));
    }
    let blob = canon(&json!({ "manifest": manifest, "files": Value::Object(map) }));
    format!("sha256:{}", sha256_hex(blob.as_bytes()))
}

fn find_shell() -> Result<Vec<String>, String> {
    for sh in ["bash", "sh"] {
        if let Ok(path) = which(sh) {
            return Ok(vec![path, "-c".into()]);
        }
    }
    Err("replay requires POSIX shell (bash/sh); Windows 请用 Git Bash".into())
}

fn which(exe: &str) -> Result<String, String> {
    let exts = if cfg!(windows) {
        vec!["", ".exe", ".cmd", ".bat"]
    } else {
        vec![""]
    };
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            for ext in &exts {
                let p = dir.join(format!("{exe}{ext}"));
                if p.is_file() {
                    return Ok(p.to_string_lossy().to_string());
                }
            }
        }
    }
    Err(format!("not found: {exe}"))
}

fn run_cmd(shell: &[String], cmd: &str, work: &Path) -> Result<(i32, String, String), String> {
    let out = std::process::Command::new(&shell[0])
        .args(&shell[1..])
        .arg(cmd)
        .current_dir(work)
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim_end().to_string(),
        String::from_utf8_lossy(&out.stderr).trim_end().to_string(),
    ))
}

fn subst(cmd: &str, pkg: &str, work: &str) -> String {
    cmd.replace("{{pkg}}", pkg).replace("{{work}}", work)
}

/// 完整验证: 返回 attestation JSON (与 Python 版同构)
pub fn verify(path: &Path, out_att: Option<&Path>) -> Result<Value, String> {
    let started = SystemTime::now();
    let (manifest, entries) = read_zip(path)?;
    validate(&manifest)?;

    // content-id (与 Python collect_files/package_id 对齐: 全部 zip 条目)
    let mut files: Vec<(String, String)> = Vec::new();
    for e in &entries {
        files.push((e.name.clone(), sha256_hex(&e.data)));
    }
    files.sort();
    let id = package_id(&manifest, &files);

    // 工具需求检查
    for t in manifest["requirements"]["tools"]
        .as_array()
        .unwrap_or(&vec![])
    {
        let name = t["name"].as_str().unwrap_or("");
        if which(name).is_err() {
            return Err(format!("tool missing on PATH: {name}"));
        }
    }

    let shell = find_shell()?;
    let base = std::env::temp_dir().join(format!("mpkg-rs-{}", &id[7..19]));
    let _ = std::fs::remove_dir_all(&base);
    let pkg = base.join("pkg").to_string_lossy().replace('\\', "/");
    let work = base.join("work").to_string_lossy().replace('\\', "/");
    std::fs::create_dir_all(&pkg).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;

    // 解包
    let mut zip = zip::ZipArchive::new(std::fs::File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    zip.extract(&pkg).map_err(|e| format!("extract: {e}"))?;

    let mut steps_log: Vec<Value> = Vec::new();
    let mut verify_log: Vec<Value> = Vec::new();
    let mut ok = true;

    for (i, step) in manifest["steps"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .enumerate()
    {
        let cmd = step["run"].as_str().unwrap_or("");
        let want = step["expect"]["exit"].as_i64().unwrap_or(0);
        let (code, so, se) = run_cmd(&shell, &subst(cmd, &pkg, &work), Path::new(&work))?;
        let step_ok = code == want as i32;
        steps_log.push(json!({"n": i + 1, "cmd": cmd, "exit": code, "ok": step_ok}));
        if !step_ok {
            ok = false;
            eprintln!(
                "mpkg-rs: step {} FAIL exit {code} != {want}\n  stderr: {}",
                i + 1,
                &se[..se.len().min(200)]
            );
            break;
        }
    }

    if ok {
        for cmd in manifest["verify"].as_array().unwrap_or(&vec![]) {
            let cmd = cmd.as_str().unwrap_or("");
            let (code, _so, se) = run_cmd(&shell, &subst(cmd, &pkg, &work), Path::new(&work))?;
            verify_log.push(json!({"cmd": cmd, "exit": code}));
            if code != 0 {
                ok = false;
                eprintln!(
                    "mpkg-rs: verify FAIL: {cmd}\n  stderr: {}",
                    &se[..se.len().min(200)]
                );
                break;
            }
        }
    }

    let att = json!({
        "mpkg_id": id,
        "name": manifest["name"],
        "ok": ok,
        "steps": steps_log,
        "verify": verify_log,
        "host": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "impl": format!("cache-node-rs {VER}"),
            "shell": shell[0],
        },
        "replayed_at": time_str(),
    });
    let _ = started;
    if let Some(out) = out_att {
        std::fs::write(
            out,
            format!("{}", serde_json::to_string_pretty(&att).unwrap_or_default()),
        )
        .map_err(|e| e.to_string())?;
    }
    let _ = std::fs::remove_dir_all(&base);
    Ok(att)
}

fn time_str() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}s", now.as_secs())
}

const VER: &str = env!("CARGO_PKG_VERSION");

pub fn handle(argv: &[String]) {
    let file = argv.first().cloned().unwrap_or_default();
    if file.is_empty() {
        eprintln!("usage: cache-node verify <file.mpkg> [--out att.json]");
        std::process::exit(2);
    }
    let out = argv
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| argv.get(i + 1))
        .map(PathBuf::from);
    match verify(Path::new(&file), out.as_deref()) {
        Ok(att) => {
            println!("{}", serde_json::to_string_pretty(&att).unwrap_or_default());
            if att["ok"] != true {
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("mpkg-rs: error: {e}");
            std::process::exit(1);
        }
    }
}
