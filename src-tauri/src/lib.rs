use serde::Serialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Default)]
struct AppState {
    custom_path: Mutex<Option<PathBuf>>,
    next_id: AtomicU32,
    scans: Mutex<HashMap<u32, Arc<Mutex<Child>>>>,
}

#[derive(Serialize, Clone)]
struct NmapInfo {
    path: String,
    version: String,
    /// "bundled" | "custom" | "path"
    source: String,
}

#[derive(Serialize, Clone)]
struct ScanLine {
    id: u32,
    stream: &'static str,
    line: String,
}

#[derive(Serialize, Clone)]
struct ScanDone {
    id: u32,
    code: Option<i32>,
    xml: String,
}

fn exe() -> &'static str {
    if cfg!(windows) { "nmap.exe" } else { "nmap" }
}

/// Directory holding the bundled nmap binary + data files (used as NMAPDIR).
/// In dev, falls back to src-tauri/resources/nmap.
fn bundled_dir(app: &AppHandle) -> Option<PathBuf> {
    let res = app.path().resource_dir().ok()?.join("nmap");
    if res.join(exe()).exists() {
        return Some(res);
    }
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/nmap");
    dev.join(exe()).exists().then_some(dev)
}

fn version_of(p: &PathBuf) -> Option<String> {
    let out = Command::new(p).arg("--version").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let first = s.lines().next()?;
    out.status.success().then(|| first.trim().to_string())
}

fn find_nmap(app: &AppHandle, state: &AppState) -> Option<(NmapInfo, Option<PathBuf>)> {
    let mut cands: Vec<(PathBuf, &str, Option<PathBuf>)> = vec![];
    if let Some(d) = bundled_dir(app) {
        cands.push((d.join(exe()), "bundled", Some(d)));
    }
    if let Some(p) = state.custom_path.lock().unwrap().clone() {
        cands.push((p, "custom", None));
    }
    cands.push((PathBuf::from(exe()), "path", None));
    cands.into_iter().find_map(|(p, source, dir)| {
        let version = version_of(&p)?;
        Some((NmapInfo { path: p.to_string_lossy().into(), version, source: source.into() }, dir))
    })
}

#[tauri::command]
fn detect_nmap(app: AppHandle, state: State<AppState>) -> Option<NmapInfo> {
    find_nmap(&app, &state).map(|(i, _)| i)
}

#[tauri::command]
fn set_nmap_path(path: Option<String>, state: State<AppState>) {
    *state.custom_path.lock().unwrap() = path.filter(|p| !p.is_empty()).map(PathBuf::from);
}

fn validate(args: &[String]) -> Result<(), String> {
    for a in args {
        if a.contains('\0') {
            return Err("argument contains NUL".into());
        }
        // Output files are managed by the app (-oX); other output flags would write arbitrary files.
        if a.starts_with("-o") || a == "--resume" || a.starts_with("--datadir") || a.starts_with("--stylesheet") {
            return Err(format!("argument not allowed: {a}"));
        }
    }
    if args.is_empty() {
        return Err("no arguments".into());
    }
    Ok(())
}

fn pump<R: Read + Send + 'static>(app: AppHandle, id: u32, stream: &'static str, r: R) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // nmap progress lines may end in \r or \n; split on both.
        let mut buf = Vec::new();
        let mut rd = BufReader::new(r);
        while rd.read_until(b'\n', &mut buf).map(|n| n > 0).unwrap_or(false) {
            let s = String::from_utf8_lossy(&buf).replace('\r', "\n");
            for line in s.lines().filter(|l| !l.is_empty()) {
                let _ = app.emit("scan-output", ScanLine { id, stream, line: line.into() });
            }
            buf.clear();
        }
    })
}

#[tauri::command]
fn start_scan(app: AppHandle, state: State<AppState>, args: Vec<String>) -> Result<u32, String> {
    validate(&args)?;
    let (info, dir) = find_nmap(&app, &state).ok_or("nmap not found")?;
    let id = state.next_id.fetch_add(1, Ordering::SeqCst) + 1;
    let xml_path = std::env::temp_dir().join(format!("pamn-scan-{}-{id}.xml", std::process::id()));

    // Argv array, no shell.
    let mut cmd = Command::new(&info.path);
    cmd.args(&args).arg("-oX").arg(&xml_path).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(d) = dir {
        cmd.env("NMAPDIR", d);
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let child = Arc::new(Mutex::new(child));
    state.scans.lock().unwrap().insert(id, child.clone());

    let (h1, h2) = (pump(app.clone(), id, "stdout", out), pump(app.clone(), id, "stderr", err));
    std::thread::spawn(move || {
        let _ = (h1.join(), h2.join()); // EOF on both pipes => process exiting
        let code = loop {
            match child.lock().unwrap().try_wait() {
                Ok(Some(s)) => break s.code(),
                Ok(None) => {}
                Err(_) => break None,
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let xml = std::fs::read_to_string(&xml_path).unwrap_or_default();
        let _ = std::fs::remove_file(&xml_path);
        app.state::<AppState>().scans.lock().unwrap().remove(&id);
        let _ = app.emit("scan-done", ScanDone { id, code, xml });
    });
    Ok(id)
}

#[tauri::command]
fn cancel_scan(id: u32, state: State<AppState>) -> Result<(), String> {
    let child = state.scans.lock().unwrap().get(&id).cloned().ok_or("no such scan")?;
    let r = child.lock().unwrap().kill().map_err(|e| e.to_string());
    r
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![detect_nmap, set_nmap_path, start_scan, cancel_scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
