//! The commands the window calls. Talking to the phone blocks, so each runs on a worker thread;
//! a copy runs on its own thread and the window reads its progress with `get_transfer`.

use crate::settings::Settings;
use crate::state::{free_space, new_id, now_ms, About, AdbTool, AppState, Live, Prepared};
use adbdata_core::devices::DeviceEntry;
use adbdata_core::fetch::fetch;
use adbdata_core::history::{Direction, Session};
use adbdata_core::phone::{self, PhoneInfo};
use adbdata_core::plan::{plan_pull, plan_push, Existing, Found, Layout, PullOptions};
use adbdata_core::remote::{self, Kind, PLACES};
use adbdata_core::runner::Adb;
use adbdata_core::sync::SyncError;
use adbdata_core::tools::{self, DOWNLOAD_URL};
use adbdata_core::transfer::{self, collect_local, collect_remote, Event, RunOptions};
use adbdata_core::wire::WireError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};

/// An error the window shows: a code it translates and the details.
#[derive(Debug, Serialize)]
pub struct CmdError {
    pub code: &'static str,
    pub detail: String,
}

impl CmdError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        CmdError {
            code,
            detail: detail.into(),
        }
    }
}

impl From<WireError> for CmdError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Refused(d) => CmdError::new("phone_refused", d),
            other => CmdError::new("adb_failed", other.to_string()),
        }
    }
}

impl From<SyncError> for CmdError {
    fn from(e: SyncError) -> Self {
        match e {
            SyncError::Failed(d) => CmdError::new("phone_refused", d),
            other => CmdError::new("adb_failed", other.to_string()),
        }
    }
}

type Shared<'a> = State<'a, Arc<AppState>>;

/// Runs blocking work off the window's thread.
async fn blocking<T: Send + 'static>(
    state: &Shared<'_>,
    work: impl FnOnce(Arc<AppState>) -> Result<T, CmdError> + Send + 'static,
) -> Result<T, CmdError> {
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || work(state))
        .await
        .map_err(|e| CmdError::new("internal", e.to_string()))?
}

/// adb must be there and its server running before a phone can be reached.
fn ready(s: &AppState) -> Result<(), CmdError> {
    let tool = s.resolve_adb().map_err(|e| CmdError::new("no_adb", e))?;
    s.ensure_server(&tool).map_err(|e| CmdError::new("adb_failed", e))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdbProblem {
    /// "missing" (no adb found) or "broken" (found, but it does not run).
    code: &'static str,
    detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    adb: Option<AdbTool>,
    adb_problem: Option<AdbProblem>,
    devices: Vec<DeviceEntry>,
    busy: bool,
    downloading: bool,
}

/// adb and the phones it sees. The window asks every two seconds.
#[tauri::command]
pub async fn get_status(state: Shared<'_>) -> Result<Status, CmdError> {
    blocking(&state, |s| {
        let (adb, problem) = match s.resolve_adb() {
            Ok(tool) => (Some(tool), None),
            Err(detail) if detail.is_empty() => (
                None,
                Some(AdbProblem {
                    code: "missing",
                    detail,
                }),
            ),
            Err(detail) => (None, Some(AdbProblem { code: "broken", detail })),
        };
        let devices = match &adb {
            Some(tool) => {
                let _ = s.ensure_server(tool);
                s.server.devices().unwrap_or_default()
            }
            None => Vec::new(),
        };
        Ok(Status {
            adb,
            adb_problem: problem,
            devices,
            busy: s.busy.load(Ordering::Relaxed),
            downloading: s.downloading.load(Ordering::Relaxed),
        })
    })
    .await
}

#[tauri::command]
pub async fn get_phone(state: Shared<'_>, serial: String) -> Result<PhoneInfo, CmdError> {
    blocking(&state, move |s| {
        ready(&s)?;
        Ok(phone::read(&s.server, &serial)?)
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    name: String,
    dir: bool,
    size: u64,
    mtime: i64,
    kind: Kind,
    hidden: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    path: String,
    items: Vec<Item>,
}

/// One folder on the phone: folders first, then files, by name. Links and names that cannot be
/// read are left out.
#[tauri::command]
pub async fn list_folder(state: Shared<'_>, serial: String, path: String) -> Result<Folder, CmdError> {
    blocking(&state, move |s| {
        ready(&s)?;
        let path = remote::normalize(&path);
        let mut sync = s.server.sync(&serial)?;
        let mut items: Vec<Item> = sync
            .list(&path)?
            .into_iter()
            .filter(|e| e.exact && (e.is_dir() || e.is_file()))
            .map(|e| Item {
                kind: if e.is_dir() { Kind::Other } else { Kind::of(&e.name) },
                hidden: remote::is_hidden(&e.name),
                dir: e.is_dir(),
                size: e.size,
                mtime: e.mtime,
                name: e.name,
            })
            .collect();
        sync.quit();
        items.sort_by(|a, b| {
            b.dir
                .cmp(&a.dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(Folder { path, items })
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlaceAt {
    key: &'static str,
    path: String,
}

/// The well-known folders this phone has.
#[tauri::command]
pub async fn get_places(state: Shared<'_>, serial: String) -> Result<Vec<PlaceAt>, CmdError> {
    blocking(&state, move |s| {
        ready(&s)?;
        let mut sync = s.server.sync(&serial)?;
        let mut found = Vec::new();
        for place in PLACES {
            for path in place.paths {
                if sync.stat(path)?.is_some_and(|st| st.is_dir()) || *path == remote::STORAGE {
                    found.push(PlaceAt {
                        key: place.key,
                        path: path.to_string(),
                    });
                    break;
                }
            }
        }
        sync.quit();
        Ok(found)
    })
    .await
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CopyOptions {
    existing: Existing,
    layout: Layout,
    keep_dates: bool,
    check: bool,
    hidden: bool,
}

/// What a copy will do, for the review screen.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    id: String,
    to: String,
    files: usize,
    bytes: u64,
    skipped: usize,
    skipped_bytes: u64,
    filtered: usize,
    renamed: usize,
    numbered: usize,
    replaced: usize,
    /// Links and names that cannot be read, left out.
    unreadable: usize,
    /// Free bytes where the files go, when known.
    free: Option<u64>,
}

/// Plans copying `names` in `base` on the phone to `dest` on the PC. Nothing is copied yet.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn plan_pull_copy(
    state: Shared<'_>,
    serial: String,
    phone: String,
    base: String,
    names: Vec<String>,
    dest: Option<String>,
    kinds: Vec<Kind>,
    options: CopyOptions,
    utc_offset_minutes: i32,
) -> Result<Summary, CmdError> {
    blocking(&state, move |s| {
        if names.is_empty() {
            return Err(CmdError::new("invalid", "nothing chosen"));
        }
        ready(&s)?;
        let base = remote::normalize(&base);
        let dest = dest
            .filter(|d| !d.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| s.destination());
        if !dest.is_absolute() {
            return Err(CmdError::new("invalid", dest.to_string_lossy()));
        }
        let mut sync = s.server.sync(&serial)?;
        let found = collect_remote(&mut sync, &base, &names, options.hidden)?;
        sync.quit();
        let o = PullOptions {
            dest: dest.clone(),
            existing: options.existing,
            layout: options.layout,
            kinds,
            utc_offset_minutes,
        };
        let plan = plan_pull(&found.files, &o, &mut |p| {
            std::fs::metadata(p).ok().map(|m| {
                if m.is_file() {
                    Found::File(m.len())
                } else {
                    Found::Other
                }
            })
        });
        let from = if names.len() == 1 {
            remote::join(&base, &names[0])
        } else {
            base.clone()
        };
        let about = About {
            id: new_id(),
            serial,
            phone,
            direction: Direction::ToPc,
            from,
            to: dest.to_string_lossy().into_owned(),
            skipped: plan.skipped.len(),
            options: RunOptions {
                keep_dates: options.keep_dates,
                check: options.check,
            },
        };
        let summary = Summary {
            id: about.id.clone(),
            to: about.to.clone(),
            files: plan.jobs.len(),
            bytes: plan.bytes,
            skipped: plan.skipped.len(),
            skipped_bytes: plan.skipped.iter().map(|j| j.size).sum(),
            filtered: plan.filtered,
            renamed: plan.renamed,
            numbered: plan.numbered,
            replaced: plan.jobs.iter().filter(|j| j.replace).count(),
            unreadable: found.unreadable.len(),
            free: free_space(&dest),
        };
        *s.prepared.lock().unwrap() = Some(Prepared::Pull { plan, about });
        Ok(summary)
    })
    .await
}

/// Plans copying files and folders from the PC into `dest` on the phone.
#[tauri::command]
pub async fn plan_push_copy(
    state: Shared<'_>,
    serial: String,
    phone: String,
    paths: Vec<String>,
    dest: String,
    options: CopyOptions,
) -> Result<Summary, CmdError> {
    blocking(&state, move |s| {
        if paths.is_empty() {
            return Err(CmdError::new("invalid", "nothing chosen"));
        }
        ready(&s)?;
        let dest = remote::normalize(&dest);
        let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
        let found = collect_local(&paths).map_err(|e| CmdError::new("local", e.to_string()))?;
        let mut sync = s.server.sync(&serial)?;
        let mut lookup_failed = None;
        let plan = plan_push(&found.files, &dest, options.existing, &mut |p| match sync.stat(p) {
            Ok(st) => st.map(|st| {
                if st.is_file() {
                    Found::File(st.size)
                } else {
                    Found::Other
                }
            }),
            Err(e) => {
                lookup_failed.get_or_insert(e);
                None
            }
        });
        if let Some(e) = lookup_failed {
            return Err(e.into());
        }
        sync.quit();
        let info = phone::read(&s.server, &serial).ok();
        let from = if paths.len() == 1 {
            paths[0].to_string_lossy().into_owned()
        } else {
            paths[0]
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let about = About {
            id: new_id(),
            serial,
            phone,
            direction: Direction::ToPhone,
            from,
            to: dest,
            skipped: plan.skipped.len(),
            options: RunOptions {
                keep_dates: true,
                check: options.check,
            },
        };
        let summary = Summary {
            id: about.id.clone(),
            to: about.to.clone(),
            files: plan.jobs.len(),
            bytes: plan.bytes,
            skipped: plan.skipped.len(),
            skipped_bytes: plan.skipped.iter().map(|j| j.size).sum(),
            filtered: plan.filtered,
            renamed: plan.renamed,
            numbered: plan.numbered,
            replaced: plan.jobs.iter().filter(|j| j.replace).count(),
            unreadable: found.unreadable.len(),
            free: info.and_then(|i| i.storage_free),
        };
        *s.prepared.lock().unwrap() = Some(Prepared::Push { plan, about });
        Ok(summary)
    })
    .await
}

/// Starts the copy last planned, if `id` is still it.
#[tauri::command]
pub fn start_copy(state: Shared<'_>, id: String) -> Result<(), CmdError> {
    let s = Arc::clone(state.inner());
    let prepared = {
        let mut slot = s.prepared.lock().unwrap();
        let same = match slot.as_ref() {
            Some(Prepared::Pull { about, .. } | Prepared::Push { about, .. }) => about.id == id,
            None => false,
        };
        if !same {
            return Err(CmdError::new("plan_gone", ""));
        }
        slot.take().expect("checked above")
    };
    if s.busy.swap(true, Ordering::SeqCst) {
        *s.prepared.lock().unwrap() = Some(prepared);
        return Err(CmdError::new("busy", ""));
    }
    s.stop.store(false, Ordering::SeqCst);
    let (about, files, bytes) = match &prepared {
        Prepared::Pull { plan, about } => (about.clone(), plan.jobs.len(), plan.bytes),
        Prepared::Push { plan, about } => (about.clone(), plan.jobs.len(), plan.bytes),
    };
    *s.live.lock().unwrap() = Some(Live {
        about: about.clone(),
        files,
        bytes,
        index: 0,
        current: String::new(),
        done: 0,
        started: now_ms(),
        checking: None,
        stopping: false,
        result: None,
    });
    std::thread::spawn(move || {
        let mut on = |e: Event| {
            if let Some(live) = s.live.lock().unwrap().as_mut() {
                match e {
                    Event::File { index, name } => {
                        live.index = index;
                        live.current = name.to_string();
                    }
                    Event::Bytes(done) => live.done = done,
                    Event::Checking { done, total } => live.checking = Some((done, total)),
                }
            }
        };
        let (outcome, files) = match &prepared {
            Prepared::Pull { plan, about } => (
                transfer::pull(&s.server, &about.serial, plan, about.options, &s.stop, &mut on),
                plan.jobs.len(),
            ),
            Prepared::Push { plan, about } => (
                transfer::push(&s.server, &about.serial, plan, about.options, &s.stop, &mut on),
                plan.jobs.len(),
            ),
        };
        let session = Session::new(
            about.id.clone(),
            now_ms(),
            about.direction,
            about.phone.clone(),
            about.from.clone(),
            about.to.clone(),
            files,
            about.skipped,
            &outcome,
        );
        let _ = s.history.add(session.clone());
        if let Some(live) = s.live.lock().unwrap().as_mut() {
            live.result = Some(session);
        }
        s.busy.store(false, Ordering::SeqCst);
    });
    Ok(())
}

#[tauri::command]
pub fn stop_copy(state: Shared<'_>) {
    state.stop.store(true, Ordering::SeqCst);
    if let Some(live) = state.live.lock().unwrap().as_mut() {
        live.stopping = true;
    }
}

/// The copy running now, or the last one.
#[tauri::command]
pub fn get_copy(state: Shared<'_>) -> Option<Live> {
    state.live.lock().unwrap().clone()
}

#[tauri::command]
pub async fn get_history(state: Shared<'_>) -> Result<Vec<Session>, CmdError> {
    blocking(&state, |s| Ok(s.history.load())).await
}

#[tauri::command]
pub async fn clear_history(state: Shared<'_>) -> Result<(), CmdError> {
    blocking(&state, |s| {
        s.history.clear().map_err(|e| CmdError::new("local", e.to_string()))
    })
    .await
}

#[derive(Clone, Serialize)]
struct DownloadProgress {
    done: u64,
    total: Option<u64>,
}

/// Downloads Google's platform-tools into the app's folder and uses them.
#[tauri::command]
pub async fn download_platform_tools(app: AppHandle, state: Shared<'_>) -> Result<AdbTool, CmdError> {
    blocking(&state, move |s| {
        if s.downloading.swap(true, Ordering::SeqCst) {
            return Err(CmdError::new("busy", ""));
        }
        let result = (|| {
            let zip = fetch(DOWNLOAD_URL, 200_000_000, &mut |done, total| {
                let _ = app.emit("download-progress", DownloadProgress { done, total });
            })
            .map_err(|e| CmdError::new("download_failed", e.to_string()))?;
            // A server started from an older copy keeps its files open.
            if let Ok(tool) = s.resolve_adb() {
                let _ = Adb::new(&tool.path).kill_server();
            }
            tools::install(&zip, &s.data_dir).map_err(|e| CmdError::new("download_failed", e.to_string()))?;
            s.forget_adb();
            s.resolve_adb().map_err(|e| CmdError::new("no_adb", e))
        })();
        s.downloading.store(false, Ordering::SeqCst);
        result
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    #[serde(flatten)]
    settings: Settings,
    /// The folder used when `destination` is empty.
    default_destination: String,
}

#[tauri::command]
pub fn get_settings(state: Shared<'_>) -> SettingsView {
    SettingsView {
        settings: state.settings(),
        default_destination: state.default_destination.to_string_lossy().into_owned(),
    }
}

#[tauri::command]
pub async fn set_settings(state: Shared<'_>, settings: Settings) -> Result<SettingsView, CmdError> {
    blocking(&state, move |s| {
        let before = s.settings();
        s.store
            .lock()
            .unwrap()
            .save(settings)
            .map_err(|e| CmdError::new("settings_not_saved", e))?;
        let after = s.settings();
        if after.adb_path != before.adb_path {
            s.forget_adb();
        }
        Ok(SettingsView {
            settings: after,
            default_destination: s.default_destination.to_string_lossy().into_owned(),
        })
    })
    .await
}
