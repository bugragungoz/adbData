//! What the app holds while it runs: settings, where adb is, the history, the copy being
//! prepared and the copy running.

use crate::settings::{Settings, Store};
use adbdata_core::history::{Direction, History, Session};
use adbdata_core::plan::{PullPlan, PushPlan};
use adbdata_core::runner::Adb;
use adbdata_core::tools::{self, AdbSource};
use adbdata_core::transfer::RunOptions;
use adbdata_core::wire::Server;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdbTool {
    pub source: AdbSource,
    pub path: String,
    pub version: String,
}

/// A copy the window has seen the plan of and may start.
pub enum Prepared {
    Pull { plan: PullPlan, about: About },
    Push { plan: PushPlan, about: About },
}

/// What the history and the progress page say about a copy.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct About {
    pub id: String,
    pub serial: String,
    pub phone: String,
    pub direction: Direction,
    pub from: String,
    pub to: String,
    pub skipped: usize,
    pub options: RunOptions,
}

/// The copy running now, or the last one, for the progress page.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Live {
    pub about: About,
    pub files: usize,
    pub bytes: u64,
    /// The file being copied (0-based) and its name.
    pub index: usize,
    pub current: String,
    pub done: u64,
    /// Milliseconds since 1970.
    pub started: u64,
    /// Checksums compared so far, of how many.
    pub checking: Option<(usize, usize)>,
    pub stopping: bool,
    /// Set when the copy is over.
    pub result: Option<Session>,
}

pub struct AppState {
    pub store: Mutex<Store>,
    pub data_dir: PathBuf,
    /// Where copies go when the settings name no folder.
    pub default_destination: PathBuf,
    pub adb: Mutex<Option<AdbTool>>,
    pub server: Server,
    pub history: History,
    pub prepared: Mutex<Option<Prepared>>,
    pub live: Mutex<Option<Live>>,
    /// A copy is running.
    pub busy: AtomicBool,
    pub stop: AtomicBool,
    /// platform-tools are downloading.
    pub downloading: AtomicBool,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A short random-enough id for a copy.
pub fn new_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", nanos ^ u128::from(std::process::id()) << 64)
}

impl AppState {
    pub fn new(config_dir: Option<PathBuf>, data_dir: PathBuf, default_destination: PathBuf) -> Self {
        AppState {
            store: Mutex::new(Store::open(config_dir)),
            history: History::new(&data_dir),
            data_dir,
            default_destination,
            adb: Mutex::new(None),
            server: Server::default(),
            prepared: Mutex::new(None),
            live: Mutex::new(None),
            busy: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            downloading: AtomicBool::new(false),
        }
    }

    pub fn settings(&self) -> Settings {
        self.store.lock().unwrap().settings.clone()
    }

    /// The folder copies go to.
    pub fn destination(&self) -> PathBuf {
        let set = self.settings().destination;
        if set.is_empty() {
            self.default_destination.clone()
        } else {
            PathBuf::from(set)
        }
    }

    /// Finds adb and asks its version; the reason when there is none that works (empty when
    /// none was found at all).
    pub fn resolve_adb(&self) -> Result<AdbTool, String> {
        if let Some(tool) = self.adb.lock().unwrap().clone() {
            return Ok(tool);
        }
        let custom = self.settings().adb_path;
        let custom = (!custom.is_empty()).then(|| PathBuf::from(custom));
        let (source, path) = tools::find(custom.as_deref(), &self.data_dir).ok_or_else(String::new)?;
        let version = Adb::new(&path).version().map_err(|e| e.to_string())?;
        let tool = AdbTool {
            source,
            path: path.to_string_lossy().into_owned(),
            version,
        };
        *self.adb.lock().unwrap() = Some(tool.clone());
        Ok(tool)
    }

    /// Forgets the adb found, after the settings or platform-tools changed.
    pub fn forget_adb(&self) {
        *self.adb.lock().unwrap() = None;
    }

    /// Makes sure adb's server runs, starting it with the adb found.
    pub fn ensure_server(&self, tool: &AdbTool) -> Result<(), String> {
        if self.server.is_running() {
            return Ok(());
        }
        Adb::new(&tool.path).start_server().map_err(|e| e.to_string())
    }
}

/// Free bytes on the drive that holds `path` (or the nearest folder above it that exists).
#[cfg(windows)]
pub fn free_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    let mut at = path;
    while !at.exists() {
        at = at.parent()?;
    }
    let wide: Vec<u16> = at.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut free = 0u64;
    // SAFETY: `wide` is a NUL-terminated path that outlives the call; the other outputs are
    // optional and passed as null.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free)
}

#[cfg(not(windows))]
pub fn free_space(_path: &Path) -> Option<u64> {
    None
}
