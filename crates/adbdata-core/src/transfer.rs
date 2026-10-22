//! Copying: finding the files under what was chosen, then running a plan over one connection to
//! the phone, reconnecting when it breaks.
//!
//! Each file from the phone is written to a temporary name in its folder and renamed when it is
//! complete, so a copy that stops half way never leaves a partial file under the real name, and
//! copying again does not mistake one for done. The phone's modification time is kept.

use crate::plan::{LocalFile, PullPlan, PushPlan, RemoteFile, Source};
use crate::remote::{self, quote};
use crate::sync::{Sync, SyncError, FILE_MODE};
use crate::wire::{Server, WireError};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Folders deeper than this are not followed (a link loop, or a folder made to trap programs).
const MAX_DEPTH: usize = 64;

/// The files under the chosen names in `base`, and the names that could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found<T> {
    pub files: Vec<T>,
    /// Names the phone gave that are not UTF-8, or links, which are not followed.
    pub unreadable: Vec<String>,
}

impl<T> Default for Found<T> {
    fn default() -> Self {
        Found {
            files: Vec::new(),
            unreadable: Vec::new(),
        }
    }
}

/// Lists the chosen names in `base` on the phone, and every file in the chosen folders.
/// Hidden names (the phone's trash, thumbnails) inside folders are left out unless `hidden`.
pub fn collect_remote<S: Read + Write>(
    sync: &mut Sync<S>,
    base: &str,
    names: &[String],
    hidden: bool,
) -> Result<Found<RemoteFile>, SyncError> {
    let mut found = Found::default();
    let entries = sync.list(base)?;
    for e in entries.iter().filter(|e| names.contains(&e.name)) {
        walk_remote(sync, base, e, &mut Vec::new(), hidden, &mut found, 0)?;
    }
    Ok(found)
}

fn walk_remote<S: Read + Write>(
    sync: &mut Sync<S>,
    dir: &str,
    e: &crate::sync::Entry,
    rel: &mut Vec<String>,
    hidden: bool,
    found: &mut Found<RemoteFile>,
    depth: usize,
) -> Result<(), SyncError> {
    let path = remote::join(dir, &e.name);
    if !e.exact || e.is_link() {
        found.unreadable.push(path);
        return Ok(());
    }
    rel.push(e.name.clone());
    if e.is_dir() && depth < MAX_DEPTH {
        for child in sync.list(&path)? {
            if hidden || !remote::is_hidden(&child.name) {
                walk_remote(sync, &path, &child, rel, hidden, found, depth + 1)?;
            }
        }
    } else if e.is_file() {
        found.files.push(Source {
            path,
            rel: rel.clone(),
            size: e.size,
            mtime: e.mtime,
        });
    }
    rel.pop();
    Ok(())
}

/// Every file under the chosen files and folders on the PC. Links are not followed.
pub fn collect_local(paths: &[PathBuf]) -> io::Result<Found<LocalFile>> {
    let mut found = Found::default();
    for p in paths {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        walk_local(p, &mut vec![name], &mut found, 0)?;
    }
    Ok(found)
}

fn walk_local(path: &Path, rel: &mut Vec<String>, found: &mut Found<LocalFile>, depth: usize) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        found.unreadable.push(path.to_string_lossy().into_owned());
    } else if meta.is_dir() && depth < MAX_DEPTH {
        let mut children: Vec<_> = fs::read_dir(path)?.flatten().collect();
        children.sort_by_key(|c| c.file_name());
        for c in children {
            rel.push(c.file_name().to_string_lossy().into_owned());
            walk_local(&c.path(), rel, found, depth + 1)?;
            rel.pop();
        }
    } else if meta.is_file() {
        found.files.push(Source {
            path: path.to_path_buf(),
            rel: rel.clone(),
            size: meta.len(),
            mtime: unix_seconds(&meta),
        });
    }
    Ok(())
}

fn unix_seconds(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunOptions {
    /// Give copies on the PC the phone's modification time.
    pub keep_dates: bool,
    /// Compare each copy's MD5 with the phone's after copying.
    pub check: bool,
}

/// What the window hears while a copy runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<'a> {
    /// The `index`th file starts.
    File { index: usize, name: &'a str },
    /// Bytes copied in all, so far.
    Bytes(u64),
    /// Comparing checksums: files compared so far.
    Checking { done: usize, total: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Failure {
    pub path: String,
    /// refused, local, diskFull, mismatch, disconnected
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub copied: usize,
    pub bytes: u64,
    pub failed: Vec<Failure>,
    /// Copies whose checksum matched the phone's.
    pub checked: usize,
    /// The phone could not compute checksums.
    pub check_unavailable: bool,
    pub stopped: bool,
    pub disconnected: bool,
    pub disk_full: bool,
    pub seconds: f64,
}

/// A file copied with its MD5, waiting to be compared with the phone's.
struct Copied {
    phone: String,
    pc: String,
    hash: String,
    size: u64,
}

/// How long to wait before each new attempt after the connection broke.
const RETRY_WAITS: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_millis(1500),
    Duration::from_millis(3000),
];

/// One file, either way. It returns the MD5 of what it moved when asked to.
type Step<'a, J> =
    dyn FnMut(&mut Sync<TcpStream>, &J, &mut dyn FnMut(u64) -> bool) -> Result<Option<String>, SyncError> + 'a;

struct Runner<'a> {
    server: &'a Server,
    serial: &'a str,
    stop: &'a AtomicBool,
    conn: Option<Sync<TcpStream>>,
    outcome: Outcome,
    started: Instant,
}

impl<'a> Runner<'a> {
    fn new(server: &'a Server, serial: &'a str, stop: &'a AtomicBool) -> Self {
        Runner {
            server,
            serial,
            stop,
            conn: None,
            outcome: Outcome {
                copied: 0,
                bytes: 0,
                failed: Vec::new(),
                checked: 0,
                check_unavailable: false,
                stopped: false,
                disconnected: false,
                disk_full: false,
                seconds: 0.0,
            },
            started: Instant::now(),
        }
    }

    fn connection(&mut self) -> Result<&mut Sync<TcpStream>, WireError> {
        if !self.conn.as_ref().is_some_and(Sync::is_open) {
            self.conn = Some(self.server.sync(self.serial)?);
        }
        Ok(self.conn.as_mut().expect("just opened"))
    }

    /// Runs every job; `label` names a job in reports and `size` gives its bytes.
    fn run<J>(
        &mut self,
        jobs: &[J],
        label: impl Fn(&J) -> String,
        size: impl Fn(&J) -> u64,
        step: &mut Step<'_, J>,
        on: &mut dyn FnMut(Event),
    ) -> Vec<Option<String>> {
        let mut hashes = vec![None; jobs.len()];
        let mut index = 0;
        let mut attempt = 0;
        while index < jobs.len() {
            let job = &jobs[index];
            if self.stop.load(Ordering::SeqCst) {
                self.outcome.stopped = true;
                break;
            }
            let name = label(job);
            if attempt == 0 {
                on(Event::File {
                    index,
                    name: remote::file_name(&name.replace('\\', "/")),
                });
            }
            let base = self.outcome.bytes;
            let stop = self.stop;
            let conn = match self.connection() {
                Ok(c) => c,
                Err(e) => {
                    if attempt < RETRY_WAITS.len() && !stop.load(Ordering::SeqCst) {
                        std::thread::sleep(RETRY_WAITS[attempt]);
                        attempt += 1;
                        continue;
                    }
                    self.outcome.disconnected = true;
                    for j in &jobs[index..] {
                        self.outcome.failed.push(Failure {
                            path: label(j),
                            code: "disconnected".into(),
                            detail: e.to_string(),
                        });
                    }
                    break;
                }
            };
            let mut progress = |done: u64| {
                on(Event::Bytes(base + done));
                !stop.load(Ordering::SeqCst)
            };
            match step(conn, job, &mut progress) {
                Ok(hash) => {
                    self.outcome.copied += 1;
                    self.outcome.bytes = base + size(job);
                    hashes[index] = hash;
                    index += 1;
                    attempt = 0;
                }
                Err(SyncError::Cancelled) => {
                    self.outcome.stopped = true;
                    on(Event::Bytes(base));
                    break;
                }
                Err(SyncError::Failed(detail)) => {
                    self.outcome.failed.push(Failure {
                        path: name,
                        code: "refused".into(),
                        detail,
                    });
                    on(Event::Bytes(base));
                    index += 1;
                    attempt = 0;
                }
                Err(SyncError::Local(e)) if is_disk_full(&e) => {
                    self.outcome.disk_full = true;
                    self.outcome.failed.push(Failure {
                        path: name,
                        code: "diskFull".into(),
                        detail: e.to_string(),
                    });
                    on(Event::Bytes(base));
                    break;
                }
                Err(SyncError::Local(e)) => {
                    self.outcome.failed.push(Failure {
                        path: name,
                        code: "local".into(),
                        detail: e.to_string(),
                    });
                    on(Event::Bytes(base));
                    index += 1;
                    attempt = 0;
                }
                Err(_broken) => {
                    // The cable, the phone or adb's server: try the same file again on a new
                    // connection a few times before giving up on the rest.
                    on(Event::Bytes(base));
                    self.conn = None;
                    if attempt < RETRY_WAITS.len() {
                        std::thread::sleep(RETRY_WAITS[attempt]);
                        attempt += 1;
                    } else {
                        self.outcome.disconnected = true;
                        for j in &jobs[index..] {
                            self.outcome.failed.push(Failure {
                                path: label(j),
                                code: "disconnected".into(),
                                detail: String::new(),
                            });
                        }
                        break;
                    }
                }
            }
        }
        if let Some(conn) = self.conn.take() {
            conn.quit();
        }
        hashes
    }

    /// Compares the MD5 of each copied file with the phone's; `remove` takes away a copy that
    /// differs, so copying again does not skip it.
    fn check(&mut self, pairs: Vec<Copied>, remove: &mut dyn FnMut(&str, &str), on: &mut dyn FnMut(Event)) {
        let total = pairs.len();
        let mut done = 0;
        for batch in batches(&pairs) {
            if self.stop.load(Ordering::SeqCst) {
                self.outcome.stopped = true;
                return;
            }
            let command = format!(
                "md5sum {}",
                batch.iter().map(|c| quote(&c.phone)).collect::<Vec<_>>().join(" ")
            );
            let answer = match self.server.shell(self.serial, &command) {
                Ok(a) => a,
                Err(_) => {
                    self.outcome.check_unavailable = true;
                    return;
                }
            };
            if answer.contains("md5sum: inaccessible or not found") || answer.contains("md5sum: not found") {
                self.outcome.check_unavailable = true;
                return;
            }
            let phone_hashes = parse_md5sum(&answer);
            for c in batch {
                match phone_hashes.get(c.phone.as_str()) {
                    Some(h) if *h == c.hash => self.outcome.checked += 1,
                    Some(h) => {
                        remove(&c.phone, &c.pc);
                        // The copy is gone, so it no longer counts as copied, in files or bytes.
                        self.outcome.copied -= 1;
                        self.outcome.bytes = self.outcome.bytes.saturating_sub(c.size);
                        self.outcome.failed.push(Failure {
                            path: c.phone.clone(),
                            code: "mismatch".into(),
                            detail: format!("{} here, {h} on the phone", c.hash),
                        });
                    }
                    // Not answered (a name md5sum escapes): left as copied, not checked.
                    None => {}
                }
                done += 1;
            }
            on(Event::Checking { done, total });
        }
    }

    fn finish(mut self) -> Outcome {
        self.outcome.seconds = self.started.elapsed().as_secs_f64();
        self.outcome
    }
}

/// Groups of paths short enough for one shell command.
fn batches(pairs: &[Copied]) -> Vec<&[Copied]> {
    const MAX: usize = 30_000;
    let mut out = Vec::new();
    let (mut start, mut len) = (0, 0);
    for (i, c) in pairs.iter().enumerate() {
        let n = c.phone.len() + 3;
        if len + n > MAX && i > start {
            out.push(&pairs[start..i]);
            start = i;
            len = 0;
        }
        len += n;
    }
    if start < pairs.len() {
        out.push(&pairs[start..]);
    }
    out
}

/// `<hash>  <path>` lines; error lines are ignored.
pub fn parse_md5sum(text: &str) -> HashMap<&str, &str> {
    text.lines()
        .filter_map(|l| {
            let (hash, path) = l.split_once("  ")?;
            (hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some((path, hash))
        })
        .collect()
}

fn is_disk_full(e: &io::Error) -> bool {
    let code = e.raw_os_error();
    if cfg!(windows) {
        // ERROR_HANDLE_DISK_FULL, ERROR_DISK_FULL
        matches!(code, Some(39) | Some(112))
    } else {
        code == Some(28) // ENOSPC
    }
}

struct Hashing<W> {
    inner: W,
    md5: Option<Md5>,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if let Some(h) = &mut self.md5 {
            h.update(&buf[..n]);
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(h) = &mut self.md5 {
            h.update(&buf[..n]);
        }
        Ok(n)
    }
}

fn hex(md5: Md5) -> String {
    md5.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// A name beside `to` that does not exist, for a file that appeared since the plan was made.
fn free_name(to: &Path) -> PathBuf {
    if !to.exists() {
        return to.to_path_buf();
    }
    let name = to
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    (2..)
        .map(|n| to.with_file_name(crate::names::numbered(&name, n)))
        .find(|p| !p.exists())
        .expect("a free name")
}

/// The temporary name a copy is written under until it is complete.
fn part_name() -> String {
    format!(".adbdata-{}.part", std::process::id())
}

/// Removes temporary files an earlier adbData left in `dir` when it was closed half way through a
/// file. Only one adbData runs at a time, so another one's part file is a leftover; one changed in
/// the last ten minutes is left alone all the same.
fn remove_stale_parts(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    let ours = part_name();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let leftover = name != ours
            && name
                .strip_prefix(".adbdata-")
                .and_then(|r| r.strip_suffix(".part"))
                .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()));
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > Duration::from_secs(600));
        if leftover && old {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// Copies the plan's files from the phone.
pub fn pull(
    server: &Server,
    serial: &str,
    plan: &PullPlan,
    o: RunOptions,
    stop: &AtomicBool,
    on: &mut dyn FnMut(Event),
) -> Outcome {
    let mut runner = Runner::new(server, serial, stop);
    // Where each copy ended up: its planned name, or a numbered one if that appeared meanwhile.
    let placed = std::cell::RefCell::new(HashMap::<String, PathBuf>::new());
    let mut cleaned = std::collections::HashSet::<PathBuf>::new();
    let mut step =
        |conn: &mut Sync<TcpStream>, job: &crate::plan::Job<String, PathBuf>, progress: &mut dyn FnMut(u64) -> bool| {
            let dir = job.to.parent().unwrap_or(Path::new("."));
            fs::create_dir_all(dir).map_err(SyncError::Local)?;
            if cleaned.insert(dir.to_path_buf()) {
                remove_stale_parts(dir);
            }
            let part = dir.join(part_name());
            let file = File::create(&part).map_err(SyncError::Local)?;
            let mut out = Hashing {
                inner: BufWriter::with_capacity(1 << 20, file),
                md5: o.check.then(Md5::new),
            };
            let received = conn.recv(&job.from, &mut out, progress);
            let finished = received.and_then(|_| {
                let Hashing { inner, md5 } = out;
                let file = inner.into_inner().map_err(|e| SyncError::Local(e.into_error()))?;
                if o.keep_dates && job.mtime > 0 {
                    // A date the file system refuses is not worth failing the copy for.
                    let _ = file.set_modified(UNIX_EPOCH + Duration::from_secs(job.mtime as u64));
                }
                drop(file);
                let to = if job.replace {
                    job.to.clone()
                } else {
                    free_name(&job.to)
                };
                fs::rename(&part, &to).map_err(SyncError::Local)?;
                Ok((to, md5.map(hex)))
            });
            match finished {
                Ok((to, hash)) => {
                    placed.borrow_mut().insert(job.from.clone(), to);
                    Ok(hash)
                }
                Err(e) => {
                    let _ = fs::remove_file(&part);
                    Err(e)
                }
            }
        };
    let hashes = runner.run(&plan.jobs, |j| j.from.clone(), |j| j.size, &mut step, on);
    if o.check && !runner.outcome.stopped {
        let placed = placed.borrow();
        let pairs: Vec<Copied> = plan
            .jobs
            .iter()
            .zip(&hashes)
            .filter_map(|(j, h)| {
                Some(Copied {
                    phone: j.from.clone(),
                    pc: placed.get(&j.from)?.to_string_lossy().into_owned(),
                    hash: h.clone()?,
                    size: j.size,
                })
            })
            .collect();
        runner.check(pairs, &mut |_, pc| drop(fs::remove_file(pc)), on);
    }
    runner.finish()
}

/// Copies the plan's files to the phone. The phone creates missing folders itself.
pub fn push(
    server: &Server,
    serial: &str,
    plan: &PushPlan,
    o: RunOptions,
    stop: &AtomicBool,
    on: &mut dyn FnMut(Event),
) -> Outcome {
    let mut runner = Runner::new(server, serial, stop);
    let mut step =
        |conn: &mut Sync<TcpStream>, job: &crate::plan::Job<PathBuf, String>, progress: &mut dyn FnMut(u64) -> bool| {
            let file = File::open(&job.from).map_err(SyncError::Local)?;
            let mut input = Hashing {
                inner: BufReader::with_capacity(1 << 20, file),
                md5: o.check.then(Md5::new),
            };
            let mtime = u32::try_from(job.mtime.max(0)).unwrap_or(u32::MAX);
            conn.send(&job.to, FILE_MODE, mtime, &mut input, progress)?;
            Ok(input.md5.map(hex))
        };
    let hashes = runner.run(&plan.jobs, |j| j.to.clone(), |j| j.size, &mut step, on);
    if o.check && !runner.outcome.stopped {
        let pairs: Vec<Copied> = plan
            .jobs
            .iter()
            .zip(&hashes)
            .filter_map(|(j, h)| {
                Some(Copied {
                    phone: j.to.clone(),
                    pc: j.from.to_string_lossy().into_owned(),
                    hash: h.clone()?,
                    size: j.size,
                })
            })
            .collect();
        let (server, serial) = (runner.server, runner.serial);
        runner.check(
            pairs,
            &mut |phone, _| drop(server.shell(serial, &format!("rm -f {}", quote(phone)))),
            on,
        );
    }
    runner.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{put, temp_root, FakeAdb, FakePhone};
    use crate::plan::{plan_pull, plan_push, Existing, Found as Seen, Layout, PullOptions};

    const SERIAL: &str = "R58M123";

    fn write(root: &Path, rel: &str, bytes: &[u8], mtime: u64) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, bytes).unwrap();
        File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(mtime))
            .unwrap();
    }

    /// A phone with a camera folder, a Turkish name, an ampersand, a name Windows refuses, a
    /// trashed photo and a block-sized-plus-one file.
    fn phone(name: &str) -> (PathBuf, FakeAdb) {
        let root = temp_root(name);
        put(&root, "/sdcard/DCIM/Camera/IMG_1.jpg", b"one", 1_700_000_000);
        put(
            &root,
            "/sdcard/DCIM/Camera/Çalışma & ödev.jpg",
            b"turkish",
            1_700_000_100,
        );
        put(
            &root,
            "/sdcard/DCIM/Camera/sub/clip.mp4",
            &vec![9u8; crate::sync::DATA_MAX + 1],
            1_700_000_200,
        );
        put(
            &root,
            "/sdcard/DCIM/Camera/.trashed-1-IMG_0.jpg",
            b"trash",
            1_700_000_300,
        );
        put(&root, "/sdcard/DCIM/Screenshot 12:30.png", b"shot", 1_700_000_400);
        let adb = FakeAdb::start(vec![FakePhone::new(SERIAL, &root)]);
        (root, adb)
    }

    fn pc_found(p: &Path) -> Option<Seen> {
        fs::metadata(p)
            .ok()
            .map(|m| if m.is_file() { Seen::File(m.len()) } else { Seen::Other })
    }

    fn pull_all(adb: &FakeAdb, dest: &Path, existing: Existing, o: RunOptions) -> (PullPlan, Outcome) {
        let server = adb.server();
        let mut sync = server.sync(SERIAL).unwrap();
        let names = vec!["Camera".to_string(), "Screenshot 12:30.png".to_string()];
        let found = collect_remote(&mut sync, "/sdcard/DCIM", &names, false).unwrap();
        let opts = PullOptions {
            dest: dest.to_path_buf(),
            existing,
            layout: Layout::Keep,
            kinds: vec![],
            utc_offset_minutes: 0,
        };
        let plan = plan_pull(&found.files, &opts, &mut pc_found);
        let outcome = pull(&server, SERIAL, &plan, o, &AtomicBool::new(false), &mut |_| {});
        (plan, outcome)
    }

    #[test]
    fn copies_a_folder_with_its_dates_and_odd_names_then_skips_it_the_next_time() {
        let (root, adb) = phone("pull");
        let dest = root.join("pc");
        let o = RunOptions {
            keep_dates: true,
            check: true,
        };
        let (plan, outcome) = pull_all(&adb, &dest, Existing::Skip, o);
        assert_eq!(plan.jobs.len(), 4, "the trashed photo is left out");
        assert_eq!(plan.renamed, 1);
        assert_eq!(outcome.copied, 4, "{:?}", outcome.failed);
        assert_eq!(outcome.checked, 4);
        assert!(outcome.failed.is_empty());
        assert_eq!(fs::read(dest.join("Camera/Çalışma & ödev.jpg")).unwrap(), b"turkish");
        assert_eq!(fs::read(dest.join("Screenshot 12_30.png")).unwrap(), b"shot");
        assert_eq!(
            fs::metadata(dest.join("Camera/sub/clip.mp4")).unwrap().len(),
            crate::sync::DATA_MAX as u64 + 1
        );
        let mtime = fs::metadata(dest.join("Camera/IMG_1.jpg")).unwrap().modified().unwrap();
        assert_eq!(mtime, UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let leftovers: Vec<_> = fs::read_dir(dest.join("Camera"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
            .collect();
        assert!(leftovers.is_empty());

        let (again, outcome) = pull_all(&adb, &dest, Existing::Skip, o);
        assert_eq!((again.jobs.len(), again.skipped.len()), (0, 4));
        assert_eq!(outcome.copied, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_refused_file_is_reported_and_the_rest_copy() {
        let (root, adb) = phone("refused");
        adb.edit(SERIAL, |p| p.denied = vec!["/sdcard/DCIM/Camera/IMG_1.jpg".into()]);
        let (_, outcome) = pull_all(&adb, &root.join("pc"), Existing::Skip, RunOptions::default());
        assert_eq!(outcome.copied, 3);
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].code, "refused");
        assert_eq!(outcome.failed[0].detail, "open failed: Permission denied");
        assert!(!root.join("pc/Camera/IMG_1.jpg").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_pulled_cable_mid_file_is_retried_on_a_new_connection() {
        let (root, adb) = phone("cut");
        adb.edit(SERIAL, |p| p.cut_after = Some(crate::sync::DATA_MAX as u64));
        let (_, outcome) = pull_all(&adb, &root.join("pc"), Existing::Skip, RunOptions::default());
        assert_eq!(outcome.copied, 4, "{:?}", outcome.failed);
        assert!(!outcome.disconnected);
        assert_eq!(
            fs::metadata(root.join("pc/Camera/sub/clip.mp4")).unwrap().len(),
            crate::sync::DATA_MAX as u64 + 1
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_phone_that_is_gone_fails_the_rest_without_waiting_forever() {
        let (root, adb) = phone("gone");
        let server = adb.server();
        let mut sync = server.sync(SERIAL).unwrap();
        let found = collect_remote(&mut sync, "/sdcard/DCIM", &["Camera".into()], false).unwrap();
        let opts = PullOptions {
            dest: root.join("pc"),
            existing: Existing::Skip,
            layout: Layout::Keep,
            kinds: vec![],
            utc_offset_minutes: 0,
        };
        let plan = plan_pull(&found.files, &opts, &mut pc_found);
        adb.phones.lock().unwrap().clear();
        let started = Instant::now();
        let outcome = pull(
            &server,
            SERIAL,
            &plan,
            RunOptions::default(),
            &AtomicBool::new(false),
            &mut |_| {},
        );
        assert!(outcome.disconnected);
        assert_eq!(outcome.failed.len(), plan.jobs.len());
        assert!(outcome.failed.iter().all(|f| f.code == "disconnected"));
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_copy_that_differs_is_removed_and_reported() {
        let (root, adb) = phone("mismatch");
        adb.edit(SERIAL, |p| p.wrong_md5 = vec!["/sdcard/DCIM/Camera/IMG_1.jpg".into()]);
        let o = RunOptions {
            keep_dates: true,
            check: true,
        };
        let (plan, outcome) = pull_all(&adb, &root.join("pc"), Existing::Skip, o);
        assert_eq!((outcome.copied, outcome.checked), (3, 3));
        assert_eq!(outcome.failed[0].code, "mismatch");
        assert_eq!(
            outcome.bytes,
            plan.bytes - 3,
            "the removed copy's bytes are not counted"
        );
        assert!(
            !root.join("pc/Camera/IMG_1.jpg").exists(),
            "so copying again does not skip it"
        );

        adb.edit(SERIAL, |p| p.no_md5sum = true);
        let (_, outcome) = pull_all(&adb, &root.join("pc2"), Existing::Skip, o);
        assert!(outcome.check_unavailable);
        assert_eq!((outcome.copied, outcome.checked), (4, 0));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn leftovers_of_an_earlier_run_are_removed() {
        let (root, adb) = phone("leftover");
        let camera = root.join("pc/Camera");
        fs::create_dir_all(&camera).unwrap();
        let old = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        for name in [
            ".adbdata-4242.part",
            ".adbdata-77.part",
            "notes.part",
            ".adbdata-x.part",
        ] {
            fs::write(camera.join(name), b"half").unwrap();
            File::options()
                .write(true)
                .open(camera.join(name))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        fs::write(camera.join(".adbdata-88.part"), b"just now").unwrap();
        let (_, outcome) = pull_all(&adb, &root.join("pc"), Existing::Skip, RunOptions::default());
        assert!(outcome.failed.is_empty());
        let left: Vec<String> = fs::read_dir(&camera)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".part"))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        assert_eq!(
            left,
            [".adbdata-88.part", ".adbdata-x.part", "notes.part"],
            "only old adbData leftovers go"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stopping_leaves_no_partial_file() {
        let (root, adb) = phone("stop");
        let server = adb.server();
        let mut sync = server.sync(SERIAL).unwrap();
        let found = collect_remote(&mut sync, "/sdcard/DCIM", &["Camera".into()], false).unwrap();
        let dest = root.join("pc");
        let opts = PullOptions {
            dest: dest.clone(),
            existing: Existing::Skip,
            layout: Layout::Keep,
            kinds: vec![],
            utc_offset_minutes: 0,
        };
        let plan = plan_pull(&found.files, &opts, &mut pc_found);
        let stop = AtomicBool::new(false);
        let outcome = pull(&server, SERIAL, &plan, RunOptions::default(), &stop, &mut |e| {
            if let Event::Bytes(b) = e {
                if b > 20 {
                    stop.store(true, Ordering::SeqCst);
                }
            }
        });
        assert!(outcome.stopped);
        assert!(outcome.copied < plan.jobs.len());
        let mut files = Vec::new();
        let mut dirs = vec![dest];
        while let Some(d) = dirs.pop() {
            for e in fs::read_dir(&d).into_iter().flatten().flatten() {
                if e.path().is_dir() {
                    dirs.push(e.path());
                } else {
                    files.push(e.file_name().to_string_lossy().into_owned());
                }
            }
        }
        assert!(files.iter().all(|f| !f.ends_with(".part")), "{files:?}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sends_a_folder_to_the_phone_and_checks_it() {
        let (root, adb) = phone("push");
        let pc = root.join("pc/Albüm");
        write(&root, "pc/Albüm/01 şarkı.mp3", b"song one", 1_600_000_000);
        write(&root, "pc/Albüm/cd2/02.mp3", &vec![1u8; 200_000], 1_600_000_100);
        let found = collect_local(&[pc]).unwrap();
        assert_eq!(found.files.len(), 2);
        let server = adb.server();
        let mut sync = server.sync(SERIAL).unwrap();
        let mut phone_found = |p: &str| {
            sync.stat(p)
                .ok()
                .flatten()
                .map(|s| if s.is_file() { Seen::File(s.size) } else { Seen::Other })
        };
        let plan = plan_push(&found.files, "/sdcard/Music", Existing::Skip, &mut phone_found);
        let o = RunOptions {
            keep_dates: true,
            check: true,
        };
        let outcome = push(&server, SERIAL, &plan, o, &AtomicBool::new(false), &mut |_| {});
        assert_eq!((outcome.copied, outcome.checked), (2, 2), "{:?}", outcome.failed);
        let on_phone = root.join("sdcard/Music/Albüm/01 şarkı.mp3");
        assert_eq!(fs::read(&on_phone).unwrap(), b"song one");
        assert_eq!(
            fs::metadata(&on_phone).unwrap().modified().unwrap(),
            UNIX_EPOCH + Duration::from_secs(1_600_000_000)
        );
        assert_eq!(
            fs::metadata(root.join("sdcard/Music/Albüm/cd2/02.mp3")).unwrap().len(),
            200_000
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn md5sum_lines_are_read_and_errors_ignored() {
        let text = "d41d8cd98f00b204e9800998ecf8427e  /sdcard/a b.txt\nmd5sum: /sdcard/x: No such file or directory\n";
        let map = parse_md5sum(text);
        assert_eq!(map.get("/sdcard/a b.txt"), Some(&"d41d8cd98f00b204e9800998ecf8427e"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn checksum_commands_stay_short() {
        let pairs: Vec<Copied> = (0..2000)
            .map(|i| Copied {
                phone: format!("/sdcard/DCIM/Camera/IMG_{i:05}_long_name.jpg"),
                pc: String::new(),
                hash: String::new(),
                size: 0,
            })
            .collect();
        let groups = batches(&pairs);
        assert!(groups.len() > 1);
        assert_eq!(groups.iter().map(|g| g.len()).sum::<usize>(), 2000);
        assert!(groups
            .iter()
            .all(|g| g.iter().map(|p| p.phone.len() + 3).sum::<usize>() <= 30_000));
    }
}
