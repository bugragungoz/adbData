//! An adb server for the tests: it listens on a free local port and answers the host requests,
//! the file service and the few shell commands adbData uses, the way adb's server and a phone do.
//! A phone's storage is a folder on this computer (`/sdcard/x` is `<root>/sdcard/x`).
//!
//! It can also misbehave: refuse paths, cut the connection part way through a file (a cable
//! pulled out), report a wrong checksum, or have no `md5sum`.

use crate::remote;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct FakePhone {
    pub serial: String,
    /// "device", "unauthorized" or "offline".
    pub state: String,
    pub model: String,
    pub maker: String,
    pub android: String,
    pub root: PathBuf,
    pub features: Vec<String>,
    /// Paths (and everything under them) the phone refuses to read or write.
    pub denied: Vec<String>,
    /// Closes the connection once after this many bytes of file data have gone out.
    pub cut_after: Option<u64>,
    /// Paths whose checksum comes back wrong.
    pub wrong_md5: Vec<String>,
    /// The phone has no `md5sum`.
    pub no_md5sum: bool,
}

impl FakePhone {
    pub fn new(serial: &str, root: &Path) -> Self {
        FakePhone {
            serial: serial.into(),
            state: "device".into(),
            model: "Example_Phone_12".into(),
            maker: "Example".into(),
            android: "15".into(),
            root: root.to_path_buf(),
            features: ["shell_v2", "cmd", "stat_v2", "ls_v2", "fixed_push_mkdir"]
                .iter()
                .map(|f| f.to_string())
                .collect(),
            denied: Vec::new(),
            cut_after: None,
            wrong_md5: Vec::new(),
            no_md5sum: false,
        }
    }

    fn local(&self, path: &str) -> PathBuf {
        on_disk(&self.root, path)
    }

    fn denies(&self, path: &str) -> bool {
        let clean = remote::normalize(path);
        self.denied
            .iter()
            .any(|d| clean == *d || clean.starts_with(&format!("{}/", d.trim_end_matches('/'))))
    }
}

/// A running fake server. It stops when dropped.
pub struct FakeAdb {
    pub port: u16,
    pub phones: Arc<Mutex<Vec<FakePhone>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for FakeAdb {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

impl FakeAdb {
    pub fn start(phones: Vec<FakePhone>) -> FakeAdb {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let port = listener.local_addr().expect("an address").port();
        let phones = Arc::new(Mutex::new(phones));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (shared, stopping) = (Arc::clone(&phones), Arc::clone(&stop));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stopping.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                let Ok(conn) = conn else { continue };
                let phones = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let _ = serve(conn, &phones);
                });
            }
        });
        FakeAdb { port, phones, stop }
    }

    pub fn server(&self) -> crate::wire::Server {
        let mut s = crate::wire::Server::on_port(self.port);
        s.timeout = Duration::from_secs(10);
        s
    }

    pub fn edit(&self, serial: &str, change: impl FnOnce(&mut FakePhone)) {
        let mut phones = self.phones.lock().unwrap();
        if let Some(p) = phones.iter_mut().find(|p| p.serial == serial) {
            change(p);
        }
    }
}

fn read_request(r: &mut impl Read) -> io::Result<String> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = usize::from_str_radix(std::str::from_utf8(&len).unwrap_or("zz"), 16)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "length"))?;
    let mut text = vec![0u8; len];
    r.read_exact(&mut text)?;
    Ok(String::from_utf8_lossy(&text).into_owned())
}

fn okay_text(w: &mut impl Write, text: &str) -> io::Result<()> {
    w.write_all(format!("OKAY{:04x}{text}", text.len()).as_bytes())
}

fn fail(w: &mut impl Write, text: &str) -> io::Result<()> {
    w.write_all(format!("FAIL{:04x}{text}", text.len()).as_bytes())
}

fn serve(mut conn: TcpStream, phones: &Mutex<Vec<FakePhone>>) -> io::Result<()> {
    let request = read_request(&mut conn)?;
    let find = |serial: &str| phones.lock().unwrap().iter().find(|p| p.serial == serial).cloned();
    if request == "host:version" {
        return okay_text(&mut conn, "0029");
    }
    if request == "host:devices-l" {
        let list: String = phones
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                if p.state == "device" {
                    format!(
                        "{} device product:{m} model:{m} device:{m} transport_id:{}\n",
                        p.serial,
                        i + 1,
                        m = p.model
                    )
                } else {
                    format!("{} {} transport_id:{}\n", p.serial, p.state, i + 1)
                }
            })
            .collect();
        return okay_text(&mut conn, &list);
    }
    if let Some(rest) = request.strip_prefix("host-serial:") {
        if let Some(serial) = rest.strip_suffix(":features") {
            return match find(serial) {
                Some(p) => okay_text(&mut conn, &p.features.join(",")),
                None => fail(&mut conn, &format!("device '{serial}' not found")),
            };
        }
    }
    let Some(serial) = request.strip_prefix("host:transport:") else {
        return fail(&mut conn, &format!("unknown host service: {request}"));
    };
    let Some(phone) = find(serial) else {
        return fail(&mut conn, &format!("device '{serial}' not found"));
    };
    if phone.state != "device" {
        return fail(&mut conn, &format!("device {}", phone.state));
    }
    conn.write_all(b"OKAY")?;
    let service = read_request(&mut conn)?;
    if service == "sync:" {
        conn.write_all(b"OKAY")?;
        return sync_loop(conn, phones, serial);
    }
    if let Some(command) = service.strip_prefix("shell:") {
        conn.write_all(b"OKAY")?;
        let out = shell(&phone, command);
        conn.write_all(out.as_bytes())?;
        return Ok(());
    }
    fail(&mut conn, &format!("unknown service: {service}"))
}

const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;

fn mode_of(meta: &fs::Metadata) -> u32 {
    if meta.is_dir() {
        S_IFDIR | 0o771
    } else {
        S_IFREG | 0o660
    }
}

fn mtime_of(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64)
}

fn dent_v2(id: &[u8; 4], error: u32, mode: u32, size: u64, mtime: i64) -> Vec<u8> {
    let mut m = id.to_vec();
    m.extend_from_slice(&error.to_le_bytes());
    m.extend_from_slice(&[0u8; 16]);
    m.extend_from_slice(&mode.to_le_bytes());
    m.extend_from_slice(&[0u8; 12]);
    m.extend_from_slice(&size.to_le_bytes());
    m.extend_from_slice(&mtime.to_le_bytes());
    m.extend_from_slice(&mtime.to_le_bytes());
    m.extend_from_slice(&mtime.to_le_bytes());
    m
}

fn sync_loop(conn: TcpStream, phones: &Mutex<Vec<FakePhone>>, serial: &str) -> io::Result<()> {
    let mut w = conn.try_clone()?;
    let mut r = BufReader::new(conn);
    loop {
        let mut head = [0u8; 8];
        r.read_exact(&mut head)?;
        let len = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
        let mut path = vec![0u8; len];
        r.read_exact(&mut path)?;
        let path = String::from_utf8_lossy(&path).into_owned();
        let phone = phones.lock().unwrap().iter().find(|p| p.serial == serial).cloned();
        let Some(phone) = phone else { return Ok(()) };
        match &head[0..4] {
            b"LIST" | b"LIS2" => {
                let v2 = &head[0..4] == b"LIS2";
                let mut out = Vec::new();
                let dir = phone.local(&path);
                let mut names: Vec<(Vec<u8>, Option<fs::Metadata>)> = vec![
                    (b".".to_vec(), fs::metadata(&dir).ok()),
                    (b"..".to_vec(), fs::metadata(&dir).ok()),
                ];
                if !phone.denies(&path) {
                    if let Ok(read) = fs::read_dir(&dir) {
                        for e in read.flatten() {
                            names.push((decode(&e.file_name().to_string_lossy()).into_bytes(), e.metadata().ok()));
                        }
                    }
                }
                if fs::metadata(&dir).is_ok() {
                    for (name, meta) in names {
                        let Some(meta) = meta else { continue };
                        if v2 {
                            let mut m = dent_v2(b"DNT2", 0, mode_of(&meta), meta.len(), mtime_of(&meta));
                            m.extend_from_slice(&(name.len() as u32).to_le_bytes());
                            m.extend_from_slice(&name);
                            out.extend(m);
                        } else {
                            out.extend_from_slice(b"DENT");
                            for v in [
                                mode_of(&meta),
                                meta.len() as u32,
                                mtime_of(&meta) as u32,
                                name.len() as u32,
                            ] {
                                out.extend_from_slice(&v.to_le_bytes());
                            }
                            out.extend_from_slice(&name);
                        }
                    }
                }
                let mut done = b"DONE".to_vec();
                done.resize(if v2 { 76 } else { 20 }, 0);
                out.extend(done);
                w.write_all(&out)?;
            }
            b"STAT" => {
                let mut m = b"STAT".to_vec();
                match fs::metadata(phone.local(&path)) {
                    Ok(meta) => {
                        for v in [mode_of(&meta), meta.len() as u32, mtime_of(&meta) as u32] {
                            m.extend_from_slice(&v.to_le_bytes());
                        }
                    }
                    Err(_) => m.extend_from_slice(&[0u8; 12]),
                }
                w.write_all(&m)?;
            }
            b"STA2" | b"LST2" => {
                let m = match fs::metadata(phone.local(&path)) {
                    Ok(meta) => dent_v2(b"STA2", 0, mode_of(&meta), meta.len(), mtime_of(&meta)),
                    Err(_) => dent_v2(b"STA2", 2, 0, 0, 0),
                };
                w.write_all(&m)?;
            }
            b"RECV" => {
                if phone.denies(&path) {
                    fail_sync(&mut w, "open failed: Permission denied")?;
                    return Ok(());
                }
                let Ok(mut file) = fs::File::open(phone.local(&path)) else {
                    fail_sync(&mut w, "open failed: No such file or directory")?;
                    return Ok(());
                };
                let mut block = vec![0u8; crate::sync::DATA_MAX];
                let mut sent = 0u64;
                loop {
                    let n = file.read(&mut block)?;
                    if n == 0 {
                        break;
                    }
                    let mut m = b"DATA".to_vec();
                    m.extend_from_slice(&(n as u32).to_le_bytes());
                    m.extend_from_slice(&block[..n]);
                    w.write_all(&m)?;
                    sent += n as u64;
                    let cut = phones
                        .lock()
                        .unwrap()
                        .iter_mut()
                        .find(|p| p.serial == serial)
                        .and_then(|p| {
                            let due = p.cut_after.is_some_and(|c| sent >= c);
                            if due {
                                p.cut_after = None;
                            }
                            due.then_some(())
                        });
                    if cut.is_some() {
                        let _ = w.shutdown(std::net::Shutdown::Both);
                        return Ok(());
                    }
                }
                w.write_all(b"DONE\0\0\0\0")?;
            }
            b"SEND" => {
                let (target, _mode) = path.rsplit_once(',').unwrap_or((&path, "0"));
                let mut data = Vec::new();
                let mtime = loop {
                    let mut h = [0u8; 8];
                    r.read_exact(&mut h)?;
                    let n = u32::from_le_bytes(h[4..8].try_into().unwrap());
                    match &h[0..4] {
                        b"DATA" => {
                            let mut block = vec![0u8; n as usize];
                            r.read_exact(&mut block)?;
                            data.extend(block);
                        }
                        b"DONE" => break n,
                        _ => return Ok(()),
                    }
                };
                if phone.denies(target) {
                    fail_sync(&mut w, "couldn't create file: Permission denied")?;
                    return Ok(());
                }
                let local = phone.local(target);
                if let Some(dir) = local.parent() {
                    fs::create_dir_all(dir)?;
                }
                fs::write(&local, &data)?;
                let when = UNIX_EPOCH + Duration::from_secs(u64::from(mtime));
                fs::File::options().write(true).open(&local)?.set_modified(when)?;
                w.write_all(b"OKAY\0\0\0\0")?;
            }
            b"QUIT" => return Ok(()),
            other => {
                fail_sync(&mut w, &format!("unknown request {}", String::from_utf8_lossy(other)))?;
                return Ok(());
            }
        }
    }
}

fn fail_sync(w: &mut impl Write, msg: &str) -> io::Result<()> {
    let mut m = b"FAIL".to_vec();
    m.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    m.extend_from_slice(msg.as_bytes());
    w.write_all(&m)
}

/// Splits a shell line into words, honouring single quotes (`'it'\''s'` is `it's`).
fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    cur.push(q);
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

fn md5_hex(bytes: &[u8]) -> String {
    use md5::{Digest, Md5};
    Md5::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The phone's shell, for the commands adbData sends; each `;` part runs in turn.
fn shell(phone: &FakePhone, command: &str) -> String {
    let mut out = String::new();
    for part in command.split(';') {
        let w = words(part);
        match w.first().map(String::as_str) {
            Some("getprop") => {
                let value = match w.get(1).map(String::as_str) {
                    Some("ro.product.model") => phone.model.replace('_', " "),
                    Some("ro.product.manufacturer") => phone.maker.clone(),
                    Some("ro.build.version.release") => phone.android.clone(),
                    Some("ro.build.version.sdk") => "35".into(),
                    _ => String::new(),
                };
                out.push_str(&value);
                out.push('\n');
            }
            Some("stat") if w.get(1).map(String::as_str) == Some("-f") => {
                out.push_str("4096 30000000 12000000\n");
            }
            Some("md5sum") => {
                if phone.no_md5sum {
                    out.push_str("/system/bin/sh: md5sum: inaccessible or not found\n");
                    continue;
                }
                for path in w.iter().skip(1).filter(|a| a.as_str() != "--") {
                    match fs::read(phone.local(path)) {
                        Ok(bytes) if !phone.denies(path) => {
                            let hash = if phone.wrong_md5.contains(path) {
                                "0".repeat(32)
                            } else {
                                md5_hex(&bytes)
                            };
                            out.push_str(&format!("{hash}  {path}\n"));
                        }
                        _ => out.push_str(&format!("md5sum: {path}: No such file or directory\n")),
                    }
                }
            }
            Some("rm") => {
                for path in w.iter().skip(1).filter(|a| !a.starts_with('-')) {
                    let _ = fs::remove_file(phone.local(path));
                }
            }
            Some(other) => out.push_str(&format!("/system/bin/sh: {other}: not found\n")),
            None => {}
        }
    }
    out
}

/// Characters a phone allows in names and Windows does not: the fake stores them as `%xx`, so a
/// phone holding `Screenshot 12:30.png` can be simulated on any computer.
const ENCODED: &[char] = &['%', ':', '?', '*', '<', '>', '|', '"', '\\'];

fn encode(name: &str) -> String {
    name.chars()
        .map(|c| {
            if ENCODED.contains(&c) {
                format!("%{:02X}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn decode(name: &str) -> String {
    let mut out = String::new();
    let mut rest = name;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let code = rest.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok());
        match code {
            Some(c) => {
                out.push(c as char);
                rest = &rest[i + 3..];
            }
            None => {
                out.push('%');
                rest = &rest[i + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Where a phone path is kept in the fake's folder.
fn on_disk(root: &Path, path: &str) -> PathBuf {
    remote::normalize(path)
        .split('/')
        .filter(|p| !p.is_empty())
        .fold(root.to_path_buf(), |d, part| d.join(encode(part)))
}

/// Puts a file on a fake phone (`path` is the phone's, such as `/sdcard/DCIM/a.jpg`), with its
/// modification time.
pub fn put(root: &Path, path: &str, bytes: &[u8], mtime: u64) {
    let local = on_disk(root, path);
    fs::create_dir_all(local.parent().expect("a folder")).expect("the folder");
    fs::write(&local, bytes).expect("the file");
    fs::File::options()
        .write(true)
        .open(&local)
        .and_then(|f| f.set_modified(UNIX_EPOCH + Duration::from_secs(mtime)))
        .expect("the time");
}

/// A folder for one test's phone, empty.
pub fn temp_root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "adbdata-{name}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a temporary folder");
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_windows_refuses_are_kept_on_disk_encoded() {
        for name in ["Screenshot 12:30.png", "what?*.txt", "100%.jpg", "a\\b", "plain.jpg"] {
            assert_eq!(decode(&encode(name)), name);
        }
        assert_eq!(encode("12:30"), "12%3A30");
        assert_eq!(decode("50%off"), "50%off", "a stray percent stays");
    }

    #[test]
    fn splits_quoted_words() {
        assert_eq!(
            words("md5sum '/sdcard/a b.jpg' '/sdcard/it'\\''s'"),
            ["md5sum", "/sdcard/a b.jpg", "/sdcard/it's"]
        );
        assert_eq!(words("  getprop   ro.product.model "), ["getprop", "ro.product.model"]);
    }

    #[test]
    fn answers_like_adb_does() {
        let root = temp_root("fake");
        fs::create_dir_all(root.join("sdcard/DCIM")).unwrap();
        fs::write(root.join("sdcard/DCIM/a.jpg"), b"abc").unwrap();
        let adb = FakeAdb::start(vec![FakePhone::new("ABC123", &root)]);
        let server = adb.server();
        assert_eq!(server.version().unwrap(), 41);
        let devices = server.devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].model.as_deref(), Some("Example_Phone_12"));
        assert!(server.features("ABC123").unwrap().contains(&"ls_v2".to_string()));
        let Err(err) = server.sync("nope") else {
            panic!("an unknown phone opened")
        };
        assert_eq!(err.to_string(), "device 'nope' not found");
        let mut sync = server.sync("ABC123").unwrap();
        let list = sync.list("/sdcard/DCIM").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].name.as_str(), list[0].size), ("a.jpg", 3));
        let _ = fs::remove_dir_all(&root);
    }
}
