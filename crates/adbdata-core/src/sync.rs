//! The phone's file service (`sync:`), the one `adb pull` and `adb push` use.
//!
//! Requests are a four-letter id, a little-endian length and a path. A listing answers with one
//! entry per name and `DONE`; a file comes back as `DATA` blocks of at most 64 KiB and `DONE`. When
//! the phone refuses a request it answers `FAIL` with a reason and closes the connection, so a
//! connection that saw a `FAIL` is not used again.
//!
//! Version 2 of the listing and of the file information carries 64-bit sizes; the phone says it
//! speaks it with the `ls_v2` and `stat_v2` features. Version 1 sizes stop at 4 GiB.

use std::io::{self, BufReader, Read, Write};

/// The largest block of a file in one message.
pub const DATA_MAX: usize = 64 * 1024;
/// The longest path the phone accepts.
pub const PATH_MAX: usize = 1024;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;
/// A regular file readable by everyone, writable by its owner: what `adb push` gives new files.
pub const FILE_MODE: u32 = S_IFREG | 0o644;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The connection broke: adb's server stopped or the phone went away.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The phone refused this file, with its reason ("open failed: Permission denied").
    #[error("{0}")]
    Failed(String),
    /// Writing or reading the file on this computer failed (a full disk).
    #[error("{0}")]
    Local(io::Error),
    #[error("unexpected answer from the phone: {0}")]
    Protocol(String),
    /// The caller stopped a copy half way.
    #[error("stopped")]
    Cancelled,
    /// An earlier error closed this connection.
    #[error("the connection to the phone was closed")]
    Closed,
}

impl SyncError {
    /// True when the phone itself refused, so another file may well work.
    pub fn is_refusal(&self) -> bool {
        matches!(self, SyncError::Failed(_))
    }
}

/// One name in a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name as the phone stores it. Names that are not UTF-8 are rare; they are read with
    /// replacement characters and `exact` is false, as they cannot be asked for again.
    pub name: String,
    pub exact: bool,
    pub mode: u32,
    pub size: u64,
    /// Seconds since 1970, UTC.
    pub mtime: i64,
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    pub fn is_link(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

/// What the phone knows about one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub mode: u32,
    pub size: u64,
    pub mtime: i64,
}

impl Stat {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

/// An open file service on one phone.
pub struct Sync<S: Read + Write> {
    stream: BufReader<S>,
    ls_v2: bool,
    stat_v2: bool,
    closed: bool,
    block: Vec<u8>,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("four bytes"))
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}
fn i64_at(b: &[u8], at: usize) -> i64 {
    i64::from_le_bytes(b[at..at + 8].try_into().expect("eight bytes"))
}

impl<S: Read + Write> Sync<S> {
    /// Wraps a connection already switched to `sync:`. `features` is what the phone reported.
    pub fn new(stream: S, features: &[String]) -> Self {
        let has = |f: &str| features.iter().any(|x| x == f);
        Sync {
            stream: BufReader::with_capacity(256 * 1024, stream),
            ls_v2: has("ls_v2"),
            stat_v2: has("stat_v2"),
            closed: false,
            block: vec![0; DATA_MAX],
        }
    }

    /// Whether listings report sizes past 4 GiB.
    pub fn large_sizes(&self) -> bool {
        self.ls_v2
    }

    /// False once an error has closed the connection.
    pub fn is_open(&self) -> bool {
        !self.closed
    }

    fn request(&mut self, id: &[u8; 4], path: &[u8]) -> Result<(), SyncError> {
        if self.closed {
            return Err(SyncError::Closed);
        }
        if path.len() > PATH_MAX {
            return Err(SyncError::Failed(format!("the path is longer than {PATH_MAX} bytes")));
        }
        let mut msg = Vec::with_capacity(8 + path.len());
        msg.extend_from_slice(id);
        msg.extend_from_slice(&(path.len() as u32).to_le_bytes());
        msg.extend_from_slice(path);
        self.write(&msg)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), SyncError> {
        self.stream.get_mut().write_all(bytes).map_err(|e| self.broke(e))
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<(), SyncError> {
        self.stream.read_exact(buf).map_err(|e| self.broke(e))
    }

    fn broke(&mut self, e: io::Error) -> SyncError {
        self.closed = true;
        SyncError::Io(e)
    }

    /// Marks the connection closed and passes the error on.
    fn close_with(&mut self, e: SyncError) -> SyncError {
        self.closed = true;
        e
    }

    /// Reads the reason after `FAIL`; the phone closes the connection after it.
    fn fail_reason(&mut self, len: u32) -> SyncError {
        if len as usize > PATH_MAX * 4 {
            return self.close_with(SyncError::Protocol(format!("a reason of {len} bytes")));
        }
        let mut msg = vec![0u8; len as usize];
        match self.read(&mut msg) {
            Ok(()) => self.close_with(SyncError::Failed(String::from_utf8_lossy(&msg).into_owned())),
            Err(e) => e,
        }
    }

    /// The names in a folder, without `.` and `..`. A folder that does not exist or may not be
    /// read lists as empty, as the phone gives no reason.
    pub fn list(&mut self, path: &str) -> Result<Vec<Entry>, SyncError> {
        let (id, head_len): (&[u8; 4], usize) = if self.ls_v2 { (b"LIS2", 76) } else { (b"LIST", 20) };
        self.request(id, path.as_bytes())?;
        let mut entries = Vec::new();
        let mut head = vec![0u8; head_len];
        loop {
            self.read(&mut head)?;
            match &head[0..4] {
                b"DONE" => return Ok(entries),
                b"DENT" | b"DNT2" => {}
                b"FAIL" => {
                    let len = u32_at(&head, 4);
                    return Err(self.fail_reason(len));
                }
                other => {
                    let what = String::from_utf8_lossy(other).into_owned();
                    return Err(self.close_with(SyncError::Protocol(what)));
                }
            }
            let (error, mode, size, mtime, name_len) = if self.ls_v2 {
                (
                    u32_at(&head, 4),
                    u32_at(&head, 24),
                    u64_at(&head, 40),
                    i64_at(&head, 56),
                    u32_at(&head, 72),
                )
            } else {
                (
                    0,
                    u32_at(&head, 4),
                    u64::from(u32_at(&head, 8)),
                    i64::from(u32_at(&head, 12)),
                    u32_at(&head, 16),
                )
            };
            if name_len as usize > PATH_MAX {
                return Err(self.close_with(SyncError::Protocol(format!("a name of {name_len} bytes"))));
            }
            let mut raw = vec![0u8; name_len as usize];
            self.read(&mut raw)?;
            if error != 0 || raw == b"." || raw == b".." {
                continue;
            }
            let (name, exact) = match String::from_utf8(raw) {
                Ok(name) => (name, true),
                Err(e) => (String::from_utf8_lossy(e.as_bytes()).into_owned(), false),
            };
            entries.push(Entry {
                name,
                exact,
                mode,
                size,
                mtime,
            });
        }
    }

    /// What the phone knows about `path`, following links; `None` when it does not exist.
    pub fn stat(&mut self, path: &str) -> Result<Option<Stat>, SyncError> {
        if self.stat_v2 {
            self.request(b"STA2", path.as_bytes())?;
            let mut msg = [0u8; 72];
            self.read(&mut msg)?;
            if &msg[0..4] != b"STA2" {
                return Err(self.unexpected(&msg));
            }
            if u32_at(&msg, 4) != 0 {
                return Ok(None);
            }
            Ok(Some(Stat {
                mode: u32_at(&msg, 24),
                size: u64_at(&msg, 40),
                mtime: i64_at(&msg, 56),
            }))
        } else {
            // Version 1 does not follow links and says "missing" with a mode of 0.
            self.request(b"STAT", path.as_bytes())?;
            let mut msg = [0u8; 16];
            self.read(&mut msg)?;
            if &msg[0..4] != b"STAT" {
                return Err(self.unexpected(&msg));
            }
            let mode = u32_at(&msg, 4);
            Ok((mode != 0).then(|| Stat {
                mode,
                size: u64::from(u32_at(&msg, 8)),
                mtime: i64::from(u32_at(&msg, 12)),
            }))
        }
    }

    fn unexpected(&mut self, msg: &[u8]) -> SyncError {
        if &msg[0..4] == b"FAIL" {
            return self.fail_reason(u32_at(msg, 4));
        }
        self.close_with(SyncError::Protocol(String::from_utf8_lossy(&msg[0..4]).into_owned()))
    }

    /// Copies the file at `path` into `out` and returns its size. `progress` hears the bytes so far
    /// after each block and stops the copy by returning false; the connection is closed then, as
    /// the rest of the file is still on its way.
    pub fn recv(
        &mut self,
        path: &str,
        out: &mut dyn Write,
        progress: &mut dyn FnMut(u64) -> bool,
    ) -> Result<u64, SyncError> {
        self.request(b"RECV", path.as_bytes())?;
        let mut done = 0u64;
        let mut head = [0u8; 8];
        loop {
            self.read(&mut head)?;
            let len = u32_at(&head, 4);
            match &head[0..4] {
                b"DATA" => {}
                b"DONE" => return Ok(done),
                b"FAIL" => return Err(self.fail_reason(len)),
                other => {
                    let what = String::from_utf8_lossy(other).into_owned();
                    return Err(self.close_with(SyncError::Protocol(what)));
                }
            }
            let len = len as usize;
            if len > DATA_MAX {
                return Err(self.close_with(SyncError::Protocol(format!("a block of {len} bytes"))));
            }
            let mut block = std::mem::take(&mut self.block);
            let read = self.read(&mut block[..len]);
            let written = read.and_then(|()| {
                out.write_all(&block[..len])
                    .map_err(|e| self.close_with(SyncError::Local(e)))
            });
            self.block = block;
            written?;
            done += len as u64;
            if !progress(done) {
                return Err(self.close_with(SyncError::Cancelled));
            }
        }
    }

    /// Writes `input` to `path` on the phone with this mode and modification time (seconds since
    /// 1970), and returns its size. The phone replaces a file that is there. `progress` works as
    /// for `recv`.
    pub fn send(
        &mut self,
        path: &str,
        mode: u32,
        mtime: u32,
        input: &mut dyn Read,
        progress: &mut dyn FnMut(u64) -> bool,
    ) -> Result<u64, SyncError> {
        // The phone reads the mode after the last comma, as a decimal number.
        self.request(b"SEND", format!("{path},{mode}").as_bytes())?;
        let mut done = 0u64;
        let mut msg = vec![0u8; 8 + DATA_MAX];
        loop {
            let n = match input.read(&mut msg[8..]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(self.close_with(SyncError::Local(e))),
            };
            msg[0..4].copy_from_slice(b"DATA");
            msg[4..8].copy_from_slice(&(n as u32).to_le_bytes());
            self.write(&msg[..8 + n])?;
            done += n as u64;
            if !progress(done) {
                return Err(self.close_with(SyncError::Cancelled));
            }
        }
        let mut finish = [0u8; 8];
        finish[0..4].copy_from_slice(b"DONE");
        finish[4..8].copy_from_slice(&mtime.to_le_bytes());
        self.write(&finish)?;
        let mut head = [0u8; 8];
        self.read(&mut head)?;
        match &head[0..4] {
            b"OKAY" => Ok(done),
            b"FAIL" => Err(self.fail_reason(u32_at(&head, 4))),
            other => {
                let what = String::from_utf8_lossy(other).into_owned();
                Err(self.close_with(SyncError::Protocol(what)))
            }
        }
    }

    /// Ends the service politely.
    pub fn quit(mut self) {
        if !self.closed {
            let _ = self.request(b"QUIT", b"");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A connection that answers from a script and keeps what was sent.
    struct Scripted {
        answers: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.answers.read(buf)
        }
    }
    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn sync(answers: Vec<u8>, features: &[&str]) -> Sync<Scripted> {
        let features: Vec<String> = features.iter().map(|f| f.to_string()).collect();
        Sync::new(
            Scripted {
                answers: Cursor::new(answers),
                sent: Vec::new(),
            },
            &features,
        )
    }

    fn dent_v1(name: &str, mode: u32, size: u32, mtime: u32) -> Vec<u8> {
        let mut m = b"DENT".to_vec();
        for v in [mode, size, mtime, name.len() as u32] {
            m.extend_from_slice(&v.to_le_bytes());
        }
        m.extend_from_slice(name.as_bytes());
        m
    }

    fn dent_v2(name: &[u8], error: u32, mode: u32, size: u64, mtime: i64) -> Vec<u8> {
        let mut m = b"DNT2".to_vec();
        m.extend_from_slice(&error.to_le_bytes());
        m.extend_from_slice(&[0u8; 16]); // dev, ino
        m.extend_from_slice(&mode.to_le_bytes());
        m.extend_from_slice(&[0u8; 12]); // nlink, uid, gid
        m.extend_from_slice(&size.to_le_bytes());
        m.extend_from_slice(&0i64.to_le_bytes());
        m.extend_from_slice(&mtime.to_le_bytes());
        m.extend_from_slice(&0i64.to_le_bytes());
        m.extend_from_slice(&(name.len() as u32).to_le_bytes());
        m.extend_from_slice(name);
        m
    }

    #[test]
    fn lists_version_one_without_dots() {
        let mut answers = Vec::new();
        answers.extend(dent_v1(".", S_IFDIR | 0o755, 0, 0));
        answers.extend(dent_v1("..", S_IFDIR | 0o755, 0, 0));
        answers.extend(dent_v1("Camera", S_IFDIR | 0o770, 3488, 1_700_000_000));
        answers.extend(dent_v1("IMG_1.jpg", S_IFREG | 0o660, 2_345_678, 1_700_000_100));
        answers.extend(b"DONE".iter().chain(&[0u8; 16]).copied());
        let mut s = sync(answers, &[]);
        let list = s.list("/sdcard/DCIM").unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].is_dir() && list[1].is_file());
        assert_eq!(list[1].size, 2_345_678);
        assert_eq!(list[1].mtime, 1_700_000_100);
        let sent = &s.stream.get_ref().sent;
        assert_eq!(&sent[0..4], b"LIST");
        assert_eq!(u32_at(sent, 4), 12);
        assert_eq!(&sent[8..], b"/sdcard/DCIM");
        assert!(s.is_open());
    }

    #[test]
    fn lists_version_two_with_large_sizes_and_odd_names() {
        let mut answers = Vec::new();
        answers.extend(dent_v2(b"film.mp4", 0, S_IFREG | 0o660, 6_000_000_000, 1_800_000_000));
        answers.extend(dent_v2(b"broken", 13, 0, 0, 0));
        answers.extend(dent_v2(b"caf\xe9.txt", 0, S_IFREG | 0o660, 5, 1));
        let mut done = b"DONE".to_vec();
        done.resize(76, 0);
        answers.extend(done);
        let mut s = sync(answers, &["shell_v2", "ls_v2", "stat_v2"]);
        assert!(s.large_sizes());
        let list = s.list("/sdcard/Movies").unwrap();
        assert_eq!(list.len(), 2, "an entry the phone could not read is left out");
        assert_eq!(list[0].size, 6_000_000_000);
        assert!(list[0].exact);
        assert!(!list[1].exact, "a name that is not UTF-8 cannot be asked for again");
        assert_eq!(&s.stream.get_ref().sent[0..4], b"LIS2");
    }

    #[test]
    fn stats_in_both_versions() {
        let mut v1 = b"STAT".to_vec();
        for v in [S_IFREG | 0o660, 10, 1_700_000_000] {
            v1.extend_from_slice(&v.to_le_bytes());
        }
        v1.extend(b"STAT".iter().chain(&[0u8; 12]).copied());
        let mut s = sync(v1, &[]);
        let st = s.stat("/sdcard/a").unwrap().unwrap();
        assert!(st.is_file() && st.size == 10);
        assert_eq!(s.stat("/sdcard/missing").unwrap(), None);

        let mut v2 = b"STA2".to_vec();
        v2.extend_from_slice(&0u32.to_le_bytes());
        v2.extend_from_slice(&[0u8; 16]);
        v2.extend_from_slice(&(S_IFDIR | 0o771).to_le_bytes());
        v2.extend_from_slice(&[0u8; 12]);
        v2.extend_from_slice(&4096u64.to_le_bytes());
        v2.extend_from_slice(&[0u8; 24]);
        let mut missing = b"STA2".to_vec();
        missing.extend_from_slice(&2u32.to_le_bytes());
        missing.resize(72, 0);
        v2.extend(missing);
        let mut s = sync(v2, &["stat_v2"]);
        assert!(s.stat("/sdcard").unwrap().unwrap().is_dir());
        assert_eq!(s.stat("/nope").unwrap(), None);
    }

    #[test]
    fn receives_blocks_and_reports_progress() {
        let mut answers = Vec::new();
        for chunk in [&b"hello "[..], &b"world"[..]] {
            answers.extend_from_slice(b"DATA");
            answers.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            answers.extend_from_slice(chunk);
        }
        answers.extend(b"DONE".iter().chain(&[0u8; 4]).copied());
        let mut s = sync(answers, &[]);
        let mut out = Vec::new();
        let mut seen = Vec::new();
        let n = s
            .recv("/sdcard/a.txt", &mut out, &mut |d| {
                seen.push(d);
                true
            })
            .unwrap();
        assert_eq!((n, out.as_slice()), (11, &b"hello world"[..]));
        assert_eq!(seen, [6, 11]);
        assert!(s.is_open());
    }

    #[test]
    fn a_refusal_closes_the_connection() {
        let mut answers = b"FAIL".to_vec();
        let msg = b"open failed: Permission denied";
        answers.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        answers.extend_from_slice(msg);
        let mut s = sync(answers, &[]);
        let err = s.recv("/data/x", &mut Vec::new(), &mut |_| true).unwrap_err();
        assert!(err.is_refusal());
        assert_eq!(err.to_string(), "open failed: Permission denied");
        assert!(!s.is_open());
        assert!(matches!(s.list("/sdcard"), Err(SyncError::Closed)));
    }

    #[test]
    fn stopping_a_copy_closes_the_connection() {
        let mut answers = b"DATA".to_vec();
        answers.extend_from_slice(&3u32.to_le_bytes());
        answers.extend_from_slice(b"abc");
        let mut s = sync(answers, &[]);
        let err = s.recv("/sdcard/a", &mut Vec::new(), &mut |_| false).unwrap_err();
        assert!(matches!(err, SyncError::Cancelled));
        assert!(!s.is_open());
    }

    #[test]
    fn a_cut_connection_is_an_io_error() {
        let mut answers = b"DATA".to_vec();
        answers.extend_from_slice(&100u32.to_le_bytes());
        answers.extend_from_slice(b"short");
        let mut s = sync(answers, &[]);
        let err = s.recv("/sdcard/a", &mut Vec::new(), &mut |_| true).unwrap_err();
        assert!(matches!(err, SyncError::Io(_)));
        assert!(!err.is_refusal() && !s.is_open());
    }

    #[test]
    fn sends_blocks_mode_and_time() {
        let mut s = sync(b"OKAY\0\0\0\0".to_vec(), &[]);
        let data = vec![7u8; DATA_MAX + 10];
        let n = s
            .send(
                "/sdcard/Music/a,b.mp3",
                FILE_MODE,
                1_700_000_000,
                &mut &data[..],
                &mut |_| true,
            )
            .unwrap();
        assert_eq!(n, data.len() as u64);
        let sent = &s.stream.get_ref().sent;
        let path = format!("/sdcard/Music/a,b.mp3,{FILE_MODE}");
        assert_eq!(&sent[0..4], b"SEND");
        assert_eq!(&sent[8..8 + path.len()], path.as_bytes());
        let mut at = 8 + path.len();
        assert_eq!(&sent[at..at + 4], b"DATA");
        assert_eq!(u32_at(sent, at + 4) as usize, DATA_MAX);
        at += 8 + DATA_MAX;
        assert_eq!(u32_at(sent, at + 4), 10);
        at += 8 + 10;
        assert_eq!(&sent[at..at + 4], b"DONE");
        assert_eq!(u32_at(sent, at + 4), 1_700_000_000);
    }

    #[test]
    fn paths_past_the_limit_are_refused_before_sending() {
        let mut s = sync(Vec::new(), &[]);
        let long = format!("/sdcard/{}", "a".repeat(PATH_MAX));
        assert!(s.list(&long).unwrap_err().is_refusal());
        assert!(s.stream.get_ref().sent.is_empty());
    }
}
