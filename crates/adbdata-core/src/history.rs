//! Every copy adbData made, newest first.

use crate::transfer::{Failure, Outcome};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// How many copies are kept.
pub const KEEP: usize = 300;
/// How many failed files one entry lists; the count is kept either way.
pub const KEEP_FAILURES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    ToPc,
    ToPhone,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    /// Milliseconds since 1970, when the copy ended.
    pub at: u64,
    pub direction: Direction,
    pub phone: String,
    /// Where the files came from and went, as the window showed them.
    pub from: String,
    pub to: String,
    /// Files the plan had to copy.
    pub planned: usize,
    pub copied: usize,
    pub bytes: u64,
    /// Already there, left alone.
    pub skipped: usize,
    pub failed_count: usize,
    pub failed: Vec<Failure>,
    pub checked: usize,
    pub check_unavailable: bool,
    pub stopped: bool,
    pub disconnected: bool,
    pub disk_full: bool,
    pub seconds: f64,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        at: u64,
        direction: Direction,
        phone: String,
        from: String,
        to: String,
        planned: usize,
        skipped: usize,
        o: &Outcome,
    ) -> Self {
        Session {
            id,
            at,
            direction,
            phone,
            from,
            to,
            planned,
            copied: o.copied,
            bytes: o.bytes,
            skipped,
            failed_count: o.failed.len(),
            failed: o.failed.iter().take(KEEP_FAILURES).cloned().collect(),
            checked: o.checked,
            check_unavailable: o.check_unavailable,
            stopped: o.stopped,
            disconnected: o.disconnected,
            disk_full: o.disk_full,
            seconds: o.seconds,
        }
    }
}

pub struct History {
    path: PathBuf,
}

impl History {
    pub fn new(dir: &Path) -> Self {
        History {
            path: dir.join("history.json"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The saved copies; an unreadable file is kept aside as history.json.broken and the history
    /// starts again, rather than failing every time.
    pub fn load(&self) -> Vec<Session> {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        match serde_json::from_str(&text) {
            Ok(sessions) => sessions,
            Err(_) => {
                let _ = fs::rename(&self.path, self.path.with_extension("json.broken"));
                Vec::new()
            }
        }
    }

    /// Adds a copy at the top and saves, through a temporary file so a crash never leaves half a
    /// file behind.
    pub fn add(&self, session: Session) -> io::Result<Vec<Session>> {
        let mut sessions = self.load();
        sessions.insert(0, session);
        sessions.truncate(KEEP);
        self.save(&sessions)?;
        Ok(sessions)
    }

    pub fn clear(&self) -> io::Result<()> {
        self.save(&[])
    }

    fn save(&self, sessions: &[Session]) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(sessions).map_err(io::Error::other)?)?;
        fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(failures: usize) -> Outcome {
        Outcome {
            copied: 10,
            bytes: 1000,
            failed: (0..failures)
                .map(|i| Failure {
                    path: format!("/sdcard/{i}"),
                    code: "refused".into(),
                    detail: String::new(),
                })
                .collect(),
            checked: 0,
            check_unavailable: false,
            stopped: false,
            disconnected: false,
            disk_full: false,
            seconds: 1.5,
        }
    }

    fn session(id: &str, failures: usize) -> Session {
        Session::new(
            id.into(),
            1,
            Direction::ToPc,
            "Example Phone 8".into(),
            "/sdcard/DCIM/Camera".into(),
            "D:\\Phone".into(),
            12,
            2,
            &outcome(failures),
        )
    }

    #[test]
    fn keeps_the_newest_first_and_survives_a_broken_file() {
        let dir = crate::fake::temp_root("history");
        let h = History::new(&dir);
        assert!(h.load().is_empty());
        h.add(session("1", 0)).unwrap();
        let all = h.add(session("2", 0)).unwrap();
        assert_eq!(all.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), ["2", "1"]);
        assert_eq!(h.load(), all);

        fs::write(h.path(), "{ not json").unwrap();
        assert!(h.load().is_empty());
        assert!(dir.join("history.json.broken").exists());
        h.add(session("3", 0)).unwrap();
        h.clear().unwrap();
        assert!(h.load().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_long_list_of_failures_is_cut_but_counted() {
        let s = session("1", KEEP_FAILURES + 50);
        assert_eq!(s.failed.len(), KEEP_FAILURES);
        assert_eq!(s.failed_count, KEEP_FAILURES + 50);
    }
}
