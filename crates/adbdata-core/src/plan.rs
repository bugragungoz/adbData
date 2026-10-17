//! What a copy will do before it starts: which files go where, which are already there, and which
//! names had to change. Nothing here touches the phone or the disk; the caller says what exists.

use crate::names::{numbered, windows_name};
use crate::remote::Kind;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// What to do when a file of the same name is already where it would go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Existing {
    /// Skip it when it is the same size, which makes copying a folder again pick up only what is
    /// new. A different file of that name is kept and the new one gets a number.
    #[default]
    Skip,
    /// Copy it again under a numbered name.
    KeepBoth,
    /// Overwrite it.
    Replace,
}

/// How copies are arranged on the PC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Layout {
    /// The folders as they are on the phone.
    #[default]
    Keep,
    /// One folder per month the file was last changed in (`2024-05`), for photos and videos.
    ByMonth,
}

/// A file found under what was chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Source<P> {
    pub path: P,
    /// The folders between the chosen place and the file, then its name.
    pub rel: Vec<String>,
    pub size: u64,
    /// Seconds since 1970, UTC.
    pub mtime: i64,
}

/// A file on the phone.
pub type RemoteFile = Source<String>;
/// A file on the PC.
pub type LocalFile = Source<PathBuf>;

/// What is at a target path already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    File(u64),
    /// A folder, or something that cannot be told apart from one.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Job<S, T> {
    pub from: S,
    pub to: T,
    pub size: u64,
    pub mtime: i64,
    /// A file is there and is overwritten.
    pub replace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan<S, T> {
    pub jobs: Vec<Job<S, T>>,
    /// Already there, same size.
    pub skipped: Vec<Job<S, T>>,
    /// Left out by the kind filter.
    pub filtered: usize,
    /// Copied under another name because Windows does not take the original.
    pub renamed: usize,
    /// Copied with a number because the name was taken.
    pub numbered: usize,
    pub bytes: u64,
}

impl<S, T> Plan<S, T> {
    fn new() -> Self {
        Plan {
            jobs: Vec::new(),
            skipped: Vec::new(),
            filtered: 0,
            renamed: 0,
            numbered: 0,
            bytes: 0,
        }
    }
}

pub type PullPlan = Plan<String, PathBuf>;
pub type PushPlan = Plan<PathBuf, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullOptions {
    pub dest: PathBuf,
    pub existing: Existing,
    pub layout: Layout,
    /// Only these kinds; empty for all.
    pub kinds: Vec<Kind>,
    /// The PC's offset from UTC, for the month a file belongs to.
    pub utc_offset_minutes: i32,
}

/// Where each file goes on the PC. `found` says what is at a path now.
pub fn plan_pull(files: &[RemoteFile], o: &PullOptions, found: &mut dyn FnMut(&Path) -> Option<Found>) -> PullPlan {
    let mut plan = Plan::new();
    let mut taken = Taken::default();
    for f in files {
        let Some(name) = f.rel.last() else { continue };
        if !o.kinds.is_empty() && !o.kinds.contains(&Kind::of(name)) {
            plan.filtered += 1;
            continue;
        }
        let parts: Vec<String> = match o.layout {
            Layout::Keep => f.rel.iter().map(|p| windows_name(p)).collect(),
            Layout::ByMonth => vec![month_of(f.mtime, o.utc_offset_minutes), windows_name(name)],
        };
        let original: Vec<&str> = match o.layout {
            Layout::Keep => f.rel.iter().map(String::as_str).collect(),
            Layout::ByMonth => vec![name.as_str()],
        };
        if parts
            .iter()
            .skip(usize::from(o.layout == Layout::ByMonth))
            .zip(&original)
            .any(|(a, b)| a != b)
        {
            plan.renamed += 1;
        }
        let file_name = parts.last().expect("a name").clone();
        let dir = parts[..parts.len() - 1].iter().fold(o.dest.clone(), |d, p| d.join(p));
        let at = |n: u32| {
            dir.join(if n == 1 {
                file_name.clone()
            } else {
                numbered(&file_name, n)
            })
        };
        let choice = choose(o.existing, f.size, |n| {
            let p = at(n);
            if taken.has(&p.to_string_lossy()) {
                Slot::Taken
            } else {
                match found(&p) {
                    None => Slot::Free,
                    Some(Found::File(size)) => Slot::File(size),
                    Some(Found::Other) => Slot::Other,
                }
            }
        });
        add(
            &mut plan,
            &mut taken,
            choice,
            f.path.clone(),
            at,
            f.size,
            f.mtime,
            |p| p.to_string_lossy().into_owned(),
        );
    }
    plan
}

/// Where each file goes on the phone, under `dest`. `found` says what is at a phone path now.
pub fn plan_push(
    files: &[LocalFile],
    dest: &str,
    existing: Existing,
    found: &mut dyn FnMut(&str) -> Option<Found>,
) -> PushPlan {
    let mut plan = Plan::new();
    let mut taken = Taken::default();
    for f in files {
        let Some(file_name) = f.rel.last() else { continue };
        // Names from Windows are valid on the phone as they are.
        let dir = f.rel[..f.rel.len() - 1]
            .iter()
            .fold(dest.trim_end_matches('/').to_string(), |d, p| format!("{d}/{p}"));
        let at = |n: u32| {
            format!(
                "{dir}/{}",
                if n == 1 {
                    file_name.clone()
                } else {
                    numbered(file_name, n)
                }
            )
        };
        let choice = choose(existing, f.size, |n| {
            let p = at(n);
            if taken.has(&p) {
                Slot::Taken
            } else {
                match found(&p) {
                    None => Slot::Free,
                    Some(Found::File(size)) => Slot::File(size),
                    Some(Found::Other) => Slot::Other,
                }
            }
        });
        add(
            &mut plan,
            &mut taken,
            choice,
            f.path.clone(),
            at,
            f.size,
            f.mtime,
            |p| p.clone(),
        );
    }
    plan
}

#[allow(clippy::too_many_arguments)]
fn add<S, T>(
    plan: &mut Plan<S, T>,
    taken: &mut Taken,
    choice: Choice,
    from: S,
    at: impl Fn(u32) -> T,
    size: u64,
    mtime: i64,
    key: impl Fn(&T) -> String,
) {
    match choice {
        Choice::Skip(n) => plan.skipped.push(Job {
            from,
            to: at(n),
            size,
            mtime,
            replace: false,
        }),
        Choice::Use { n, replace } => {
            let to = at(n);
            taken.add(&key(&to));
            if n > 1 {
                plan.numbered += 1;
            }
            plan.bytes += size;
            plan.jobs.push(Job {
                from,
                to,
                size,
                mtime,
                replace,
            });
        }
    }
}

/// Target paths already given to a file in this plan, compared the way Windows does.
#[derive(Default)]
struct Taken(HashSet<String>);

impl Taken {
    fn has(&self, path: &str) -> bool {
        self.0.contains(&path.to_uppercase())
    }
    fn add(&mut self, path: &str) {
        self.0.insert(path.to_uppercase());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Free,
    /// Given to another file of this copy.
    Taken,
    File(u64),
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    Skip(u32),
    Use { n: u32, replace: bool },
}

/// Picks the name for one file: `look(1)` is its own name, `look(n)` the `n`th numbered one.
fn choose(existing: Existing, size: u64, mut look: impl FnMut(u32) -> Slot) -> Choice {
    if existing == Existing::Replace {
        match look(1) {
            Slot::Free => return Choice::Use { n: 1, replace: false },
            Slot::File(_) => return Choice::Use { n: 1, replace: true },
            Slot::Taken | Slot::Other => {}
        }
    }
    for n in 1..=100_000 {
        match look(n) {
            Slot::Free => return Choice::Use { n, replace: false },
            // An earlier copy, perhaps numbered by an earlier run.
            Slot::File(s) if s == size && existing == Existing::Skip => return Choice::Skip(n),
            _ => {}
        }
    }
    // A hundred thousand copies of one name: give up numbering and overwrite the last.
    Choice::Use {
        n: 100_000,
        replace: true,
    }
}

/// `2024-05` for a time, in the PC's time zone.
pub fn month_of(mtime: i64, utc_offset_minutes: i32) -> String {
    let days = (mtime + i64::from(utc_offset_minutes) * 60).div_euclid(86_400);
    let (y, m, _) = civil_from_days(days);
    format!("{y:04}-{m:02}")
}

/// Year, month and day of a day count since 1970 (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn file(path: &str, size: u64, mtime: i64) -> RemoteFile {
        let rel: Vec<String> = path
            .trim_start_matches("/sdcard/DCIM/")
            .split('/')
            .map(String::from)
            .collect();
        Source {
            path: path.into(),
            rel,
            size,
            mtime,
        }
    }

    fn opts(existing: Existing, layout: Layout) -> PullOptions {
        PullOptions {
            dest: PathBuf::from("D:/Phone"),
            existing,
            layout,
            kinds: vec![],
            utc_offset_minutes: 180,
        }
    }

    fn on_pc(files: &[(&str, u64)]) -> impl Fn(&Path) -> Option<Found> {
        let map: HashMap<String, u64> = files.iter().map(|(p, s)| (p.to_uppercase(), *s)).collect();
        move |p: &Path| {
            let key = p.to_string_lossy().replace('\\', "/").to_uppercase();
            map.get(&key)
                .map(|s| if *s == u64::MAX { Found::Other } else { Found::File(*s) })
        }
    }

    fn targets(plan: &PullPlan) -> Vec<String> {
        plan.jobs
            .iter()
            .map(|j| j.to.to_string_lossy().replace('\\', "/"))
            .collect()
    }

    #[test]
    fn keeps_the_folders_and_counts_the_bytes() {
        let files = [
            file("/sdcard/DCIM/Camera/IMG_1.jpg", 10, 0),
            file("/sdcard/DCIM/Camera/sub/VID.mp4", 20, 0),
        ];
        let plan = plan_pull(&files, &opts(Existing::Skip, Layout::Keep), &mut on_pc(&[]));
        assert_eq!(
            targets(&plan),
            ["D:/Phone/Camera/IMG_1.jpg", "D:/Phone/Camera/sub/VID.mp4"]
        );
        assert_eq!(plan.bytes, 30);
        assert_eq!((plan.renamed, plan.numbered, plan.skipped.len()), (0, 0, 0));
    }

    #[test]
    fn copying_again_skips_what_is_there_including_numbered_copies() {
        let files = [
            file("/sdcard/DCIM/Camera/same.jpg", 10, 0),
            file("/sdcard/DCIM/Camera/changed.jpg", 12, 0),
            file("/sdcard/DCIM/Camera/second.jpg", 7, 0),
        ];
        let mut pc = on_pc(&[
            ("D:/Phone/Camera/same.jpg", 10),
            ("D:/Phone/Camera/changed.jpg", 11),
            ("D:/Phone/Camera/second.jpg", 5),
            ("D:/Phone/Camera/second (2).jpg", 7),
        ]);
        let plan = plan_pull(&files, &opts(Existing::Skip, Layout::Keep), &mut pc);
        assert_eq!(
            targets(&plan),
            ["D:/Phone/Camera/changed (2).jpg"],
            "a different file keeps its name"
        );
        assert_eq!(plan.skipped.len(), 2);
        assert_eq!(plan.numbered, 1);
    }

    #[test]
    fn keep_both_and_replace() {
        let files = [file("/sdcard/DCIM/a.jpg", 10, 0)];
        let mut pc = on_pc(&[("D:/Phone/a.jpg", 10)]);
        let both = plan_pull(&files, &opts(Existing::KeepBoth, Layout::Keep), &mut pc);
        assert_eq!(targets(&both), ["D:/Phone/a (2).jpg"]);
        let replace = plan_pull(&files, &opts(Existing::Replace, Layout::Keep), &mut pc);
        assert_eq!(targets(&replace), ["D:/Phone/a.jpg"]);
        assert!(replace.jobs[0].replace);
        let mut folder = on_pc(&[("D:/Phone/a.jpg", u64::MAX)]);
        let over_folder = plan_pull(&files, &opts(Existing::Replace, Layout::Keep), &mut folder);
        assert_eq!(
            targets(&over_folder),
            ["D:/Phone/a (2).jpg"],
            "a folder is never replaced"
        );
    }

    #[test]
    fn names_windows_refuses_are_changed_and_clashes_numbered() {
        let files = [
            file("/sdcard/DCIM/Shot 12:30.png", 1, 0),
            file("/sdcard/DCIM/Shot 12?30.png", 2, 0),
            file("/sdcard/DCIM/IMG.JPG", 3, 0),
            file("/sdcard/DCIM/img.jpg", 4, 0),
            file("/sdcard/DCIM/../../x.jpg", 5, 0),
        ];
        let plan = plan_pull(&files, &opts(Existing::Skip, Layout::Keep), &mut on_pc(&[]));
        assert_eq!(
            targets(&plan),
            [
                "D:/Phone/Shot 12_30.png",
                "D:/Phone/Shot 12_30 (2).png",
                "D:/Phone/IMG.JPG",
                "D:/Phone/img (2).jpg",
                "D:/Phone/_/_/x.jpg",
            ]
        );
        assert_eq!(plan.renamed, 3);
        assert_eq!(plan.numbered, 2);
    }

    #[test]
    fn months_follow_the_pc_time_zone() {
        // 2024-04-30 22:30 UTC is already May in Istanbul (UTC+3).
        let late_april = 1_714_516_200;
        let files = [file("/sdcard/DCIM/Camera/IMG.jpg", 1, late_april)];
        let plan = plan_pull(&files, &opts(Existing::Skip, Layout::ByMonth), &mut on_pc(&[]));
        assert_eq!(targets(&plan), ["D:/Phone/2024-05/IMG.jpg"]);
        assert_eq!(month_of(late_april, 0), "2024-04");
        assert_eq!(month_of(0, 0), "1970-01");
        assert_eq!(month_of(951_782_400, 0), "2000-02", "2000-02-29");
        assert_eq!(month_of(-1, 0), "1969-12");
        assert_eq!(plan.renamed, 0, "the month folder is not a rename");
    }

    #[test]
    fn the_kind_filter_counts_what_it_leaves_out() {
        let files = [
            file("/sdcard/DCIM/a.jpg", 1, 0),
            file("/sdcard/DCIM/b.mp4", 1, 0),
            file("/sdcard/DCIM/c.txt", 1, 0),
        ];
        let mut o = opts(Existing::Skip, Layout::Keep);
        o.kinds = vec![Kind::Photo, Kind::Video];
        let plan = plan_pull(&files, &o, &mut on_pc(&[]));
        assert_eq!(plan.jobs.len(), 2);
        assert_eq!(plan.filtered, 1);
    }

    #[test]
    fn pushing_numbers_names_taken_on_the_phone() {
        let files = [
            Source {
                path: PathBuf::from("C:/Music/a.mp3"),
                rel: vec!["Album".into(), "a.mp3".into()],
                size: 5,
                mtime: 0,
            },
            Source {
                path: PathBuf::from("C:/Music/b.mp3"),
                rel: vec!["Album".into(), "b.mp3".into()],
                size: 6,
                mtime: 0,
            },
        ];
        let mut phone = |p: &str| match p {
            "/sdcard/Music/Album/a.mp3" => Some(Found::File(5)),
            "/sdcard/Music/Album/b.mp3" => Some(Found::File(1)),
            _ => None,
        };
        let plan = plan_push(&files, "/sdcard/Music/", Existing::Skip, &mut phone);
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.jobs.len(), 1);
        assert_eq!(plan.jobs[0].to, "/sdcard/Music/Album/b (2).mp3");
    }
}
