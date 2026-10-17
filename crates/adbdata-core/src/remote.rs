//! Paths on the phone, the kinds of file people copy, and the places they usually are.

use serde::{Deserialize, Serialize};

/// The phone's shared storage, where photos, downloads and documents live.
pub const STORAGE: &str = "/sdcard";

/// `/sdcard/DCIM` + `Camera` = `/sdcard/DCIM/Camera`. A name never adds more than one level.
pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// The folder a path is in; `None` for the root.
pub fn parent(path: &str) -> Option<&str> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rfind('/') {
        Some(0) => Some("/"),
        Some(i) => Some(&trimmed[..i]),
        None => None,
    }
}

/// The last part of a path.
pub fn file_name(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or(path)
}

/// A path as the phone expects it: absolute, single slashes, no trailing slash, no `.` or `..`
/// parts (they are resolved, and never climb above the root).
pub fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

/// A word for the phone's shell, in single quotes: nothing in it is special there.
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Names a person rarely wants copied: hidden files, thumbnails and the phone's trash
/// (`.trashed-1700000000-IMG_1.jpg` on Android 11 and later).
pub fn is_hidden(name: &str) -> bool {
    name.starts_with('.')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Photo,
    Video,
    Audio,
    Document,
    Archive,
    App,
    Other,
}

impl Kind {
    /// The kind of a file, from its extension.
    pub fn of(name: &str) -> Kind {
        let ext = match name.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() => ext.to_ascii_lowercase(),
            _ => return Kind::Other,
        };
        match ext.as_str() {
            "jpg" | "jpeg" | "png" | "heic" | "heif" | "webp" | "gif" | "bmp" | "dng" | "raw" | "avif" => Kind::Photo,
            "mp4" | "mov" | "mkv" | "3gp" | "webm" | "avi" | "m4v" | "ts" => Kind::Video,
            "mp3" | "m4a" | "aac" | "ogg" | "opus" | "flac" | "wav" | "amr" | "wma" | "mid" => Kind::Audio,
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" | "txt" | "rtf"
            | "csv" | "md" | "epub" | "json" | "xml" | "html" | "htm" | "vcf" => Kind::Document,
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" => Kind::Archive,
            "apk" | "apks" | "xapk" | "apkm" => Kind::App,
            _ => Kind::Other,
        }
    }
}

/// A folder people often copy from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Place {
    /// The key the window translates ("camera").
    pub key: &'static str,
    /// Where it is; the first one that exists is used.
    pub paths: &'static [&'static str],
}

pub const PLACES: &[Place] = &[
    Place {
        key: "storage",
        paths: &[STORAGE],
    },
    Place {
        key: "camera",
        paths: &["/sdcard/DCIM/Camera"],
    },
    Place {
        key: "screenshots",
        paths: &["/sdcard/Pictures/Screenshots", "/sdcard/DCIM/Screenshots"],
    },
    Place {
        key: "pictures",
        paths: &["/sdcard/Pictures"],
    },
    Place {
        key: "downloads",
        paths: &["/sdcard/Download"],
    },
    Place {
        key: "documents",
        paths: &["/sdcard/Documents"],
    },
    Place {
        key: "whatsapp",
        // Android 11 moved app folders under Android/media.
        paths: &[
            "/sdcard/Android/media/com.whatsapp/WhatsApp/Media",
            "/sdcard/WhatsApp/Media",
        ],
    },
    Place {
        key: "music",
        paths: &["/sdcard/Music"],
    },
    Place {
        key: "movies",
        paths: &["/sdcard/Movies"],
    },
    Place {
        key: "recordings",
        paths: &["/sdcard/Recordings", "/sdcard/Music/Recordings"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_and_splits_paths() {
        assert_eq!(join("/sdcard/DCIM", "Camera"), "/sdcard/DCIM/Camera");
        assert_eq!(join("/", "sdcard"), "/sdcard");
        assert_eq!(parent("/sdcard/DCIM/Camera"), Some("/sdcard/DCIM"));
        assert_eq!(parent("/sdcard"), Some("/"));
        assert_eq!(parent("/sdcard/"), Some("/"));
        assert_eq!(parent("/"), None);
        assert_eq!(file_name("/sdcard/DCIM/IMG 1.jpg"), "IMG 1.jpg");
        assert_eq!(file_name("/sdcard/DCIM/"), "DCIM");
    }

    #[test]
    fn normalizes_without_climbing_above_the_root() {
        assert_eq!(normalize("/sdcard//DCIM/./Camera/"), "/sdcard/DCIM/Camera");
        assert_eq!(normalize("/sdcard/DCIM/../Download"), "/sdcard/Download");
        assert_eq!(normalize("/../../etc"), "/etc");
        assert_eq!(normalize("sdcard"), "/sdcard");
        assert_eq!(normalize(""), "/");
    }

    #[test]
    fn quotes_anything_for_the_shell() {
        assert_eq!(quote("/sdcard/a b.jpg"), "'/sdcard/a b.jpg'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("$(rm -rf /);`x`&&|"), "'$(rm -rf /);`x`&&|'");
    }

    #[test]
    fn kinds_come_from_the_extension() {
        assert_eq!(Kind::of("IMG_20240501.JPG"), Kind::Photo);
        assert_eq!(Kind::of("VID.mp4"), Kind::Video);
        assert_eq!(Kind::of("voice.opus"), Kind::Audio);
        assert_eq!(Kind::of("Ödev.pdf"), Kind::Document);
        assert_eq!(Kind::of("app.apk"), Kind::App);
        assert_eq!(Kind::of(".jpg"), Kind::Other, "a hidden file named after an extension");
        assert_eq!(Kind::of("README"), Kind::Other);
    }

    #[test]
    fn hidden_names_include_the_trash() {
        assert!(is_hidden(".trashed-1700000000-IMG_1.jpg"));
        assert!(is_hidden(".thumbnails"));
        assert!(!is_hidden("IMG_1.jpg"));
    }
}
