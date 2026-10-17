//! Finding adb, and getting Google's platform-tools when the computer has none.

use serde::Serialize;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AdbSource {
    /// The path set in the settings.
    Custom,
    /// The copy adbData downloaded.
    Managed,
    /// Found on the PATH.
    Path,
    /// Android Studio's SDK.
    Sdk,
}

/// Google's latest platform-tools for this system.
pub const DOWNLOAD_URL: &str = if cfg!(windows) {
    "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
} else if cfg!(target_os = "macos") {
    "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip"
} else {
    "https://dl.google.com/android/repository/platform-tools-latest-linux.zip"
};

/// The terms the download is under, shown before it starts.
pub const TERMS_URL: &str = "https://developer.android.com/studio/releases/platform-tools";

pub const EXE: &str = if cfg!(windows) { "adb.exe" } else { "adb" };

/// Where adb may be, in the order it is looked for.
pub fn candidates(
    custom: Option<&Path>,
    managed_dir: &Path,
    path_var: Option<&str>,
    home: Option<&Path>,
) -> Vec<(AdbSource, PathBuf)> {
    let mut list = Vec::new();
    if let Some(c) = custom {
        list.push((AdbSource::Custom, c.to_path_buf()));
    }
    list.push((AdbSource::Managed, managed_dir.join("platform-tools").join(EXE)));
    if let Some(var) = path_var {
        for dir in std::env::split_paths(var) {
            list.push((AdbSource::Path, dir.join(EXE)));
        }
    }
    if let Some(home) = home {
        let sdk = if cfg!(windows) {
            home.join("AppData").join("Local").join("Android").join("Sdk")
        } else if cfg!(target_os = "macos") {
            home.join("Library").join("Android").join("sdk")
        } else {
            home.join("Android").join("Sdk")
        };
        list.push((AdbSource::Sdk, sdk.join("platform-tools").join(EXE)));
    }
    list
}

/// The first adb that exists. A custom path that does not exist is not skipped silently: it is
/// returned, so the owner sees that it is wrong.
pub fn find(custom: Option<&Path>, managed_dir: &Path) -> Option<(AdbSource, PathBuf)> {
    if let Some(c) = custom {
        return Some((AdbSource::Custom, c.to_path_buf()));
    }
    let path_var = std::env::var("PATH").ok();
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from);
    candidates(None, managed_dir, path_var.as_deref(), home.as_deref())
        .into_iter()
        .find(|(_, p)| p.is_file())
}

#[derive(Debug, thiserror::Error)]
pub enum ToolsError {
    #[error("the download is not a platform-tools archive: {0}")]
    Archive(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Unpacks a platform-tools zip into `dir/platform-tools`, replacing an older copy, and returns
/// the path of adb. Entries outside `platform-tools/` and paths that leave it are skipped. The
/// new copy is written beside the old one first, so a failed download leaves the old one working.
pub fn install(zip: &[u8], dir: &Path) -> Result<PathBuf, ToolsError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(zip)).map_err(|e| ToolsError::Archive(e.to_string()))?;
    let staging = dir.join("platform-tools.new");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    let mut has_adb = false;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| ToolsError::Archive(e.to_string()))?;
        let Some(path) = file.enclosed_name() else { continue };
        let Ok(rest) = path.strip_prefix("platform-tools") else {
            continue;
        };
        if rest.as_os_str().is_empty() {
            continue;
        }
        let target = staging.join(rest);
        if file.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut bytes)?;
        fs::write(&target, bytes)?;
        #[cfg(unix)]
        if let Some(mode) = file.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(mode & 0o777))?;
        }
        if rest == Path::new(EXE) {
            has_adb = true;
        }
    }
    if !has_adb {
        let _ = fs::remove_dir_all(&staging);
        return Err(ToolsError::Archive(format!("no platform-tools/{EXE} inside")));
    }
    let final_dir = dir.join("platform-tools");
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir)?;
    }
    fs::rename(&staging, &final_dir)?;
    Ok(final_dir.join(EXE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
            for (name, data) in files {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("adbdata-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn installs_platform_tools_and_replaces_an_old_copy() {
        let dir = temp_dir("tools");
        fs::create_dir_all(dir.join("platform-tools")).unwrap();
        fs::write(dir.join("platform-tools").join("old.txt"), "old").unwrap();
        let exe = format!("platform-tools/{EXE}");
        let zip = zip_of(&[
            (&exe, b"adb"),
            ("platform-tools/fastboot", b"fb"),
            ("../evil", b"x"),
            ("other/readme", b"r"),
        ]);
        let adb = install(&zip, &dir).unwrap();
        assert_eq!(adb, dir.join("platform-tools").join(EXE));
        assert_eq!(fs::read(&adb).unwrap(), b"adb");
        assert!(dir.join("platform-tools").join("fastboot").exists());
        assert!(!dir.join("platform-tools").join("old.txt").exists());
        assert!(!dir.join("evil").exists() && !dir.join("other").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&adb).unwrap().permissions().mode() & 0o777, 0o755);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_an_archive_without_adb_and_keeps_the_old_copy() {
        let dir = temp_dir("tools-bad");
        fs::create_dir_all(dir.join("platform-tools")).unwrap();
        fs::write(dir.join("platform-tools").join(EXE), "old adb").unwrap();
        assert!(matches!(
            install(&zip_of(&[("platform-tools/fastboot", b"fb")]), &dir),
            Err(ToolsError::Archive(_))
        ));
        assert!(matches!(install(b"not a zip", &dir), Err(ToolsError::Archive(_))));
        assert_eq!(fs::read(dir.join("platform-tools").join(EXE)).unwrap(), b"old adb");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn looks_in_the_right_order() {
        let managed = Path::new("/data/app");
        let path_var = std::env::join_paths(["/usr/local/bin", "/opt/tools"]).unwrap();
        let list = candidates(
            Some(Path::new("/custom/adb")),
            managed,
            path_var.to_str(),
            Some(Path::new("/home/me")),
        );
        let sources: Vec<AdbSource> = list.iter().map(|(s, _)| *s).collect();
        assert_eq!(
            sources,
            [
                AdbSource::Custom,
                AdbSource::Managed,
                AdbSource::Path,
                AdbSource::Path,
                AdbSource::Sdk
            ]
        );
        assert_eq!(list[1].1, managed.join("platform-tools").join(EXE));
        assert_eq!(list[2].1, Path::new("/usr/local/bin").join(EXE));
    }
}
