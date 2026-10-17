//! What the window shows about a phone: its name, Android version and free storage, read in one
//! shell call.

use crate::wire::{Server, WireError};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneInfo {
    pub serial: String,
    /// "Example Phone 8"; the model alone when the maker is already in it.
    pub name: String,
    pub android: String,
    pub sdk: u32,
    /// Bytes on the shared storage, when the phone tells.
    pub storage_total: Option<u64>,
    pub storage_free: Option<u64>,
    /// Sizes past 4 GiB are reported correctly.
    pub large_files: bool,
}

const COMMAND: &str = "getprop ro.product.manufacturer; getprop ro.product.model; \
                       getprop ro.build.version.release; getprop ro.build.version.sdk; \
                       stat -f -c '%S %b %a' /sdcard";

pub fn read(server: &Server, serial: &str) -> Result<PhoneInfo, WireError> {
    let text = server.shell(serial, COMMAND)?;
    let features = server.features(serial).unwrap_or_default();
    Ok(parse(serial, &text, features.iter().any(|f| f == "ls_v2")))
}

pub fn parse(serial: &str, text: &str, large_files: bool) -> PhoneInfo {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let line = |i: usize| lines.get(i).copied().unwrap_or("");
    let (maker, model) = (line(0), line(1));
    let name = if model.is_empty() {
        serial.to_string()
    } else if maker.is_empty() || model.to_lowercase().starts_with(&maker.to_lowercase()) {
        model.to_string()
    } else {
        // Some makers write themselves in lower case ("example").
        let mut m = maker.chars();
        let maker: String = m
            .next()
            .map(|c| c.to_uppercase().chain(m).collect())
            .unwrap_or_default();
        format!("{maker} {model}")
    };
    let storage: Option<(u64, u64)> = (|| {
        let mut n = line(4).split_whitespace().map(|w| w.parse::<u64>().ok());
        let (block, total, free) = (n.next()??, n.next()??, n.next()??);
        Some((block.checked_mul(total)?, block.checked_mul(free)?))
    })();
    PhoneInfo {
        serial: serial.to_string(),
        name,
        android: line(2).to_string(),
        sdk: line(3).parse().unwrap_or(0),
        storage_total: storage.map(|s| s.0),
        storage_free: storage.map(|s| s.1),
        large_files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_name_version_and_storage() {
        let info = parse("X1", "example\nEX-A525F\n14\n34\n4096 27000000 9000000\n", true);
        assert_eq!(info.name, "Example EX-A525F");
        assert_eq!((info.android.as_str(), info.sdk), ("14", 34));
        assert_eq!(info.storage_total, Some(4096 * 27_000_000));
        assert_eq!(info.storage_free, Some(4096 * 9_000_000));
    }

    #[test]
    fn the_maker_is_not_repeated_and_gaps_are_tolerated() {
        let info = parse("X1", "Example\nExample 13T\n13\n33\nstat: bad -f\n", false);
        assert_eq!(info.name, "Example 13T");
        assert_eq!(info.storage_free, None);
        let bare = parse("SERIAL9", "", false);
        assert_eq!((bare.name.as_str(), bare.sdk), ("SERIAL9", 0));
    }
}
