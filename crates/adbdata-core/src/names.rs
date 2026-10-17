//! Names a phone allows and Windows does not: `Screenshot 12:30.png`, `what?.txt`, `notes.` or
//! `CON.txt`. Each is copied under a name Windows accepts, as close to the original as it can be.

/// Windows refuses these characters in a name.
const FORBIDDEN: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Names Windows keeps for devices, with or without an extension.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT0",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The longest name Windows takes, in UTF-16 units.
const MAX_UNITS: usize = 255;

/// A name Windows accepts: forbidden and control characters become `_`, trailing dots and spaces
/// go, device names get a `_` in front, and a name too long is shortened before its extension.
pub fn windows_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if FORBIDDEN.contains(&c) || (c as u32) < 32 {
                '_'
            } else {
                c
            }
        })
        .collect();
    while out.ends_with(['.', ' ']) {
        out.pop();
    }
    if out.is_empty() {
        return "_".into();
    }
    let stem = out.split('.').next().unwrap_or("").trim_end();
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        out.insert(0, '_');
    }
    shorten(&out, MAX_UNITS)
}

/// Cuts a name to `max` UTF-16 units, keeping its extension when it is short.
fn shorten(name: &str, max: usize) -> String {
    if name.encode_utf16().count() <= max {
        return name.to_string();
    }
    let (stem, ext) = split_ext(name);
    let ext_units = ext.encode_utf16().count();
    let keep_ext = ext_units < 32;
    let budget = if keep_ext { max - ext_units } else { max };
    let mut out = String::new();
    let mut units = 0;
    for c in (if keep_ext { stem } else { name }).chars() {
        let n = c.len_utf16();
        if units + n > budget {
            break;
        }
        out.push(c);
        units += n;
    }
    if keep_ext {
        out.push_str(ext);
    }
    out
}

/// `("IMG_1", ".jpg")`; a name without an extension, or a hidden one, has none.
fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// The `n`th alternative for a name that is taken: `IMG_1 (2).jpg`.
pub fn numbered(name: &str, n: u32) -> String {
    let (stem, ext) = split_ext(name);
    format!("{stem} ({n}){ext}")
}

/// Whether two names are probably the same file on Windows, where case does not count. NTFS
/// compares upper-cased names; the writer still asks the file system, so a rare miss here only
/// costs a number.
pub fn same_on_windows(a: &str, b: &str) -> bool {
    a.to_uppercase() == b.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_stay_as_they_are() {
        for name in [
            "IMG_20240501_123456.jpg",
            "Çalışma Ödevi (son).docx",
            "日本語.txt",
            ".nomedia",
            "a b",
        ] {
            assert_eq!(windows_name(name), name);
        }
    }

    #[test]
    fn forbidden_characters_become_underscores() {
        assert_eq!(windows_name("Screenshot 12:30:01.png"), "Screenshot 12_30_01.png");
        assert_eq!(windows_name("what?*.txt"), "what__.txt");
        assert_eq!(windows_name("a<b>c|d\"e\\f"), "a_b_c_d_e_f");
        assert_eq!(windows_name("tab\there"), "tab_here");
    }

    #[test]
    fn trailing_dots_and_spaces_go() {
        assert_eq!(windows_name("notes."), "notes");
        assert_eq!(windows_name("folder . "), "folder");
        assert_eq!(windows_name("..."), "_");
        assert_eq!(windows_name(""), "_");
    }

    #[test]
    fn device_names_are_kept_away_from() {
        assert_eq!(windows_name("CON"), "_CON");
        assert_eq!(windows_name("con.txt"), "_con.txt");
        assert_eq!(windows_name("Nul.tar.gz"), "_Nul.tar.gz");
        assert_eq!(windows_name("COM1"), "_COM1");
        assert_eq!(windows_name("CONSOLE.txt"), "CONSOLE.txt");
        assert_eq!(windows_name("aux .txt"), "_aux .txt");
    }

    #[test]
    fn long_names_keep_their_extension() {
        let long = format!("{}.jpg", "ğ".repeat(300));
        let short = windows_name(&long);
        assert_eq!(short.encode_utf16().count(), MAX_UNITS);
        assert!(short.ends_with(".jpg"));
        // Characters outside the basic plane take two units and are never cut in half.
        let emoji = "😀".repeat(200);
        let cut = windows_name(&emoji);
        assert!(cut.encode_utf16().count() <= MAX_UNITS);
        assert!(cut.chars().all(|c| c == '😀'));
    }

    #[test]
    fn numbering_goes_before_the_extension() {
        assert_eq!(numbered("IMG_1.jpg", 2), "IMG_1 (2).jpg");
        assert_eq!(numbered("archive.tar.gz", 3), "archive.tar (3).gz");
        assert_eq!(numbered("README", 2), "README (2)");
        assert_eq!(numbered(".nomedia", 2), ".nomedia (2)");
        assert!(same_on_windows("IMG.JPG", "img.jpg"));
        assert!(same_on_windows("ŞARKI.mp3", "şarkı.mp3"));
        assert!(!same_on_windows("a.jpg", "b.jpg"));
    }
}
