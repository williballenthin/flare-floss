//! Finding strings in bytes, and filtering out junk.
//!
//! This is a port of FLOSS's `strings.py` and the false-positive filters
//! in `utils.py`, so that the strings found in emulated memory match FLOSS's.
use std::sync::OnceLock;

use regex::{bytes::Regex as BytesRegex, Regex};
use serde::Serialize;

pub const MIN_LENGTH: usize = 4;
pub const MAX_STRING_LENGTH: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Encoding {
    #[serde(rename = "ASCII")]
    Ascii,
    #[serde(rename = "UTF-16LE")]
    Utf16Le,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundString {
    pub string:   String,
    /// offset into the buffer.
    pub offset:   usize,
    /// bytes in the buffer, before any junk was stripped from the string.
    pub len:      usize,
    pub encoding: Encoding,
}

fn ascii_re() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(r"(?-u)[\x20-\x7E\t]{4,}").unwrap())
}

fn utf16_re() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(r"(?-u)(?:[\x20-\x7E\t]\x00){4,}").unwrap())
}

/// a buffer of nothing but one of these bytes has no strings.
const REPEATS: [u8; 4] = [b'A', 0x00, 0xFE, 0xFF];

/// Find ASCII and UTF-16LE strings of at least 4 characters, ASCII first.
pub fn extract_ascii_utf16(buf: &[u8]) -> Vec<FoundString> {
    if buf.is_empty() || (REPEATS.contains(&buf[0]) && buf.iter().all(|&b| b == buf[0])) {
        return vec![];
    }

    let ascii = ascii_re().find_iter(buf).map(|m| FoundString {
        string:   String::from_utf8_lossy(m.as_bytes()).to_string(),
        offset:   m.start(),
        len:      m.len(),
        encoding: Encoding::Ascii,
    });

    let utf16 = utf16_re().find_iter(buf).map(|m| FoundString {
        string:   m.as_bytes().iter().step_by(2).map(|&b| b as char).collect(),
        offset:   m.start(),
        len:      m.len(),
        encoding: Encoding::Utf16Le,
    });

    ascii.chain(utf16).collect()
}

/// strings that show up a lot but aren't interesting,
/// mostly from the Microsoft C runtime.
const FP_STRINGS: &[&str] = &[
    "R6002",
    "R6016",
    "R6030",
    "Program: ",
    "Runtime Error!",
    "bad locale name",
    "ios_base::badbit set",
    "ios_base::eofbit set",
    "ios_base::failbit set",
    "- CRT not initialized",
    "program name unknown>",
    "<program name unknown>",
    "- floating point not loaded",
    "Program: <program name unknown>",
    "- not enough space for thread data",
    // all printable ASCII chars
    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
];

/// strings that the emulator itself creates:
/// the module filename from the GetModuleFileName model (possibly within a longer message),
/// and the fill byte for uninitialized memory, 0xFE, formatted as text.
fn is_floss_artifact(s: &str) -> bool {
    const MOD_NAME: &str = "c:\\users\\flare\\program.exe";
    let lower = s.to_lowercase();
    // the part of the module filename that a real string wouldn't contain.
    let distinctive = MOD_NAME.find("flare").unwrap()..MOD_NAME.find(".exe").unwrap();
    lower.contains("\\flare\\program.exe")
        // a piece of the module filename, like "rogram.exe", but not "C:\\Users".
        || (lower.len() >= 4
            && MOD_NAME
                .match_indices(lower.as_str())
                .any(|(i, m)| i < distinctive.end && distinctive.start < i + m.len()))
        || lower.contains("fefefefe")
        || lower.contains("fe fe fe fe")
        // 0xFEFEFEFE as signed and unsigned decimal
        || s.contains("16843010")
        || s.contains("4278124286")
}

struct Filters {
    /// removed from every string, in order.
    general: Vec<Regex>,
    /// short strings that match this are kept as-is.
    strict_include: Regex,
    /// removed from short strings, in order.
    strict: Vec<Regex>,
}

fn filters() -> &'static Filters {
    static FILTERS: OnceLock<Filters> = OnceLock::new();
    FILTERS.get_or_init(|| Filters {
        general: [
            // FP string starts: pVA, VA, 0VA, ..VA
            r"^.{0,2}[0pP]?[\]\^\[_\\V]A",
            // FP string ends
            r"[0pP]?[VWU][A@]$|Tp$",
            // (the repeated-character filters are in `strip_repeats`)
            // AaaAaAAaAAAaaAA-LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32
            r"[aA]*-LIBGCCW32-.*-GTHR-MINGW32",
            // aeriedjD#shasj
            r"(aeriedjD#shasj)+",
            // fatal error:
            r".*fatal error: .*",
            // lAll0Y
            r"^lAll",
        ]
        .iter()
        .map(|re| Regex::new(re).unwrap())
        .collect(),
        // e.g. [ESC], [Alt], %d.dll
        strict_include: Regex::new(r"^(?:\[.*?\]$|%[sd])").unwrap(),
        strict: [r"^O.*A$", r"[^A-Za-z0-9.]"]
            .iter()
            .map(|re| Regex::new(re).unwrap())
            .collect(),
    })
}

/// be stricter removing junk from short strings.
const MAX_STRING_LENGTH_FILTER_STRICT: usize = 6;

/// remove runs of the same printable character, four or more times (`([ -~])\1{3,}`),
/// then runs of the same four characters, five or more times (`([^% ]{4})\1{4,}`).
/// (Rust's regex crate doesn't do backreferences.)
fn strip_repeats(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();

    let mut once: Vec<char> = vec![];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let run = chars[i..].iter().take_while(|&&d| d == c).count();
        if (' '..='~').contains(&c) && run >= 4 {
            i += run;
        } else {
            once.push(c);
            i += 1;
        }
    }

    let mut out = String::new();
    let mut i = 0;
    while i < once.len() {
        if i + 4 <= once.len() && once[i..i + 4].iter().all(|&c| c != '%' && c != ' ') {
            let unit = &once[i..i + 4];
            let mut repeats = 1;
            while i + 4 * (repeats + 1) <= once.len() && &once[i + 4 * repeats..i + 4 * (repeats + 1)] == unit {
                repeats += 1;
            }
            if repeats >= 5 {
                i += 4 * repeats;
                continue;
            }
        }
        out.push(once[i]);
        i += 1;
    }
    out
}

/// Remove junk that commonly surrounds real strings in memory,
/// like fragments of instructions or pointers.
/// This is FLOSS's `strip_string`.
pub fn strip_string(s: &str) -> String {
    let filters = filters();
    let mut s = s.to_string();
    for (i, re) in filters.general.iter().enumerate() {
        s = re.replace_all(&s, "").to_string();
        // the repeated-character filters come after the prefix and suffix filters.
        if i == 1 {
            s = strip_repeats(&s);
        }
    }

    if s.len() <= MAX_STRING_LENGTH_FILTER_STRICT && !filters.strict_include.is_match(&s) {
        for re in filters.strict.iter() {
            s = re.replace_all(&s, "").to_string();
        }
    }
    s
}

/// Find the interesting strings in a buffer from emulated memory,
/// skipping strings in `exclude`. This is FLOSS's `extract_strings`.
pub fn extract_strings(
    buf: &[u8],
    min_length: usize,
    exclude: &std::collections::HashSet<String>,
) -> Vec<FoundString> {
    if buf.len() < min_length {
        return vec![];
    }

    extract_ascii_utf16(buf)
        .into_iter()
        .filter_map(|s| clean(s, min_length, exclude))
        .collect()
}

/// drop junk strings, and strip junk from the rest, like FLOSS.
fn clean(s: FoundString, min_length: usize, exclude: &std::collections::HashSet<String>) -> Option<FoundString> {
    if s.string.len() > MAX_STRING_LENGTH || FP_STRINGS.contains(&s.string.as_str()) || is_floss_artifact(&s.string) {
        return None;
    }
    let stripped = strip_string(&s.string);
    if stripped.len() < min_length || exclude.contains(&stripped) {
        None
    } else {
        Some(FoundString { string: stripped, ..s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // see also `tests/strings.rs`, which compares against Python FLOSS.

    #[test]
    fn test_extract() {
        let buf = b"\x00\x00hello world\x00h\x00i\x00 \x00t\x00h\x00e\x00r\x00e\x00\x00\x00";
        let found = extract_ascii_utf16(buf);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].string, "hello world");
        assert_eq!(found[0].offset, 2);
        // the trailing "d\0" of "world" looks like a UTF-16 character, too.
        assert_eq!(found[1].string, "dhi there");
        assert_eq!(found[1].encoding, Encoding::Utf16Le);
    }

    #[test]
    fn test_artifacts() {
        assert!(is_floss_artifact("Program: C:\\Users\\flare\\program.exe"));
        assert!(is_floss_artifact("rogram.exe"));
        assert!(is_floss_artifact("C:\\Users\\flare\\"));
        assert!(is_floss_artifact("fefefefe"));
        assert!(!is_floss_artifact("C:\\Users"));
        assert!(!is_floss_artifact(".exe"));
    }

    #[test]
    fn test_strip() {
        assert_eq!(strip_string("hello world"), "hello world");
        assert_eq!(strip_string("pVAhello"), "hello");
        assert_eq!(strip_string("helloAAAAAworld"), "helloworld");
        assert_eq!(strip_string("ab/v7+/v7+/v7+/v7+/v7+cd"), "abcd");
        assert_eq!(strip_string("%d.dll"), "%d.dll");
        assert_eq!(strip_string("[ESC]"), "[ESC]");
        assert_eq!(strip_string("a-b!c"), "abc");
    }
}

/// how far around a change to look for the rest of a string that it touches.
const CONTEXT: u64 = 1024;

/// A string that some code wrote.
#[derive(Debug, Clone)]
pub struct Written {
    /// where the string is.
    pub va:      u64,
    pub string:  FoundString,
    /// the part of the string that changed, from its first changed character to its last:
    /// where it is, and its text.
    pub changed: (u64, String),
}

/// Find the strings that some code wrote: the strings in `after` that overlap the bytes
/// that changed since `before`.
///
/// FLOSS extracts strings from just the bytes that changed. But code may leave
/// some bytes as they were: the zero high bytes of UTF-16 characters written to a zeroed
/// buffer, or characters that are the same in the ciphertext and plaintext, like the
/// first and last characters of a string decoded in place. So report the whole strings
/// in memory that overlap the changes.
///
/// `changes` (from `MemoryView::changes_since`) say where to look.
pub fn strings_touching(
    before: &crate::emu::MemoryView,
    after: &crate::emu::MemoryView,
    changes: &[crate::emu::snapshot::Change],
    min_length: usize,
    exclude: &std::collections::HashSet<String>,
) -> Vec<Written> {
    let mut found = vec![];
    // look at nearby changes together, since a string may span several of them,
    // like a UTF-16 string written to zeroed memory, which changes every other byte.
    for cluster in changes.chunk_by(|a, b| b.va <= a.va + a.bytes.len() as u64 + CONTEXT) {
        let last = &cluster[cluster.len() - 1];
        let start = cluster[0].va.saturating_sub(CONTEXT);
        let len = (last.va + last.bytes.len() as u64 + CONTEXT - start) as usize;
        let before = before.read(start, len);
        let after = after.read(start, len);

        for s in extract_ascii_utf16(&after) {
            let width = match s.encoding {
                Encoding::Ascii => 1,
                Encoding::Utf16Le => 2,
            };
            let changed =
                |i: usize| (s.offset + i * width..s.offset + (i + 1) * width).any(|j| after[j] != before[j]);
            let n = s.len / width;
            let Some(lo) = (0..n).find(|&i| changed(i)) else {
                continue;
            };
            let hi = (0..n).rfind(|&i| changed(i)).unwrap_or(lo);
            let changed = (
                start + (s.offset + lo * width) as u64,
                s.string.chars().skip(lo).take(hi + 1 - lo).collect(),
            );

            if let Some(s) = clean(s, min_length, exclude) {
                found.push(Written {
                    va: start + s.offset as u64,
                    string: s,
                    changed,
                });
            }
        }
    }
    found
}
