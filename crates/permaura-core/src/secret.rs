//! Holding a decrypted secret without leaving copies of it behind.
//!
//! [`zeroize::Zeroizing`] wipes the buffer it owns when it drops, and nothing else: a `Vec` or `String` that grows moves its bytes to a new block and frees the old one as it was, and serde copies every string it reads into a fresh `String` that nothing wipes. The types here close those gaps for the paths that carry plaintext:
//!
//! - [`SecretString`] is text that is wiped when it drops and renders as `[redacted]` in debug output. Read through serde it is copied once, into a buffer of exactly its length, when the string holds no JSON escape.
//! - [`unescaped`] reads a member that may hold an escape (any multi-line value such as a PEM key, and any answer from a writer that escapes `/` or `+`, as PHP's and .NET's defaults do) from its raw JSON text and unescapes it straight into a wiping buffer, so serde_json's own scratch buffer, which it never wipes, is not used for it.
//! - [`to_json`] and [`WipingBuffer`] write JSON (or any text) into a buffer that wipes each block it outgrows before freeing it, so the whole document is never left behind in pieces.
//! - [`SecretString::from_utf8_lossy`] decodes bytes that may not be UTF-8 into a buffer sized for the worst case up front.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Text holding a secret: wiped when it drops, never printed by `Debug`, and with no `Display`. Its plaintext leaves only through [`SecretString::expose`], [`SecretString::as_bytes`], or `Serialize`, which writes it verbatim for the request bodies and sealed payloads that need it.
#[derive(Clone, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Take ownership of `text`. Its buffer is the one wiped, so the caller keeps no other copy.
    pub fn new(text: String) -> Self {
        SecretString(Zeroizing::new(text))
    }

    /// A copy of `text` in a buffer of exactly its length, so building it frees nothing unwiped.
    pub fn copied(text: &str) -> Self {
        let mut owned = String::with_capacity(text.len());
        owned.push_str(text);
        SecretString::new(owned)
    }

    /// `bytes` as text, invalid sequences replaced by U+FFFD as [`String::from_utf8_lossy`] does, in a buffer sized for
    /// the worst case before anything is written (each replaced byte becomes at most three), so decoding never moves
    /// a partial copy to a block it frees.
    pub fn from_utf8_lossy(bytes: &[u8]) -> Self {
        let mut out = String::with_capacity(bytes.len().saturating_mul(3));
        for chunk in bytes.utf8_chunks() {
            out.push_str(chunk.valid());
            if !chunk.invalid().is_empty() {
                out.push(char::REPLACEMENT_CHARACTER);
            }
        }
        SecretString::new(out)
    }

    /// The text of a JSON string literal (its quotes included, as a [`serde_json::value::RawValue`] holds it),
    /// unescaped into a buffer that never outgrows the literal. `None` for a value without its quotes or with a
    /// malformed escape; it does not reject an unescaped quote or control character inside, so it expects text serde_json
    /// has already read as a string, as a `RawValue` is.
    pub fn from_json_literal(raw: &str) -> Option<Self> {
        let raw = raw.as_bytes();
        let body = raw.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
        let mut out = WipingBuffer::with_capacity(body.len());
        let mut i = 0;
        while i < body.len() {
            if body[i] != b'\\' {
                let start = i;
                while i < body.len() && body[i] != b'\\' {
                    i += 1;
                }
                out.extend_from_slice(&body[start..i]);
                continue;
            }
            let escape = *body.get(i + 1)?;
            i += 2;
            let plain = match escape {
                b'"' => b'"',
                b'\\' => b'\\',
                b'/' => b'/',
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'u' => {
                    let high = hex4(body.get(i..i + 4)?)?;
                    i += 4;
                    let code = match high {
                        0xD800..=0xDBFF => {
                            if body.get(i..i + 2)? != b"\\u" {
                                return None;
                            }
                            let low = hex4(body.get(i + 2..i + 6)?)?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return None;
                            }
                            i += 6;
                            0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                        }
                        0xDC00..=0xDFFF => return None,
                        other => other,
                    };
                    let mut utf8 = [0u8; 4];
                    out.extend_from_slice(char::from_u32(code)?.encode_utf8(&mut utf8).as_bytes());
                    utf8.zeroize();
                    continue;
                }
                _ => return None,
            };
            out.extend_from_slice(&[plain]);
        }
        out.into_secret_string()
    }

    /// The secret, for the one place it is used.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The secret's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The text's buffer as bytes, moved out rather than copied, for a caller that wraps it in a wiping type at once (as [`crate::OpenedSecret`]'s `From` does). What is left behind is empty.
    pub(crate) fn into_bytes_wiped(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0).into_bytes()
    }

    /// Its length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ZeroizeOnDrop for SecretString {}

impl From<String> for SecretString {
    fn from(text: String) -> Self {
        SecretString::new(text)
    }
}

impl From<&str> for SecretString {
    fn from(text: &str) -> Self {
        SecretString::copied(text)
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString([redacted])")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.as_bytes(), other.as_bytes())
    }
}

impl Eq for SecretString {}

impl PartialEq<str> for SecretString {
    fn eq(&self, other: &str) -> bool {
        constant_time_eq(self.as_bytes(), other.as_bytes())
    }
}

impl PartialEq<&str> for SecretString {
    fn eq(&self, other: &&str) -> bool {
        constant_time_eq(self.as_bytes(), other.as_bytes())
    }
}

fn hex4(digits: &[u8]) -> Option<u32> {
    digits.iter().try_fold(0u32, |acc, d| Some(acc * 16 + char::from(*d).to_digit(16)?))
}

/// Read a [`SecretString`] member from its raw JSON text, so an escaped value is unescaped into a wiping buffer
/// rather than through serde_json's scratch buffer: `#[serde(deserialize_with = "permaura_core::secret::unescaped::deserialize")]`,
/// or `#[serde(default, deserialize_with = "permaura_core::secret::unescaped::option")]` for an `Option`, where
/// `null` and an absent member are `None`. It borrows from the input, so it needs a serde_json reader over a slice
/// or a `str` (`from_slice`, `from_str`), which is how every body it is used on is read.
pub mod unescaped {
    use super::SecretString;
    use serde::de::Error as _;
    use serde::Deserialize;

    /// A required string member.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        let raw: &'de serde_json::value::RawValue = Deserialize::deserialize(d)?;
        SecretString::from_json_literal(raw.get()).ok_or_else(|| D::Error::custom("expected a string"))
    }

    /// An optional string member: `null` is `None`.
    pub fn option<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
        let raw: &'de serde_json::value::RawValue = Deserialize::deserialize(d)?;
        if raw.get() == "null" {
            return Ok(None);
        }
        SecretString::from_json_literal(raw.get()).map(Some).ok_or_else(|| D::Error::custom("expected a string or null"))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SecretString;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SecretString, E> {
                Ok(SecretString::copied(v))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<SecretString, E> {
                Ok(SecretString::new(v))
            }
        }
        d.deserialize_string(Visitor)
    }
}

/// A growable byte buffer that wipes every block it outgrows before freeing it, and its last one when it drops. [`std::io::Write`] and [`std::fmt::Write`] both append, so serde_json and `write!` can fill it.
pub struct WipingBuffer(Zeroizing<Vec<u8>>);

impl WipingBuffer {
    /// An empty buffer with room for `capacity` bytes before it first grows.
    pub fn with_capacity(capacity: usize) -> Self {
        WipingBuffer(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    /// Append `bytes`, moving to a larger block (and wiping the one left) only when they do not fit.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(needed.max(self.0.capacity().saturating_mul(2))));
            grown.extend_from_slice(&self.0);
            self.0 = grown;
        }
        self.0.extend_from_slice(bytes);
    }

    /// What has been written.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// The bytes written, still wiped on drop.
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// The bytes written as text. Only text was written by a caller that wrote through [`std::fmt::Write`] or serialized JSON, so a buffer that is not UTF-8 is wiped and refused.
    pub fn into_secret_string(self) -> Option<SecretString> {
        let mut bytes = self.0;
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(text) => Some(SecretString::new(text)),
            Err(e) => {
                e.into_bytes().zeroize();
                None
            }
        }
    }
}

impl std::io::Write for WipingBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Write for WipingBuffer {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// How much of the stack [`clear_stack`] overwrites.
pub const STACK_CLEAR_BYTES: usize = 64 * 1024;

/// Overwrite [`STACK_CLEAR_BYTES`] of the stack below the caller with zeros ([`zeroize::zeroize_stack`]).
///
/// Best effort, as defense in depth. A function that has just returned leaves its locals and the compiler's
/// spills in the dead frames below its caller, and Rust moves a new future or a boxed value by copying a
/// whole frame-sized struct, padding and uninitialized bytes included, so plaintext a parser or a formatter
/// held there can be carried into a heap block that is later freed unwiped. Called right after code that
/// handled plaintext, before the caller makes its next future, this clears those dead frames. It does not
/// reach the caller's own frame or any frame above it (where an optimized build inlines most of those
/// helpers, and so keeps their temporaries), async state already on the heap, registers, or another
/// thread's stack, and that it removed the copy the runtime pin found is established for the unoptimized
/// test build only. Call it only at request-handler depth on a full-size thread, never inside recursion:
/// it takes 64 KiB of stack.
#[inline(always)]
pub fn clear_stack() {
    zeroize::zeroize_stack::<STACK_CLEAR_BYTES>();
}

/// Serialize `value` as JSON into a buffer that leaves no unwiped copy of it behind, however large it grows.
pub fn to_json<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    let mut out = WipingBuffer::with_capacity(256);
    serde_json::to_writer(&mut out, value)?;
    Ok(out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_string_never_prints_and_round_trips_through_json() {
        let s = SecretString::from("hunter2-but-longer");
        assert_eq!(format!("{s:?}"), "SecretString([redacted])");
        let json = to_json(&s).unwrap();
        assert_eq!(&*json, b"\"hunter2-but-longer\"");
        let back: SecretString = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, s);
        assert_eq!(back, "hunter2-but-longer");
        let escaped: SecretString = serde_json::from_str("\"a\\\"b\"").unwrap();
        assert_eq!(escaped.expose(), "a\"b");
    }

    /// The type-level pin: these fail to compile if the field stops being a wiping type, which an empty
    /// `ZeroizeOnDrop` marker could not catch.
    #[allow(dead_code)]
    fn holders_keep_their_plaintext_in_wiping_types<'a>(s: &'a SecretString, w: &'a WipingBuffer) -> (&'a Zeroizing<String>, &'a Zeroizing<Vec<u8>>) {
        (&s.0, &w.0)
    }

    #[test]
    fn a_json_literal_unescapes_as_serde_json_does() {
        for literal in [
            r#""plain""#,
            r#""a\"b\\c\/d\b\f\n\r\t""#,
            r#""café ☃ 😀""#,
            r#""""#,
            r#""zz\/php\/token""#,
        ] {
            let ours = SecretString::from_json_literal(literal).unwrap();
            let theirs: String = serde_json::from_str(literal).unwrap();
            assert_eq!(ours.expose(), theirs, "{literal}");
        }
        for bad in [r#"plain"#, r#""unterminated"#, r#""\q""#, r#""\ud83d""#, r#""\ude00""#, r#""\u12""#, "null", "12"] {
            assert!(SecretString::from_json_literal(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn lossy_decoding_matches_std() {
        for bytes in [&b"plain"[..], b"\xff", b"a\xffb\xfe\xfd", b"\xe2\x82", b"caf\xc3\xa9", b""] {
            assert_eq!(SecretString::from_utf8_lossy(bytes).expose(), String::from_utf8_lossy(bytes), "{bytes:?}");
        }
    }

    #[test]
    fn the_unescaped_helpers_read_members_and_nulls() {
        #[derive(Deserialize)]
        struct Answer {
            #[serde(deserialize_with = "unescaped::deserialize")]
            token: SecretString,
            #[serde(default, deserialize_with = "unescaped::option")]
            refresh: Option<SecretString>,
            #[serde(default, deserialize_with = "unescaped::option")]
            missing: Option<SecretString>,
        }
        let a: Answer = serde_json::from_slice(br#"{"token":"x\/y\n","refresh":null}"#).unwrap();
        assert_eq!(a.token, "x/y\n");
        assert!(a.refresh.is_none() && a.missing.is_none());
        let a: Answer = serde_json::from_str(r#"{"token":"t","refresh":"ré"}"#).unwrap();
        assert_eq!(a.refresh.unwrap(), "ré");
        assert!(serde_json::from_str::<Answer>(r#"{"token":5}"#).is_err());
    }

    #[test]
    fn a_wiping_buffer_keeps_everything_written_across_growth() {
        let mut b = WipingBuffer::with_capacity(1);
        for chunk in ["ab", "cdef", "ghijklmnop", ""] {
            std::io::Write::write_all(&mut b, chunk.as_bytes()).unwrap();
        }
        std::fmt::Write::write_str(&mut b, "qr").unwrap();
        assert_eq!(b.as_slice(), b"abcdefghijklmnopqr");
        assert_eq!(b.into_secret_string().unwrap(), "abcdefghijklmnopqr");
        let mut bad = WipingBuffer::with_capacity(2);
        bad.extend_from_slice(&[0xff, 0xfe]);
        assert!(bad.into_secret_string().is_none());
    }
}
