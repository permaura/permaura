//! Credential scrubbing: the value half of response redaction.
//!
//! [`crate::redact`] replaces a field by its name, so a credential an upstream echoes under a name the
//! list does not carry, or quotes inside an error sentence, passes straight through it. A
//! [`CredentialScrub`] is built from the plaintext of the secrets one call injected and replaces every
//! occurrence of them with [`SCRUBBED`], in the forms an upstream plausibly reflects:
//!
//! - the value as stored and trimmed of surrounding whitespace, and its JSON-escaped spelling;
//! - base64 of the value (standard and URL-safe alphabets, padded or not), including the middle of a
//!   longer blob at any byte alignment, and base64 of `<value>:`, which is what HTTP Basic sends when
//!   the key is the username;
//! - the password half of a `user:pass` value, and the decoded `user:pass` of a value that is itself
//!   base64 of one;
//! - each base64 line of a PEM-armored key, so a key echoed with different line breaks still matches;
//! - any percent-encoding of all of the above, matched on a decoded view of the text so it does not
//!   matter which bytes the upstream chose to escape, or whether it wrote `+` for a space.
//!
//! A value shorter than [`MIN_SECRET_LEN`] bytes is never scrubbed: a short secret is a substring of
//! ordinary text often enough that replacing it would corrupt responses, and the name-based redaction
//! still applies to it.
//!
//! Cost: linear in the text. Each string is read once, testing the 8-byte window at every position
//! against a 64 Kbit filter of needle prefixes; only on a filter hit are the prefixes compared, and a
//! needle is compared in full only where its first eight bytes are present. For a needle whose first
//! eight bytes do not recur inside it (any credential with real entropy) two such comparisons overlap
//! by fewer than eight bytes, so they add at most nine reads per text byte; a needle whose prefix does
//! recur gets its own KMP pass instead. A string containing `%` is read once more as a percent-decoded
//! copy, and once more with `+` read as a space when some needle contains a space. The bound is
//! therefore three passes of O(text length x needles), with at most [`MAX_NEEDLES`] needles, and in
//! practice one filter probe per byte; [`CredentialScrub::scrub_truncated`] adds O(total needle
//! length) per string.

use std::borrow::Cow;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::engine::GeneralPurpose;
use base64::Engine as _;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

/// The placeholder substituted for an occurrence of an injected credential.
pub const SCRUBBED: &str = "[redacted-credential]";

/// The shortest value, in bytes after trimming, that is scrubbed by value.
pub const MIN_SECRET_LEN: usize = 8;

/// The most needles one scrub keeps. Comfortably above what a call produces (an OAuth bundle with a
/// refreshed token is four secrets, about fifteen needles each), so it only bites on a key with an
/// unusual number of PEM lines, whose first lines are kept.
pub const MAX_NEEDLES: usize = 256;

const FILTER_BITS: usize = 1 << 16;

/// The literal plaintexts of the secrets one call injected, and the encodings of them that are removed
/// from anything the call hands back. Never prints its contents; zeroes them on drop.
pub struct CredentialScrub {
    needles: Vec<Zeroizing<Vec<u8>>>,
    /// The first eight bytes of each needle as the scan reads them, index-aligned with `needles`.
    prefixes: Vec<u64>,
    /// The KMP table of each needle whose first eight bytes recur inside it, index-aligned with
    /// `needles`; such a needle is searched by its own pass so the prefix scan stays linear.
    recurring: Vec<Option<Zeroizing<Vec<usize>>>>,
    filter: Vec<u64>,
    /// Whether any needle contains a space, which makes a `+`-as-space reading of the text worth doing.
    space: bool,
    /// Whether any needle is all digits, which makes a JSON number worth reading as text.
    numeric: bool,
}

impl std::fmt::Debug for CredentialScrub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialScrub").field("needles", &self.needles.len()).finish()
    }
}

impl Drop for CredentialScrub {
    fn drop(&mut self) {
        self.prefixes.zeroize();
        self.filter.zeroize();
    }
}

impl Default for CredentialScrub {
    fn default() -> Self {
        CredentialScrub::new()
    }
}

impl CredentialScrub {
    /// A scrub that removes nothing until a secret is added.
    pub fn new() -> Self {
        CredentialScrub {
            needles: Vec::new(),
            // Each entry is a needle's first eight bytes, so the table is sized once and never outgrows a block it would free unwiped.
            prefixes: Vec::with_capacity(MAX_NEEDLES),
            recurring: Vec::new(),
            filter: vec![0; FILTER_BITS / 64],
            space: false,
            numeric: false,
        }
    }

    /// True when no secret long enough to scrub has been added.
    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// Whether a JSON number is read as text by [`Self::scrub_value`]: some needle is all digits.
    pub fn scrubs_numbers(&self) -> bool {
        self.numeric && !self.needles.is_empty()
    }

    /// Add one injected secret, with every encoding of it this module removes.
    pub fn add_secret(&mut self, secret: &[u8]) {
        let text = crate::secret::SecretString::from_utf8_lossy(secret);
        let text = text.expose();
        self.add_value(text);
        if let Some(pair) = decoded_basic_pair(text.trim()) {
            self.add_value(&pair);
        }
        if text.contains("-----BEGIN ") {
            for line in text.lines().map(str::trim) {
                let armored = line.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b));
                if armored && !line.starts_with("-----") {
                    self.push(line.as_bytes());
                }
            }
        }
    }

    fn add_value(&mut self, value: &str) {
        let mut forms = vec![value];
        if value.trim() != value {
            forms.push(value.trim());
        }
        for form in forms {
            if form.trim().len() < MIN_SECRET_LEN {
                continue;
            }
            self.push(form.as_bytes());
            // Every form below is built in a wiped buffer that never outgrows itself, so building the
            // needles leaves no copy of the secret behind.
            let json = crate::secret::to_json(form).unwrap_or_default();
            let escaped = json.get(1..json.len().saturating_sub(1)).unwrap_or_default();
            self.push(escaped);
            let slashes = escaped.iter().filter(|b| **b == b'/').count();
            if slashes > 0 {
                let mut spelled = Zeroizing::new(Vec::with_capacity(escaped.len() + slashes));
                for &b in escaped {
                    if b == b'/' {
                        spelled.push(b'\\');
                    }
                    spelled.push(b);
                }
                self.push(&spelled);
            }
            let mut with_colon = Zeroizing::new(String::with_capacity(form.len() + 1));
            with_colon.push_str(form);
            with_colon.push(':');
            for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
                self.push(Zeroizing::new(engine.encode(form)).as_bytes());
                self.push(Zeroizing::new(engine.encode(with_colon.as_bytes())).as_bytes());
                for offset in 0..3 {
                    self.push(&base64_core(engine, form.as_bytes(), offset));
                }
            }
            if let Some((_, password)) = form.split_once(':') {
                self.push(password.trim().as_bytes());
            }
        }
    }

    fn push(&mut self, needle: &[u8]) {
        if needle.len() < MIN_SECRET_LEN
            || self.needles.len() >= MAX_NEEDLES
            || self.needles.iter().any(|n| n.as_slice() == needle)
        {
            return;
        }
        let prefix = window(needle, 0);
        let bit = filter_bit(prefix);
        self.filter[bit / 64] |= 1 << (bit % 64);
        self.prefixes.push(prefix);
        let recurs = (1..=needle.len() - 8).any(|at| needle[at..at + 8] == needle[..8]);
        self.recurring.push(recurs.then(|| failure_table(needle)));
        self.space |= needle.contains(&b' ');
        self.numeric |= needle.iter().all(u8::is_ascii_digit);
        self.needles.push(Zeroizing::new(needle.to_vec()));
    }

    /// `text` with every occurrence of a needle replaced by [`SCRUBBED`]; borrowed when nothing matched.
    pub fn scrub_str<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if self.needles.is_empty() || text.len() < MIN_SECRET_LEN {
            return Cow::Borrowed(text);
        }
        let bytes = text.as_bytes();
        let mut spans = Vec::new();
        self.find(bytes, &mut spans);
        if bytes.contains(&b'%') {
            self.find_decoded(bytes, false, &mut spans);
        }
        if self.space && bytes.contains(&b'+') {
            self.find_decoded(bytes, true, &mut spans);
        }
        if spans.is_empty() {
            return Cow::Borrowed(text);
        }
        Cow::Owned(replace_spans(text, spans))
    }

    /// [`Self::scrub_str`] for text that may have been cut short before it got here (a capped header
    /// value or error body): a tail that is the first [`MIN_SECRET_LEN`] or more bytes of a needle is
    /// replaced too, because the cut can fall inside the credential.
    pub fn scrub_truncated<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let scrubbed = self.scrub_str(text);
        let bytes = scrubbed.as_bytes();
        let longest_tail = self.needles.iter().map(|needle| tail_overlap(bytes, needle)).max();
        let Some(tail) = longest_tail.filter(|&k| k >= MIN_SECRET_LEN) else { return scrubbed };
        let mut cut = bytes.len() - tail;
        while !scrubbed.is_char_boundary(cut) {
            cut -= 1;
        }
        Cow::Owned(format!("{}{SCRUBBED}", &scrubbed[..cut]))
    }

    /// Scrub every string, object key and (when a needle is all digits) number in `value`, in place.
    pub fn scrub_value(&self, value: &mut Value) {
        if self.needles.is_empty() {
            return;
        }
        match value {
            Value::String(text) => {
                if let Cow::Owned(clean) = self.scrub_str(text) {
                    *text = clean;
                }
            }
            Value::Number(number) => {
                if self.numeric {
                    let text = number.to_string();
                    if let Cow::Owned(clean) = self.scrub_str(&text) {
                        *value = Value::String(clean);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|item| self.scrub_value(item)),
            Value::Object(map) => {
                if map.keys().any(|key| matches!(self.scrub_str(key), Cow::Owned(_))) {
                    for (key, mut child) in std::mem::take(map) {
                        self.scrub_value(&mut child);
                        map.insert(self.scrub_str(&key).into_owned(), child);
                    }
                } else {
                    map.values_mut().for_each(|child| self.scrub_value(child));
                }
            }
            Value::Bool(_) | Value::Null => {}
        }
    }

    fn find(&self, hay: &[u8], spans: &mut Vec<(usize, usize)>) {
        if hay.len() < MIN_SECRET_LEN {
            return;
        }
        for at in 0..=hay.len() - MIN_SECRET_LEN {
            let w = window(hay, at);
            let bit = filter_bit(w);
            if self.filter[bit / 64] & (1 << (bit % 64)) == 0 {
                continue;
            }
            for ((needle, prefix), recurring) in self.needles.iter().zip(&self.prefixes).zip(&self.recurring) {
                if *prefix == w && recurring.is_none() && hay[at..].starts_with(needle) {
                    spans.push((at, at + needle.len()));
                }
            }
        }
        for (needle, table) in self.needles.iter().zip(&self.recurring) {
            if let Some(table) = table {
                find_recurring(hay, needle, table, spans);
            }
        }
    }

    /// Search a percent-decoded copy of `hay` and report the matches as spans of `hay` itself.
    fn find_decoded(&self, hay: &[u8], plus_is_space: bool, spans: &mut Vec<(usize, usize)>) {
        let mut decoded = Zeroizing::new(Vec::with_capacity(hay.len()));
        let mut origin = Vec::with_capacity(hay.len());
        let mut at = 0;
        while at < hay.len() {
            origin.push(at);
            let escaped = (hay[at] == b'%')
                .then(|| Some((hex(*hay.get(at + 1)?)? << 4) | hex(*hay.get(at + 2)?)?))
                .flatten();
            match escaped {
                Some(byte) => {
                    decoded.push(byte);
                    at += 3;
                }
                None => {
                    decoded.push(if plus_is_space && hay[at] == b'+' { b' ' } else { hay[at] });
                    at += 1;
                }
            }
        }
        let mut found = Vec::new();
        self.find(&decoded, &mut found);
        spans.extend(
            found
                .into_iter()
                .map(|(start, end)| (origin[start], origin.get(end).copied().unwrap_or(hay.len()))),
        );
    }
}

fn window(bytes: &[u8], at: usize) -> u64 {
    let mut eight = [0u8; 8];
    eight.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(eight)
}

fn filter_bit(window: u64) -> usize {
    (window.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 48) as usize
}

/// The KMP failure table of `needle`: entry `i` is the length of the longest proper prefix of
/// `needle[..=i]` that is also a suffix of it.
fn failure_table(needle: &[u8]) -> Zeroizing<Vec<usize>> {
    let mut table = Zeroizing::new(vec![0usize; needle.len()]);
    let mut k = 0;
    for i in 1..needle.len() {
        while k > 0 && needle[i] != needle[k] {
            k = table[k - 1];
        }
        if needle[i] == needle[k] {
            k += 1;
        }
        table[i] = k;
    }
    table
}

/// Every occurrence of `needle` in `hay`, overlapping ones included, in one linear pass.
fn find_recurring(hay: &[u8], needle: &[u8], table: &[usize], spans: &mut Vec<(usize, usize)>) {
    let mut k = 0;
    for (at, &byte) in hay.iter().enumerate() {
        while k > 0 && needle[k] != byte {
            k = table[k - 1];
        }
        if needle[k] == byte {
            k += 1;
        }
        if k == needle.len() {
            spans.push((at + 1 - k, at + 1));
            k = table[k - 1];
        }
    }
}

/// The length of the longest proper prefix of `needle` that `text` ends with, in O(needle length).
fn tail_overlap(text: &[u8], needle: &[u8]) -> usize {
    let table = failure_table(needle);
    let mut k = 0;
    for &byte in &text[text.len().saturating_sub(needle.len() - 1)..] {
        while k > 0 && needle[k] != byte {
            k = table[k - 1];
        }
        if needle[k] == byte {
            k += 1;
        }
    }
    k
}

fn hex(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|d| d as u8)
}

/// The base64 characters that encode `bytes` alone when they sit `offset` bytes into a 3-byte group of
/// a longer encoded blob: the characters that mix in a neighboring byte's bits are dropped.
fn base64_core(engine: &GeneralPurpose, bytes: &[u8], offset: usize) -> Zeroizing<Vec<u8>> {
    let mut shifted = Zeroizing::new(vec![0u8; offset]);
    shifted.extend_from_slice(bytes);
    let encoded = Zeroizing::new(engine.encode(shifted.as_slice()));
    let skip = [0, 2, 3][offset];
    let whole = shifted.len() * 8 / 6;
    Zeroizing::new(encoded.as_bytes()[skip..whole].to_vec())
}

/// The `user:pass` a value decodes to when it is itself the base64 a Basic header carries.
fn decoded_basic_pair(value: &str) -> Option<Zeroizing<String>> {
    // Decoded into a wiped buffer on every path: a value that is base64 of a binary key decodes to the key itself.
    let mut bytes = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(value.len())]);
    let written = STANDARD
        .decode_slice(value, &mut bytes)
        .or_else(|_| STANDARD_NO_PAD.decode_slice(value, &mut bytes))
        .ok()?;
    let text = std::str::from_utf8(&bytes[..written]).ok()?;
    let mut pair = Zeroizing::new(String::with_capacity(text.len()));
    pair.push_str(text);
    let printable = pair.chars().all(|c| !c.is_control());
    (printable && pair.contains(':') && pair.len() >= MIN_SECRET_LEN).then_some(pair)
}

/// `text` with each span replaced by one [`SCRUBBED`], overlapping and adjacent spans merged and each
/// widened to whole characters.
fn replace_spans(text: &str, mut spans: Vec<(usize, usize)>) -> String {
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut current: Option<(usize, usize)> = None;
    for (start, end) in spans {
        match current {
            Some((s, e)) if start <= e => current = Some((s, e.max(end))),
            _ => {
                if let Some((s, e)) = current.take() {
                    copied = emit(text, &mut out, copied, s, e);
                }
                current = Some((start, end));
            }
        }
    }
    if let Some((s, e)) = current {
        copied = emit(text, &mut out, copied, s, e);
    }
    out.push_str(&text[copied..]);
    out
}

fn emit(text: &str, out: &mut String, copied: usize, mut start: usize, mut end: usize) -> usize {
    start = start.max(copied);
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    out.push_str(&text[copied..start.max(copied)]);
    out.push_str(SCRUBBED);
    end.max(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "sk_test_Zx9fQ2vLm7RtA4pW";

    fn scrub() -> CredentialScrub {
        let mut s = CredentialScrub::new();
        s.add_secret(SECRET.as_bytes());
        s
    }

    fn clean(text: &str) -> String {
        scrub().scrub_str(text).into_owned()
    }

    #[test]
    fn the_raw_value_is_replaced_wherever_it_sits() {
        assert_eq!(clean(&format!("invalid key {SECRET} supplied")), format!("invalid key {SCRUBBED} supplied"));
        assert_eq!(clean(SECRET), SCRUBBED);
        assert_eq!(clean(&format!("{SECRET}{SECRET}")), SCRUBBED, "adjacent occurrences merge into one marker");
    }

    #[test]
    fn base64_forms_are_replaced_including_the_middle_of_a_longer_blob() {
        assert!(!clean(&STANDARD.encode(SECRET)).contains(&STANDARD_NO_PAD.encode(SECRET)));
        assert!(clean(&format!("Basic {}", STANDARD.encode(format!("{SECRET}:")))).starts_with(&format!("Basic {SCRUBBED}")));
        for prefix in ["", "a", "ab", "Authorization: Bearer "] {
            let blob = STANDARD.encode(format!("{prefix}{SECRET} trailing bytes"));
            let out = clean(&blob);
            assert!(out.contains(SCRUBBED), "offset {} of {prefix:?}", prefix.len() % 3);
            let core = base64_core(&STANDARD_NO_PAD, SECRET.as_bytes(), prefix.len() % 3);
            assert!(!out.contains(std::str::from_utf8(&core).unwrap()));
        }
        let url_safe = URL_SAFE_NO_PAD.encode(format!("{SECRET}??>>"));
        assert!(clean(&url_safe).contains(SCRUBBED));
    }

    #[test]
    fn percent_encodings_are_replaced_whichever_bytes_were_escaped() {
        let every: String = SECRET.bytes().map(|b| format!("%{b:02X}")).collect();
        let lower: String = SECRET.bytes().map(|b| format!("%{b:02x}")).collect();
        let partial = SECRET.replace('_', "%5F");
        for encoded in [every, lower, partial] {
            let out = clean(&format!("https://api.example.test/next?api_key={encoded}&page=2"));
            assert_eq!(out, format!("https://api.example.test/next?api_key={SCRUBBED}&page=2"));
        }
    }

    #[test]
    fn a_secret_with_spaces_is_replaced_in_its_form_encoding() {
        let mut s = CredentialScrub::new();
        s.add_secret(b"abcd efgh ijkl mnop");
        assert_eq!(s.scrub_str("password=abcd+efgh+ijkl+mnop&x=1"), format!("password={SCRUBBED}&x=1"));
    }

    #[test]
    fn surrounding_whitespace_on_the_stored_value_does_not_hide_it() {
        let mut s = CredentialScrub::new();
        s.add_secret(format!("  {SECRET}\n").as_bytes());
        assert_eq!(s.scrub_str(&format!("got {SECRET}.")), format!("got {SCRUBBED}."));
    }

    #[test]
    fn the_halves_of_a_basic_pair_are_covered() {
        let mut s = CredentialScrub::new();
        s.add_secret(b"public_id:priv_Qw8eR5tY2u");
        assert_eq!(s.scrub_str("key priv_Qw8eR5tY2u rejected"), format!("key {SCRUBBED} rejected"));
        assert_eq!(s.scrub_str("user public_id"), "user public_id", "the username alone is not the secret");

        let mut s = CredentialScrub::new();
        s.add_secret(STANDARD.encode("public_id:priv_Qw8eR5tY2u").as_bytes());
        assert_eq!(s.scrub_str("decoded public_id:priv_Qw8eR5tY2u"), format!("decoded {SCRUBBED}"));
    }

    #[test]
    fn json_values_keys_and_numbers_are_scrubbed() {
        let mut s = CredentialScrub::new();
        s.add_secret(SECRET.as_bytes());
        s.add_secret(b"4111222233334444");
        let mut v = json!({
            "a": { "b": [ format!("x {SECRET}") ] },
            SECRET: 1,
            "n": 4111222233334444u64,
            "keep": "ordinary",
            "count": 3
        });
        s.scrub_value(&mut v);
        assert_eq!(v["a"]["b"][0], format!("x {SCRUBBED}"));
        assert_eq!(v[SCRUBBED], 1);
        assert_eq!(v["n"], SCRUBBED);
        assert_eq!(v["keep"], "ordinary");
        assert_eq!(v["count"], 3);
        assert!(!v.to_string().contains(SECRET));
    }

    #[test]
    fn a_short_secret_is_never_scrubbed() {
        let mut s = CredentialScrub::new();
        s.add_secret(b"abc123");
        assert!(s.is_empty());
        assert_eq!(s.scrub_str("abc123abc123"), "abc123abc123");
    }

    #[test]
    fn a_short_common_substring_of_the_secret_is_left_alone() {
        let text = "keys look like sk_test_ and the docs say Zx9fQ2v is fine; sk_test_Zx9f";
        assert_eq!(clean(text), text);
        let mut v = json!({ "prefix": "sk_test_", "id": "Zx9fQ2vL" });
        let before = v.clone();
        scrub().scrub_value(&mut v);
        assert_eq!(v, before);
    }

    #[test]
    fn a_tail_cut_inside_the_secret_is_replaced_only_where_text_may_be_truncated() {
        let cut = format!("token={}", &SECRET[..12]);
        assert_eq!(scrub().scrub_truncated(&cut), format!("token={SCRUBBED}"));
        assert_eq!(clean(&cut), cut, "scrub_str does not guess at truncation");
        let short = format!("token={}", &SECRET[..7]);
        assert_eq!(scrub().scrub_truncated(&short), short);
    }

    #[test]
    fn pem_lines_are_covered_individually() {
        let mut s = CredentialScrub::new();
        s.add_secret(b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nQUJDREVGR0hJSktMTU5PUA==\n-----END OPENSSH PRIVATE KEY-----\n");
        assert_eq!(s.scrub_str("line: QUJDREVGR0hJSktMTU5PUA=="), format!("line: {SCRUBBED}"));
        assert_eq!(s.scrub_str("-----BEGIN OPENSSH PRIVATE KEY-----"), "-----BEGIN OPENSSH PRIVATE KEY-----");
    }

    #[test]
    fn multibyte_text_around_a_match_stays_valid() {
        let text = format!("é{SECRET}ü and 😀");
        assert_eq!(clean(&text), format!("é{SCRUBBED}ü and 😀"));
        let encoded: String = SECRET.bytes().map(|b| format!("%{b:02X}")).collect();
        assert_eq!(clean(&format!("ü%C3{encoded}é")), format!("ü%C3{SCRUBBED}é"));
    }

    #[test]
    fn a_large_ordinary_body_is_scanned_without_change() {
        let body = "lorem ipsum %20 dolor + sit amet ".repeat(200_000);
        let started = std::time::Instant::now();
        assert!(matches!(scrub().scrub_str(&body), Cow::Borrowed(_)));
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[test]
    fn a_secret_that_repeats_itself_is_found_in_overlapping_text_in_linear_time() {
        let mut s = CredentialScrub::new();
        s.add_secret(b"abcdabcdabcdabcd");
        assert_eq!(s.scrub_str("x abcdabcdabcdabcdabcd y"), format!("x {SCRUBBED} y"));
        assert_eq!(s.scrub_str("abcdabcdabcdabc"), "abcdabcdabcdabc");

        let mut long = CredentialScrub::new();
        long.add_secret("a".repeat(4096).as_bytes());
        let near_misses = format!("{}b", "a".repeat(4095)).repeat(256);
        let started = std::time::Instant::now();
        assert!(matches!(long.scrub_str(&near_misses), Cow::Borrowed(_)));
        assert_eq!(long.scrub_truncated(&format!("x{}", "a".repeat(4095))), format!("x{SCRUBBED}"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[test]
    fn debug_never_prints_a_needle() {
        assert!(!format!("{:?}", scrub()).contains("sk_test"));
    }
}
