//! Passes over a JSON document that read it with serde_json's own parser and write it straight back out, without ever building a `serde_json::Value`.
//!
//! The gateway never needs the structure of an upstream body for what it does to it: the credential scrub works on each string, number and key, and redaction works on each member by its key path.
//! Building a tree for that cost about 85 bytes per byte of input for a body of one-key objects, so a 5 MiB response could hold more than a 512 MiB worker. A pass here costs its output and a stack of the keys above the current member.
//!
//! Every pass is driven by serde_json's own `Deserializer`, so it reads the same grammar and numbers as `serde_json::from_slice::<Value>`, and writes scalars with serde_json's own serializer, so a number reads back as it would have through a `Value`.
//! One difference in what is accepted: a member a pass skips unread (a redacted value, a cut container, everything off a lookup's path) goes through serde_json's `IgnoredAny`, which has no nesting limit, so `{"password": <an array 1,000 deep>}` becomes `{"password":"[redacted]"}` where a tree's 128-level limit refused the whole body. What is written out still nests at most 128 levels.
//! What differs from the tree, deliberately: an object's members keep the order they arrived in instead of being sorted, and a key that appears twice is written twice (each one judged by the redaction on its own) instead of keeping only the last.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::io::Write;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize as _;
use serde::ser::{self, Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::ser::{CompactFormatter, Formatter, PrettyFormatter};
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};

use crate::json_text::JsonText;
use crate::redact::{Targets, REDACTED};
use crate::scrub::CredentialScrub;

/// What a pass changes on the way through.
#[derive(Default)]
struct Rules<'a> {
    /// Scrub every string, object key and (when a secret is all digits) number with this.
    scrub: Option<&'a CredentialScrub>,
    /// Replace the value of every member whose key path these match with [`REDACTED`].
    redact: Option<&'a Targets>,
    /// Write every array or object at this depth or deeper (the document itself is depth 0) as `cut_marker`.
    cut_at: Option<usize>,
    cut_marker: &'a str,
    /// Refuse an object whose keys are not strictly ascending, so the output is the canonical form.
    ascending_keys: bool,
}

/// What a pass observed, beside what it wrote.
#[derive(Default)]
struct Seen {
    /// A string, key or number was scrubbed, or a member redacted.
    changed: Cell<bool>,
    /// A container was replaced by the cut marker.
    cut: Cell<bool>,
}

#[derive(Clone, Copy)]
struct Ctx<'a> {
    rules: &'a Rules<'a>,
    seen: &'a Seen,
    /// The lowercased keys of the members enclosing the current value; arrays add nothing.
    path: &'a RefCell<Vec<String>>,
    depth: usize,
}

impl<'a> Ctx<'a> {
    fn child(self) -> Self {
        Ctx { depth: self.depth + 1, ..self }
    }

    fn scrubbed<'s>(&self, text: &'s str) -> Cow<'s, str> {
        let Some(scrub) = self.rules.scrub else { return Cow::Borrowed(text) };
        let out = scrub.scrub_str(text);
        if matches!(out, Cow::Owned(_)) {
            self.seen.changed.set(true);
        }
        out
    }

    /// A number's scrubbed text, when the scrub reads numbers as text and found a secret in this one.
    fn scrubbed_number(&self, number: Number) -> Option<String> {
        let scrub = self.rules.scrub.filter(|s| s.scrubs_numbers())?;
        match scrub.scrub_str(&number.to_string()) {
            Cow::Owned(clean) => {
                self.seen.changed.set(true);
                Some(clean)
            }
            Cow::Borrowed(_) => None,
        }
    }

    fn cuts_here(&self) -> bool {
        self.rules.cut_at.is_some_and(|at| self.depth >= at)
    }
}

fn to_ser<E: ser::Error>(e: impl std::fmt::Display) -> E {
    E::custom(e)
}

fn to_de<E: de::Error>(e: impl std::fmt::Display) -> E {
    E::custom(e)
}

/// A value still in the deserializer, written to whatever serializer it is handed.
struct Transcode<'a, D> {
    de: RefCell<Option<D>>,
    ctx: Ctx<'a>,
}

impl<'a, D> Transcode<'a, D> {
    fn new(de: D, ctx: Ctx<'a>) -> Self {
        Transcode { de: RefCell::new(Some(de)), ctx }
    }
}

impl<'a, 'de, D: Deserializer<'de>> Serialize for Transcode<'a, D> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let de = self.de.borrow_mut().take().ok_or_else(|| to_ser::<S::Error>("a value was written twice"))?;
        de.deserialize_any(Visit { ser: serializer, ctx: self.ctx }).map_err(to_ser)
    }
}

struct Visit<'a, S> {
    ser: S,
    ctx: Ctx<'a>,
}

impl<'a, S: Serializer> Visit<'a, S> {
    fn number<E: de::Error>(self, number: Option<Number>, write: impl FnOnce(S) -> Result<S::Ok, S::Error>) -> Result<S::Ok, E> {
        match number.and_then(|n| self.ctx.scrubbed_number(n)) {
            Some(clean) => self.ser.serialize_str(&clean).map_err(to_de),
            None => write(self.ser).map_err(to_de),
        }
    }
}

impl<'a, 'de, S: Serializer> Visitor<'de> for Visit<'a, S> {
    type Value = S::Ok;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<S::Ok, E> {
        self.ser.serialize_bool(v).map_err(to_de)
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<S::Ok, E> {
        self.number(Some(Number::from(v)), |s| s.serialize_i64(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<S::Ok, E> {
        self.number(Some(Number::from(v)), |s| s.serialize_u64(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<S::Ok, E> {
        self.number(Number::from_f64(v), |s| s.serialize_f64(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<S::Ok, E> {
        let text = self.ctx.scrubbed(v);
        self.ser.serialize_str(&text).map_err(to_de)
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<S::Ok, E> {
        self.visit_str(&v)
    }

    fn visit_unit<E: de::Error>(self) -> Result<S::Ok, E> {
        self.ser.serialize_unit().map_err(to_de)
    }

    fn visit_none<E: de::Error>(self) -> Result<S::Ok, E> {
        self.ser.serialize_unit().map_err(to_de)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<S::Ok, A::Error> {
        if self.ctx.cuts_here() {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            self.ctx.seen.cut.set(true);
            return self.ser.serialize_str(self.ctx.rules.cut_marker).map_err(to_de);
        }
        let mut out = self.ser.serialize_seq(None).map_err(to_de)?;
        while seq.next_element_seed(ElementSeed { out: &mut out, ctx: self.ctx.child() })?.is_some() {}
        out.end().map_err(to_de)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<S::Ok, A::Error> {
        let ctx = self.ctx;
        if ctx.cuts_here() {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            ctx.seen.cut.set(true);
            return self.ser.serialize_str(ctx.rules.cut_marker).map_err(to_de);
        }
        let mut out = self.ser.serialize_map(None).map_err(to_de)?;
        let mut previous: Option<String> = None;
        while let Some(key) = map.next_key_seed(KeySeed)? {
            if ctx.rules.ascending_keys {
                if previous.as_deref().is_some_and(|p| p >= key.as_str()) {
                    return Err(to_de("the object's keys are not in ascending order"));
                }
                previous = Some(key.clone());
            }
            let key = ctx.scrubbed(&key).into_owned();
            out.serialize_key(&key).map_err(to_de)?;
            let Some(targets) = ctx.rules.redact else {
                map.next_value_seed(ValueSeed { out: &mut out, ctx: ctx.child() })?;
                continue;
            };
            ctx.path.borrow_mut().push(key.to_ascii_lowercase());
            let matched = targets.matches(&ctx.path.borrow());
            let written = if matched {
                ctx.seen.changed.set(true);
                map.next_value::<IgnoredAny>().and_then(|_| out.serialize_value(REDACTED).map_err(to_de))
            } else {
                map.next_value_seed(ValueSeed { out: &mut out, ctx: ctx.child() })
            };
            ctx.path.borrow_mut().pop();
            written?;
        }
        out.end().map_err(to_de)
    }
}

struct KeySeed;

impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = String;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        String::deserialize(deserializer)
    }
}

struct ElementSeed<'o, 'a, O> {
    out: &'o mut O,
    ctx: Ctx<'a>,
}

impl<'o, 'a, 'de, O: SerializeSeq> DeserializeSeed<'de> for ElementSeed<'o, 'a, O> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.out.serialize_element(&Transcode::new(deserializer, self.ctx)).map_err(to_de)
    }
}

struct ValueSeed<'o, 'a, O> {
    out: &'o mut O,
    ctx: Ctx<'a>,
}

impl<'o, 'a, 'de, O: SerializeMap> DeserializeSeed<'de> for ValueSeed<'o, 'a, O> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.out.serialize_value(&Transcode::new(deserializer, self.ctx)).map_err(to_de)
    }
}

/// Run one pass over `input`, writing to `out` with `formatter`.
fn run<W: Write, F: Formatter>(input: &[u8], out: W, formatter: F, rules: &Rules<'_>, seen: &Seen) -> Result<W, serde_json::Error> {
    let path = RefCell::new(Vec::new());
    let ctx = Ctx { rules, seen, path: &path, depth: 0 };
    let mut de = serde_json::Deserializer::from_slice(input);
    let mut ser = serde_json::Serializer::with_formatter(out, formatter);
    Transcode::new(&mut de, ctx).serialize(&mut ser)?;
    de.end()?;
    Ok(ser.into_inner())
}

fn into_text(bytes: Vec<u8>) -> JsonText {
    // serde_json's serializer writes UTF-8 only.
    JsonText::from_trusted(String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// What an upstream body becomes before an agent may see it: every string, key and number scrubbed of the call's credential, then every member whose key path `redact_keys` names replaced by [`REDACTED`].
/// The same result `CredentialScrub::scrub_value` followed by `redact` gave on the tree, in the upstream's member order. An error when `input` is not exactly one JSON document, which the caller treats as it treated a body that would not parse: as no document at all.
pub fn agent_view(input: &[u8], scrub: &CredentialScrub, redact_keys: &[String]) -> Result<JsonText, serde_json::Error> {
    let targets = Targets::new(redact_keys);
    let rules = Rules { scrub: Some(scrub), redact: Some(&targets), ..Rules::default() };
    Ok(into_text(written_once(input, &rules)?))
}

/// What [`agent_view_within`] made of a body.
#[derive(Debug)]
pub enum Viewed {
    /// The view, no longer than the allowance.
    Written(JsonText),
    /// The view would be this many bytes, more than the allowance; nothing was written.
    Longer(usize),
}

/// [`agent_view`] when it is at most `allowance` bytes long. A longer view is measured and not written, so the caller can find room for it before [`agent_view_at`] writes it.
pub fn agent_view_within(input: &[u8], scrub: &CredentialScrub, redact_keys: &[String], allowance: usize) -> Result<Viewed, serde_json::Error> {
    let targets = Targets::new(redact_keys);
    let rules = Rules { scrub: Some(scrub), redact: Some(&targets), ..Rules::default() };
    Ok(match written_within(input, &rules, allowance)? {
        Ok(bytes) => Viewed::Written(into_text(bytes)),
        Err(len) => Viewed::Longer(len),
    })
}

/// [`agent_view`] written into a buffer of `len` bytes, the length [`agent_view_within`] measured.
pub fn agent_view_at(input: &[u8], scrub: &CredentialScrub, redact_keys: &[String], len: usize) -> Result<JsonText, serde_json::Error> {
    let targets = Targets::new(redact_keys);
    let rules = Rules { scrub: Some(scrub), redact: Some(&targets), ..Rules::default() };
    Ok(into_text(run(input, Vec::with_capacity(len), CompactFormatter, &rules, &Seen::default())?))
}

/// One pass of `rules` over `input`, written into a buffer allocated once at the size of what it writes.
/// A view no longer than its input, which every realistic document's is, takes one pass; a longer one is measured and then written, so it never holds a growing buffer beside the doubled one it moves into. serde_json writes `1e15` as `1000000000000000.0`, so an array of them comes out 3.8 times its input.
fn written_once(input: &[u8], rules: &Rules<'_>) -> Result<Vec<u8>, serde_json::Error> {
    Ok(written_within(input, rules, usize::MAX)?.unwrap_or_default())
}

/// [`written_once`], or the length of what it would write when that is more than `allowance`.
fn written_within(input: &[u8], rules: &Rules<'_>, allowance: usize) -> Result<Result<Vec<u8>, usize>, serde_json::Error> {
    let limit = input.len().min(allowance);
    let mut first = Limited { out: Vec::with_capacity(limit), limit, over: false };
    let written = run(input, &mut first, CompactFormatter, rules, &Seen::default()).map(drop);
    match written {
        Ok(()) => return Ok(Ok(first.out)),
        Err(e) if !first.over => return Err(e),
        Err(_) => {}
    }
    drop(first);
    let Counted(len) = run(input, Counted(0), CompactFormatter, rules, &Seen::default())?;
    if len > allowance {
        return Ok(Err(len));
    }
    Ok(Ok(run(input, Vec::with_capacity(len), CompactFormatter, rules, &Seen::default())?))
}

/// A writer that only counts what it is given.
struct Counted(usize);

impl Write for Counted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// [`agent_view`] for a process's standard output: a document when the output is JSON, and otherwise the output as one scrubbed string, which key-name redaction has nothing to act on.
pub fn agent_view_of_output(output: &str, scrub: &CredentialScrub, redact_keys: &[String]) -> JsonText {
    agent_view(output.as_bytes(), scrub, redact_keys).unwrap_or_else(|_| {
        let clean = scrub.scrub_str(output);
        JsonText::from_serialize(clean.as_ref()).unwrap_or_default()
    })
}

/// `doc` with every string, key and number scrubbed again, or `None` when the scrub finds nothing in it, so a document that is already clean is read once and not copied.
pub fn rescrubbed(doc: &JsonText, scrub: &CredentialScrub) -> Option<JsonText> {
    if scrub.is_empty() {
        return None;
    }
    let rules = Rules { scrub: Some(scrub), ..Rules::default() };
    let seen = Seen::default();
    run(doc.get().as_bytes(), std::io::sink(), CompactFormatter, &rules, &seen).ok()?;
    if !seen.changed.get() {
        return None;
    }
    Some(into_text(written_once(doc.get().as_bytes(), &rules).ok()?))
}

/// What [`cut_deeper_than`] made of a document.
#[derive(Debug, PartialEq, Eq)]
pub enum Cut {
    /// Nothing is that deep (or the text is not one document): keep it as it is.
    Unchanged,
    /// The document with its deeper part replaced.
    Cut(JsonText),
    /// The cut document would be this many bytes, over the limit; nothing was written.
    TooLarge(usize),
}

/// `doc` with every array or object nested `levels` deep or deeper (the document itself is level 0) replaced by the string `marker`.
/// The cut is measured before it is written, and one longer than `limit` is never written at all: a marker can be many times longer than the `[]` it replaces, so a cut can be many times its document.
pub fn cut_deeper_than(doc: &JsonText, levels: usize, marker: &str, limit: usize) -> Cut {
    let rules = Rules { cut_at: Some(levels), cut_marker: marker, ..Rules::default() };
    let seen = Seen::default();
    let Ok(Counted(len)) = run(doc.get().as_bytes(), Counted(0), CompactFormatter, &rules, &seen) else { return Cut::Unchanged };
    if !seen.cut.get() {
        return Cut::Unchanged;
    }
    if len > limit {
        return Cut::TooLarge(len);
    }
    match run(doc.get().as_bytes(), Vec::with_capacity(len), CompactFormatter, &rules, &Seen::default()) {
        Ok(out) => Cut::Cut(into_text(out)),
        Err(_) => Cut::Unchanged,
    }
}

/// A writer that refuses to grow past a limit, and remembers that it did.
struct Limited {
    out: Vec<u8>,
    limit: usize,
    over: bool,
}

impl Write for Limited {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.out.len() + buf.len() > self.limit {
            self.over = true;
            return Err(std::io::Error::other("over the limit"));
        }
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `doc` pretty-printed as serde_json's `to_string_pretty` prints it, or `None` when that text would pass `limit` bytes: each line is indented by its depth, so a deep document grows far past its own size when printed this way.
pub fn pretty_within(doc: &JsonText, limit: usize) -> Option<String> {
    let out = run(doc.get().as_bytes(), Limited { out: Vec::new(), limit, over: false }, PrettyFormatter::new(), &Rules::default(), &Seen::default()).ok()?;
    String::from_utf8(out.out).ok()
}

/// A writer that only feeds a hash.
struct Hashing(Sha256);

impl Write for Hashing {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// [`crate::request_hash`] of the document `params`, computed from its text without a tree, or `None` when that text is not in canonical key order (every object's keys strictly ascending), which a caller then answers from a tree.
/// Text serde_json wrote from a `Value` is always in that order.
pub fn request_hash_of_text(capability: &str, params: &str) -> Option<String> {
    let mut hasher = Sha256::new();
    hasher.update(capability.as_bytes());
    hasher.update(b"\0");
    let rules = Rules { ascending_keys: true, ..Rules::default() };
    let Hashing(hasher) = run(params.as_bytes(), Hashing(hasher), CompactFormatter, &rules, &Seen::default()).ok()?;
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    Some(s)
}

/// The shape of `doc` as the signed audit summary records it: `{"records": n}` for an array, `{"fields": n}` for an object, `{"chars": n}` for a string, and a scalar as itself.
/// Nothing below the top level is parsed, and nothing is kept per member: a key the document repeats is counted each time, where a tree would have kept one.
pub fn summary(doc: &JsonText) -> Value {
    struct Top;
    impl<'de> Visitor<'de> for Top {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
            Ok(Value::from(v))
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
            Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
            Ok(serde_json::json!({ "chars": v.chars().count() }))
        }
        fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
            let mut records = 0usize;
            while seq.next_element::<IgnoredAny>()?.is_some() {
                records += 1;
            }
            Ok(serde_json::json!({ "records": records }))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            let mut fields = 0usize;
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                fields += 1;
            }
            Ok(serde_json::json!({ "fields": fields }))
        }
    }
    let mut de = serde_json::Deserializer::from_str(doc.get());
    de.deserialize_any(Top).unwrap_or(Value::Null)
}

/// The string at the JSON pointer `pointer` in `doc`, as `Value::pointer` would find it (a member named twice resolves to its last occurrence), or `None` when nothing is there or it is not a string. Everything off the pointer's path is skipped unparsed.
pub fn string_at(doc: &JsonText, pointer: &str) -> Option<String> {
    if !(pointer.is_empty() || pointer.starts_with('/')) {
        return None;
    }
    let tokens: Vec<String> = pointer.split('/').skip(1).map(|t| t.replace("~1", "/").replace("~0", "~")).collect();
    let mut de = serde_json::Deserializer::from_str(doc.get());
    Lookup { tokens: &tokens }.deserialize(&mut de).ok().flatten()
}

struct Lookup<'t> {
    tokens: &'t [String],
}

impl<'t, 'de> DeserializeSeed<'de> for Lookup<'t> {
    type Value = Option<String>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Option<String>, D::Error> {
        deserializer.deserialize_any(self)
    }
}

/// `Value::pointer`'s reading of an array index: no sign and no leading zero.
fn array_index(token: &str) -> Option<usize> {
    if token.starts_with('+') || (token.starts_with('0') && token.len() != 1) {
        return None;
    }
    token.parse().ok()
}

impl<'t, 'de> Visitor<'de> for Lookup<'t> {
    type Value = Option<String>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(self.tokens.is_empty().then(|| v.to_string()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let wanted = self.tokens.first().and_then(|t| array_index(t));
        let mut found = None;
        let mut at = 0usize;
        loop {
            if Some(at) == wanted {
                match seq.next_element_seed(Lookup { tokens: &self.tokens[1..] })? {
                    Some(hit) => found = hit,
                    None => break,
                }
            } else if seq.next_element::<IgnoredAny>()?.is_none() {
                break;
            }
            at += 1;
        }
        Ok(found)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let Some(wanted) = self.tokens.first() else {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            return Ok(None);
        };
        let mut found = None;
        while let Some(key) = map.next_key::<String>()? {
            if &key == wanted {
                found = map.next_value_seed(Lookup { tokens: &self.tokens[1..] })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scrub_of(secret: &str) -> CredentialScrub {
        let mut scrub = CredentialScrub::new();
        scrub.add_secret(secret.as_bytes());
        scrub
    }

    /// The tree path this replaces: scrub the whole value, then redact by key.
    fn tree_view(value: &Value, scrub: &CredentialScrub, keys: &[String]) -> Value {
        let mut value = value.clone();
        scrub.scrub_value(&mut value);
        crate::redact(value, keys)
    }

    fn keys(names: &[&str]) -> Vec<String> {
        crate::effective_redact_keys(names.iter().copied())
    }

    #[test]
    fn the_stream_gives_what_the_tree_gave() {
        let secret = "sk_live_0123456789abcdef";
        let scrub = scrub_of(secret);
        let keys = keys(&["card.number", "email"]);
        let corpus = vec![
            json!({ "id": 1, "token": "abc", "nested": { "Authorization": "Bearer x", "ok": [1, 2, 3] } }),
            json!([{ "card": { "number": "4111", "brand": "visa" } }, { "number": "keep" }]),
            json!({ "card": [{ "number": "4111" }, { "number": "4222" }] }),
            json!({ "echo": format!("the key was {secret}"), secret: "a key named by the secret" }),
            json!({ "users": [{ "Email": "a@b.c", "name": "A" }], "count": 2, "ratio": 0.25, "neg": -3, "big": 18446744073709551615u64 }),
            json!("a bare string with sk_live_0123456789abcdef in it"),
            json!(42),
            json!(null),
            json!({ "deep": [[[{ "password": { "x": 1 } }]]] }),
            json!({ "unicode": "é\u{0}\n\"\\", "float": 1.0e300 }),
        ];
        for value in corpus {
            let streamed = agent_view(value.to_string().as_bytes(), &scrub, &keys).unwrap();
            assert_eq!(streamed.to_value_unbounded(), tree_view(&value, &scrub, &keys), "for {value}");
        }
    }

    #[test]
    fn a_numeric_secret_is_scrubbed_out_of_numbers_as_the_tree_did() {
        let scrub = scrub_of("123456789012");
        let value = json!({ "account": 123456789012u64, "other": 7, "list": [123456789012u64] });
        let streamed = agent_view(value.to_string().as_bytes(), &scrub, &[]).unwrap();
        assert_eq!(streamed.to_value_unbounded(), tree_view(&value, &scrub, &[]));
        assert!(streamed.get().contains(crate::SCRUBBED));
    }

    #[test]
    fn members_keep_their_order_and_a_repeated_key_is_redacted_every_time() {
        let scrub = CredentialScrub::new();
        let out = agent_view(br#"{"z":1,"token":"a","a":2,"token":{"x":"b"}}"#, &scrub, &keys(&[])).unwrap();
        assert_eq!(out.get(), r#"{"z":1,"token":"[redacted]","a":2,"token":"[redacted]"}"#);
    }

    #[test]
    fn what_a_tree_would_not_read_is_refused() {
        let scrub = CredentialScrub::new();
        for bad in [&b"{\"a\":"[..], b"[1,]", b"1 2", b"", b"\xff", b"not json"] {
            assert!(agent_view(bad, &scrub, &[]).is_err(), "{:?}", String::from_utf8_lossy(bad));
            assert!(serde_json::from_slice::<Value>(bad).is_err());
        }
        let deep = format!("{}{}", "[".repeat(129), "]".repeat(129));
        assert!(agent_view(deep.as_bytes(), &scrub, &[]).is_err(), "past serde_json's nesting limit");
        let ok = format!("{}{}", "[".repeat(127), "]".repeat(127));
        assert!(agent_view(ok.as_bytes(), &scrub, &[]).is_ok());
    }

    #[test]
    fn the_raw_value_key_is_an_ordinary_key() {
        let inner = format!("[{}]", vec!["{\"a\":1}"; 1000].join(","));
        let doc = serde_json::to_string(&json!({ "$serde_json::private::RawValue": inner })).unwrap();
        let out = agent_view(doc.as_bytes(), &CredentialScrub::new(), &[]).unwrap();
        assert_eq!(out.get(), doc, "the string under the key stays a string");
    }

    #[test]
    fn stdout_that_is_not_json_is_one_scrubbed_string() {
        let scrub = scrub_of("sk_live_0123456789abcdef");
        let out = agent_view_of_output("line one\nkey=sk_live_0123456789abcdef\n", &scrub, &[]);
        assert_eq!(out.to_value_unbounded(), json!(format!("line one\nkey={}\n", crate::SCRUBBED)));
        let json_out = agent_view_of_output("{\"password\":\"x\"}", &scrub, &keys(&[]));
        assert_eq!(json_out.get(), r#"{"password":"[redacted]"}"#);
    }

    #[test]
    fn a_rescrub_copies_only_when_it_finds_something() {
        let scrub = scrub_of("sk_live_0123456789abcdef");
        let clean = JsonText::from_value(&json!({ "a": "nothing here" }));
        assert!(rescrubbed(&clean, &scrub).is_none());
        let dirty = JsonText::from_value(&json!({ "a": "sk_live_0123456789abcdef" }));
        assert_eq!(rescrubbed(&dirty, &scrub).unwrap().to_value_unbounded(), json!({ "a": crate::SCRUBBED }));
    }

    #[test]
    fn a_cut_replaces_what_is_too_deep() {
        let nested = (0..10).fold(json!("leaf"), |inner, _| json!([inner]));
        let doc = JsonText::from_value(&nested);
        let Cut::Cut(cut) = cut_deeper_than(&doc, 4, "[cut]", usize::MAX) else { panic!("cut") };
        assert_eq!(cut.get(), r#"[[[["[cut]"]]]]"#);
        assert_eq!(cut_deeper_than(&doc, 11, "[cut]", usize::MAX), Cut::Unchanged);
        assert_eq!(cut_deeper_than(&doc, 4, "[cut]", 10), Cut::TooLarge(15), "measured, never written past the limit");
    }

    /// A skipped member is read without a nesting limit, so a redacted value deeper than serde_json's 128 levels is redacted where a tree refused the body; a written one still meets the limit.
    #[test]
    fn a_redacted_value_is_skipped_at_any_depth_and_a_written_one_meets_the_limit() {
        let deep = format!("{}{}", "[".repeat(1000), "]".repeat(1000));
        let scrub = CredentialScrub::default();
        let redacted = agent_view(format!(r#"{{"password":{deep},"ok":1}}"#).as_bytes(), &scrub, &["password".to_string()]).unwrap();
        assert_eq!(redacted.get(), r#"{"password":"[redacted]","ok":1}"#);
        assert!(serde_json::from_str::<Value>(&format!(r#"{{"password":{deep}}}"#)).is_err(), "the tree refused it");
        assert!(agent_view(format!(r#"{{"kept":{deep}}}"#).as_bytes(), &scrub, &["password".to_string()]).is_err());
    }

    /// A view longer than its input (serde_json writes `1e15` as `1000000000000000.0`) is written into a buffer of exactly its length, and one no longer than its input in one pass.
    #[test]
    fn the_agent_view_is_written_into_one_buffer_of_its_own_length() {
        let scrub = CredentialScrub::default();
        let grown = format!("[{}]", vec!["1e15"; 1000].join(","));
        let view = agent_view(grown.as_bytes(), &scrub, &[]).unwrap();
        assert_eq!(view.len(), 1 + 1000 * 18 + 999 + 1);
        assert!(view.len() * 10 >= grown.len() * 37, "the 3.8x case: {} from {}", view.len(), grown.len());
        let back: Vec<f64> = serde_json::from_str(view.get()).unwrap();
        assert!(back.iter().all(|&n| n == 1e15));

        let pretty = serde_json::to_string_pretty(&json!({ "a": [1, 2, { "password": "x" }] })).unwrap();
        let view = agent_view(pretty.as_bytes(), &scrub, &["password".to_string()]).unwrap();
        assert_eq!(view.get(), r#"{"a":[1,2,{"password":"[redacted]"}]}"#);
        assert!(agent_view(b"", &scrub, &[]).is_err(), "nothing is not a document");
        assert!(agent_view(b"[1,", &scrub, &[]).is_err());
    }

    #[test]
    fn the_text_hash_is_the_tree_hash() {
        for value in [
            json!({ "b": 1, "a": [1, { "z": "x", "y": null }], "c": 2.5, "é": "\u{1}" }),
            json!([]),
            json!("s"),
            json!({}),
        ] {
            let text = JsonText::from_value(&value);
            assert_eq!(request_hash_of_text("cap.x", text.get()).unwrap(), crate::request_hash("cap.x", &value));
            let spaced = serde_json::to_string_pretty(&value).unwrap();
            assert_eq!(request_hash_of_text("cap.x", &spaced).unwrap(), crate::request_hash("cap.x", &value), "whitespace is not part of it");
        }
        assert!(request_hash_of_text("cap.x", r#"{"b":1,"a":2}"#).is_none(), "keys out of order");
        assert!(request_hash_of_text("cap.x", r#"{"a":1,"a":2}"#).is_none(), "a repeated key");
    }

    #[test]
    fn the_summary_counts_the_top_level() {
        let s = |v: Value| summary(&JsonText::from_value(&v));
        assert_eq!(s(json!([1, [2, 3], {}])), json!({ "records": 3 }));
        assert_eq!(s(json!({ "a": 1, "b": [1, 2] })), json!({ "fields": 2 }));
        assert_eq!(s(json!("héllo")), json!({ "chars": 5 }));
        assert_eq!(s(json!(7)), json!(7));
        assert_eq!(s(json!(null)), json!(null));
        assert_eq!(summary(&JsonText::from_string(r#"{"a":1,"a":2,"b":3}"#.into()).unwrap()), json!({ "fields": 3 }));
    }

    #[test]
    fn string_at_follows_value_pointer() {
        let value = json!({ "error": { "message": "bad key" }, "errors": [{ "detail": "d0" }, { "detail": "d1" }], "n": 1, "o": { "0": { "message": "zero" } } });
        let doc = JsonText::from_value(&value);
        for pointer in ["/error/message", "/errors/0/detail", "/errors/1/detail", "/n", "/missing", "/o/0/message", "/errors/01/detail", "", "/error"] {
            assert_eq!(string_at(&doc, pointer), value.pointer(pointer).and_then(|v| v.as_str()).map(str::to_string), "{pointer}");
        }
        assert_eq!(string_at(&JsonText::from_value(&json!("top")), ""), Some("top".into()));
        let repeated = JsonText::from_string(r#"{"message":"first","message":"last"}"#.into()).unwrap();
        assert_eq!(string_at(&repeated, "/message"), Some("last".into()));
    }

    #[test]
    fn pretty_is_serde_jsons_and_stops_at_its_limit() {
        let value = json!({ "a": [1, { "b": "c" }], "d": null });
        let doc = JsonText::from_value(&value);
        assert_eq!(pretty_within(&doc, 1 << 20).unwrap(), serde_json::to_string_pretty(&value).unwrap());
        let deep = JsonText::from_value(&(0..100).fold(json!([1, 2, 3]), |inner, _| json!([inner])));
        assert!(pretty_within(&deep, deep.len() * 4).is_none(), "indentation grows with depth");
    }
}
