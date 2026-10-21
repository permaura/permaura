//! A JSON document held as its text.
//!
//! A `serde_json::Value` costs per node, not per byte: an upstream body of one-key objects builds about 85 bytes of heap for every byte it arrived in.
//! [`JsonText`] is the form the gateway keeps a document in when it only needs to carry it (an agent's result, a held call's parameters): it costs its length, it is always one valid JSON document, and it serializes as that document verbatim.
//!
//! The streaming passes in [`crate::json_stream`] read it without building a tree, and the gateway's metered parse builds one under a memory charge when a tree is really needed.
//! The one method here that builds a tree, [`JsonText::to_value_unbounded`], is for tests and for documents the gateway wrote itself.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

/// One valid JSON document, kept as its text.
#[derive(Clone)]
pub struct JsonText(Box<RawValue>);

impl JsonText {
    /// The document `null`.
    pub fn null() -> Self {
        JsonText::from_value(&serde_json::Value::Null)
    }

    /// `value` written compactly. For a `Value` that is serde_json's canonical form: object keys ascending (the map is a `BTreeMap`) and no whitespace, which is what [`crate::request_hash`] hashes.
    pub fn from_value(value: &serde_json::Value) -> Self {
        JsonText(serde_json::value::to_raw_value(value).unwrap_or_else(|_| null_raw()))
    }

    /// `value` serialized compactly.
    pub fn from_serialize<T: Serialize + ?Sized>(value: &T) -> Result<Self, serde_json::Error> {
        serde_json::value::to_raw_value(value).map(JsonText)
    }

    /// `text`, once it has been checked to be exactly one JSON document. The check reads it without building anything; surrounding whitespace is dropped.
    pub fn from_string(text: String) -> Result<Self, serde_json::Error> {
        RawValue::from_string(text).map(JsonText)
    }

    /// Text the caller has just written with serde_json's own serializer, so it is one document by construction. A debug build checks it.
    pub(crate) fn from_trusted(text: String) -> Self {
        debug_assert!(serde_json::from_str::<serde::de::IgnoredAny>(&text).is_ok(), "not one JSON document: {text:.80}");
        RawValue::from_string(text).map(JsonText).unwrap_or_else(|_| JsonText(null_raw()))
    }

    /// The document's text.
    pub fn get(&self) -> &str {
        self.0.get()
    }

    /// The document's length in bytes.
    pub fn len(&self) -> usize {
        self.0.get().len()
    }

    /// Never true: the shortest document is one byte. Here so a length check reads naturally.
    pub fn is_empty(&self) -> bool {
        self.0.get().is_empty()
    }

    /// Whether the document is `null`.
    pub fn is_null(&self) -> bool {
        self.0.get() == "null"
    }

    /// The document as the raw value serde_json embeds verbatim when it writes a struct holding it.
    pub fn as_raw(&self) -> &RawValue {
        &self.0
    }

    /// The document's text, owned, without copying it.
    pub fn into_string(self) -> String {
        let text: Box<str> = self.0.into();
        text.into_string()
    }

    /// The whole document as a tree, with no bound on what that costs. For tests, and for documents the gateway wrote itself and knows to be small; anything an agent or an upstream shaped goes through the gateway's metered parse instead.
    pub fn to_value_unbounded(&self) -> serde_json::Value {
        serde_json::from_str(self.0.get()).unwrap_or(serde_json::Value::Null)
    }
}

fn null_raw() -> Box<RawValue> {
    RawValue::from_string("null".to_string()).expect("null is a JSON document")
}

impl Default for JsonText {
    fn default() -> Self {
        JsonText::null()
    }
}

impl PartialEq for JsonText {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for JsonText {}

impl fmt::Debug for JsonText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const SHOWN: usize = 256;
        let text = self.get();
        if text.len() <= SHOWN {
            return write!(f, "JsonText({text})");
        }
        let mut cut = SHOWN;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        write!(f, "JsonText({}... {} bytes)", &text[..cut], text.len())
    }
}

impl fmt::Display for JsonText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.get())
    }
}

impl From<&serde_json::Value> for JsonText {
    fn from(value: &serde_json::Value) -> Self {
        JsonText::from_value(value)
    }
}

impl From<serde_json::Value> for JsonText {
    fn from(value: serde_json::Value) -> Self {
        JsonText::from_value(&value)
    }
}

impl Serialize for JsonText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for JsonText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Box::<RawValue>::deserialize(deserializer).map(JsonText)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_value_is_kept_compact_and_reads_back_whole() {
        let value = json!({ "b": [1, 2.5, "x"], "a": { "c": null } });
        let text = JsonText::from_value(&value);
        assert_eq!(text.get(), r#"{"a":{"c":null},"b":[1,2.5,"x"]}"#);
        assert_eq!(text.to_value_unbounded(), value);
    }

    #[test]
    fn it_serializes_verbatim_inside_a_struct() {
        #[derive(Serialize, Deserialize)]
        struct Row {
            id: String,
            #[serde(default)]
            params: JsonText,
            #[serde(default)]
            result: Option<JsonText>,
        }
        let row = Row { id: "a".into(), params: JsonText::from_value(&json!({ "k": [1, { "z": 2 }] })), result: None };
        let written = serde_json::to_string(&row).unwrap();
        assert_eq!(written, r#"{"id":"a","params":{"k":[1,{"z":2}]},"result":null}"#);
        let read: Row = serde_json::from_str(&written).unwrap();
        assert_eq!(read.params.get(), r#"{"k":[1,{"z":2}]}"#);
        assert!(read.result.is_none());
        let defaulted: Row = serde_json::from_str(r#"{"id":"b"}"#).unwrap();
        assert!(defaulted.params.is_null());
    }

    #[test]
    fn text_that_is_not_one_document_is_refused() {
        assert!(JsonText::from_string("{\"a\":".into()).is_err());
        assert!(JsonText::from_string("1 2".into()).is_err());
        assert_eq!(JsonText::from_string("  [1] ".into()).unwrap().get(), "[1]");
    }
}
