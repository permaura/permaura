//! Every decrypting path in this crate leaves no copy of the plaintext in freed memory: the secret is wiped wherever it was copied, not only in the buffer handed back. Run with its own global allocator, which reads each block as it is freed.

mod freed_scan;

use base64::Engine as _;
use freed_scan::{needles_for, watch, FreedScan};
use permaura_core::{bundle_kdf_params, Cipher, KdfParams};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOC: FreedScan = FreedScan;

const SECRET: &str = "zz-plaintext-lifetime-probe-01234567-abcdefghijk";
const PASS: &[u8] = b"probe-passphrase";

/// A caller's secret field that never makes an unwiped copy of its own, so what the scan finds is the crate's.
struct Probe(Zeroizing<Vec<u8>>);

impl Serialize for Probe {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let engine = base64::engine::general_purpose::STANDARD;
        let mut out = Zeroizing::new(vec![0u8; base64::encoded_len(self.0.len(), true).unwrap()]);
        let n = engine.encode_slice(&*self.0, &mut out).map_err(serde::ser::Error::custom)?;
        s.serialize_str(std::str::from_utf8(&out[..n]).map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for Probe {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Probe;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("base64")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Probe, E> {
                let mut out = Zeroizing::new(vec![0u8; v.len()]);
                let n = base64::engine::general_purpose::STANDARD.decode_slice(v, &mut out).map_err(E::custom)?;
                out.truncate(n);
                Ok(Probe(out))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Probe, E> {
                let v = Zeroizing::new(v);
                self.visit_str(&v)
            }
        }
        d.deserialize_str(V)
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    id: String,
    value: Probe,
    token: permaura_core::SecretString,
}

impl permaura_core::TypedPayload for Payload {}

fn floor_params() -> KdfParams {
    KdfParams { mem_cost_kib: 32 * 1024, time_cost: 1, parallelism: 1, ..bundle_kdf_params() }
}

#[test]
fn every_open_wipes_the_plaintext_it_returns() {
    let needles = needles_for(SECRET);
    let sealed = permaura_core::seal(Cipher::Aes256Gcm, PASS, SECRET.as_bytes()).unwrap();
    let kek = permaura_core::Kek::derive(PASS, &sealed.kdf_params).unwrap();
    let keks = permaura_core::KekCache::new(PASS.to_vec());

    let w = watch(&needles);
    drop(permaura_core::open(&sealed, PASS).unwrap());
    assert_eq!(w.hits(), 0, "crypto::open left the plaintext in freed memory");
    drop(permaura_core::open_with_kek(&sealed, &kek).unwrap());
    assert_eq!(w.hits(), 0, "crypto::open_with_kek left the plaintext in freed memory");
    drop(keks.open(&sealed).unwrap());
    drop(keks.open(&sealed).unwrap());
    assert_eq!(w.hits(), 0, "KekCache::open left the plaintext in freed memory");
}

#[test]
fn sealing_and_opening_a_bundle_leaves_no_copy_of_its_secrets() {
    let needles = needles_for(SECRET);
    let source = permaura_core::BundleSource { gateway_id: "gw_probe".into(), mode: "self-run".into() };
    let payload = Payload {
        id: "sec_probe".into(),
        value: Probe(Zeroizing::new(SECRET.as_bytes().to_vec())),
        token: permaura_core::SecretString::from(SECRET),
    };

    let w = watch(&needles);
    let bundle = permaura_core::seal_bundle_with_params(PASS, &payload, 1_754_500_000_000, source, floor_params()).unwrap();
    drop(payload);
    assert_eq!(w.hits(), 0, "sealing a bundle left a copy of a secret in freed memory");

    let opened = permaura_core::open_bundle(&bundle, PASS).unwrap();
    let back: Payload = opened.payload().unwrap();
    drop(opened);
    assert_eq!(&*back.value.0, SECRET.as_bytes());
    assert_eq!(back.token, SECRET);
    drop(back);
    assert_eq!(w.hits(), 0, "opening a bundle left a copy of a secret in freed memory");
}

#[test]
fn a_large_document_written_through_the_wiping_writer_leaves_no_piece_behind() {
    let needles = needles_for(SECRET);
    let many: Vec<permaura_core::SecretString> = (0..64).map(|_| permaura_core::SecretString::from(SECRET)).collect();
    let w = watch(&needles);
    let json = permaura_core::secret::to_json(&many).unwrap();
    assert!(json.len() > 64 * SECRET.len());
    drop(json);
    drop(many);
    assert_eq!(w.hits(), 0, "growing the JSON buffer left a copy of a secret in freed memory");
}

/// A credential with reserved and non-ASCII characters, of a length that is not a multiple of 3, so every size-changing encoding is exercised.
const RESERVED: &str = "zz+/=&%~é probe-reserved-0123456789-abcdefghijklmnop";

#[test]
fn a_scrub_built_from_a_credential_that_is_not_utf8_leaves_no_copy() {
    let needles = needles_for(SECRET);
    let w = watch(&needles);
    let not_utf8 = Zeroizing::new([SECRET.as_bytes(), b"\xff\xfe tail"].concat());
    let mut scrub = permaura_core::scrub::CredentialScrub::new();
    scrub.add_secret(&not_utf8);
    drop(scrub);
    drop(not_utf8);
    assert_eq!(w.hits(), 0, "the scrub's lossy decode left a copy of the credential in freed memory: {:?}", w.last_hit());
}

#[test]
fn a_scrub_leaves_no_eight_byte_prefix_of_its_needles_behind() {
    let prefix: &'static [u8] = &SECRET.as_bytes()[..8];
    let w = watch(&[prefix]);
    let mut scrub = permaura_core::scrub::CredentialScrub::new();
    scrub.add_secret(SECRET.as_bytes());
    scrub.add_secret(RESERVED.as_bytes());
    drop(scrub);
    assert_eq!(w.hits(), 0, "the scrub's prefix table left the first bytes of a needle in freed memory: {:?}", w.last_hit());
}

#[test]
fn a_secret_that_arrives_json_escaped_is_unescaped_without_an_unwiped_copy() {
    #[derive(Deserialize)]
    struct Answer {
        #[serde(deserialize_with = "permaura_core::secret::unescaped::deserialize")]
        value: permaura_core::SecretString,
    }
    let needles = needles_for(SECRET);
    let w = watch(&needles);
    // A PHP or .NET writer, or a PEM's line breaks: every escape sends the string through the parser's own scratch.
    let mut body = Zeroizing::new(Vec::with_capacity(256));
    body.extend_from_slice(b"{\"value\":\"\\/");
    body.extend_from_slice(SECRET.as_bytes());
    body.extend_from_slice(b"\\n\"}");
    let answer: Answer = serde_json::from_slice(&body).unwrap();
    assert!(answer.value.expose().contains(SECRET));
    drop(answer);
    drop(body);
    assert_eq!(w.hits(), 0, "unescaping the secret left a copy in freed memory: {:?}", w.last_hit());
}

/// The type-level half of the pin, for the items it names and only those: each decrypting function in this crate names a wiping type as what it returns, so changing one back to a plain `Vec` stops this binary compiling. The fields of the holders (`SecretString`, `WipingBuffer`, `OpenedBundle`) are pinned inside the crate, where they can be named, and a bundle's payload cannot be read as a `serde_json::Value` at all (`TypedPayload`).
#[allow(dead_code)]
fn decrypting_functions_return_wiping_types() {
    use permaura_core::{crypto, KekCache, OpenedBundle, SealedSecret, VaultBundle};
    let _: fn(&SealedSecret, &[u8]) -> permaura_core::Result<Zeroizing<Vec<u8>>> = crypto::open;
    let _: fn(&SealedSecret, &permaura_core::Kek) -> permaura_core::Result<Zeroizing<Vec<u8>>> = crypto::open_with_kek;
    let _: fn(&KekCache, &SealedSecret) -> permaura_core::Result<Zeroizing<Vec<u8>>> = KekCache::open;
    let _: fn(&VaultBundle, &[u8]) -> permaura_core::Result<OpenedBundle> = permaura_core::open_bundle;
    let _: fn(&[u8]) -> permaura_core::SecretString = permaura_core::SecretString::from_utf8_lossy;
}
