//! Proof that whatever answers `/health` on a gateway's port holds this home's operator token, without the token crossing the wire.
//!
//! A client about to hand a local gateway its operator bearer first sends `GET /health` with a fresh [`CHALLENGE_HEADER`] and no bearer. A gateway holding an operator token answers with [`PROOF_HEADER`]: lowercase hex of HMAC-SHA256, keyed with the token's bytes, over `permaura-health-proof:<port>:<challenge>`, `<port>` being the TCP port it listens on in decimal. The client recomputes it from its own token and the port it dialed, and only a match makes the listener its gateway.
//!
//! A gateway linked to permaura.com also answers with [`CONSOLE_PROOF_HEADER`]: the same construction keyed on each console session permaura.com may hold for it, since that, not the operator token, is the bearer the browser-direct console holds.
//!
//! A client about to present any other bearer the gateway stores (an agent's token, an enrolment code not yet redeemed, a session opened through `POST /v1/sessions`) asks the same way, adding [`BEARER_KEY_HEADER`]: [`bearer_key`] of the bearer's [`bearer_digest`], which names it without revealing it. A self-run gateway storing that bearer answers with [`BEARER_PROOF_HEADER`]: [`bearer_proof`], keyed with the digest it keeps in place of the bearer. A listener that learns the key cannot work back to the digest, so it cannot give the proof.
//!
//! The port is in the message because the gateway answers anyone: without it, a squatter on the port a client probes could relay the challenge to the real gateway on another port and pass off the answer as its own.

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// The request header carrying the client's challenge.
pub const CHALLENGE_HEADER: &str = "x-permaura-challenge";

/// The response header carrying the gateway's proof.
pub const PROOF_HEADER: &str = "x-permaura-proof";

/// The response header carrying the gateway's proofs of the console sessions permaura.com may hold for it: the same [`proof`] keyed on each console session instead of the operator token, lowercase hex, comma separated, newest first. The browser-direct console holds one of those sessions and never the operator token, so this is the answer it checks.
pub const CONSOLE_PROOF_HEADER: &str = "x-permaura-console-proof";

/// The most proofs [`CONSOLE_PROOF_HEADER`] lists. The console reads no further than this, so a gateway holding more sessions lists its newest.
pub const CONSOLE_PROOF_MAX: usize = 4;

const DOMAIN: &[u8] = b"permaura-health-proof:";

/// The request header naming, without revealing, the bearer a client is about to present: [`bearer_key`].
pub const BEARER_KEY_HEADER: &str = "x-permaura-bearer-key";

/// The response header carrying a gateway's proof that it stores the bearer [`BEARER_KEY_HEADER`] named: [`bearer_proof`], or [`BEARER_PROOF_NONE`].
pub const BEARER_PROOF_HEADER: &str = "x-permaura-bearer-proof";

/// What [`BEARER_PROOF_HEADER`] says when the gateway understood the question but holds no live bearer by that key, so a client can tell a token to enrol again from a listener that gives no proof at all. Never a valid proof, which is 64 hex characters.
pub const BEARER_PROOF_NONE: &str = "none";

const BEARER_KEY_DOMAIN: &[u8] = b"permaura-bearer-key:";

const BEARER_PROOF_DOMAIN: &[u8] = b"permaura-bearer-proof:";

/// The digest a gateway keeps in place of a bearer: `sha256:` and the lowercase hex SHA-256 of its bytes.
pub fn bearer_digest(bearer: &str) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bearer.as_bytes())))
}

/// What a client sends in [`BEARER_KEY_HEADER`] to name the bearer whose `digest` ([`bearer_digest`]) it holds: lowercase hex SHA-256 over a domain and the digest. One-way, so a listener that receives it learns nothing it can key a proof with.
pub fn bearer_key(digest: &str) -> String {
    let mut h = Sha256::new();
    h.update(BEARER_KEY_DOMAIN);
    h.update(digest.as_bytes());
    hex(&h.finalize())
}

/// Whether `key` has the shape [`bearer_key`] gives: 64 lowercase hex characters.
pub fn is_valid_bearer_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The proof a gateway listening on `port` and storing the bearer whose digest is `digest` gives for `challenge`, or `None` for an invalid challenge or an empty digest. Domain separated from [`proof`], so neither answers for the other.
pub fn bearer_proof(digest: &str, port: u16, challenge: &str) -> Option<String> {
    if digest.is_empty() || !is_valid_challenge(challenge) {
        return None;
    }
    let port = port.to_string();
    let mac = hmac_sha256(digest.as_bytes(), &[BEARER_PROOF_DOMAIN, port.as_bytes(), b":", challenge.as_bytes()]);
    Some(hex(&mac))
}

/// Whether `offered` is the proof the gateway storing `bearer` gives for `challenge` on `port`. Compared in constant time.
pub fn verify_bearer_proof(bearer: &str, port: u16, challenge: &str, offered: &str) -> bool {
    match bearer_proof(&bearer_digest(bearer), port, challenge) {
        Some(expected) => constant_time_eq(expected.as_bytes(), offered.trim().as_bytes()),
        None => false,
    }
}

/// The shortest challenge a gateway answers.
pub const CHALLENGE_MIN_LEN: usize = 16;

/// The longest challenge a gateway answers.
pub const CHALLENGE_MAX_LEN: usize = 64;

/// A fresh challenge: 32 bytes from the OS RNG, as 64 lowercase hex characters.
pub fn new_challenge() -> String {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    hex(&nonce)
}

/// Whether `challenge` is one a gateway answers: 16 to 64 characters of hex or base64url
/// (`[A-Za-z0-9_-]`, which hex is a subset of). The proof covers the characters as sent, not a
/// decoding of them.
pub fn is_valid_challenge(challenge: &str) -> bool {
    (CHALLENGE_MIN_LEN..=CHALLENGE_MAX_LEN).contains(&challenge.len())
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The proof a gateway listening on `port` and holding `token` gives for `challenge`, or `None` when
/// the challenge is not a valid one or there is no token to key it with.
pub fn proof(token: &str, port: u16, challenge: &str) -> Option<String> {
    if token.is_empty() || !is_valid_challenge(challenge) {
        return None;
    }
    let port = port.to_string();
    let mac = hmac_sha256(
        token.as_bytes(),
        &[DOMAIN, port.as_bytes(), b":", challenge.as_bytes()],
    );
    Some(hex(&mac))
}

/// Whether `offered` is the proof `token` gives for `challenge` on `port`. Compared in constant time.
/// Exact match only: a gateway always writes lowercase hex.
pub fn verify(token: &str, port: u16, challenge: &str, offered: &str) -> bool {
    match proof(token, port, challenge) {
        Some(expected) => constant_time_eq(expected.as_bytes(), offered.trim().as_bytes()),
        None => false,
    }
}

/// HMAC-SHA256 (RFC 2104) over the concatenation of `parts`. Written out over `sha2` rather than
/// taken from the `hmac` crate so the desktop, which builds against this crate from git, gains no
/// new dependency in its lockfile.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    block.zeroize();
    ipad.zeroize();
    opad.zeroize();
    outer.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "pgt_ag01testvectortoken";
    const CHALLENGE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// The vectors the bridge and the SDK check theirs against, so the three implementations agree byte for byte (computed independently with Python's hashlib and hmac).
    #[test]
    fn the_bearer_proof_matches_its_vectors() {
        let digest = bearer_digest("ENRL-TEST-VECT-OR00-0000-0000-0000-0000-0000");
        assert_eq!(digest, "sha256:405283dfd17c92b452c30a21e0de754202b76d2cb7a61580f3d06e5771b7cfc1");
        assert_eq!(bearer_key(&digest), "fb242f590b12bc7ab2b3f67e0de1e5ca705f266fe508c8abe77967510f797db0");
        assert_eq!(bearer_proof(&digest, 7376, CHALLENGE).unwrap(), "7e3d8599336f829b37c33d8ac496f5b99749a809f6fa9b9694aae9411958dbff");
    }

    /// The proof is keyed on the digest the gateway keeps, which the key does not reveal, and it is bound to the port and to the challenge; the operator-token proof answers for none of it.
    #[test]
    fn the_bearer_proof_is_bound_to_the_bearer_the_port_and_the_challenge() {
        let bearer = "tok_agentbearer";
        let digest = bearer_digest(bearer);
        let proof = bearer_proof(&digest, 7376, CHALLENGE).unwrap();
        assert!(verify_bearer_proof(bearer, 7376, CHALLENGE, &proof));
        assert!(!verify_bearer_proof("tok_another", 7376, CHALLENGE, &proof));
        assert!(!verify_bearer_proof(bearer, 7377, CHALLENGE, &proof));
        assert!(!verify_bearer_proof(bearer, 7376, &CHALLENGE.replace('0', "1"), &proof));
        assert!(!verify_bearer_proof(bearer, 7376, CHALLENGE, &bearer_proof(&bearer_key(&digest), 7376, CHALLENGE).unwrap()), "the key is not the proof's key");
        assert_ne!(proof, super::proof(bearer, 7376, CHALLENGE).unwrap(), "domain separated from the operator-token proof");
        assert!(is_valid_bearer_key(&bearer_key(&digest)));
        assert!(!is_valid_bearer_key(&digest));
        assert_eq!(bearer_proof(&digest, 7376, "short"), None);
    }

    /// RFC 4231 test cases 1, 2 and 6: the HMAC itself, including a key longer than one block.
    #[test]
    fn hmac_matches_rfc_4231() {
        let one = hmac_sha256(&[0x0b; 20], &[b"Hi There"]);
        assert_eq!(hex(&one), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        let two = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(hex(&two), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let six = hmac_sha256(
            &[0xaa; 131],
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"],
        );
        assert_eq!(hex(&six), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    /// Fixed vectors for the proof, computed independently (Python `hmac` + `hashlib.sha256`) over
    /// `permaura-health-proof:<port>:<challenge>`. Every client and the gateway are held to these.
    #[test]
    fn proof_vectors() {
        assert_eq!(
            proof(TOKEN, 7376, CHALLENGE).as_deref(),
            Some("4900eebce3ab46dfd1a9fa5d468d6f7021db4d73e4b37ba51fc75db2e223f767")
        );
        assert_eq!(
            proof(TOKEN, 7399, CHALLENGE).as_deref(),
            Some("2113557bb0c5c1811fd553ba0180fcc7b0314b92055601779cbab61edd661deb")
        );
        assert_eq!(
            proof(TOKEN, 7376, "AbCdEf_-0123456789").as_deref(),
            Some("a09bf5e8d626c26a083efef3b9354a784fb034b1d56a230a05d9a3587caa1845")
        );
    }

    #[test]
    fn verify_accepts_only_the_matching_proof() {
        let p = proof(TOKEN, 7376, CHALLENGE).unwrap();
        assert!(verify(TOKEN, 7376, CHALLENGE, &p));
        assert!(!verify("pgt_someoneelse", 7376, CHALLENGE, &p), "another token");
        assert!(!verify(TOKEN, 7399, CHALLENGE, &p), "the same answer relayed from another port");
        let other = new_challenge();
        assert!(!verify(TOKEN, 7376, &other, &p), "an answer to another challenge");
        assert!(!verify(TOKEN, 7376, CHALLENGE, &p.to_uppercase()), "exact match only");
        assert!(!verify(TOKEN, 7376, CHALLENGE, &p[..63]), "truncated");
        assert!(!verify(TOKEN, 7376, CHALLENGE, ""), "no answer");
        assert!(!verify("", 7376, CHALLENGE, &p), "no token to check with");
    }

    #[test]
    fn challenges_are_bounded_and_plain() {
        assert!(is_valid_challenge(&"a".repeat(16)));
        assert!(is_valid_challenge(&"Z9_-".repeat(16)));
        assert!(!is_valid_challenge(&"a".repeat(15)), "too short");
        assert!(!is_valid_challenge(&"a".repeat(65)), "too long");
        assert!(!is_valid_challenge("0123456789abcdef+"), "base64 standard alphabet");
        assert!(!is_valid_challenge("0123456789abcdef=="), "padding");
        assert!(!is_valid_challenge("0123456789abcdef\r\nx"), "header injection");
        assert!(!is_valid_challenge("0123456789abcdéf0"), "non-ASCII");
        assert_eq!(proof(TOKEN, 7376, "short"), None);
        assert_eq!(proof("", 7376, CHALLENGE), None);
    }

    #[test]
    fn a_fresh_challenge_is_valid_and_fresh() {
        let a = new_challenge();
        assert_eq!(a.len(), 64);
        assert!(is_valid_challenge(&a));
        assert_ne!(a, new_challenge());
    }
}
