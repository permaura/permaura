//! Ed25519 signing of control frames + the canonical signing preimage.
//!
//! High-risk frames are wrapped in [`Signed`], so the type system forbids an unsigned
//! `Revoke`/`ApprovalResult`. Signatures are computed over a **canonical, length-prefixed,
//! domain-separated preimage** ([`signing_preimage`]), never over serialized JSON, whose key
//! order and whitespace are ambiguous. `connection_id` + `seq` bind a signature to one socket
//! and position, so it cannot be replayed across connections or reordered.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::RelayError;
use crate::ProtocolVersion;

/// A payload plus a detached ed25519 signature over its canonical preimage. The type system
/// forbids an unsigned high-risk frame: `Frame::Revoke(Signed<Revoke>)` cannot be constructed
/// without a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    /// The signed payload.
    pub payload: T,
    /// base64(ed25519 64-byte signature) over the canonical preimage for this frame.
    pub sig: String,
}

impl<T> Signed<T> {
    /// Wrap a payload with an already-computed base64 signature.
    pub fn new(payload: T, sig: String) -> Self {
        Signed { payload, sig }
    }
}

/// Canonical signing preimage: deterministic, length-prefixed (`u32` BE length + bytes for
/// each field), domain-separated. A signature for one `domain` can never be lifted onto another
/// frame type; `connection_id` + `seq` bind it to this socket and order.
pub fn signing_preimage(
    domain: &[u8],
    version: ProtocolVersion,
    connection_id: &str,
    seq: u64,
    ts: i64,
    body: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut put = |b: &[u8]| {
        buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
        buf.extend_from_slice(b);
    };
    put(domain);
    put(&(version as u16).to_be_bytes());
    put(connection_id.as_bytes());
    put(&seq.to_be_bytes());
    put(&ts.to_be_bytes());
    put(body);
    buf
}

/// The Hello preimage binds (worker_id, org_id, challenge) to the connection. The Hello is
/// seq-less (pre-`AuthAck`); the server-issued `challenge` provides the freshness instead. Each
/// field is length-prefixed like every other body here, since nothing stops an id from holding the
/// NUL byte that once separated them.
pub fn hello_preimage(
    worker_id: &str,
    org_id: &str,
    challenge: &str,
    connection_id: &str,
    version: ProtocolVersion,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut put = |b: &[u8]| {
        body.extend_from_slice(&(b.len() as u32).to_be_bytes());
        body.extend_from_slice(b);
    };
    put(worker_id.as_bytes());
    put(org_id.as_bytes());
    put(challenge.as_bytes());
    signing_preimage(b"permaura-relay/v2/hello", version, connection_id, 0, 0, &body)
}

/// The approval-result preimage: what the **approver's device key** signs.
///
/// It binds the human decision to the exact held call: `job_id` + `approval_id` (single-use,
/// worker-minted) + `approve` + `request_hash` (must equal the held `PendingApproval`'s hash, so
/// the relay cannot redirect an approval onto a different call) + `approver` + `decided_at`. Each
/// field is length-prefixed so no concatenation collision is possible.
///
/// The device is **not** on the relay socket (the control plane is), so this inner preimage is
/// deliberately socket-agnostic (`connection_id=""`, `seq=0`, `ts=0`): freshness comes from the
/// single-use `approval_id` (a resolved approval is idempotent and never re-runs) and the held
/// call's TTL, not from socket binding. The worker verifies this signature against an approver key
/// it holds **locally**, so a compromised control plane can drop or delay an approval but can never
/// forge one.
///
/// How that local key was enrolled depends on placement. A local or tunnelled gateway pairs it
/// out-of-band, from a client on its own host, and the control plane has no write path at all. A
/// hosted worker has no such host, so its FIRST device is paired under an owner-scoped Operator
/// session plus a single-use step-up ticket (a control-plane-adjacent anchor), and every device
/// after it must be co-signed by a device already trusted. The forgery bound therefore still holds
/// once a hosted worker has one device: from then on the CP cannot add a signer on its own.
pub fn approval_result_preimage(
    job_id: &str,
    approval_id: &str,
    approve: bool,
    request_hash: &str,
    approver: &str,
    decided_at: i64,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut put = |b: &[u8]| {
        body.extend_from_slice(&(b.len() as u32).to_be_bytes());
        body.extend_from_slice(b);
    };
    put(job_id.as_bytes());
    put(approval_id.as_bytes());
    put(&[approve as u8]);
    put(request_hash.as_bytes());
    put(approver.as_bytes());
    put(&decided_at.to_be_bytes());
    signing_preimage(
        b"permaura-relay/v1/approval-result",
        ProtocolVersion::CURRENT,
        "",
        0,
        0,
        &body,
    )
}

/// The approver-pairing preimage: what a device signs to PROVE POSSESSION of its private key during
/// the pairing ceremony that promotes a recorded key to a trusted one. Domain-separated from the
/// approval preimage, so a pairing signature can never be replayed as an approval. `issued_at`
/// bounds replay.
///
/// A possession proof only shows that whoever sent the blob holds the matching private key; it says
/// nothing about whether that device should be trusted, so it is never the whole gate. On a local or
/// tunnelled gateway the rest of the gate is positional: the pairing endpoint is reachable only off
/// the broker (LAN-direct / loopback, operator-authed). A fresh proof is then enough to trust
/// the key. A hosted worker has no loopback peer to require, so the rest of the gate is identity:
/// an owner-scoped Operator session plus a single-use, key-bound, short-TTL step-up ticket, and that
/// combination enrols the first device only; every later device additionally needs a co-signature
/// from a device already in the keyring.
pub fn approver_pairing_preimage(approver_id: &str, pubkey_b64: &str, issued_at: i64) -> Vec<u8> {
    let mut body = Vec::new();
    let mut put = |b: &[u8]| {
        body.extend_from_slice(&(b.len() as u32).to_be_bytes());
        body.extend_from_slice(b);
    };
    put(approver_id.as_bytes());
    put(pubkey_b64.as_bytes());
    put(&issued_at.to_be_bytes());
    signing_preimage(
        b"permaura-relay/v1/approver-pairing",
        ProtocolVersion::CURRENT,
        "",
        0,
        0,
        &body,
    )
}

/// What a trusted device signs to authorise a control-plane request made ON ITS BEHALF but not
/// through the approval queue: re-registering its own push entry, and asking for a fresh set of
/// recovery codes.
///
/// Domain-separated from both the approval and the pairing preimages, so neither of those signatures
/// can be replayed as one of these and vice versa. `issued_at` bounds replay the same way pairing
/// does; the worker checks it against its own clock.
///
/// `subject` is whatever the action is about and is part of the signature rather than beside it: for
/// a push re-registration it is the push token being installed, so a signature obtained for one token
/// cannot be used to install another, and for a request that is about nothing in particular it is
/// empty. The pair `(action, subject)` is what the signature commits to.
pub fn device_control_preimage(
    action: &str,
    approver_id: &str,
    subject: &str,
    issued_at: i64,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut put = |b: &[u8]| {
        body.extend_from_slice(&(b.len() as u32).to_be_bytes());
        body.extend_from_slice(b);
    };
    put(action.as_bytes());
    put(approver_id.as_bytes());
    put(subject.as_bytes());
    put(&issued_at.to_be_bytes());
    signing_preimage(
        b"permaura-relay/v1/device-control",
        ProtocolVersion::CURRENT,
        "",
        0,
        0,
        &body,
    )
}

/// The approval-result preimage bound to ONE gateway: [`approval_result_preimage`] with the target
/// gateway's `audience` as the first body field, under its own domain.
///
/// The v1 preimage names nothing about which gateway it was meant for, and one device key is trusted
/// by every gateway its owner pairs it with. So a gateway that showed the device a held call with
/// another gateway's `approval_id` and `request_hash` could collect a signature and replay it there,
/// and it would verify. The audience is a random value each gateway mints once and serves beside its
/// approvals; the device pins it per gateway at pairing, and a gateway refuses a v2 signature whose
/// audience is not its own. A v1 signature can never be read as a v2 one or the reverse, because the
/// domains differ.
pub fn approval_result_preimage_v2(
    audience: &str,
    job_id: &str,
    approval_id: &str,
    approve: bool,
    request_hash: &str,
    approver: &str,
    decided_at: i64,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut put = |b: &[u8]| {
        body.extend_from_slice(&(b.len() as u32).to_be_bytes());
        body.extend_from_slice(b);
    };
    put(audience.as_bytes());
    put(job_id.as_bytes());
    put(approval_id.as_bytes());
    put(&[approve as u8]);
    put(request_hash.as_bytes());
    put(approver.as_bytes());
    put(&decided_at.to_be_bytes());
    signing_preimage(
        b"permaura-relay/v2/approval-result",
        ProtocolVersion::CURRENT,
        "",
        0,
        0,
        &body,
    )
}

/// The approval-result preimage that also binds WHAT THE APPROVER WAS SHOWN: the v2 fields
/// with the device's own [`crate::display::approval_display_full_digest`] of the rendering it put on screen
/// placed after `request_hash`, under its own domain.
///
/// `request_hash` alone binds the full parameters, but no approval surface showed them, so an agent
/// could ask for one thing in its reason and have the approver sign another. The display digest is
/// computed by the device over the rows it rendered, and the gateway recomputes it from the held row,
/// so a broker that shows one rendering while the device signs for another call is refused.
///
/// `audience` is empty for a device that has no audience pinned for this gateway; the gateway then
/// applies the v1 rules to it, so binding the display never widens which gateways a signature is
/// good for.
#[allow(clippy::too_many_arguments)]
pub fn approval_result_preimage_v3(
    audience: &str,
    job_id: &str,
    approval_id: &str,
    approve: bool,
    request_hash: &str,
    display_digest: &str,
    approver: &str,
    decided_at: i64,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut put = |b: &[u8]| {
        body.extend_from_slice(&(b.len() as u32).to_be_bytes());
        body.extend_from_slice(b);
    };
    put(audience.as_bytes());
    put(job_id.as_bytes());
    put(approval_id.as_bytes());
    put(&[approve as u8]);
    put(request_hash.as_bytes());
    put(display_digest.as_bytes());
    put(approver.as_bytes());
    put(&decided_at.to_be_bytes());
    signing_preimage(
        b"permaura-relay/v3/approval-result",
        ProtocolVersion::CURRENT,
        "",
        0,
        0,
        &body,
    )
}

/// The device-control preimage bound to ONE gateway: [`device_control_preimage`] with the target
/// gateway's `audience` as the first body field, under its own domain. See
/// [`approval_result_preimage_v2`] for why: a recovery-code request signed for one gateway must not
/// be redeemable on another that trusts the same key.
pub fn device_control_preimage_v2(
    audience: &str,
    action: &str,
    approver_id: &str,
    subject: &str,
    issued_at: i64,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut put = |b: &[u8]| {
        body.extend_from_slice(&(b.len() as u32).to_be_bytes());
        body.extend_from_slice(b);
    };
    put(audience.as_bytes());
    put(action.as_bytes());
    put(approver_id.as_bytes());
    put(subject.as_bytes());
    put(&issued_at.to_be_bytes());
    signing_preimage(
        b"permaura-relay/v2/device-control",
        ProtocolVersion::CURRENT,
        "",
        0,
        0,
        &body,
    )
}

/// Sign `preimage` with an ed25519 key → base64 signature.
pub fn sign(signing_key: &SigningKey, preimage: &[u8]) -> String {
    STANDARD.encode(signing_key.sign(preimage).to_bytes())
}

/// A raw 32-byte ed25519 public key, refusing the two kinds no key generator produces: a point of
/// small order, under which one fixed signature verifies as every message, and a non-canonical
/// encoding (`y >= p`), which would give one point two spellings and so two fingerprints.
pub fn strict_verifying_key(raw: &[u8; 32]) -> Result<VerifyingKey, RelayError> {
    let vk = VerifyingKey::from_bytes(raw).map_err(|_| RelayError::signature("invalid public key"))?;
    if vk.is_weak() {
        return Err(RelayError::signature("public key has small order"));
    }
    if vk.to_edwards().compress().as_bytes() != raw {
        return Err(RelayError::signature("public key is not canonically encoded"));
    }
    Ok(vk)
}

fn decode_verifying_key(verifying_key_b64: &str) -> Result<VerifyingKey, RelayError> {
    let vk_bytes = STANDARD
        .decode(verifying_key_b64)
        .map_err(|_| RelayError::signature("bad public-key encoding"))?;
    let vk_arr: [u8; 32] = vk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RelayError::signature("public key must be 32 bytes"))?;
    strict_verifying_key(&vk_arr)
}

/// Verify a base64 signature over `preimage` against a base64-encoded 32-byte ed25519 public
/// key. Returns `Ok(())` only on a valid signature; any decoding/length/verification failure
/// is a [`RelayError::Signature`]. The check is `verify_strict` over a [`strict_verifying_key`], so
/// neither a small-order key nor a small-order or non-canonical `R` passes.
pub fn verify(verifying_key_b64: &str, preimage: &[u8], sig_b64: &str) -> Result<(), RelayError> {
    let vk = decode_verifying_key(verifying_key_b64)?;
    let sig_bytes = STANDARD
        .decode(sig_b64)
        .map_err(|_| RelayError::signature("bad signature encoding"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| RelayError::signature("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(preimage, &sig)
        .map_err(|_| RelayError::signature("signature verification failed"))
}

/// True iff `b64` is the one canonical base64 spelling of a [`strict_verifying_key`]. Used to reject
/// a malformed or weak key at enrollment: an invalid key would otherwise be stored verbatim and
/// permanently brick relay authentication for that worker, and a weak one would let anyone sign as
/// it. Because only one spelling of one point passes, a fingerprint of the text names the point.
pub fn validate_pubkey(b64: &str) -> bool {
    decode_verifying_key(b64).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (SigningKey, String) {
        // Deterministic seed → no RNG needed in tests.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk_b64 = STANDARD.encode(sk.verifying_key().to_bytes());
        (sk, vk_b64)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, vk) = keypair();
        let pre = signing_preimage(b"permaura-relay/v1/test", ProtocolVersion::V1, "conn-1", 5, 123, b"body");
        let sig = sign(&sk, &pre);
        assert!(verify(&vk, &pre, &sig).is_ok());
    }

    #[test]
    fn tampered_preimage_fails() {
        let (sk, vk) = keypair();
        let pre = signing_preimage(b"permaura-relay/v1/test", ProtocolVersion::V1, "conn-1", 5, 123, b"body");
        let sig = sign(&sk, &pre);
        // Same everything but seq 6 → different preimage → must fail.
        let other = signing_preimage(b"permaura-relay/v1/test", ProtocolVersion::V1, "conn-1", 6, 123, b"body");
        assert!(verify(&vk, &other, &sig).is_err());
    }

    #[test]
    fn wrong_domain_fails() {
        let (sk, vk) = keypair();
        let pre = signing_preimage(b"permaura-relay/v1/hello", ProtocolVersion::V1, "c", 0, 0, b"x");
        let sig = sign(&sk, &pre);
        let other = signing_preimage(b"permaura-relay/v1/revoke", ProtocolVersion::V1, "c", 0, 0, b"x");
        assert!(verify(&vk, &other, &sig).is_err(), "a sig must not lift across domains");
    }

    #[test]
    fn wrong_connection_fails() {
        let (sk, vk) = keypair();
        let pre = hello_preimage("worker_1", "org_1", "chal", "conn-A", ProtocolVersion::V1);
        let sig = sign(&sk, &pre);
        let other = hello_preimage("worker_1", "org_1", "chal", "conn-B", ProtocolVersion::V1);
        assert!(verify(&vk, &other, &sig).is_err(), "a sig must bind to its connection");
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _vk) = keypair();
        let pre = signing_preimage(b"d", ProtocolVersion::V1, "c", 1, 1, b"b");
        let sig = sign(&sk, &pre);
        let other_vk = STANDARD.encode(SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes());
        assert!(verify(&other_vk, &pre, &sig).is_err());
    }

    #[test]
    fn malformed_inputs_fail_cleanly() {
        let (_sk, vk) = keypair();
        assert!(verify("not-base64!!", b"x", "also-bad").is_err());
        assert!(verify(&vk, b"x", "AAAA").is_err()); // valid base64, wrong sig length
    }

    #[test]
    fn approval_result_signature_roundtrips_and_binds_every_field() {
        let (sk, vk) = keypair();
        let pre = approval_result_preimage("job_1", "appr_1", true, "hash_abc", "device:phone", 1_700_000_000_000);
        let sig = sign(&sk, &pre);
        assert!(verify(&vk, &pre, &sig).is_ok());

        // Each security-critical field is bound: flipping any one breaks the signature.
        let flips = [
            approval_result_preimage("job_2", "appr_1", true, "hash_abc", "device:phone", 1_700_000_000_000),
            approval_result_preimage("job_1", "appr_2", true, "hash_abc", "device:phone", 1_700_000_000_000),
            approval_result_preimage("job_1", "appr_1", false, "hash_abc", "device:phone", 1_700_000_000_000),
            approval_result_preimage("job_1", "appr_1", true, "hash_XYZ", "device:phone", 1_700_000_000_000),
            approval_result_preimage("job_1", "appr_1", true, "hash_abc", "device:other", 1_700_000_000_000),
            approval_result_preimage("job_1", "appr_1", true, "hash_abc", "device:phone", 1_700_000_000_001),
        ];
        for other in flips {
            assert!(verify(&vk, &other, &sig).is_err(), "every field must be bound by the signature");
        }
    }

    #[test]
    fn approval_result_does_not_lift_across_domains() {
        let (sk, vk) = keypair();
        // A signature over the approval preimage must not verify if someone re-labels the bytes as
        // another frame's preimage (length-prefix + domain separation).
        let pre = approval_result_preimage("j", "a", true, "h", "device:p", 1);
        let sig = sign(&sk, &pre);
        let masquerade = signing_preimage(b"permaura-relay/v1/hello", ProtocolVersion::CURRENT, "", 0, 0, b"x");
        assert!(verify(&vk, &masquerade, &sig).is_err());
    }

    #[test]
    fn pairing_signature_verifies_and_does_not_lift_to_an_approval() {
        let (sk, vk) = keypair();
        let pairing = approver_pairing_preimage("device:phone", &vk, 1_700_000_000_000);
        let sig = sign(&sk, &pairing);
        assert!(verify(&vk, &pairing, &sig).is_ok());
        // A pairing (proof-of-possession) signature must never verify as an approval: domain
        // separation stops a captured pairing sig from being replayed to approve a held call.
        let approval =
            approval_result_preimage("j", "a", true, "h", "device:phone", 1_700_000_000_000);
        assert!(
            verify(&vk, &approval, &sig).is_err(),
            "a pairing signature must not lift onto an approval"
        );
    }

    /// Frozen cross-implementation vectors. The same tuples are asserted in the TypeScript
    /// (the phone app's `lib/__tests__/approvalSig.test.ts`) and Swift ports, which are hand-written
    /// re-derivations of this format: without a shared fixture a silent divergence in any of the
    /// three ships as "the gateway rejects my signature" with no way to tell which side is wrong.
    ///
    /// Note the version field is `0000` (`ProtocolVersion::V1` has no explicit discriminant), NOT
    /// the `RELAY_PROTOCOL_VERSION = 1` logging constant. That trap is why these are pinned.
    #[test]
    fn preimage_vectors_are_frozen() {
        const JOB: &str = "job_7f3a9c2e";
        const APPROVAL: &str = "apr_1b8d4f60";
        const HASH: &str = "5f2c1d9e8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d";
        const APPROVER: &str = "device:a1b2c3d4e5f6";
        const PUBKEY: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
        const AT: i64 = 1_753_440_000_000;

        assert_eq!(
            hex(&approval_result_preimage(JOB, APPROVAL, true, HASH, APPROVER, AT)),
            "000000217065726d617572612d72656c61792f76312f617070726f76616c2d726573756c74000000\
             020000000000000000000800000000000000000000000800000000000000000000008c0000000c6a\
             6f625f37663361396332650000000c6170725f31623864346636300000000101000000403566326331\
             6439653862376136633564346533663261316230633964386537663661356234633364326531663061\
             396238633764366535663461336232633164000000136465766963653a61316232633364346535663\
             60000000800000198412b1800"
                .replace([' ', '\n'], "")
        );

        assert_eq!(
            hex(&approval_result_preimage(JOB, APPROVAL, false, HASH, APPROVER, AT)),
            "000000217065726d617572612d72656c61792f76312f617070726f76616c2d726573756c74000000\
             020000000000000000000800000000000000000000000800000000000000000000008c0000000c6a\
             6f625f37663361396332650000000c6170725f31623864346636300000000100000000403566326331\
             6439653862376136633564346533663261316230633964386537663661356234633364326531663061\
             396238633764366535663461336232633164000000136465766963653a61316232633364346535663\
             60000000800000198412b1800"
                .replace([' ', '\n'], "")
        );

        assert_eq!(
            hex(&approver_pairing_preimage(APPROVER, PUBKEY, AT)),
            "000000227065726d617572612d72656c61792f76312f617070726f7665722d70616972696e6700000\
             0020000000000000000000800000000000000000000000800000000000000000000006700000013646\
             5766963653a613162326333643465356636000000403362366132376263636562366134326436326133\
             613864303261366630643733363533323135373731646532343361363361633034386131386235396461\
             32390000000800000198412b1800"
                .replace([' ', '\n'], "")
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const AUDIENCE: &str = "aud_0f1e2d3c4b5a69788796a5b4c3d2e1f0";

    /// The v2 (gateway-bound) preimages, frozen the same way and for the same reason as
    /// [`preimage_vectors_are_frozen`]: the phone (`lib/__tests__/preimage.test.ts`) and the watch
    /// (`scripts/watch/PreimageVectors.swift`) assert these exact strings.
    #[test]
    fn v2_preimage_vectors_are_frozen() {
        const JOB: &str = "job_7f3a9c2e";
        const APPROVAL: &str = "apr_1b8d4f60";
        const HASH: &str = "5f2c1d9e8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d";
        const APPROVER: &str = "device:a1b2c3d4e5f6";
        const AT: i64 = 1_753_440_000_000;

        assert_eq!(
            hex(&approval_result_preimage_v2(AUDIENCE, JOB, APPROVAL, true, HASH, APPROVER, AT)),
            "000000217065726d617572612d72656c61792f76322f617070726f76616c2d726573756c74000000\
             02000000000000000000080000000000000000000000080000000000000000000000b40000002461\
             75645f30663165326433633462356136393738383739366135623463336432653166300000000c6a\
             6f625f37663361396332650000000c6170725f31623864346636300000000101000000403566326331\
             6439653862376136633564346533663261316230633964386537663661356234633364326531663061\
             396238633764366535663461336232633164000000136465766963653a61316232633364346535663\
             60000000800000198412b1800"
                .replace([' ', '\n'], "")
        );
        assert_eq!(
            hex(&approval_result_preimage_v2(AUDIENCE, JOB, APPROVAL, false, HASH, APPROVER, AT)),
            "000000217065726d617572612d72656c61792f76322f617070726f76616c2d726573756c74000000\
             02000000000000000000080000000000000000000000080000000000000000000000b40000002461\
             75645f30663165326433633462356136393738383739366135623463336432653166300000000c6a\
             6f625f37663361396332650000000c6170725f31623864346636300000000100000000403566326331\
             6439653862376136633564346533663261316230633964386537663661356234633364326531663061\
             396238633764366535663461336232633164000000136465766963653a61316232633364346535663\
             60000000800000198412b1800"
                .replace([' ', '\n'], "")
        );
        assert_eq!(
            hex(&device_control_preimage_v2(
                AUDIENCE,
                "device-enroll",
                APPROVER,
                "ExponentPushToken[abc123]",
                AT
            )),
            "000000207065726d617572612d72656c61792f76322f6465766963652d636f6e74726f6c00000002\
             000000000000000000080000000000000000000000080000000000000000000000790000002461756\
             45f30663165326433633462356136393738383739366135623463336432653166300000000d646576\
             6963652d656e726f6c6c000000136465766963653a613162326333643465356636000000194578706f\
             6e656e7450757368546f6b656e5b6162633132335d0000000800000198412b1800"
                .replace([' ', '\n'], "")
        );
        assert_eq!(
            hex(&device_control_preimage_v2(AUDIENCE, "recovery-codes", APPROVER, "", AT)),
            "000000207065726d617572612d72656c61792f76322f6465766963652d636f6e74726f6c00000002\
             000000000000000000080000000000000000000000080000000000000000000000610000002461756\
             45f30663165326433633462356136393738383739366135623463336432653166300000000e726563\
             6f766572792d636f646573000000136465766963653a61316232633364346535663600000000000000\
             0800000198412b1800"
                .replace([' ', '\n'], "")
        );
    }

    /// The v3 (display-bound) preimage, frozen like the others: the phone, the watch and the desktop
    /// assert these exact strings. `DISPLAY` is an opaque 64-hex input here; the digests themselves are
    /// frozen in `display.rs`.
    #[test]
    fn v3_preimage_vectors_are_frozen() {
        const JOB: &str = "job_7f3a9c2e";
        const APPROVAL: &str = "apr_1b8d4f60";
        const HASH: &str = "5f2c1d9e8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d";
        const DISPLAY: &str = "870da75652dd2bc268b3452957f6e0b4177de4ad62d4cde9a2c1a60a27a1fd65";
        const APPROVER: &str = "device:a1b2c3d4e5f6";
        const AT: i64 = 1_753_440_000_000;

        assert_eq!(
            hex(&approval_result_preimage_v3(AUDIENCE, JOB, APPROVAL, true, HASH, DISPLAY, APPROVER, AT)),
            "000000217065726d617572612d72656c61792f76332f617070726f76616c2d726573756c74000000\
             02000000000000000000080000000000000000000000080000000000000000000000f80000002461\
             75645f30663165326433633462356136393738383739366135623463336432653166300000000c6a\
             6f625f37663361396332650000000c6170725f31623864346636300000000101000000403566326331\
             6439653862376136633564346533663261316230633964386537663661356234633364326531663061\
             396238633764366535663461336232633164000000403837306461373536353264643262633236386233\
             3435323935376636653062343137376465346164363264346364653961326331613630613237613166\
             643635000000136465766963653a6131623263336434653566360000000800000198412b1800"
                .replace([' ', '\n'], "")
        );
        // No audience pinned: the field is present and empty.
        assert_eq!(
            hex(&approval_result_preimage_v3("", JOB, APPROVAL, true, HASH, DISPLAY, APPROVER, AT)),
            "000000217065726d617572612d72656c61792f76332f617070726f76616c2d726573756c74000000\
             02000000000000000000080000000000000000000000080000000000000000000000d40000000000\
             00000c6a6f625f37663361396332650000000c6170725f31623864346636300000000101000000403566\
             3263316439653862376136633564346533663261316230633964386537663661356234633364326531\
             6630613962386337643665356634613362326331640000004038373064613735363532646432626332\
             3638623334353239353766366530623431373764653461643632643463646539613263316136306132\
             37613166643635000000136465766963653a6131623263336434653566360000000800000198412b1800"
                .replace([' ', '\n'], "")
        );
    }

    #[test]
    fn a_v3_signature_binds_the_display_and_stands_in_for_no_other_version() {
        let (sk, vk) = keypair();
        let at = 1_700_000_000_000;
        let pre = approval_result_preimage_v3(AUDIENCE, "job_1", "appr_1", true, "hash_abc", "shown_1", "device:phone", at);
        let sig = sign(&sk, &pre);
        assert!(verify(&vk, &pre, &sig).is_ok());
        let other_display =
            approval_result_preimage_v3(AUDIENCE, "job_1", "appr_1", true, "hash_abc", "shown_2", "device:phone", at);
        assert!(verify(&vk, &other_display, &sig).is_err(), "a different rendering is a different preimage");
        let v2 = approval_result_preimage_v2(AUDIENCE, "job_1", "appr_1", true, "hash_abc", "device:phone", at);
        assert!(verify(&vk, &v2, &sig).is_err());
        assert!(verify(&vk, &v2, &sign(&sk, &v2)).is_ok());
        let v1 = approval_result_preimage("job_1", "appr_1", true, "hash_abc", "device:phone", at);
        assert!(verify(&vk, &v1, &sig).is_err());
        let unbound =
            approval_result_preimage_v3("", "job_1", "appr_1", true, "hash_abc", "shown_1", "device:phone", at);
        assert!(verify(&vk, &unbound, &sig).is_err(), "the audience is still bound");
    }

    #[test]
    fn a_v2_signature_is_bound_to_its_audience() {
        let (sk, vk) = keypair();
        let at = 1_700_000_000_000;
        let pre = approval_result_preimage_v2(AUDIENCE, "job_1", "appr_1", true, "hash_abc", "device:phone", at);
        let sig = sign(&sk, &pre);
        assert!(verify(&vk, &pre, &sig).is_ok());
        // The same decision for another gateway is a different preimage: a signature collected by one
        // gateway cannot be presented to another.
        let elsewhere =
            approval_result_preimage_v2("aud_other", "job_1", "appr_1", true, "hash_abc", "device:phone", at);
        assert!(verify(&vk, &elsewhere, &sig).is_err());
        let control = device_control_preimage_v2(AUDIENCE, "recovery-codes", "device:phone", "", at);
        let control_sig = sign(&sk, &control);
        assert!(verify(&vk, &control, &control_sig).is_ok());
        assert!(verify(
            &vk,
            &device_control_preimage_v2("aud_other", "recovery-codes", "device:phone", "", at),
            &control_sig
        )
        .is_err());
    }

    #[test]
    fn v1_and_v2_signatures_never_stand_in_for_each_other() {
        let (sk, vk) = keypair();
        let at = 1_700_000_000_000;
        let v1 = approval_result_preimage("job_1", "appr_1", true, "hash_abc", "device:phone", at);
        let v2 = approval_result_preimage_v2("", "job_1", "appr_1", true, "hash_abc", "device:phone", at);
        // Even with an empty audience the domains differ, so neither verifies as the other.
        assert!(verify(&vk, &v2, &sign(&sk, &v1)).is_err());
        assert!(verify(&vk, &v1, &sign(&sk, &v2)).is_err());
        let c1 = device_control_preimage("recovery-codes", "device:phone", "", at);
        let c2 = device_control_preimage_v2("", "recovery-codes", "device:phone", "", at);
        assert!(verify(&vk, &c2, &sign(&sk, &c1)).is_err());
        assert!(verify(&vk, &c1, &sign(&sk, &c2)).is_err());
        // And an approval signature never verifies as device control, in either version.
        assert!(verify(&vk, &c2, &sign(&sk, &v2)).is_err());
    }

    #[test]
    fn validate_pubkey_accepts_real_rejects_garbage() {
        let (_sk, vk) = keypair();
        assert!(validate_pubkey(&vk));
        assert!(!validate_pubkey("not-base64!!"));
        assert!(!validate_pubkey(&STANDARD.encode([0u8; 10]))); // wrong length
        assert!(!validate_pubkey(""));
    }

    #[test]
    fn hello_fields_cannot_slide_past_each_other() {
        let a = hello_preimage("worker\0org-b", "org-a", "chal", "conn", ProtocolVersion::CURRENT);
        let b = hello_preimage("worker", "org-b\0org-a", "chal", "conn", ProtocolVersion::CURRENT);
        assert_ne!(a, b, "a NUL in an id must not move a field boundary");
    }

    fn unhex32(s: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        bytes.try_into().unwrap()
    }

    /// The eight points of small order, canonically encoded: the identity, the point of order 2, two of order 4 and four of order 8.
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    ];

    /// The identity point as a key, and the 64 bytes `R = identity, s = 0`, which a non-strict verify accepts under that key for every message.
    fn identity_forgery() -> (String, String) {
        let mut forged = [0u8; 64];
        forged[0] = 1;
        (STANDARD.encode(unhex32(SMALL_ORDER[0])), STANDARD.encode(forged))
    }

    #[test]
    fn a_small_order_key_is_never_enrolled_and_one_fixed_signature_verifies_nothing() {
        let (vk, sig) = identity_forgery();
        assert!(!validate_pubkey(&vk), "a weak key must not be enrollable");
        let every_message = [
            approver_pairing_preimage("device:x", &vk, 1_753_440_000_000),
            approval_result_preimage_v3("aud_a", "job_1", "apr_a", true, "rh_a", "dd_a", "device:x", 1),
            approval_result_preimage_v3("aud_b", "job_2", "apr_b", true, "rh_b", "dd_b", "device:x", 2),
            approval_result_preimage_v2("aud_a", "job_1", "apr_a", true, "rh_a", "device:x", 1),
            approval_result_preimage("job_1", "apr_a", true, "rh_a", "device:x", 1),
            device_control_preimage_v2("aud_a", "recovery-codes", "device:x", "", 1),
            device_control_preimage("push-register", "device:x", "token", 1),
            b"any bytes at all".to_vec(),
        ];
        for pre in &every_message {
            assert!(verify(&vk, pre, &sig).is_err(), "the identity key must not verify {pre:?}");
        }
    }

    #[test]
    fn every_small_order_key_is_refused() {
        for point in SMALL_ORDER {
            let vk = STANDARD.encode(unhex32(point));
            assert!(!validate_pubkey(&vk), "{point} has small order and must not be enrollable");
            let mut forged = [0u8; 64];
            forged[..32].copy_from_slice(&unhex32(point));
            assert!(verify(&vk, b"x", &STANDARD.encode(forged)).is_err(), "{point} must verify nothing");
        }
    }

    /// One point, one encoding: a key written with `y >= p` names a point that also has a canonical encoding, and the two would fingerprint as two devices.
    #[test]
    fn a_non_canonical_key_encoding_is_refused() {
        for (what, noncanonical) in [
            ("the identity, y = p + 1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            ("a point of large order, y = p + 3", "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            ("the same point with the sign bit set", "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ] {
            let vk = STANDARD.encode(unhex32(noncanonical));
            assert!(!validate_pubkey(&vk), "{what} must not be enrollable");
            let mut forged = [0u8; 64];
            forged[0] = 1;
            assert!(verify(&vk, b"x", &STANDARD.encode(forged)).is_err(), "{what} must verify nothing");
        }
        // The last base64 digit of a 32-byte key carries two padding bits; setting one spells the same bytes differently.
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let (_sk, vk) = keypair();
        let mut text = vk.into_bytes();
        let digit = ALPHABET.iter().position(|&c| c == text[42]).unwrap();
        text[42] = ALPHABET[digit ^ 1];
        assert!(!validate_pubkey(&String::from_utf8(text).unwrap()), "a second spelling of the same key must not be enrollable");
    }
}
