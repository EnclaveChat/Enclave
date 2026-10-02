//! Heads as C2SP checkpoints, cosigned by witnesses in the C2SP formats
//! (`docs/12-servers.md` §3.3a).
//!
//! Enclave's own cosignatures are composite (Ed448 + ML-DSA-87) over the
//! 64-byte head; that's what clients check. Each witness also cosigns the
//! same head, at the same time, the way the transparency-log ecosystem does
//! ([c2sp.org/tlog-checkpoint], [c2sp.org/tlog-cosignature],
//! [c2sp.org/signed-note]), with an Ed25519 `cosignature/v1` and an
//! ML-DSA-44 `subtree/v1` cosignature, so tools built for that ecosystem
//! can follow Enclave's witnesses:
//!
//! ```text
//! checkpoint = origin "\n" decimal(epoch) "\n" base64(root) "\n"
//! origin     = "enclave-kt/" hex(server id)
//! key name   = "enclave-witness/" hex(witness id)
//! key id     = SHA-256(key name ‖ "\n" ‖ type ‖ public key)[0..4]        type 0x04 Ed25519, 0x06 ML-DSA-44
//! vkey       = key name "+" hex(key id) "+" base64(type ‖ public key)
//! Ed25519    signs "cosignature/v1\n" "time " decimal(time) "\n" checkpoint
//! ML-DSA-44  signs "subtree/v1\n\0" ‖ u8 len ‖ key name ‖ u64(time) ‖ u8 len ‖ origin
//!                  ‖ u64(0) ‖ u64(epoch) ‖ root (32), empty context
//! note       = checkpoint "\n" ("— " key name " " base64(key id ‖ u64(time) ‖ signature) "\n")×2
//! ```
//!
//! Both keys are derived from the witness's composite seed (label
//! `enclave/v1/kt/c2sp-key`) and named in its descriptor, which the
//! composite key signs. A checkpoint's tree size is the akd epoch.
//!
//! [c2sp.org/tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
//! [c2sp.org/tlog-cosignature]: https://c2sp.org/tlog-cosignature
//! [c2sp.org/signed-note]: https://c2sp.org/signed-note

use crate::head::TreeHead;
use crate::{KtError, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{MlDsa44SigningKey, mldsa44_verify};
use sha2::{Digest, Sha256};

/// Label deriving a witness's C2SP keys from its composite seed.
pub const C2SP_KEY_LABEL: &str = "enclave/v1/kt/c2sp-key";
/// Signed-note key type of an Ed25519 `cosignature/v1` key.
pub const COSIGNATURE_V1: u8 = 0x04;
/// Signed-note key type of an ML-DSA-44 cosignature key.
pub const MLDSA44: u8 = 0x06;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The checkpoint origin of a server's log.
pub fn origin(server: &[u8; 16]) -> String {
    format!("enclave-kt/{}", hex(server))
}

/// A head as a checkpoint body.
pub fn checkpoint(head: &TreeHead) -> String {
    format!(
        "{}\n{}\n{}\n",
        origin(&head.server),
        head.epoch,
        B64.encode(head.root)
    )
}

/// What an Ed25519 `cosignature/v1` signs.
pub fn cosignature_message(checkpoint: &str, time: u64) -> Vec<u8> {
    format!("cosignature/v1\ntime {time}\n{checkpoint}").into_bytes()
}

/// What an ML-DSA-44 cosignature signs: the `subtree/v1` message for the
/// whole tree.
pub fn subtree_message(name: &str, time: u64, origin: &str, size: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut m = b"subtree/v1\n\0".to_vec();
    m.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
    m.extend_from_slice(name.as_bytes());
    m.extend_from_slice(&time.to_be_bytes());
    m.push(u8::try_from(origin.len()).unwrap_or(u8::MAX));
    m.extend_from_slice(origin.as_bytes());
    m.extend_from_slice(&0u64.to_be_bytes());
    m.extend_from_slice(&size.to_be_bytes());
    m.extend_from_slice(root);
    m
}

/// The signed-note key name of a witness.
pub fn key_name(witness: &[u8; 16]) -> String {
    format!("enclave-witness/{}", hex(witness))
}

/// The signed-note key id of a key of type `kind`.
pub fn key_id(name: &str, kind: u8, public: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([kind]);
    h.update(public);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// The verifier key string (`name+keyid+base64`).
pub fn vkey(name: &str, kind: u8, public: &[u8]) -> String {
    let mut k = vec![kind];
    k.extend_from_slice(public);
    format!(
        "{name}+{}+{}",
        hex(&key_id(name, kind, public)),
        B64.encode(k)
    )
}

/// A witness's C2SP cosigning keys.
pub struct C2spKey {
    name: String,
    ed: SigningKey,
    ml: MlDsa44SigningKey,
}

impl C2spKey {
    /// The keys of witness `witness`, derived from its composite seed.
    pub fn derive(witness: &[u8; 16], composite_seed: &[u8]) -> Self {
        let ed: [u8; 32] =
            enclave_crypto::kmac::kmac256(composite_seed, b"ed25519", C2SP_KEY_LABEL);
        let ml: [u8; 32] =
            enclave_crypto::kmac::kmac256(composite_seed, b"ml-dsa-44", C2SP_KEY_LABEL);
        Self {
            name: key_name(witness),
            ed: SigningKey::from_bytes(&ed),
            ml: MlDsa44SigningKey::from_seed(&ml),
        }
    }

    /// The verifier keys: Ed25519, then ML-DSA-44.
    pub fn vkeys(&self) -> Vec<String> {
        vec![
            vkey(
                &self.name,
                COSIGNATURE_V1,
                &self.ed.verifying_key().to_bytes(),
            ),
            vkey(&self.name, MLDSA44, self.ml.public()),
        ]
    }

    /// The signed note: `head` as a checkpoint, cosigned at `time`.
    pub fn cosign(&self, head: &TreeHead, time: u64, rng: &mut HedgedRng) -> Result<String> {
        let text = checkpoint(head);
        let ed_pk = self.ed.verifying_key().to_bytes();
        let ed_sig = self.ed.sign(&cosignature_message(&text, time));
        let ml_sig = self
            .ml
            .sign(
                &subtree_message(
                    &self.name,
                    time,
                    &origin(&head.server),
                    head.epoch,
                    &head.root,
                ),
                rng,
            )
            .map_err(|_| KtError::Signature)?;
        let line = |id: [u8; 4], sig: &[u8]| {
            let mut b = id.to_vec();
            b.extend_from_slice(&time.to_be_bytes());
            b.extend_from_slice(sig);
            format!("\u{2014} {} {}\n", self.name, B64.encode(b))
        };
        Ok(format!(
            "{text}\n{}{}",
            line(
                key_id(&self.name, COSIGNATURE_V1, &ed_pk),
                &ed_sig.to_bytes()
            ),
            line(key_id(&self.name, MLDSA44, self.ml.public()), &ml_sig)
        ))
    }
}

/// Verify a signed note against one verifier key (either type): the
/// checkpoint it carries and the time it was cosigned.
pub fn verify_note(vkey: &str, note: &str) -> Result<(String, u64)> {
    let bad = || KtError::Malformed;
    let mut parts = vkey.splitn(3, '+');
    let (name, id, key) = (
        parts.next().ok_or_else(bad)?,
        parts.next().ok_or_else(bad)?,
        parts.next().ok_or_else(bad)?,
    );
    let key = B64.decode(key).map_err(|_| bad())?;
    let (&kind, public) = key.split_first().ok_or_else(bad)?;
    let want = key_id(name, kind, public);
    if id != hex(&want) {
        return Err(bad());
    }
    let (text, sigs) = note.split_once("\n\n").ok_or_else(bad)?;
    let text = format!("{text}\n");
    let mut lines = text.lines();
    let (Some(origin), Some(size), Some(root)) = (lines.next(), lines.next(), lines.next()) else {
        return Err(bad());
    };
    let size: u64 = size.parse().map_err(|_| bad())?;
    let root: [u8; 32] = B64
        .decode(root)
        .ok()
        .and_then(|r| r.try_into().ok())
        .ok_or_else(bad)?;
    for line in sigs.lines() {
        let rest = line.strip_prefix("\u{2014} ").ok_or_else(bad)?;
        let (n, b) = rest.split_once(' ').ok_or_else(bad)?;
        let raw = B64.decode(b).map_err(|_| bad())?;
        if n != name || raw.len() < 12 || raw[..4] != want {
            continue;
        }
        let time = u64::from_be_bytes(raw[4..12].try_into().map_err(|_| bad())?);
        let sig = &raw[12..];
        let ok = match kind {
            COSIGNATURE_V1 => {
                let pk: [u8; 32] = public.try_into().map_err(|_| bad())?;
                let vk = VerifyingKey::from_bytes(&pk).map_err(|_| KtError::Signature)?;
                let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| bad())?;
                vk.verify(&cosignature_message(&text, time), &s).is_ok()
            }
            MLDSA44 => mldsa44_verify(
                public,
                &subtree_message(name, time, origin, size, &root),
                sig,
            ),
            _ => return Err(bad()),
        };
        return if ok {
            Ok((text, time))
        } else {
            Err(KtError::Signature)
        };
    }
    Err(KtError::Signature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn head() -> TreeHead {
        TreeHead {
            server: [7; 16],
            epoch: 42,
            root: [9; 32],
            time: 1_800_000_000,
        }
    }

    #[test]
    fn notes_verify_under_both_keys() {
        let mut rng = HedgedRng::new().unwrap();
        let k = C2spKey::derive(&[3; 16], &[5; 64]);
        let note = k.cosign(&head(), 1_800_000_100, &mut rng).unwrap();
        for v in k.vkeys() {
            let (text, time) = verify_note(&v, &note).unwrap();
            assert_eq!(text, checkpoint(&head()));
            assert_eq!(time, 1_800_000_100);
        }
        assert!(note.starts_with("enclave-kt/07070707070707070707070707070707\n42\n"));
        // Another witness's keys, or a changed checkpoint, don't verify.
        let other = C2spKey::derive(&[3; 16], &[6; 64]);
        for v in other.vkeys() {
            assert!(verify_note(&v, &note).is_err());
        }
        let forged = note.replacen("\n42\n", "\n43\n", 1);
        for v in k.vkeys() {
            assert_eq!(verify_note(&v, &forged), Err(KtError::Signature));
        }
    }

    #[test]
    fn key_ids_follow_signed_note() {
        // `name+id+base64`; base64 itself may hold `+`.
        let k = C2spKey::derive(&[3; 16], &[5; 64]);
        let v = k.vkeys();
        assert!(v[0].starts_with("enclave-witness/03030303030303030303030303030303+"));
        let key = B64.decode(v[0].splitn(3, '+').nth(2).unwrap()).unwrap();
        assert_eq!(key[0], COSIGNATURE_V1);
        assert_eq!(
            v[0].splitn(3, '+').nth(1).unwrap(),
            hex(&key_id(&key_name(&[3; 16]), key[0], &key[1..]))
        );
        let key = B64.decode(v[1].splitn(3, '+').nth(2).unwrap()).unwrap();
        assert_eq!((key[0], key.len()), (MLDSA44, 1 + 1312));
    }
}
