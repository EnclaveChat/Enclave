//! SecP384r1MLKEM1024 for rustls.
//!
//! ```text
//! client share = P-384 point (97, uncompressed) ‖ ML-KEM-1024 encapsulation key (1,568)
//! server share = P-384 point (97, uncompressed) ‖ ML-KEM-1024 ciphertext (1,568)
//! secret       = P-384 ECDH x-coordinate (48) ‖ ML-KEM shared secret (32)
//! ```

use enclave_crypto::kem::{MLKEM_CT_LEN, MLKEM_PK_LEN, MlKemCiphertext, MlKemPublic, MlKemSecret};
use enclave_crypto::rng::HedgedRng;
use p384::PublicKey;
use p384::ecdh::EphemeralSecret;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

/// The TLS codepoint of SecP384r1MLKEM1024.
pub const SECP384R1_MLKEM1024_ID: u16 = 0x11ED;

/// The SecP384r1MLKEM1024 key exchange.
pub static SECP384R1_MLKEM1024: &dyn SupportedKxGroup = &Hybrid;

const P384_LEN: usize = 97;

fn bad() -> Error {
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

fn rng() -> Result<HedgedRng, Error> {
    HedgedRng::new().map_err(|_| Error::FailedToGetRandomBytes)
}

/// A fresh P-384 key pair: the secret and the uncompressed point.
fn p384_keypair(rng: &mut HedgedRng) -> Result<(EphemeralSecret, Vec<u8>), Error> {
    // p384 takes a rand_core RNG; HedgedRng implements it.
    let secret = EphemeralSecret::random(rng);
    let point = secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    Ok((secret, point))
}

fn p384_shared(secret: &EphemeralSecret, peer: &[u8]) -> Result<Vec<u8>, Error> {
    // TLS sends the uncompressed form only; `from_sec1_bytes` checks the
    // point is on the curve and not the identity.
    if peer.len() != P384_LEN || peer[0] != 0x04 {
        return Err(bad());
    }
    let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| bad())?;
    Ok(secret.diffie_hellman(&peer).raw_secret_bytes().to_vec())
}

#[derive(Debug)]
struct Hybrid;

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut rng = rng()?;
        let (ecdh, point) = p384_keypair(&mut rng)?;
        let (kem, ek) =
            MlKemSecret::generate(&mut rng).map_err(|_| Error::FailedToGetRandomBytes)?;
        let mut share = point;
        share.extend_from_slice(&ek.0[..]);
        Ok(Box::new(Active { ecdh, kem, share }))
    }

    /// Server side: answer a client share with ours, encapsulating to the
    /// client's ML-KEM key.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != P384_LEN + MLKEM_PK_LEN {
            return Err(bad());
        }
        let (point, ek) = client_share.split_at(P384_LEN);
        let ek = MlKemPublic::from_slice(ek).map_err(|_| bad())?;
        let mut rng = rng()?;
        let (ecdh, our_point) = p384_keypair(&mut rng)?;
        let mut secret = zeroize::Zeroizing::new(p384_shared(&ecdh, point)?);
        let (ct, ss) = ek
            .encapsulate(&mut rng)
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        secret.extend_from_slice(&ss[..]);
        let mut pub_key = our_point;
        pub_key.extend_from_slice(&ct.0[..]);
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key,
            secret: SharedSecret::from(secret.to_vec()),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::Unknown(SECP384R1_MLKEM1024_ID)
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct Active {
    ecdh: EphemeralSecret,
    kem: MlKemSecret,
    share: Vec<u8>,
}

impl ActiveKeyExchange for Active {
    /// Client side: finish with the server's share.
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        if server_share.len() != P384_LEN + MLKEM_CT_LEN {
            return Err(bad());
        }
        let (point, ct) = server_share.split_at(P384_LEN);
        let mut secret = zeroize::Zeroizing::new(p384_shared(&self.ecdh, point)?);
        let ct = MlKemCiphertext::from_slice(ct).map_err(|_| bad())?;
        secret.extend_from_slice(&self.kem.decapsulate(&ct)[..]);
        Ok(SharedSecret::from(secret.to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::Unknown(SECP384R1_MLKEM1024_ID)
    }
}
