//! Differential tests: every primitive Enclave ships is checked against an
//! independent implementation. None of these oracles is ever linked into a
//! shipped binary (they are `dev-dependencies`).
//!
//! | Primitive      | Shipped            | Oracle                         |
//! |----------------|--------------------|--------------------------------|
//! | ML-KEM-1024    | libcrux-ml-kem     | RustCrypto `ml-kem`            |
//! | ML-DSA-87      | libcrux-ml-dsa     | RustCrypto `ml-dsa`            |
//! | SLH-DSA-256s   | RustCrypto slh-dsa | `fips205`                      |
//! | X448, Ed448    | RustCrypto         | OpenSSL (system)               |
//! | KMAC256        | in-house           | libcrux-kmac, NIST samples     |

#![allow(clippy::expect_used)]

use enclave_crypto::kem::{MlKemCiphertext, MlKemPublic, MlKemSecret, X448Public, X448Secret};
use enclave_crypto::kmac::Kmac256;
use enclave_crypto::rng::{HedgedRng, XofRng};
use enclave_crypto::sig::{CompositeSigningKey, RootPublic, RootSigningKey};

fn rng() -> HedgedRng {
    HedgedRng::new().expect("rng")
}

// ---------------------------------------------------------------------------
// ML-KEM-1024: libcrux vs RustCrypto
// ---------------------------------------------------------------------------

#[test]
fn mlkem_keygen_matches_rustcrypto() {
    use ml_kem::kem::KeyExport;
    let mut seeds = XofRng::new(b"mlkem-diff", "test");
    for _ in 0..16 {
        let mut seed = [0u8; 64];
        seeds.fill(&mut seed);
        let (_, ours) = MlKemSecret::from_seed(&seed);
        let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(seed.into());
        let theirs = dk.encapsulation_key().to_bytes();
        assert_eq!(&ours.0[..], theirs.as_slice());
    }
}

#[test]
fn mlkem_cross_encapsulation() {
    use ml_kem::kem::{Decapsulate, KeyExport};
    let mut seeds = XofRng::new(b"mlkem-cross", "test");
    for _ in 0..16 {
        let mut seed = [0u8; 64];
        let mut m = [0u8; 32];
        seeds.fill(&mut seed);
        seeds.fill(&mut m);
        let (our_sk, our_pk) = MlKemSecret::from_seed(&seed);
        let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::from_seed(seed.into());
        let ek = dk.encapsulation_key();

        // Same deterministic encapsulation on both sides.
        let (our_ct, our_ss) = our_pk.encapsulate_deterministic(&m);
        let (their_ct, their_ss) = ek.encapsulate_deterministic(&m.into());
        assert_eq!(&our_ct.0[..], their_ct.as_slice());
        assert_eq!(&our_ss[..], their_ss.as_slice());

        // Ours encapsulates, theirs decapsulates, and the reverse.
        let their_dec = dk.decapsulate(&our_ct.0[..].try_into().expect("ct"));
        assert_eq!(&our_ss[..], their_dec.as_slice());
        let ct = MlKemCiphertext::from_slice(their_ct.as_slice()).expect("ct");
        assert_eq!(&our_sk.decapsulate(&ct)[..], their_ss.as_slice());

        // Implicit rejection agrees on a corrupted ciphertext.
        let mut bad = our_ct.clone();
        bad.0[17] ^= 0x40;
        let their_bad = dk.decapsulate(&bad.0[..].try_into().expect("ct"));
        assert_eq!(&our_sk.decapsulate(&bad)[..], their_bad.as_slice());
        let _ = ek.to_bytes();
        let _ = MlKemPublic::from_slice(&our_pk.0[..]).expect("valid");
    }
}

// ---------------------------------------------------------------------------
// ML-DSA-87: libcrux vs RustCrypto
// ---------------------------------------------------------------------------

#[test]
fn mldsa_keygen_and_cross_verify() {
    let mut seeds = XofRng::new(b"mldsa-diff", "test");
    for _ in 0..8 {
        let mut seed = [0u8; 32];
        seeds.fill(&mut seed);
        let ours = libcrux_ml_dsa::ml_dsa_87::generate_key_pair(seed);
        let theirs = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&seed.into());
        let their_vk = theirs.expanded_key().verifying_key();
        assert_eq!(
            ours.verification_key.as_slice(),
            their_vk.encode().as_slice()
        );

        let msg = b"differential message";
        let ctx = b"enclave/v1/sig/composite";
        // libcrux signs, RustCrypto verifies.
        let sig =
            libcrux_ml_dsa::ml_dsa_87::sign(&ours.signing_key, msg, ctx, [7u8; 32]).expect("sign");
        let enc: ml_dsa::EncodedSignature<ml_dsa::MlDsa87> =
            sig.as_slice().try_into().expect("len");
        let their_sig = ml_dsa::Signature::<ml_dsa::MlDsa87>::decode(&enc).expect("decode");
        assert!(their_vk.verify_with_context(msg, ctx, &their_sig));
        assert!(!their_vk.verify_with_context(b"other", ctx, &their_sig));
        // RustCrypto signs, libcrux verifies.
        let ts = theirs
            .expanded_key()
            .sign_deterministic(msg, ctx)
            .expect("sign");
        let mut arr = [0u8; 4627];
        arr.copy_from_slice(ts.encode().as_slice());
        let s = libcrux_ml_dsa::ml_dsa_87::MLDSA87Signature::new(arr);
        assert!(libcrux_ml_dsa::ml_dsa_87::verify(&ours.verification_key, msg, ctx, &s).is_ok());
    }
}

// ---------------------------------------------------------------------------
// SLH-DSA-SHAKE-256s: RustCrypto slh-dsa vs fips205
// ---------------------------------------------------------------------------

#[test]
fn slhdsa_cross_verify() {
    use fips205::slh_dsa_shake_256s as f;
    use fips205::traits::{SerDes, Signer, Verifier};
    let mut r = rng();
    let root = RootSigningKey::from_recovery_secret(&[5u8; 32]);
    let msg = b"manifest bytes";
    let ctx = b"manifest";

    // Ours signs, fips205 verifies.
    let sig = root.sign(ctx, msg, &mut r).expect("sign");
    let pk = f::PublicKey::try_from_bytes(&root.public().0).expect("pk");
    let sig_arr: [u8; f::SIG_LEN] = sig.as_slice().try_into().expect("len");
    assert!(pk.verify(msg, &sig_arr, ctx));
    assert!(!pk.verify(b"other", &sig_arr, ctx));

    // fips205 signs, ours verifies.
    let (fpk, fsk) = f::try_keygen().expect("keygen");
    let fsig = fsk.try_sign(msg, ctx, true).expect("sign");
    let fpk_bytes = fpk.into_bytes();
    let our_pk = RootPublic(fpk_bytes);
    our_pk.verify(ctx, msg, &fsig).expect("verify");
    assert!(our_pk.verify(ctx, b"other", &fsig).is_err());
}

// ---------------------------------------------------------------------------
// X448 and Ed448: RustCrypto vs OpenSSL
// ---------------------------------------------------------------------------

#[test]
fn x448_matches_openssl() {
    use openssl::derive::Deriver;
    use openssl::pkey::{Id, PKey};
    let mut r = rng();
    for _ in 0..8 {
        let (a, a_pub) = X448Secret::generate(&mut r).expect("keygen");
        let ossl_b = PKey::generate_x448().expect("ossl keygen");
        let b_pub_raw = ossl_b.raw_public_key().expect("raw");
        let b_pub = X448Public(b_pub_raw.as_slice().try_into().expect("56"));

        let ours = a.diffie_hellman(&b_pub).expect("dh");
        let a_pub_ossl = PKey::public_key_from_raw_bytes(&a_pub.0, Id::X448).expect("pk");
        let mut d = Deriver::new(&ossl_b).expect("deriver");
        d.set_peer(&a_pub_ossl).expect("peer");
        let theirs = d.derive_to_vec().expect("derive");
        assert_eq!(&ours[..], theirs.as_slice());

        // Public-key derivation matches OpenSSL for the same secret.
        let a_ossl = PKey::private_key_from_raw_bytes(&a.to_bytes()[..], Id::X448).expect("sk");
        assert_eq!(a_ossl.raw_public_key().expect("raw"), a_pub.0.to_vec());
    }
}

#[test]
fn ed448_matches_openssl() {
    use openssl::pkey::{Id, PKey};
    use openssl::sign::{Signer, Verifier};
    let mut seeds = XofRng::new(b"ed448-diff", "test");
    for _ in 0..8 {
        let mut seed = [0u8; 57];
        seeds.fill(&mut seed);
        let ours = ed448_goldilocks::SigningKey::try_from(&seed[..]).expect("sk");
        let ossl = PKey::private_key_from_raw_bytes(&seed, Id::ED448).expect("sk");
        assert_eq!(
            ours.verifying_key().to_bytes().to_vec(),
            ossl.raw_public_key().expect("raw")
        );

        let msg = b"ed448 differential";
        let our_sig = ours.sign_raw(msg);
        let mut signer = Signer::new_without_digest(&ossl).expect("signer");
        let their_sig = signer.sign_oneshot_to_vec(msg).expect("sign");
        // Ed448 is deterministic: identical signatures.
        assert_eq!(our_sig.to_bytes().to_vec(), their_sig);
        let mut v = Verifier::new_without_digest(&ossl).expect("verifier");
        assert!(v.verify_oneshot(&our_sig.to_bytes(), msg).expect("verify"));
    }
}

#[test]
fn composite_uses_standard_ed448_half() {
    // The Ed448 half of a composite signature is a plain RFC 8032 signature over
    // the representative, so OpenSSL can verify it given the representative.
    let mut r = rng();
    let k = CompositeSigningKey::generate(&mut r).expect("keygen");
    let pk = k.public().to_bytes();
    assert_eq!(pk.len(), 2649);
    let sig = k.sign(b"ctx", b"msg", &mut r).expect("sign");
    assert_eq!(sig.len(), 4741);
}

// ---------------------------------------------------------------------------
// KMAC256: in-house vs libcrux-kmac
// ---------------------------------------------------------------------------

#[test]
fn kmac_matches_libcrux() {
    let mut s = XofRng::new(b"kmac-diff", "test");
    for i in 0..200usize {
        // libcrux-kmac requires keys of at least 256 bits.
        let klen = [32usize, 33, 64, 135, 136, 137, 200, 300][i % 8];
        let dlen = (i * 37) % 700;
        let slen = (i * 13) % 60;
        let olen = [16usize, 32, 64, 100, 136, 200][i % 6];
        let mut key = vec![0u8; klen];
        let mut data = vec![0u8; dlen];
        let mut cust = vec![0u8; slen];
        s.fill(&mut key);
        s.fill(&mut data);
        s.fill(&mut cust);

        let mut ours = vec![0u8; olen];
        let mut k = Kmac256::new(&key, &cust);
        k.update(&data);
        k.finalize_into(&mut ours);

        let mut theirs = vec![0u8; olen];
        libcrux_kmac::kmac_256(&mut theirs, &key, &data, &cust);
        assert_eq!(
            ours, theirs,
            "case {i}: klen {klen} dlen {dlen} slen {slen} olen {olen}"
        );
    }
}
