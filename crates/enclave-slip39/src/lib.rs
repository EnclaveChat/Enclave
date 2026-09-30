//! SLIP-0039: Shamir's secret sharing for mnemonic codes, for social
//! recovery (`docs/03-identity.md` §8.3).
//!
//! A port of the reference implementation (`shamir-mnemonic` 0.3,
//! SatoshiLabs, MIT), checked against it: the tests replay vectors the
//! reference produced from a deterministic byte stream, and generating from
//! the same stream here must give the same words.
//!
//! The master secret is first encrypted with a 4-round Feistel network
//! (PBKDF2-HMAC-SHA256, `10000 << e` iterations spread over the rounds),
//! then split in two levels: `group_threshold` of the groups, and within
//! each group `member_threshold` of its members. Shares are polynomials over
//! GF(256) with the secret at x = 255 and a 4-byte HMAC digest at x = 254,
//! so a wrong set of shares is detected. Each share is a mnemonic of 10-bit
//! words from a 1024-word list with an RS1024 checksum.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const RADIX_BITS: usize = 10;
const ID_LENGTH_BITS: u32 = 15;
const ITERATION_EXP_LENGTH_BITS: u32 = 4;
const ID_EXP_LENGTH_WORDS: usize = 2;
/// Most shares in a group, and most groups.
pub const MAX_SHARE_COUNT: u8 = 16;
const CHECKSUM_LENGTH_WORDS: usize = 3;
const DIGEST_LENGTH_BYTES: usize = 4;
const CUSTOM_ORIG: &[u8] = b"shamir";
const CUSTOM_EXTENDABLE: &[u8] = b"shamir_extendable";
const METADATA_LENGTH_WORDS: usize = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS;
const MIN_STRENGTH_BITS: usize = 128;
const MIN_MNEMONIC_LENGTH_WORDS: usize =
    METADATA_LENGTH_WORDS + MIN_STRENGTH_BITS.div_ceil(RADIX_BITS);
const BASE_ITERATION_COUNT: u32 = 10_000;
const ROUND_COUNT: u8 = 4;
const SECRET_INDEX: u8 = 255;
const DIGEST_INDEX: u8 = 254;

const WORDLIST: &str = include_str!("wordlist.txt");

/// Why shares could not be made or combined.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Slip39Error {
    /// Bad parameters for splitting.
    #[error("invalid parameters: {0}")]
    Parameters(&'static str),
    /// A word isn't in the list, the length is wrong, or the checksum fails.
    #[error("that isn't a valid share")]
    Mnemonic,
    /// The shares don't belong together, or there are too few.
    #[error("these shares don't fit together: {0}")]
    Shares(&'static str),
    /// The shares combine to something whose digest doesn't match.
    #[error("the shares don't match")]
    Digest,
}

/// Result alias.
pub type Result<T> = core::result::Result<T, Slip39Error>;

fn words() -> Vec<&'static str> {
    WORDLIST.lines().collect()
}

// ---------------------------------------------------------------- RS1024

fn polymod(values: &[u32]) -> u32 {
    const GEN: [u32; 10] = [
        0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009, 0x1C0C2412, 0x38086C24, 0x3090FC48,
        0x21B1F890, 0x3F3F120,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 20;
        chk = ((chk & 0xFFFFF) << 10) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn custom(extendable: bool) -> &'static [u8] {
    if extendable {
        CUSTOM_EXTENDABLE
    } else {
        CUSTOM_ORIG
    }
}

fn create_checksum(data: &[u32], extendable: bool) -> [u32; 3] {
    let mut values: Vec<u32> = custom(extendable).iter().map(|&b| u32::from(b)).collect();
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; CHECKSUM_LENGTH_WORDS]);
    let p = polymod(&values) ^ 1;
    [(p >> 20) & 1023, (p >> 10) & 1023, p & 1023]
}

fn verify_checksum(data: &[u32], extendable: bool) -> bool {
    let mut values: Vec<u32> = custom(extendable).iter().map(|&b| u32::from(b)).collect();
    values.extend_from_slice(data);
    polymod(&values) == 1
}

// ---------------------------------------------------------------- cipher

fn round_function(i: u8, passphrase: &[u8], e: u8, salt: &[u8], r: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut pass = Zeroizing::new(vec![i]);
    pass.extend_from_slice(passphrase);
    let mut s = salt.to_vec();
    s.extend_from_slice(r);
    let mut out = Zeroizing::new(vec![0u8; r.len()]);
    let iterations = (BASE_ITERATION_COUNT << e) / u32::from(ROUND_COUNT);
    pbkdf2::pbkdf2_hmac::<Sha256>(&pass, &s, iterations, &mut out);
    out
}

fn salt(identifier: u16, extendable: bool) -> Vec<u8> {
    if extendable {
        Vec::new()
    } else {
        [CUSTOM_ORIG, &identifier.to_be_bytes()].concat()
    }
}

fn feistel(
    input: &[u8],
    passphrase: &[u8],
    e: u8,
    identifier: u16,
    extendable: bool,
    decrypt: bool,
) -> Zeroizing<Vec<u8>> {
    let half = input.len() / 2;
    let mut l = Zeroizing::new(input[..half].to_vec());
    let mut r = Zeroizing::new(input[half..].to_vec());
    let s = salt(identifier, extendable);
    let rounds: Vec<u8> = if decrypt {
        (0..ROUND_COUNT).rev().collect()
    } else {
        (0..ROUND_COUNT).collect()
    };
    for i in rounds {
        let f = round_function(i, passphrase, e, &s, &r);
        let next: Vec<u8> = l.iter().zip(f.iter()).map(|(a, b)| a ^ b).collect();
        l = std::mem::replace(&mut r, Zeroizing::new(next));
    }
    let mut out = Zeroizing::new(r.to_vec());
    out.extend_from_slice(&l);
    out
}

// ---------------------------------------------------------------- GF(256)

struct Tables {
    exp: [u8; 255],
    log: [u8; 256],
}

fn tables() -> Tables {
    let mut exp = [0u8; 255];
    let mut log = [0u8; 256];
    let mut poly: u16 = 1;
    for (i, e) in exp.iter_mut().enumerate() {
        *e = poly as u8;
        log[poly as usize] = i as u8;
        poly = (poly << 1) ^ poly;
        if poly & 0x100 != 0 {
            poly ^= 0x11B;
        }
    }
    Tables { exp, log }
}

struct RawShare {
    x: u8,
    data: Zeroizing<Vec<u8>>,
}

fn interpolate(shares: &[RawShare], x: u8) -> Result<Zeroizing<Vec<u8>>> {
    let len = shares.first().map(|s| s.data.len()).unwrap_or(0);
    for (i, s) in shares.iter().enumerate() {
        if shares[..i].iter().any(|o| o.x == s.x) {
            return Err(Slip39Error::Shares("two shares have the same index"));
        }
        if s.data.len() != len {
            return Err(Slip39Error::Shares("share lengths differ"));
        }
    }
    if let Some(s) = shares.iter().find(|s| s.x == x) {
        return Ok(s.data.clone());
    }
    let t = tables();
    let log = |v: u8| u32::from(t.log[v as usize]);
    let log_prod: u32 = shares.iter().map(|s| log(s.x ^ x)).sum();
    let mut result = Zeroizing::new(vec![0u8; len]);
    for s in shares {
        let others: u32 = shares
            .iter()
            .filter(|o| o.x != s.x)
            .map(|o| log(s.x ^ o.x))
            .sum();
        // log_prod − log(x_i ⊕ x) − Σ log(x_i ⊕ x_j), taken mod 255 (the
        // reference also sums log(0) = 0 for j = i).
        let basis = (log_prod + 255 * 32 - log(s.x ^ x) - others) % 255;
        for (r, &v) in result.iter_mut().zip(s.data.iter()) {
            if v != 0 {
                *r ^= t.exp[((log(v) + basis) % 255) as usize];
            }
        }
    }
    Ok(result)
}

fn digest(random: &[u8], secret: &[u8]) -> [u8; DIGEST_LENGTH_BYTES] {
    // HMAC takes keys of any length, so this never fails.
    let Ok(mut m) = <Hmac<Sha256> as Mac>::new_from_slice(random) else {
        return [0; DIGEST_LENGTH_BYTES];
    };
    m.update(secret);
    let d = m.finalize().into_bytes();
    let mut out = [0u8; DIGEST_LENGTH_BYTES];
    out.copy_from_slice(&d[..DIGEST_LENGTH_BYTES]);
    out
}

fn split_secret(
    threshold: u8,
    count: u8,
    secret: &[u8],
    random: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<RawShare>> {
    if threshold < 1 || threshold > count || count > MAX_SHARE_COUNT {
        return Err(Slip39Error::Parameters("threshold and count"));
    }
    if threshold == 1 {
        return Ok((0..count)
            .map(|i| RawShare {
                x: i,
                data: Zeroizing::new(secret.to_vec()),
            })
            .collect());
    }
    let random_count = threshold - 2;
    let mut shares: Vec<RawShare> = (0..random_count)
        .map(|i| {
            let mut d = Zeroizing::new(vec![0u8; secret.len()]);
            random(&mut d);
            RawShare { x: i, data: d }
        })
        .collect();
    let mut random_part = Zeroizing::new(vec![0u8; secret.len() - DIGEST_LENGTH_BYTES]);
    random(&mut random_part);
    let d = digest(&random_part, secret);
    let mut base: Vec<RawShare> = shares
        .iter()
        .map(|s| RawShare {
            x: s.x,
            data: s.data.clone(),
        })
        .collect();
    let mut digest_share = Zeroizing::new(d.to_vec());
    digest_share.extend_from_slice(&random_part);
    base.push(RawShare {
        x: DIGEST_INDEX,
        data: digest_share,
    });
    base.push(RawShare {
        x: SECRET_INDEX,
        data: Zeroizing::new(secret.to_vec()),
    });
    for i in random_count..count {
        shares.push(RawShare {
            x: i,
            data: interpolate(&base, i)?,
        });
    }
    Ok(shares)
}

fn recover_secret(threshold: u8, shares: &[RawShare]) -> Result<Zeroizing<Vec<u8>>> {
    if threshold == 1 {
        return shares
            .first()
            .map(|s| s.data.clone())
            .ok_or(Slip39Error::Shares("no shares"));
    }
    let secret = interpolate(shares, SECRET_INDEX)?;
    let ds = interpolate(shares, DIGEST_INDEX)?;
    if ds.len() < DIGEST_LENGTH_BYTES
        || ds[..DIGEST_LENGTH_BYTES] != digest(&ds[DIGEST_LENGTH_BYTES..], &secret)
    {
        return Err(Slip39Error::Digest);
    }
    Ok(secret)
}

// ---------------------------------------------------------------- shares

/// One decoded share.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Share {
    identifier: u16,
    extendable: bool,
    iteration_exponent: u8,
    group_index: u8,
    group_threshold: u8,
    group_count: u8,
    index: u8,
    member_threshold: u8,
    value: Vec<u8>,
}

fn int_to_words(bytes: &[u8], count: usize) -> Vec<u32> {
    // Big-endian bytes as a big integer, cut into `count` 10-bit words.
    let mut bits: Vec<bool> = bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect();
    let pad = count * RADIX_BITS - bits.len();
    let mut v = vec![false; pad];
    v.append(&mut bits);
    v.chunks(RADIX_BITS)
        .map(|c| c.iter().fold(0u32, |a, &b| (a << 1) | u32::from(b)))
        .collect()
}

impl Share {
    fn mnemonic(&self) -> String {
        let list = words();
        let id_exp = (u32::from(self.identifier) << (ITERATION_EXP_LENGTH_BITS + 1))
            | (u32::from(self.extendable) << ITERATION_EXP_LENGTH_BITS)
            | u32::from(self.iteration_exponent);
        let params = (u32::from(self.group_index) << 16)
            | (u32::from(self.group_threshold - 1) << 12)
            | (u32::from(self.group_count - 1) << 8)
            | (u32::from(self.index) << 4)
            | u32::from(self.member_threshold - 1);
        let mut data = vec![id_exp >> 10, id_exp & 1023, params >> 10, params & 1023];
        data.extend(int_to_words(
            &self.value,
            (self.value.len() * 8).div_ceil(RADIX_BITS),
        ));
        let cs = create_checksum(&data, self.extendable);
        data.extend_from_slice(&cs);
        data.iter()
            .map(|&i| list[i as usize])
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn from_mnemonic(m: &str) -> Result<Self> {
        let list = words();
        let data: Vec<u32> = m
            .split_whitespace()
            .map(|w| {
                let w = w.to_lowercase();
                list.iter()
                    .position(|x| *x == w)
                    .map(|p| p as u32)
                    .ok_or(Slip39Error::Mnemonic)
            })
            .collect::<Result<_>>()?;
        if data.len() < MIN_MNEMONIC_LENGTH_WORDS {
            return Err(Slip39Error::Mnemonic);
        }
        let padding = (RADIX_BITS * (data.len() - METADATA_LENGTH_WORDS)) % 16;
        if padding > 8 {
            return Err(Slip39Error::Mnemonic);
        }
        let id_exp = (data[0] << 10) | data[1];
        let identifier = (id_exp >> (ITERATION_EXP_LENGTH_BITS + 1)) as u16;
        let extendable = (id_exp >> ITERATION_EXP_LENGTH_BITS) & 1 == 1;
        let iteration_exponent = (id_exp & 0xF) as u8;
        if !verify_checksum(&data, extendable) {
            return Err(Slip39Error::Mnemonic);
        }
        let params = (data[2] << 10) | data[3];
        let n = |shift: u32| ((params >> shift) & 0xF) as u8;
        let (group_index, gt, gc, index, mt) = (n(16), n(12), n(8), n(4), n(0));
        if gc < gt {
            return Err(Slip39Error::Mnemonic);
        }
        let value_words = &data[4..data.len() - CHECKSUM_LENGTH_WORDS];
        let bits: Vec<bool> = value_words
            .iter()
            .flat_map(|w| (0..RADIX_BITS).rev().map(move |i| (w >> i) & 1 == 1))
            .collect();
        // The first `padding` bits must be zero.
        if bits[..padding].iter().any(|&b| b) {
            return Err(Slip39Error::Mnemonic);
        }
        let value: Vec<u8> = bits[padding..]
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | u8::from(b)))
            .collect();
        Ok(Self {
            identifier,
            extendable,
            iteration_exponent,
            group_index,
            group_threshold: gt + 1,
            group_count: gc + 1,
            index,
            member_threshold: mt + 1,
            value,
        })
    }
}

/// Split `master` (16 bytes or more, even length) into shares: of
/// `groups` (member threshold, member count), any `group_threshold` groups
/// recover it, each from its member threshold of shares. `random` fills
/// buffers with random bytes (in the reference's order, so tests can replay
/// its vectors).
pub fn generate(
    group_threshold: u8,
    groups: &[(u8, u8)],
    master: &[u8],
    passphrase: &[u8],
    extendable: bool,
    iteration_exponent: u8,
    random: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<Vec<String>>> {
    if master.len() * 8 < MIN_STRENGTH_BITS || !master.len().is_multiple_of(2) {
        return Err(Slip39Error::Parameters("master secret length"));
    }
    if !passphrase.iter().all(|c| (32..=126).contains(c)) {
        return Err(Slip39Error::Parameters(
            "passphrase must be printable ASCII",
        ));
    }
    if iteration_exponent > 15
        || group_threshold == 0
        || usize::from(group_threshold) > groups.len()
        || groups.len() > usize::from(MAX_SHARE_COUNT)
    {
        return Err(Slip39Error::Parameters("group threshold"));
    }
    if groups.iter().any(|&(t, c)| t == 1 && c > 1) {
        return Err(Slip39Error::Parameters(
            "member threshold 1 needs one share",
        ));
    }
    let mut id = [0u8; 2];
    random(&mut id);
    let identifier = u16::from_be_bytes(id) & ((1 << ID_LENGTH_BITS) - 1);
    let ems = feistel(
        master,
        passphrase,
        iteration_exponent,
        identifier,
        extendable,
        false,
    );
    let group_shares = split_secret(group_threshold, groups.len() as u8, &ems, random)?;
    let mut out = Vec::new();
    for (&(mt, mc), g) in groups.iter().zip(group_shares) {
        let members = split_secret(mt, mc, &g.data, random)?;
        out.push(
            members
                .into_iter()
                .map(|m| {
                    Share {
                        identifier,
                        extendable,
                        iteration_exponent,
                        group_index: g.x,
                        group_threshold,
                        group_count: groups.len() as u8,
                        index: m.x,
                        member_threshold: mt,
                        value: m.data.to_vec(),
                    }
                    .mnemonic()
                })
                .collect(),
        );
    }
    Ok(out)
}

/// Recover the master secret from enough shares (exactly the thresholds'
/// worth: extra or missing shares are errors, as in the reference).
pub fn combine(mnemonics: &[&str], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let shares: Vec<Share> = mnemonics
        .iter()
        .map(|m| Share::from_mnemonic(m))
        .collect::<Result<_>>()?;
    let first = shares.first().ok_or(Slip39Error::Shares("no shares"))?;
    let common = |s: &Share| {
        (
            s.identifier,
            s.extendable,
            s.iteration_exponent,
            s.group_threshold,
            s.group_count,
        )
    };
    if shares.iter().any(|s| common(s) != common(first)) {
        return Err(Slip39Error::Shares("they come from different sets"));
    }
    let mut groups: std::collections::BTreeMap<u8, Vec<&Share>> = Default::default();
    for s in &shares {
        groups.entry(s.group_index).or_default().push(s);
    }
    if groups.len() != usize::from(first.group_threshold) {
        return Err(Slip39Error::Shares("wrong number of groups"));
    }
    let mut group_raw = Vec::new();
    for (gi, members) in &groups {
        let mt = members[0].member_threshold;
        if members.iter().any(|m| m.member_threshold != mt) || members.len() != usize::from(mt) {
            return Err(Slip39Error::Shares("wrong number of shares in a group"));
        }
        let raw: Vec<RawShare> = members
            .iter()
            .map(|m| RawShare {
                x: m.index,
                data: Zeroizing::new(m.value.clone()),
            })
            .collect();
        group_raw.push(RawShare {
            x: *gi,
            data: recover_secret(mt, &raw)?,
        });
    }
    let ems = recover_secret(first.group_threshold, &group_raw)?;
    Ok(feistel(
        &ems,
        passphrase,
        first.iteration_exponent,
        first.identifier,
        first.extendable,
        true,
    ))
}
