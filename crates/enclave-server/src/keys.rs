//! The server's long-term keys on disk (`docs/12-servers.md` §1.4).
//!
//! * **Identity:** a composite (Ed448 + ML-DSA-87) signing key. The server
//!   id is derived from its public half, so an id in a contact card pins
//!   the key that signs the server's descriptor and request-key
//!   certificates (`server_id`).
//! * **Request-key chain:** the daily X448 + ML-KEM-1024 request keys are
//!   derived from a seed that steps forward once a day
//!   (`ServerSecret::from_seed`, `ServerSecret::next_seed`). Only today's
//!   and yesterday's seeds are on disk; stepping overwrites the file, so a
//!   seized disk doesn't open requests recorded before yesterday.
//! * **Key transparency:** the head-signing key (composite) and the VRF
//!   secret of the username log. Clients pin both, so they never change
//!   for the life of the log.
//!
//! Files are created by `enclave-server init` with mode 0600 and replaced
//! atomically (write, fsync, rename).

use enclave_crypto::hash::shake256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_SEED_LEN, CompositePublic, CompositeSigningKey};
use enclave_rpc::ServerSecret;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Label of the server id (`docs/label-registry.md`).
pub const SERVER_ID_LABEL: &str = "enclave/v1/net/server-id";

const IDENTITY_FILE: &str = "identity.key";
const CHAIN_FILE: &str = "request-chain.key";
const KT_HEAD_FILE: &str = "kt-head.key";
const KT_VRF_FILE: &str = "kt-vrf.key";

/// Key file trouble.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Reading or writing failed.
    #[error("key file {0}: {1}")]
    Io(PathBuf, std::io::Error),
    /// A key file is damaged.
    #[error("key file {0} is damaged")]
    Damaged(PathBuf),
    /// `init` would overwrite existing keys.
    #[error("keys already exist in {0}; refusing to overwrite them")]
    Exists(PathBuf),
    /// Key generation failed.
    #[error("crypto: {0}")]
    Crypto(#[from] enclave_crypto::Error),
}

/// The server id: the first 16 bytes of
/// `SHAKE256("enclave/v1/net/server-id" ‖ identity public key)`.
pub fn server_id(identity: &CompositePublic) -> [u8; 16] {
    let h: [u8; 32] = shake256(&[SERVER_ID_LABEL.as_bytes(), &identity.to_bytes()].concat());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

/// The request-key chain: the seed for `day`, and the previous day's seed
/// while it may still be needed.
pub struct RequestChain {
    day: u32,
    seed: Zeroizing<[u8; 32]>,
    prev: Option<Zeroizing<[u8; 32]>>,
    path: PathBuf,
}

impl RequestChain {
    /// The day the chain is at.
    pub fn day(&self) -> u32 {
        self.day
    }

    /// Request keys, newest first: today's, and yesterday's if kept.
    pub fn keys(&self) -> Vec<ServerSecret> {
        let mut v = vec![ServerSecret::from_seed(self.day, &self.seed)];
        if let Some(p) = &self.prev {
            v.push(ServerSecret::from_seed(self.day.saturating_sub(1), p));
        }
        v
    }

    /// The key for `day + 1`, published ahead in the descriptor.
    pub fn next_key(&self) -> ServerSecret {
        ServerSecret::from_seed(self.day + 1, &ServerSecret::next_seed(&self.seed))
    }

    /// Step the chain to `today` and persist it. Returns whether it moved.
    /// Seeds older than yesterday are gone afterwards.
    pub fn advance_to(&mut self, today: u32) -> Result<bool, KeyError> {
        if today <= self.day {
            return Ok(false);
        }
        while self.day < today {
            let next = Zeroizing::new(ServerSecret::next_seed(&self.seed));
            self.prev = (self.day + 1 == today).then(|| self.seed.clone());
            self.seed = next;
            self.day += 1;
        }
        self.save()?;
        Ok(true)
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(Vec::with_capacity(4 + 32 + 1 + 32));
        b.extend_from_slice(&self.day.to_be_bytes());
        b.extend_from_slice(&self.seed[..]);
        match &self.prev {
            Some(p) => {
                b.push(1);
                b.extend_from_slice(&p[..]);
            }
            None => b.push(0),
        }
        b
    }

    fn decode(path: PathBuf, b: &[u8]) -> Result<Self, KeyError> {
        let bad = || KeyError::Damaged(path.clone());
        if b.len() != 37 && b.len() != 69 {
            return Err(bad());
        }
        let day = u32::from_be_bytes(b[..4].try_into().map_err(|_| bad())?);
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&b[4..36]);
        let prev = match b[36] {
            0 if b.len() == 37 => None,
            1 if b.len() == 69 => {
                let mut p = Zeroizing::new([0u8; 32]);
                p.copy_from_slice(&b[37..69]);
                Some(p)
            }
            _ => return Err(bad()),
        };
        Ok(Self {
            day,
            seed,
            prev,
            path,
        })
    }

    fn save(&self) -> Result<(), KeyError> {
        write_secret(&self.path, &self.encode())
    }
}

/// The server's keys.
pub struct ServerKeys {
    /// Identity signing key (descriptor, request-key certificates).
    pub identity: CompositeSigningKey,
    /// Daily request keys.
    pub chain: RequestChain,
    /// Key-transparency head-signing key.
    pub kt_head: CompositeSigningKey,
    /// Key-transparency VRF secret.
    pub kt_vrf: Zeroizing<[u8; 32]>,
}

impl ServerKeys {
    /// The server id.
    pub fn id(&self) -> [u8; 16] {
        server_id(self.identity.public())
    }

    /// Create fresh keys in `dir`, starting the chain at `today`. Refuses
    /// to overwrite keys that exist.
    pub fn init(dir: &Path, today: u32) -> Result<Self, KeyError> {
        let id_path = dir.join(IDENTITY_FILE);
        let chain_path = dir.join(CHAIN_FILE);
        if [IDENTITY_FILE, CHAIN_FILE, KT_HEAD_FILE, KT_VRF_FILE]
            .iter()
            .any(|f| dir.join(f).exists())
        {
            return Err(KeyError::Exists(dir.to_path_buf()));
        }
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(dir)
            .map_err(|e| KeyError::Io(dir.to_path_buf(), e))?;
        let mut rng = HedgedRng::new()?;
        let identity = CompositeSigningKey::generate(&mut rng)?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("server/request-chain")?);
        let kt_head = CompositeSigningKey::generate(&mut rng)?;
        let kt_vrf: Zeroizing<[u8; 32]> = Zeroizing::new(rng.array("server/kt-vrf")?);
        write_secret(&id_path, identity.seed().as_slice())?;
        write_secret(&dir.join(KT_HEAD_FILE), kt_head.seed().as_slice())?;
        write_secret(&dir.join(KT_VRF_FILE), &kt_vrf[..])?;
        let chain = RequestChain {
            day: today,
            seed,
            prev: None,
            path: chain_path,
        };
        chain.save()?;
        Ok(Self {
            identity,
            chain,
            kt_head,
            kt_vrf,
        })
    }

    /// Load the keys in `dir`.
    pub fn load(dir: &Path) -> Result<Self, KeyError> {
        let identity = load_signing(&dir.join(IDENTITY_FILE))?;
        let kt_head = load_signing(&dir.join(KT_HEAD_FILE))?;
        let vrf_path = dir.join(KT_VRF_FILE);
        let raw = Zeroizing::new(
            std::fs::read(&vrf_path).map_err(|e| KeyError::Io(vrf_path.clone(), e))?,
        );
        if raw.len() != 32 {
            return Err(KeyError::Damaged(vrf_path));
        }
        let mut kt_vrf = Zeroizing::new([0u8; 32]);
        kt_vrf.copy_from_slice(&raw);
        let chain_path = dir.join(CHAIN_FILE);
        let raw = Zeroizing::new(
            std::fs::read(&chain_path).map_err(|e| KeyError::Io(chain_path.clone(), e))?,
        );
        let chain = RequestChain::decode(chain_path, &raw)?;
        Ok(Self {
            identity,
            chain,
            kt_head,
            kt_vrf,
        })
    }

    /// A copy of the head-signing key (the log runs on its own thread).
    pub fn kt_head_copy(&self) -> Result<CompositeSigningKey, KeyError> {
        Ok(CompositeSigningKey::from_seed(self.kt_head.seed())?)
    }
}

fn load_signing(path: &Path) -> Result<CompositeSigningKey, KeyError> {
    let raw = Zeroizing::new(std::fs::read(path).map_err(|e| KeyError::Io(path.to_path_buf(), e))?);
    let seed: &[u8; COMPOSITE_SEED_LEN] = raw
        .as_slice()
        .try_into()
        .map_err(|_| KeyError::Damaged(path.to_path_buf()))?;
    CompositeSigningKey::from_seed(seed).map_err(|_| KeyError::Damaged(path.to_path_buf()))
}

/// Write `bytes` to `path` atomically, readable by the owner only.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), KeyError> {
    let err = |e| KeyError::Io(path.to_path_buf(), e);
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(err)?;
        f.write_all(bytes).map_err(err)?;
        f.sync_all().map_err(err)?;
    }
    std::fs::rename(&tmp, path).map_err(err)?;
    if let Some(dir) = path.parent()
        && let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("enclave-keys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn init_load_and_advance() {
        let d = dir("a");
        let k = ServerKeys::init(&d, 100).unwrap();
        assert!(ServerKeys::init(&d, 100).is_err(), "never overwrites");
        let id = k.id();
        let today = k.chain.keys()[0].public().clone();
        let tomorrow = k.chain.next_key().public().clone();
        let mut l = ServerKeys::load(&d).unwrap();
        assert_eq!(l.id(), id, "the id survives a restart");
        assert_eq!(l.chain.keys()[0].public(), &today, "so does today's key");
        assert_eq!(l.kt_head.public(), k.kt_head.public(), "and the KT pins");
        assert_eq!(*l.kt_vrf, *k.kt_vrf);
        assert!(l.chain.advance_to(101).unwrap());
        let keys = l.chain.keys();
        assert_eq!(keys[0].public(), &tomorrow, "the published next key");
        assert_eq!(keys[1].public(), &today, "yesterday's is kept");
        // Several days later: only the newest two remain, and the file
        // holds nothing older.
        assert!(l.chain.advance_to(105).unwrap());
        let reloaded = ServerKeys::load(&d).unwrap();
        assert_eq!(reloaded.chain.day(), 105);
        assert_eq!(reloaded.chain.keys().len(), 2);
        assert!(reloaded.chain.keys().iter().all(|k| k.public() != &today));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn damaged_files_refused() {
        let d = dir("b");
        ServerKeys::init(&d, 1).unwrap();
        std::fs::write(d.join(CHAIN_FILE), b"short").unwrap();
        assert!(matches!(ServerKeys::load(&d), Err(KeyError::Damaged(_))));
        let d = dir("c");
        ServerKeys::init(&d, 1).unwrap();
        std::fs::write(d.join(KT_VRF_FILE), [0u8; 31]).unwrap();
        assert!(matches!(ServerKeys::load(&d), Err(KeyError::Damaged(_))));
        let _ = std::fs::remove_dir_all(&d);
        let d = dir("b");
        let _ = std::fs::remove_dir_all(&d);
    }
}
