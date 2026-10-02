//! Key directories and secret files.

use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Key file trouble.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Reading or writing failed.
    #[error("key file {0}: {1}")]
    Io(PathBuf, std::io::Error),
    /// A key file is damaged.
    #[error("key file {0} is damaged")]
    Damaged(PathBuf),
    /// Creating keys would overwrite existing ones.
    #[error("{0} already exists; refusing to overwrite keys")]
    Exists(PathBuf),
    /// Randomness or key generation failed.
    #[error("key generation failed")]
    Crypto,
}

/// Create `dir` (and its parents), readable by the owner only. A directory
/// that already exists (a container volume, say) is made owner-only too.
pub fn create_key_dir(dir: &Path) -> Result<(), KeyError> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| KeyError::Io(dir.to_path_buf(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| KeyError::Io(dir.to_path_buf(), e))?;
    }
    Ok(())
}

/// Write `bytes` to `path` atomically (temporary file, fsync, rename, fsync
/// of the directory), readable by the owner only.
pub fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), KeyError> {
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

/// Write a new secret file; refuses to overwrite one.
pub fn create_secret(path: &Path, bytes: &[u8]) -> Result<(), KeyError> {
    if path.exists() {
        return Err(KeyError::Exists(path.to_path_buf()));
    }
    write_secret(path, bytes)
}

/// Read a secret file.
pub fn read_secret(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| KeyError::Io(path.to_path_buf(), e))
}

/// Read a secret file that must hold exactly `N` bytes.
pub fn read_array<const N: usize>(path: &Path) -> Result<Zeroizing<[u8; N]>, KeyError> {
    let b = read_secret(path)?;
    if b.len() != N {
        return Err(KeyError::Damaged(path.to_path_buf()));
    }
    let mut a = Zeroizing::new([0u8; N]);
    a.copy_from_slice(&b);
    Ok(a)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn modes_and_sizes() {
        let d = std::env::temp_dir().join(format!("enclave-keyfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        create_key_dir(&d).unwrap();
        let p = d.join("k.key");
        create_secret(&p, &[7; 32]).unwrap();
        assert!(create_secret(&p, &[8; 32]).is_err(), "never overwrites");
        assert_eq!(*read_array::<32>(&p).unwrap(), [7; 32]);
        assert!(matches!(read_array::<31>(&p), Err(KeyError::Damaged(_))));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&d), 0o700);
            assert_eq!(mode(&p), 0o600);
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
