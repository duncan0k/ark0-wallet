//! What the wallet keeps on disk besides the vault: the settings, and the transactions it sent. Neither
//! holds a secret; both are plain JSON in the app's data directory, replaced as a whole when they change.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;

pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 15;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    /// "auto" follows the system; otherwise "zh-Hans", "zh-Hant" or "en".
    pub language: String,
    /// The wallet locks itself after this many minutes without use; 0 turns that off.
    pub auto_lock_minutes: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { language: "auto".into(), auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES }
    }
}

impl Settings {
    pub fn valid(&self) -> bool {
        matches!(self.language.as_str(), "auto" | "zh-Hans" | "zh-Hant" | "en") && self.auto_lock_minutes <= 240
    }
}

/// A transaction this wallet signed and handed to the network.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Sent {
    pub txid: String,
    /// Seconds since 1970.
    pub created: u64,
    /// "schnorr", "mldsa44" or "mixed".
    pub from: String,
    pub to: String,
    pub send: u64,
    pub fee: u64,
    pub change: u64,
    pub vsize: usize,
    pub size: usize,
    /// "schnorr" or "mldsa44": the signature its inputs carry.
    pub signature: String,
    pub inputs: usize,
    /// Milliseconds the signing core took for all inputs.
    pub sign_ms: f64,
    /// "submitting" (being handed to the API), "mempool", "confirmed", "unknown" (no answer said what
    /// happened, or the node no longer has it), "rejected" (the node refused it), "failed" (the API did not
    /// pass it on) or "replaced" (unknown, and a proven payment of the wallet spends one of its coins).
    pub status: String,
    pub confirmations: u32,
    /// Older versions took the count from the API; true only once six signed blocks have been verified.
    #[serde(default)]
    pub proof_verified: bool,
    #[serde(default)]
    pub reason: String,
    /// The coins it spends, as "txid:vout".
    #[serde(default)]
    pub outpoints: Vec<String>,
    /// The wallet once did not know it went out (no clear answer, or a refusal): finding out later that it
    /// did is pointed out before the next payment.
    #[serde(default)]
    pub doubted: bool,
    /// The order in which its last lookup started; 0 means never looked up.
    #[serde(default)]
    pub lookup_mark: u64,
}

impl Sent {
    /// Settled for good: six signed blocks verified. Such a payment is not looked up again. On a signet only
    /// the block signer can make a competing chain, so the wallet does not watch for a reorganisation deeper
    /// than that.
    pub fn proven(&self) -> bool {
        self.status == "confirmed" && self.proof_verified && self.confirmations >= crate::proof::REQUIRED_BLOCKS
    }
}

/// The most the wallet reads of one of its files; its own files are far smaller.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Held before any wallet file is read. Closing the file releases the OS lock, including after a crash.
pub fn lock_wallet(dir: &Path) -> Result<std::fs::File, std::fs::TryLockError> {
    std::fs::create_dir_all(dir).map_err(std::fs::TryLockError::Error)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(dir.join("wallet.lock")).map_err(std::fs::TryLockError::Error)?;
    file.try_lock()?;
    Ok(file)
}

/// A file of the wallet's, read whole, unless it is larger than any the wallet writes.
pub fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(bytes)
}

/// Writes a file whole: a new temporary file beside it under a random name (readable by its owner only
/// on Unix), flushed, then durably replaced (a directory sync on Unix, write-through on Windows).
/// The file is either the old one or the new one, never a mixture, and nothing already in the directory
/// is followed or overwritten.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with(path, bytes, sync_directory)
}

fn write_atomic_with(path: &Path, bytes: &[u8], sync_dir: impl FnOnce(&Path) -> std::io::Result<()>) -> std::io::Result<()> {
    let dir = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let name = path.file_name().ok_or(std::io::ErrorKind::InvalidInput)?.to_string_lossy();
    std::fs::create_dir_all(dir)?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| std::io::ErrorKind::Other)?;
    let tmp = dir.join(format!(".{name}.{}.tmp", hex::encode(random)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        replace(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    sync_dir(dir)
}

fn sync_directory(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
    let wide = |path: &Path| -> std::io::Result<Vec<u16>> {
        let mut name: Vec<u16> = path.as_os_str().encode_wide().collect();
        if name.contains(&0) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        name.push(0);
        Ok(name)
    };
    // Canonical parents give Win32 extended paths too, preserving support for long file names.
    let from = std::fs::canonicalize(from)?;
    let to = std::fs::canonicalize(to.parent().ok_or(std::io::ErrorKind::InvalidInput)?)?
        .join(to.file_name().ok_or(std::io::ErrorKind::InvalidInput)?);
    let (from, to) = (wide(&from)?, wide(&to)?);
    // SAFETY: both names are NUL-terminated and live until the synchronous call returns.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn load<T: DeserializeOwned + Default>(path: &Path) -> T {
    read_capped(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Like `load`, for a file about to be changed: the default only when there is no file yet, and an error
/// when it cannot be read or is not what the wallet wrote, so that it is not replaced by a fresh one.
pub fn load_existing<T: DeserializeOwned + Default>(path: &Path) -> std::io::Result<T> {
    match read_capped(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e),
    }
}

pub fn save<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replacement_is_whole_and_failed_replacements_leave_no_temporary_file() {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-atomic-test-{}", hex::encode(nonce)));
        let path = dir.join("sent.json");
        write_atomic(&path, b"old").unwrap();
        write_atomic(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let blocked = dir.join("directory");
        std::fs::create_dir(&blocked).unwrap();
        assert!(write_atomic(&blocked, b"cannot replace a directory").is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn directory_open_and_sync_failures_fail_the_save_even_after_rename() {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!("pqw-directory-sync-{}", hex::encode(nonce)));
        let path = dir.join("sent.json");
        let error = write_atomic_with(&path, b"open failed", |dir| sync_directory(&dir.join("missing"))).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        let error = write_atomic_with(&path, b"sync failed", |dir| {
            let _directory = std::fs::File::open(dir)?;
            Err(std::io::Error::new(std::io::ErrorKind::Other, "directory sync failed"))
        }).unwrap_err();
        assert_eq!(error.to_string(), "directory sync failed");
        assert_eq!(std::fs::read(&path).unwrap(), b"sync failed");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_file_that_cannot_be_read_is_not_taken_for_an_empty_one() {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("pqw-store-test-{}", hex::encode(nonce))).join("sent.json");
        assert_eq!(load_existing::<Vec<u32>>(&path).unwrap(), Vec::<u32>::new());
        save(&path, &vec![1u32, 2]).unwrap();
        assert_eq!(load_existing::<Vec<u32>>(&path).unwrap(), vec![1, 2]);
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load_existing::<Vec<u32>>(&path).is_err());
        assert_eq!(load::<Vec<u32>>(&path), Vec::<u32>::new());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
