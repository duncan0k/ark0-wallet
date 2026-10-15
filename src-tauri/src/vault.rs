//! The vault: the wallet's secret on disk, encrypted under the wallet password.
//!
//! Argon2id turns the password into a 256-bit key (64 MiB, 3 passes, 1 lane, a random 16-byte salt), and
//! AES-256-GCM encrypts the secret with a random 96-bit nonce. Everything in the file's header (format,
//! version, Argon2id parameters, salt, nonce) is bound to the ciphertext as associated data, so a header
//! changed on disk makes the vault fail to open, like a wrong password. Only the secret is encrypted:
//! there is nothing else in the file.
//!
//! The file is replaced, never edited (store::write_atomic): written in full beside it, flushed, then
//! renamed over it. On Unix it is readable by its owner only (Windows keeps it in the user's own profile).
//! A vault opens only with the Argon2id parameters this version writes, so a file changed to demand
//! more memory or time than that is refused before any work is done.
use crate::keys::Secret;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

const FORMAT: &str = "ark0-wallet-vault";
const VERSION: u32 = 1;
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;
/// A password shorter than this is refused when a vault is made or its password changed.
pub const MIN_PASSWORD_CHARS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultError {
    /// The password does not open the vault (or the file was changed).
    WrongPassword,
    /// Not a vault this version can read.
    Unreadable,
    /// A vault exists already; it is never overwritten by a new wallet.
    Exists,
    PasswordTooShort,
    Io,
}

#[derive(Serialize, Deserialize)]
struct Kdf {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: u32,
    kdf: Kdf,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

/// The associated data: the header, in a fixed binary layout.
fn header_bytes(kdf: &Kdf, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(FORMAT.as_bytes());
    aad.extend_from_slice(&VERSION.to_be_bytes());
    aad.extend_from_slice(b"argon2id/aes-256-gcm");
    aad.extend_from_slice(&kdf.memory_kib.to_be_bytes());
    aad.extend_from_slice(&kdf.iterations.to_be_bytes());
    aad.extend_from_slice(&kdf.parallelism.to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

fn derive_key(password: &str, kdf: &Kdf, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32)).map_err(|_| VaultError::Unreadable)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| VaultError::Unreadable)?;
    Ok(key)
}

fn seal(password: &str, secret: &Secret) -> Result<VaultFile, VaultError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::PasswordTooShort);
    }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|_| VaultError::Io)?;
    getrandom::fill(&mut nonce).map_err(|_| VaultError::Io)?;
    let kdf = Kdf {
        algorithm: "argon2id".into(),
        memory_kib: MEMORY_KIB,
        iterations: ITERATIONS,
        parallelism: PARALLELISM,
        salt: hex::encode(salt),
    };
    let key = derive_key(password, &kdf, &salt)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(secret).map_err(|_| VaultError::Io)?);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Io)?;
    let aad = header_bytes(&kdf, &salt, &nonce);
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce), Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| VaultError::Io)?;
    Ok(VaultFile {
        format: FORMAT.into(),
        version: VERSION,
        kdf,
        cipher: "aes-256-gcm".into(),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

fn unseal(file: &VaultFile, password: &str) -> Result<Secret, VaultError> {
    if file.format != FORMAT || file.version != VERSION || file.kdf.algorithm != "argon2id" || file.cipher != "aes-256-gcm" {
        return Err(VaultError::Unreadable);
    }
    let salt = hex::decode(&file.kdf.salt).map_err(|_| VaultError::Unreadable)?;
    let nonce: [u8; 12] = hex::decode(&file.nonce).ok().and_then(|n| n.try_into().ok()).ok_or(VaultError::Unreadable)?;
    let ciphertext = hex::decode(&file.ciphertext).map_err(|_| VaultError::Unreadable)?;
    // Version 1 has one set of parameters; anything else is not a vault this version wrote.
    if (file.kdf.memory_kib, file.kdf.iterations, file.kdf.parallelism) != (MEMORY_KIB, ITERATIONS, PARALLELISM) || salt.len() != 16 {
        return Err(VaultError::Unreadable);
    }
    let key = derive_key(password, &file.kdf, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::Unreadable)?;
    let aad = header_bytes(&file.kdf, &salt, &nonce);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(&Nonce::from(nonce), Payload { msg: &ciphertext, aad: &aad })
            .map_err(|_| VaultError::WrongPassword)?,
    );
    serde_json::from_slice(&plaintext).map_err(|_| VaultError::Unreadable)
}

fn write_replacing(path: &Path, file: &VaultFile) -> Result<(), VaultError> {
    let json = serde_json::to_vec_pretty(file).map_err(|_| VaultError::Io)?;
    crate::store::write_atomic(path, &json).map_err(|_| VaultError::Io)
}

fn read(path: &Path) -> Result<VaultFile, VaultError> {
    let bytes = crate::store::read_capped(path).map_err(|_| VaultError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| VaultError::Unreadable)
}

pub fn exists(path: &Path) -> bool {
    path.is_file()
}

/// A new vault at `path`; refused when one is there already.
pub fn create(path: &Path, password: &str, secret: &Secret) -> Result<(), VaultError> {
    if exists(path) {
        return Err(VaultError::Exists);
    }
    write_replacing(path, &seal(password, secret)?)
}

pub fn open(path: &Path, password: &str) -> Result<Secret, VaultError> {
    unseal(&read(path)?, password)
}

/// The same secret under a new password; the old password must open the vault first.
pub fn change_password(path: &Path, old: &str, new: &str) -> Result<(), VaultError> {
    let secret = open(path, old)?;
    write_replacing(path, &seal(new, &secret)?)
}

/// Deletes the vault; the old password must open it first.
pub fn delete(path: &Path, password: &str) -> Result<(), VaultError> {
    open(path, password)?;
    std::fs::remove_file(path).map_err(|_| VaultError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        std::env::temp_dir().join(format!("pqw-vault-test-{name}-{}", hex::encode(nonce))).join("vault.json")
    }

    #[test]
    fn round_trips_and_refuses_the_wrong_password() {
        let path = temp_path("round");
        let secret = Secret::new_bip39();
        create(&path, "correct horse", &secret).unwrap();
        assert_eq!(create(&path, "correct horse", &secret).err(), Some(VaultError::Exists));
        let opened = open(&path, "correct horse").unwrap();
        assert_eq!(opened.recovery_text(), secret.recovery_text());
        assert_eq!(open(&path, "correct horsf").err(), Some(VaultError::WrongPassword));
        change_password(&path, "correct horse", "battery staple").unwrap();
        assert_eq!(open(&path, "correct horse").err(), Some(VaultError::WrongPassword));
        assert_eq!(open(&path, "battery staple").unwrap().recovery_text(), secret.recovery_text());
        assert_eq!(delete(&path, "correct horse").err(), Some(VaultError::WrongPassword));
        delete(&path, "battery staple").unwrap();
        assert!(!exists(&path));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_changed_header_or_ciphertext_does_not_open() {
        let path = temp_path("tamper");
        create(&path, "correct horse", &Secret::new_bip39()).unwrap();
        let original = std::fs::read_to_string(&path).unwrap();
        let mut file: serde_json::Value = serde_json::from_str(&original).unwrap();
        file["kdf"]["iterations"] = serde_json::json!(4);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(open(&path, "correct horse").err(), Some(VaultError::Unreadable));
        let mut file: serde_json::Value = serde_json::from_str(&original).unwrap();
        file["nonce"] = serde_json::json!("00".repeat(12));
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(open(&path, "correct horse").err(), Some(VaultError::WrongPassword));
        let mut file: serde_json::Value = serde_json::from_str(&original).unwrap();
        let ct = file["ciphertext"].as_str().unwrap().to_string();
        let flipped = format!("{}{}", if ct.starts_with('0') { '1' } else { '0' }, &ct[1..]);
        file["ciphertext"] = serde_json::json!(flipped);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(open(&path, "correct horse").err(), Some(VaultError::WrongPassword));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode");
        create(&path, "correct horse", &Secret::new_bip39()).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn short_passwords_are_refused() {
        let path = temp_path("short");
        assert_eq!(create(&path, "1234567", &Secret::new_bip39()).err(), Some(VaultError::PasswordTooShort));
        assert!(!exists(&path));
    }
}
