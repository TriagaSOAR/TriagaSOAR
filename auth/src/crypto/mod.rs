use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Algorithm, Params, Version,
};
use rand::RngCore;
use sha2::{Sha256, Digest};

/// Hash a password with Argon2id (mandatory variant).
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 4, None)?, // 64MB, 3 iterations, 4 parallelism
    );
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

/// Verify a password against an argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Generate a 32-byte CSPRNG opaque session token, returned as hex.
pub fn generate_token_hex() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Hash a token with argon2id for storage — DB leak renders all tokens useless.
pub fn hash_token(token: &str) -> Result<String, argon2::password_hash::Error> {
    hash_password(token)
}

/// Verify a token against its stored argon2id hash.
pub fn verify_token(token: &str, hash: &str) -> bool {
    verify_password(token, hash)
}

/// Compute SHA-256 of a string, return hex.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute the audit log entry hash.
/// Canonical form: prev_hash|event_type|actor|action|outcome|timestamp
pub fn audit_entry_hash(
    prev_hash: Option<&str>,
    event_type: &str,
    actor: &str,
    action: &str,
    outcome: &str,
    timestamp: &str,
) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}",
        prev_hash.unwrap_or("GENESIS"),
        event_type,
        actor,
        action,
        outcome,
        timestamp,
    );
    sha256_hex(&canonical)
}

/// Generate a device fingerprint from user agent and other stable headers.
pub fn device_fingerprint(user_agent: &str, accept_language: &str, accept_encoding: &str) -> String {
    let input = format!("{}|{}|{}", user_agent, accept_language, accept_encoding);
    sha256_hex(&input)
}