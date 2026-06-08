// auth/src/totp/mod.rs
use anyhow::Result;
use totp_rs::{Algorithm, Secret, TOTP};

/// Verify a TOTP code against a stored base32 secret.
pub fn verify(secret: &str, code: &str) -> bool {
    let bytes = match Secret::Encoded(secret.to_string()).to_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, "soc-triage".to_string()) {
        Ok(t) => t,
        Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}

/// Generate a new TOTP secret and return (secret_base32, otpauth_url).
pub fn generate(username: &str, issuer: &str) -> Result<(String, String)> {
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();
    let bytes = secret.to_bytes()?;
    let totp = TOTP::new(
        Algorithm::SHA1, 6, 1, 30, bytes,
        Some(issuer.to_string()),
        username.to_string(),
    )?;
    let url = totp.get_url();
    Ok((secret_base32, url))
}