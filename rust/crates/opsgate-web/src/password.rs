//! The approver's credentials check of `ui_login` (PLAN.md 4.5.3).
//!
//! `bcrypt.checkpw(password, hash)` of pyca bcrypt 4.3 (pinned `<5.0`),
//! with its `ValueError` counting as a mismatch: pyca parses the stored hash
//! itself (`$`-separated version, cost and salt, empty parts skipped), hashes
//! the password truncated to 72 bytes with the `bcrypt` crate's
//! `hash_with_salt`, formats the result for the parsed version and compares
//! it with the stored bytes in constant time. This module is that wrapper
//! around the same crate, so every hash Python accepts or refuses is
//! accepted or refused here too (`fixtures/bcrypt.json`): `$2a$`, `$2b$`,
//! `$2x$` and `$2y$`, embedded NUL bytes passed on unchanged, malformed
//! hashes a mismatch.

use base64::Engine as _;
use base64::alphabet::BCRYPT;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::NO_PAD;

use crate::client::constant_time_eq;

/// bcrypt reads at most 72 bytes of the password (pyca truncates first).
const MAX_PASSWORD_BYTES: usize = 72;

/// pyca's `BASE64_ENGINE`: the bcrypt alphabet without padding (strict
/// about trailing bits, as the `base64` crate's default).
const BASE64_ENGINE: GeneralPurpose = GeneralPurpose::new(&BCRYPT, NO_PAD);

/// `hashpw(password, salt)` of pyca bcrypt 4.3: the hash string, or `None`
/// where pyca raises `ValueError("Invalid salt")`.
fn hashpw(password: &[u8], salt: &[u8]) -> Option<String> {
    let password = &password[..password.len().min(MAX_PASSWORD_BYTES)];
    let parts: Vec<&[u8]> = salt
        .split(|&byte| byte == b'$')
        .filter(|part| !part.is_empty())
        .collect();
    let [raw_version, raw_cost, remainder] = parts.as_slice() else {
        return None;
    };
    let version = match *raw_version {
        b"2y" => bcrypt::Version::TwoY,
        b"2b" => bcrypt::Version::TwoB,
        b"2a" => bcrypt::Version::TwoA,
        b"2x" => bcrypt::Version::TwoX,
        _ => return None,
    };
    // Rust's `u32` parsing, as pyca's: an optional `+`, ASCII digits.
    let cost = std::str::from_utf8(raw_cost).ok()?.parse::<u32>().ok()?;
    let raw_salt: [u8; 16] = BASE64_ENGINE
        .decode(remainder.get(..22)?)
        .ok()?
        .try_into()
        .ok()?;
    let hashed = bcrypt::hash_with_salt(password, cost, raw_salt).ok()?;
    Some(hashed.format_for_version(version))
}

/// `bcrypt.checkpw(password, hashed)`, `ValueError` → `false`.
pub fn checkpw(password: &[u8], hashed: &[u8]) -> bool {
    hashpw(password, hashed).is_some_and(|computed| constant_time_eq(computed.as_bytes(), hashed))
}

/// The credentials check of `ui_login`: the stripped form username compared
/// with the configured one in constant time over UTF-8 bytes, and **always**
/// the password check (`verify`, [`checkpw`] in the server), so a wrong
/// username costs as much as a wrong password and the timing does not
/// reveal the approver's name.
pub fn credentials_match(
    username: &str,
    password: &str,
    configured_username: &str,
    password_bcrypt: &str,
    verify: impl FnOnce(&[u8], &[u8]) -> bool,
) -> bool {
    let username_matches = constant_time_eq(username.as_bytes(), configured_username.as_bytes());
    let password_matches = verify(password.as_bytes(), password_bcrypt.as_bytes());
    username_matches && password_matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_password_check_always_runs() {
        for (username, expected) in [
            ("opsgate-admin", true),
            ("someone-else", false),
            ("", false),
        ] {
            let mut calls = Vec::new();
            let matched = credentials_match(
                username,
                "secret-password",
                "opsgate-admin",
                "hash",
                |password, hash| {
                    calls.push((password.to_vec(), hash.to_vec()));
                    true
                },
            );
            assert_eq!(matched, expected, "{username}");
            assert_eq!(
                calls,
                vec![(b"secret-password".to_vec(), b"hash".to_vec())],
                "{username}"
            );
        }
        assert!(!credentials_match(
            "opsgate-admin",
            "wrong",
            "opsgate-admin",
            "hash",
            |_, _| false
        ));
    }
}
