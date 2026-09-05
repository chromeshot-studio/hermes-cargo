//! Module 3b - Ed25519 verification and streaming SHA-256.
//!
//! The chain of trust has exactly two links and no third party:
//!
//! ```text
//!   .origin (on the user's disk, pinned)  --verifies-->  manifest.json (studio CDN)
//!   manifest.checksum_sha256              --verifies-->  update .zip   (studio CDN)
//! ```
//!
//! TLS is transport hygiene, not trust: a hostile CDN, a mirror, or anyone who
//! can mint a certificate still cannot produce a manifest that verifies, and
//! cannot alter a byte of the archive without breaking the checksum.

use crate::error::{SecResult, SecurityError};
use crate::schema::{Manifest, OriginFile, SignedManifest};
use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

/// Manifests older than this are still accepted (studios publish rarely), but
/// one dated in the future by more than this is rejected as a clock attack.
const MAX_CLOCK_SKEW_SECS: i64 = 24 * 60 * 60;

/// Accept base64 (standard or url-safe) or hex key material.
fn decode_key_material(s: &str, what: &str) -> SecResult<Vec<u8>> {
    let trimmed = s.trim();
    if let Ok(bytes) = STANDARD.decode(trimmed) {
        return Ok(bytes);
    }
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(trimmed.trim_end_matches('=')) {
        return Ok(bytes);
    }
    hex::decode(trimmed).map_err(|_| match what {
        "signature" => SecurityError::MalformedSignature("not valid base64 or hex".into()),
        _ => SecurityError::MalformedPublicKey("not valid base64 or hex".into()),
    })
}

/// Parse the studio's pinned Ed25519 public key from a `.origin` file.
pub fn parse_public_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes = decode_key_material(encoded, "public key")?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        SecurityError::MalformedPublicKey(format!("expected 32 bytes, got {}", bytes.len()))
    })?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| SecurityError::MalformedPublicKey(e.to_string()).into())
}

pub fn parse_signature(encoded: &str) -> Result<Signature> {
    let bytes = decode_key_material(encoded, "signature")?;
    let arr: [u8; 64] = bytes.as_slice().try_into().map_err(|_| {
        SecurityError::MalformedSignature(format!("expected 64 bytes, got {}", bytes.len()))
    })?;
    Ok(Signature::from_bytes(&arr))
}

/// Verify a fetched `manifest.json` against the key pinned in the `.origin`.
///
/// Returns the manifest **only** if:
/// 1. the signature is a valid Ed25519 signature by the pinned key over the
///    exact bytes of the `payload` object as they appear on the wire,
/// 2. the payload is structurally sound,
/// 3. it names this origin, and
/// 4. it is fresh (not expired, not implausibly future-dated).
pub fn verify_manifest(origin: &OriginFile, raw: &[u8], now: i64) -> Result<Manifest> {
    let text = std::str::from_utf8(raw).context("manifest.json is not valid UTF-8")?;
    let signed: SignedManifest =
        serde_json::from_str(text).context("manifest.json is not a signed HERMES manifest")?;

    if !signed.signature.algorithm.eq_ignore_ascii_case("ed25519") {
        return Err(SecurityError::UnsupportedAlgorithm(signed.signature.algorithm).into());
    }

    let key = parse_public_key(&origin.public_key)?;
    let signature = parse_signature(&signed.signature.value)?;

    // Sign/verify over the raw payload bytes: no re-serialisation, so no
    // canonicalisation mismatch to exploit. `verify_strict` additionally
    // rejects small-order keys and non-canonical signature encodings.
    let payload_bytes = signed.payload.get().as_bytes();
    key.verify_strict(payload_bytes, &signature)
        .map_err(|_| SecurityError::BadSignature)?;

    let manifest: Manifest = serde_json::from_str(signed.payload.get())
        .context("manifest payload is signed but malformed")?;
    manifest.validate_shape()?;

    if manifest.origin_id != origin.id {
        return Err(SecurityError::OriginMismatch {
            expected: origin.id.clone(),
            found: manifest.origin_id,
        }
        .into());
    }
    if let Some(expires) = manifest.expires_at {
        if now > expires {
            return Err(SecurityError::ManifestExpired {
                expires_at: expires,
                now,
            }
            .into());
        }
    }
    if manifest.issued_at > now + MAX_CLOCK_SKEW_SECS {
        return Err(SecurityError::ManifestFromFuture {
            issued_at: manifest.issued_at,
            now,
        }
        .into());
    }
    Ok(manifest)
}

/// Refuse a downgrade. A CDN that replays an old (validly signed!) manifest
/// would otherwise be able to walk a user back onto a patched-out version.
pub fn assert_no_rollback(installed: Option<&semver::Version>, offered: &semver::Version) -> Result<()> {
    if let Some(installed) = installed {
        if offered < installed {
            return Err(SecurityError::RollbackRefused {
                installed: installed.to_string(),
                offered: offered.to_string(),
            }
            .into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Streaming SHA-256
// ---------------------------------------------------------------------------

/// A `Write` adapter that hashes on the way past.
///
/// This is what keeps Module 4 honest: bytes go network -> hasher -> disk in
/// one pass, so the digest is known the moment the last byte lands and the
/// file never needs a second read (or a second copy in memory).
pub struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }

    /// Consume the writer and return the digest as lowercase hex.
    pub fn finish(self) -> (String, u64) {
        let digest = self.hasher.finalize();
        (hex::encode(digest), self.bytes)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Compare a computed digest against the manifest's, in constant time.
pub fn verify_checksum(expected_hex: &str, actual_hex: &str) -> SecResult<()> {
    let expected = hex::decode(expected_hex).unwrap_or_default();
    let actual = hex::decode(actual_hex).unwrap_or_default();
    let equal = expected.len() == actual.len()
        && expected.len() == 32
        && expected
            .iter()
            .zip(actual.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    if equal {
        Ok(())
    } else {
        Err(SecurityError::ChecksumMismatch {
            expected: expected_hex.to_ascii_lowercase(),
            actual: actual_hex.to_ascii_lowercase(),
        })
    }
}

/// Hash a file that is already on disk, streamed.
pub fn sha256_file(path: &std::path::Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening {} to hash", path.display()))?;
    let mut writer = HashingWriter::new(io::sink());
    crate::security::safepath::stream_copy(&mut file, &mut writer)?;
    Ok(writer.finish().0)
}

// ---------------------------------------------------------------------------
// Studio-side signing (`hermes studio ...`)
// ---------------------------------------------------------------------------

/// Sign raw payload bytes with a studio signing key.
pub fn sign_payload(signing_key: &ed25519_dalek::SigningKey, payload: &[u8]) -> String {
    use ed25519_dalek::Signer;
    STANDARD.encode(signing_key.sign(payload).to_bytes())
}

pub fn encode_public(key: &VerifyingKey) -> String {
    STANDARD.encode(key.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_origin(public_key: String) -> OriginFile {
        OriginFile {
            schema: crate::schema::ORIGIN_SCHEMA.into(),
            id: "studio.game".into(),
            name: "Game".into(),
            upstream_manifest_url: "https://cdn.example.com/manifest.json".into(),
            studio_auth_url: None,
            public_key,
            publisher: None,
            homepage: None,
            install_dir: None,
            requires_auth: false,
        }
    }

    fn signed_manifest(key: &SigningKey, payload: &str) -> String {
        let sig = sign_payload(key, payload.as_bytes());
        format!(
            r#"{{"payload":{payload},"signature":{{"algorithm":"ed25519","value":"{sig}"}}}}"#
        )
    }

    const PAYLOAD: &str = r#"{"schema":"hermes.manifest/v1","origin_id":"studio.game","latest_version":"1.2.0","download_url":"https://cdn.example.com/v1.2.0.zip","checksum_sha256":"aa00bb11cc22dd33ee44ff5500112233445566778899aabbccddeeff00112233","size_bytes":1024,"issued_at":1000}"#;

    #[test]
    fn accepts_a_correctly_signed_manifest() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let origin = test_origin(encode_public(&key.verifying_key()));
        let doc = signed_manifest(&key, PAYLOAD);
        let manifest = verify_manifest(&origin, doc.as_bytes(), 2000).expect("verifies");
        assert_eq!(manifest.latest_version, "1.2.0");
    }

    #[test]
    fn rejects_a_manifest_signed_by_another_key() {
        let studio = SigningKey::from_bytes(&[7u8; 32]);
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let origin = test_origin(encode_public(&studio.verifying_key()));
        let doc = signed_manifest(&attacker, PAYLOAD);
        let err = verify_manifest(&origin, doc.as_bytes(), 2000).unwrap_err();
        assert!(err.to_string().contains("SIGNATURE VERIFICATION FAILED"));
    }

    #[test]
    fn rejects_a_tampered_payload() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let origin = test_origin(encode_public(&key.verifying_key()));
        // Sign the real payload, then swap the download URL on the wire.
        let doc = signed_manifest(&key, PAYLOAD)
            .replace("cdn.example.com/v1.2.0.zip", "evil.example.net/pwn.zip");
        assert!(verify_manifest(&origin, doc.as_bytes(), 2000).is_err());
    }

    #[test]
    fn rejects_a_manifest_for_a_different_origin() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut origin = test_origin(encode_public(&key.verifying_key()));
        origin.id = "studio.otherapp".into();
        let doc = signed_manifest(&key, PAYLOAD);
        let err = verify_manifest(&origin, doc.as_bytes(), 2000).unwrap_err();
        assert!(err.to_string().contains("studio.game"));
    }

    #[test]
    fn refuses_version_rollback() {
        let installed = semver::Version::parse("2.0.0").unwrap();
        let offered = semver::Version::parse("1.0.0").unwrap();
        assert!(assert_no_rollback(Some(&installed), &offered).is_err());
        assert!(assert_no_rollback(Some(&installed), &installed).is_ok());
    }

    #[test]
    fn checksum_comparison_detects_a_flipped_bit() {
        let a = "aa00bb11cc22dd33ee44ff5500112233445566778899aabbccddeeff00112233";
        let b = "aa00bb11cc22dd33ee44ff5500112233445566778899aabbccddeeff00112234";
        assert!(verify_checksum(a, a).is_ok());
        assert!(verify_checksum(a, b).is_err());
    }

    #[test]
    fn hashing_writer_matches_sha256() {
        let mut w = HashingWriter::new(io::sink());
        w.write_all(b"abc").unwrap();
        let (digest, n) = w.finish();
        assert_eq!(n, 3);
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
