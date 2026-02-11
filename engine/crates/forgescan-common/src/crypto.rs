//! Cryptographic utilities for ForgeScan

use forgescan_core::{Error, Result};
use sha2::{Digest, Sha256};

/// Compute SHA-256 hash of data
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute SHA-256 hash and return as hex string
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Verify a SHA-256 checksum
pub fn verify_sha256(data: &[u8], expected_hex: &str) -> bool {
    sha256_hex(data).eq_ignore_ascii_case(expected_hex)
}

/// Generate a self-signed certificate for testing/development
pub fn generate_self_signed_cert(
    common_name: &str,
    validity_days: u32,
) -> Result<(String, String)> {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    let subject_alt_names = vec![common_name.to_string()];

    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| Error::Internal(format!("Failed to generate certificate: {}", e)))?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Generate a certificate signing request (CSR)
pub fn generate_csr(common_name: &str) -> Result<(String, String)> {
    use rcgen::{CertificateSigningRequestParams, KeyPair};

    let key_pair = KeyPair::generate()
        .map_err(|e| Error::Internal(format!("Failed to generate key pair: {}", e)))?;

    let mut params = CertificateSigningRequestParams::default();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String(common_name.to_string()),
    );

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| Error::Internal(format!("Failed to serialize CSR: {}", e)))?;

    Ok((csr.pem().map_err(|e| Error::Internal(format!("Failed to encode CSR: {}", e)))?, key_pair.serialize_pem()))
}

/// Load a PEM-encoded certificate
pub fn load_certificate(pem: &str) -> Result<Vec<u8>> {
    let pem_parsed = pem::parse(pem)
        .map_err(|e| Error::Configuration(format!("Invalid PEM certificate: {}", e)))?;
    Ok(pem_parsed.contents().to_vec())
}

/// Load a PEM-encoded private key
pub fn load_private_key(pem: &str) -> Result<Vec<u8>> {
    let pem_parsed = pem::parse(pem)
        .map_err(|e| Error::Configuration(format!("Invalid PEM private key: {}", e)))?;
    Ok(pem_parsed.contents().to_vec())
}

/// Generate a random UUID-based identifier
pub fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate a random API key (32 bytes, hex encoded = 64 chars)
pub fn generate_api_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256_hex(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_verify_sha256() {
        let data = b"test data";
        let hash = sha256_hex(data);
        assert!(verify_sha256(data, &hash));
        assert!(!verify_sha256(data, "invalid"));
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let (cert, key) = generate_self_signed_cert("test.local", 365).unwrap();
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(key.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_generate_id() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36); // UUID format
    }
}
